
import os
import sqlite3
import uuid
import json
import hmac
import hashlib

from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session,
    flash, send_file, abort, render_template_string, g
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = Path(
    os.environ.get("TRUSTVAULT_DB", BASE_DIR / "trustvault.db")
)

STORAGE_DIR = Path(
    os.environ.get("TRUSTVAULT_STORAGE", BASE_DIR / "private_uploads")
)

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "png", "jpg", "jpeg", "docx"
}

MAX_BYTES = 10 * 1024 * 1024

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "dev-only-change-this-secret"
)

AUDIT_KEY = os.environ.get(
    "AUDIT_HMAC_KEY",
    "dev-only-change-this-audit-key"
).encode()

STYLES = """
<style>
* {
    box-sizing: border-box;
}

body {
    font-family: Arial, sans-serif;
    background: #f4f6fb;
    color: #202638;
    margin: 0;
}

nav {
    background: #17233d;
    color: white;
    padding: 16px 5%;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

nav a {
    color: white;
    margin-left: 16px;
    text-decoration: none;
}

.wrap {
    max-width: 1050px;
    margin: 28px auto;
    padding: 0 18px;
}

.card {
    background: white;
    padding: 22px;
    border-radius: 12px;
    margin: 16px 0;
    box-shadow: 0 2px 12px #18243a12;
}

h1, h2 {
    margin-top: 0;
}

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
}

input, select, button {
    padding: 10px;
    border: 1px solid #ccd2df;
    border-radius: 7px;
    margin: 5px 0;
    max-width: 100%;
}

button, .btn {
    background: #2457c5;
    color: white;
    border: 0;
    padding: 10px 14px;
    border-radius: 7px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
}

.danger {
    background: #b42318;
}

.muted {
    color: #667085;
}

.msg {
    padding: 10px;
    background: #e8f4ff;
    border-radius: 7px;
    margin: 8px 0;
}

table {
    width: 100%;
    border-collapse: collapse;
}

td, th {
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #e5e7eb;
}

.small {
    font-size: 13px;
}

.inline {
    display: inline-block;
}

a {
    color: #2457c5;
}
</style>
"""


LAYOUT = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TrustVault</title>
""" + STYLES + """
</head>

<body>

<nav>
    <strong>🔐 TrustVault</strong>

    <div>
        {% if user %}
            <span>{{ user['username'] }} ({{ user['role'] }})</span>

            <a href="{{ url_for('dashboard') }}">Dashboard</a>

            {% if user['role'] == 'admin' %}
                <a href="{{ url_for('admin') }}">Admin</a>
            {% endif %}

            <a href="{{ url_for('logout') }}">Logout</a>
        {% endif %}
    </div>
</nav>

<main class="wrap">

    {% for m in get_flashed_messages() %}
        <div class="msg">{{ m }}</div>
    {% endfor %}

    {{ content|safe }}

</main>

</body>
</html>
"""

def connect():

    if "db" not in g:

        g.db = sqlite3.connect(DB_PATH)

        g.db.row_factory = sqlite3.Row

        g.db.execute("PRAGMA foreign_keys=ON")

    return g.db


@app.teardown_appcontext
def close_db(exc):

    db = g.pop("db", None)

    if db is not None:
        db.close()

def init_db():

    STORAGE_DIR.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(DB_PATH)

    db.execute("PRAGMA foreign_keys=ON")

    db.executescript("""

    CREATE TABLE IF NOT EXISTS users(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE NOT NULL,

        password_hash TEXT NOT NULL,

        role TEXT NOT NULL
        CHECK(role IN ('admin','owner','viewer')),

        created_at TEXT NOT NULL
    );


    CREATE TABLE IF NOT EXISTS documents(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        original_name TEXT NOT NULL,

        stored_name TEXT NOT NULL UNIQUE,

        owner_id INTEGER NOT NULL
        REFERENCES users(id),

        category TEXT NOT NULL,

        size_bytes INTEGER NOT NULL,

        created_at TEXT NOT NULL
    );


    CREATE TABLE IF NOT EXISTS permissions(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        document_id INTEGER NOT NULL
        REFERENCES documents(id) ON DELETE CASCADE,

        user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

        permission TEXT NOT NULL
        CHECK(permission IN ('read','edit')),

        UNIQUE(document_id,user_id)
    );


    CREATE TABLE IF NOT EXISTS audit_log(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        actor_id INTEGER,

        action TEXT NOT NULL,

        document_id INTEGER,

        target_user_id INTEGER,

        details TEXT NOT NULL,

        created_at TEXT NOT NULL,

        previous_hash TEXT NOT NULL,

        entry_hash TEXT NOT NULL
    );


    CREATE TRIGGER IF NOT EXISTS audit_no_update

    BEFORE UPDATE ON audit_log

    BEGIN

        SELECT RAISE(ABORT,'Audit records are append-only');

    END;


    CREATE TRIGGER IF NOT EXISTS audit_no_delete

    BEFORE DELETE ON audit_log

    BEGIN

        SELECT RAISE(ABORT,'Audit records are append-only');

    END;

    """)

    db.commit()

    db.close()
def now():

    return datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

def audit(
    actor_id,
    action,
    document_id=None,
    target_user_id=None,
    details=""
):

    db = connect()

    last = db.execute(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()

    prev = last["entry_hash"] if last else "GENESIS"

    record = {

        "actor_id": actor_id,

        "action": action,

        "document_id": document_id,

        "target_user_id": target_user_id,

        "details": details,

        "created_at": now(),

        "previous_hash": prev
    }

    payload = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    ).encode()

    digest = hmac.new(
        AUDIT_KEY,
        payload,
        hashlib.sha256
    ).hexdigest()

    db.execute("""

        INSERT INTO audit_log(

            actor_id,
            action,
            document_id,
            target_user_id,
            details,
            created_at,
            previous_hash,
            entry_hash

        )

        VALUES(?,?,?,?,?,?,?,?)

    """, (

        actor_id,
        action,
        document_id,
        target_user_id,
        details,
        record["created_at"],
        prev,
        digest

    ))

    db.commit()

def current_user():

    uid = session.get("user_id")

    if uid:

        return connect().execute(
            "SELECT * FROM users WHERE id=?",
            (uid,)
        ).fetchone()

    return None


def login_required(fn):

    @wraps(fn)

    def wrapper(*args, **kwargs):

        if not current_user():

            flash("Please log in first.")

            return redirect(url_for("login"))

        return fn(*args, **kwargs)

    return wrapper

def get_doc(doc_id):

    return connect().execute(
        "SELECT * FROM documents WHERE id=?",
        (doc_id,)
    ).fetchone()


def permission_for(user, doc):

    if not user or not doc:
        return None

    if (
        user["role"] == "admin"
        or user["id"] == doc["owner_id"]
    ):

        return "owner"

    row = connect().execute("""

        SELECT permission
        FROM permissions
        WHERE document_id=? AND user_id=?

    """, (doc["id"], user["id"])).fetchone()

    return row["permission"] if row else None


def require_doc_access(doc, needed="read"):

    user = current_user()

    if not doc or not user:
        abort(404)

    perm = permission_for(user, doc)

    allowed = (
        perm in ("owner", "edit")
        or (needed == "read" and perm == "read")
    )

    if not allowed:

        audit(
            user["id"],
            "ACCESS_DENIED",
            doc["id"],
            details=f"required={needed}"
        )

        abort(403)

    return user

def page(content, **kwargs):

    return render_template_string(

        LAYOUT,

        content=render_template_string(content, **kwargs),

        user=current_user()

    )
@app.route("/")
def home():

    if current_user():

        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        role = request.form.get(
            "role", "viewer"
        )

        if (
            not username
            or len(password) < 8
            or role not in ("owner", "viewer")
        ):

            flash(
                "Enter a username, a password of at least 8 characters, and a valid role."
            )

        else:

            try:

                db = connect()

                db.execute("""

                    INSERT INTO users(
                        username,
                        password_hash,
                        role,
                        created_at
                    )

                    VALUES(?,?,?,?)

                """, (

                    username,
                    generate_password_hash(password),
                    role,
                    now()

                ))

                db.commit()

                flash("Account created. Please log in.")

                return redirect(url_for("login"))

            except sqlite3.IntegrityError:

                flash("Username already exists.")

    return page("""

        <div class="card">

            <h1>Create account</h1>

            <form method="post">

                <input
                    name="username"
                    placeholder="Username"
                    required
                >

                <input
                    name="password"
                    type="password"
                    placeholder="Password (8+ characters)"
                    required
                >

                <select name="role">

                    <option value="owner">
                        Document owner
                    </option>

                    <option value="viewer">
                        Viewer
                    </option>

                </select>

                <button>Create account</button>

            </form>

            <a href="{{ url_for('login') }}">
                Back to login
            </a>

        </div>

    """)
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        user = connect().execute("""

            SELECT *
            FROM users
            WHERE username=?

        """, (username,)).fetchone()

        if user and check_password_hash(

            user["password_hash"],

            request.form.get("password", "")

        ):

            session.clear()

            session["user_id"] = user["id"]

            audit(user["id"], "LOGIN")

            return redirect(url_for("dashboard"))

        audit(
            None,
            "LOGIN_FAILED",
            details=f"username={username[:80]}"
        )

        flash("Invalid username or password.")

    return page("""

        <div class="card"
             style="max-width:430px;margin:50px auto">

            <h1>TrustVault Login</h1>

            <form method="post">

                <input
                    name="username"
                    placeholder="Username"
                    required
                    style="width:100%"
                >

                <input
                    name="password"
                    type="password"
                    placeholder="Password"
                    required
                    style="width:100%"
                >

                <button>Login</button>

            </form>

            <p>
                New user?
                <a href="{{ url_for('register') }}">
                    Create account
                </a>
            </p>

        </div>

    """)
@app.route("/logout")
@login_required
def logout():

    u = current_user()

    audit(u["id"], "LOGOUT")

    session.clear()

    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():

    u = current_user()

    db = connect()

    if u["role"] == "admin":

        docs = db.execute("""

            SELECT d.*, u.username owner_name

            FROM documents d

            JOIN users u ON u.id=d.owner_id

            ORDER BY d.id DESC

        """).fetchall()

    else:

        docs = db.execute("""

            SELECT DISTINCT
                d.*,
                u.username owner_name

            FROM documents d

            JOIN users u ON u.id=d.owner_id

            LEFT JOIN permissions p
                ON p.document_id=d.id

            WHERE d.owner_id=? OR p.user_id=?

            ORDER BY d.id DESC

        """, (u["id"], u["id"])).fetchall()

    content = """

        <div class="card">

            <h1>Document dashboard</h1>

            <p class="muted">
                Documents visible to your account.
            </p>

            {% if user['role'] in ['owner','admin'] %}

                <a class="btn" href="{{ url_for('upload') }}">
                    Upload document
                </a>

            {% endif %}

            <form method="get"
                  action="{{ url_for('dashboard') }}">

                <input
                    name="q"
                    placeholder="Search document name, owner or category"
                    value="{{ q }}"
                >

                <input
                    type="date"
                    name="date"
                    value="{{ date_filter }}"
                >

                <button>Search</button>

            </form>

            <table>

                <tr>
                    <th>Document</th>
                    <th>Owner</th>
                    <th>Category</th>
                    <th>Created</th>
                    <th>Action</th>
                </tr>

                {% for d in docs %}

                <tr>

                    <td>{{ d['original_name'] }}</td>

                    <td>{{ d['owner_name'] }}</td>

                    <td>{{ d['category'] }}</td>

                    <td>{{ d['created_at'][:10] }}</td>

                    <td>

                        <a href="{{ url_for(
                            'download',
                            doc_id=d['id']
                        ) }}">Download</a>

                        |

                        <a href="{{ url_for(
                            'document_detail',
                            doc_id=d['id']
                        ) }}">Details</a>

                    </td>

                </tr>

                {% else %}

                <tr>
                    <td colspan="5">No documents found.</td>
                </tr>

                {% endfor %}

            </table>

        </div>

    """

    q = request.args.get(
        "q", ""
    ).strip().lower()

    date_filter = request.args.get(
        "date", ""
    ).strip()

    if q:

        docs = [

            d for d in docs

            if (
                q in d["original_name"].lower()
                or q in d["owner_name"].lower()
                or q in d["category"].lower()
            )

        ]

    if date_filter:

        docs = [

            d for d in docs

            if d["created_at"].startswith(date_filter)

        ]

    return page(

        content,

        docs=docs,

        q=q,

        date_filter=date_filter,

        user=u

    )

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():

    u = current_user()

    if u["role"] not in ("owner", "admin"):
        abort(403)

    if request.method == "POST":

        f = request.files.get("file")

        category = request.form.get(
            "category", "General"
        ).strip()[:60] or "General"

        if not f or not f.filename:

            flash("Choose a file.")

        else:

            original = secure_filename(f.filename)

            ext = (
                original.rsplit(".", 1)[-1].lower()
                if "." in original else ""
            )

            data = f.read(MAX_BYTES + 1)

            if ext not in ALLOWED_EXTENSIONS:

                flash(
                    "Unsupported file type. Allowed: PDF, TXT, PNG, JPG, DOCX."
                )

            elif len(data) > MAX_BYTES:

                flash("File exceeds 10 MB.")

            elif not data:

                flash("Empty files are not accepted.")

            else:

                stored = uuid.uuid4().hex

                (STORAGE_DIR / stored).write_bytes(data)

                cur = connect().execute("""

                    INSERT INTO documents(

                        original_name,
                        stored_name,
                        owner_id,
                        category,
                        size_bytes,
                        created_at

                    )

                    VALUES(?,?,?,?,?,?)

                """, (

                    original,
                    stored,
                    u["id"],
                    category,
                    len(data),
                    now()

                ))

                connect().commit()

                audit(

                    u["id"],
                    "UPLOAD",
                    cur.lastrowid,
                    details=f"name={original};bytes={len(data)}"

                )

                flash("Document uploaded securely.")

                return redirect(url_for("dashboard"))

    return page("""

        <div class="card">

            <h1>Upload document</h1>

            <form method="post"
                  enctype="multipart/form-data">

                <label>Choose file (max 10 MB)</label>

                <br>

                <input
                    type="file"
                    name="file"
                    required
                >

                <br>

                <label>Category</label>

                <br>

                <input
                    name="category"
                    placeholder="Contracts, HR, Finance..."
                    value="General"
                >

                <br>

                <button>Upload</button>

            </form>

        </div>

    """)

@app.route("/document/<int:doc_id>")
@login_required
def document_detail(doc_id):

    doc = get_doc(doc_id)

    u = require_doc_access(doc, "read")

    is_owner = (
        u["id"] == doc["owner_id"]
        or u["role"] == "admin"
    )

    can_edit = permission_for(
        u, doc
    ) in ("owner", "edit")

    grants = connect().execute("""

        SELECT
            p.permission,
            u.username,
            u.id AS user_id

        FROM permissions p

        JOIN users u ON u.id = p.user_id

        WHERE p.document_id = ?

    """, (doc_id,)).fetchall() if is_owner else []

    users = connect().execute("""

        SELECT id, username

        FROM users

        WHERE role != 'admin'
        AND id != ?

        ORDER BY username

    """, (doc["owner_id"],)).fetchall() if is_owner else []

    return page("""

        <div class="card">

            <h1>{{ doc['original_name'] }}</h1>

            <p>
                Category: {{ doc['category'] }} |
                Size: {{ doc['size_bytes'] }} bytes
            </p>

            <a class="btn"
               href="{{ url_for(
                   'download',
                   doc_id=doc['id']
               ) }}">
                Download
            </a>


            {% if can_edit %}

            <h2>Edit document category</h2>

            <form method="post"
                  action="{{ url_for(
                      'edit_document',
                      doc_id=doc['id']
                  ) }}">

                <input
                    type="text"
                    name="category"
                    value="{{ doc['category'] }}"
                    required
                >

                <button type="submit">
                    Save changes
                </button>

            </form>

            {% endif %}


            {% if is_owner %}

            <h2>Grant access</h2>

            <form method="post"
                  action="{{ url_for(
                      'grant',
                      doc_id=doc['id']
                  ) }}">

                <select name="user_id" required>

                    {% for x in users %}

                    <option value="{{ x['id'] }}">
                        {{ x['username'] }}
                    </option>

                    {% endfor %}

                </select>

                <select name="permission">

                    <option value="read">READ</option>

                    <option value="edit">EDIT</option>

                </select>

                <button type="submit">
                    Grant Access
                </button>

            </form>


            <h2>Current permissions</h2>

            <table>

                <tr>
                    <th>User</th>
                    <th>Permission</th>
                    <th>Action</th>
                </tr>

                {% for grant in grants %}

                <tr>

                    <td>{{ grant['username'] }}</td>

                    <td>{{ grant['permission'] }}</td>

                    <td>

                        <form method="post"

                              action="{{ url_for(
                                  'revoke',
                                  doc_id=doc['id'],
                                  user_id=grant['user_id']
                              ) }}"

                              onsubmit="return confirm(
                                  'Revoke this permission?'
                              )">

                            <button
                                type="submit"
                                class="danger"
                            >
                                Revoke Access
                            </button>

                        </form>

                    </td>

                </tr>

                {% endfor %}

            </table>

            {% endif %}

        </div>

    """,

        doc=doc,

        is_owner=is_owner,

        can_edit=can_edit,

        grants=grants,

        users=users

    )
@app.route("/document/<int:doc_id>/download")
@login_required
def download(doc_id):

    doc = get_doc(doc_id)

    u = require_doc_access(doc, "read")

    path = STORAGE_DIR / doc["stored_name"]

    if not path.is_file():
        abort(404)

    audit(

        u["id"],
        "DOWNLOAD",
        doc_id,
        details=f"name={doc['original_name']}"

    )

    return send_file(

        path,

        as_attachment=True,

        download_name=doc["original_name"]

    )

@app.route(
    "/document/<int:doc_id>/edit",
    methods=["POST"]
)
@login_required
def edit_document(doc_id):

    doc = get_doc(doc_id)

    u = require_doc_access(doc, "edit")

    category = request.form.get(
        "category", ""
    ).strip()[:60]

    if not category:

        flash("Category cannot be empty.")

    else:

        connect().execute("""

            UPDATE documents

            SET category=?

            WHERE id=?

        """, (category, doc_id))

        connect().commit()

        audit(

            u["id"],
            "EDIT_METADATA",
            doc_id,
            details=f"category={category}"

        )

        flash("Document metadata updated.")

    return redirect(
        url_for("document_detail", doc_id=doc_id)
    )
@app.route(
    "/document/<int:doc_id>/grant",
    methods=["POST"]
)
@login_required
def grant(doc_id):

    doc = get_doc(doc_id)

    u = require_doc_access(doc, "read")

    if (
        u["id"] != doc["owner_id"]
        and u["role"] != "admin"
    ):
        abort(403)

    try:

        target = int(
            request.form.get("user_id")
        )

    except (TypeError, ValueError):

        abort(400)

    perm = request.form.get("permission")

    target_user = connect().execute("""

        SELECT id

        FROM users

        WHERE id=?
        AND role != 'admin'

    """, (target,)).fetchone()

    if not target_user or perm not in ("read", "edit"):
        abort(400)

    db = connect()

    db.execute("""

        INSERT INTO permissions(
            document_id,
            user_id,
            permission
        )

        VALUES(?,?,?)

        ON CONFLICT(document_id,user_id)

        DO UPDATE SET
            permission=excluded.permission

    """, (doc_id, target, perm))

    db.commit()

    audit(
        u["id"],
        "GRANT_PERMISSION",
        doc_id,
        target,
        details=perm
    )

    flash("Permission granted.")

    return redirect(
        url_for("document_detail", doc_id=doc_id)
    )
@app.route(
    "/document/<int:doc_id>/revoke/<int:user_id>",
    methods=["POST"]
)
@login_required
def revoke(doc_id, user_id):

    doc = get_doc(doc_id)

    u = require_doc_access(doc, "read")

    if (
        u["id"] != doc["owner_id"]
        and u["role"] != "admin"
    ):
        abort(403)

    db = connect()

    db.execute("""

        DELETE FROM permissions

        WHERE document_id=?
        AND user_id=?

    """, (doc_id, user_id))

    db.commit()

    audit(
        u["id"],
        "REVOKE_PERMISSION",
        doc_id,
        user_id
    )

    flash("Access revoked immediately.")

    return redirect(
        url_for("document_detail", doc_id=doc_id)
    )
@app.route(
    "/document/<int:doc_id>/delete",
    methods=["POST"]
)
@login_required
def delete_document(doc_id):

    doc = get_doc(doc_id)

    u = require_doc_access(doc, "read")

    if (
        u["id"] != doc["owner_id"]
        and u["role"] != "admin"
    ):
        abort(403)

    audit(

        u["id"],
        "DELETE",
        doc_id,
        details=f"name={doc['original_name']}"

    )

    (STORAGE_DIR / doc["stored_name"]).unlink(
        missing_ok=True
    )

    connect().execute(

        "DELETE FROM documents WHERE id=?",

        (doc_id,)

    )

    connect().commit()

    flash("Document deleted.")

    return redirect(url_for("dashboard"))
@app.route("/admin")
@login_required
def admin():

    u = current_user()

    if u["role"] != "admin":
        abort(403)

    logs = connect().execute("""

        SELECT
            a.*,
            u.username actor_name

        FROM audit_log a

        LEFT JOIN users u
            ON u.id=a.actor_id

        ORDER BY a.id DESC

        LIMIT 200

    """).fetchall()

    return page("""

        <div class="card">

            <h1>Administrator activity</h1>

            <p>Latest 200 audit events</p>

            <table>

                <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Document</th>
                    <th>Details</th>
                </tr>

                {% for x in logs %}

                <tr>

                    <td class="small">
                        {{ x['created_at'] }}
                    </td>

                    <td>
                        {{ x['actor_name'] or 'Unknown' }}
                    </td>

                    <td>{{ x['action'] }}</td>

                    <td>
                        {{ x['document_id'] or '-' }}
                    </td>

                    <td>{{ x['details'] }}</td>

                </tr>

                {% endfor %}

            </table>

        </div>

    """, logs=logs)

@app.errorhandler(403)
def forbidden(e):

    return page("""

        <div class="card">

            <h1>403 – Access denied</h1>

            <p>
                You do not have permission to access this resource.
                This attempt may be recorded in the audit trail.
            </p>

            <a href="{{ url_for('dashboard') }}">
                Return to dashboard
            </a>

        </div>

    """), 403


@app.errorhandler(404)
def not_found(e):

    return page("""

        <div class="card">

            <h1>404 – Not found</h1>

            <p>Document or page not found.</p>

        </div>

    """), 404
if __name__ == "__main__":

    init_db()

    app.run(debug=True)
