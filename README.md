# TrustVault — Secure Document Sharing

Beginner-friendly Flask + SQLite implementation of the Snovasys TrustVault challenge.

## Requirements
- Python 3.10+
- pip

## Setup (Windows)
1. Open this folder in VS Code.
2. Open Terminal.
3. Create and activate a virtual environment:

   ```powershell
   py -m venv venv
   .\venv\Scripts\activate
   ```

4. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

5. Create demo accounts:

   ```powershell
   py seed.py
   ```

6. Start the application:

   ```powershell
   py app.py
   ```

7. Open http://127.0.0.1:5000

## Demo accounts — local demonstration only
- admin / Admin@12345
- owner1 / Owner@12345
- viewer1 / Viewer@12345
- viewer2 / Viewer2@12345

Change demo passwords before any deployment. Never use the development secret keys in production.

## Demonstration workflow
1. Login as owner1 and upload a PDF or TXT document.
2. Open its Details page.
3. Grant READ access to viewer1.
4. Log out and log in as viewer1; verify the document is visible and downloadable.
5. Log in as viewer2; verify the same document is not visible and direct download returns 403.
6. As owner1, revoke viewer1 permission; test that viewer1 can no longer download.
7. Log in as admin and inspect the audit log.

## Run automated security tests
```powershell
python -m unittest discover -s tests -v
```

## Security design
- Uploaded files are stored in private_uploads, never in Flask's static folder.
- The only download route checks authorization on the server.
- Passwords are stored as Werkzeug password hashes.
- Audit records are append-only through SQLite triggers and linked by an HMAC chain.
- Permission revocation is checked on each request.

## Important limitations before production
This is a learning MVP, not a production-certified document security product. Add CSRF protection, HTTPS, secure cookie settings, login rate limiting, malware/content scanning, robust MIME and file-signature checks, backups, external immutable audit storage, and operational monitoring. Test every API route. The dashboard supports basic search by filename, owner, category and upload date. See API.md for the route and authorization reference.
