import os, tempfile, unittest
from pathlib import Path
from app import app, init_db, connect

class TrustVaultSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        app.config["TESTING"]=True
        import app as module
        module.DB_PATH=Path(self.tmp.name)/"test.db"
        module.STORAGE_DIR=Path(self.tmp.name)/"uploads"
        init_db()
        self.client=app.test_client()
        with app.app_context():
            db=connect()
            from werkzeug.security import generate_password_hash
            from app import now
            for name,pw,role in [("alice","Password123","owner"),("bob","Password123","viewer")]:
                db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                           (name,generate_password_hash(pw),role,now()))
            db.commit()
            self.alice=db.execute("SELECT id FROM users WHERE username='alice'").fetchone()["id"]
            self.bob=db.execute("SELECT id FROM users WHERE username='bob'").fetchone()["id"]
            cur=db.execute("""INSERT INTO documents(original_name,stored_name,owner_id,category,size_bytes,created_at)
                VALUES('secret.txt','stored-secret',?,'Private',6,?)""",(self.alice,now()))
            self.doc_id=cur.lastrowid
            (module.STORAGE_DIR/"stored-secret").write_text("secret")
            db.commit()

    def tearDown(self): self.tmp.cleanup()

    def login(self,name):
        return self.client.post("/login",data={"username":name,"password":"Password123"},follow_redirects=True)

    def test_ungranted_user_cannot_download(self):
        self.login("bob")
        response=self.client.get(f"/document/{self.doc_id}/download")
        self.assertEqual(response.status_code,403)

    def test_granted_user_can_download(self):
        with app.app_context():
            connect().execute("INSERT INTO permissions(document_id,user_id,permission) VALUES(?,?,?)",
                              (self.doc_id,self.bob,"read"))
            connect().commit()
        self.login("bob")
        response=self.client.get(f"/document/{self.doc_id}/download")
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.data,b"secret")

    def test_revoked_access_stops_working(self):
        with app.app_context():
            db=connect()
            db.execute("INSERT INTO permissions(document_id,user_id,permission) VALUES(?,?,?)",
                       (self.doc_id,self.bob,"read")); db.commit()
        self.login("bob")
        self.assertEqual(self.client.get(f"/document/{self.doc_id}/download").status_code,200)
        with app.app_context():
            connect().execute("DELETE FROM permissions WHERE document_id=? AND user_id=?",
                              (self.doc_id,self.bob)); connect().commit()
        self.assertEqual(self.client.get(f"/document/{self.doc_id}/download").status_code,403)

if __name__=="__main__": unittest.main()
