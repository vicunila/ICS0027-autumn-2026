#Made by Victor Laino
#student number 251773iCVM
import os
import getpass
import logging
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, send_file, abort
from functools import wraps
import bcrypt
import io
import secrets
import hmac
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM #I will use CBC for now because I had implemented it in the past. will switch to GCM in checkpoint 3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.exceptions import InvalidTag

#TODO checkpoint 3 and final: session timeout, logging, gitignore, pw change, user blocking, input sanitazation in auth, tls with mkcert, randomized user and file ids


# directories, locally simulates having some server structure
MainDir = os.path.dirname(os.path.abspath(__file__)) #secure directory used
db = os.path.join(MainDir, "databases", "main.db") #database
fs = os.path.join(MainDir, "files_storage") #file storage server object
lg = os.path.join(MainDir, "logging.log") #logging

#logging in variables
maxpwL = 20
minpwL = 8
maxusrnL = 20
minusrnL = 5

#upload limits
maxnameL = 100
maxfiles = 1000
maxsize = 16 * 1024 * 1024 * 1024 #16GB
allowedExt = {"txt", "pdf", "png", "jpg", "gif", "docx"} #I will add more

#crypto stuff
SaltSize = 32
def password2key(password, salt):
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=salt, length=32, iterations=9999)
    return key.derive(password)

def encrypt(file, password):

    key = b'\x00'
    salt = os.urandom(SaltSize)
    nonce = os.urandom(12)
    key = password2key(password, salt)
    ciphered = AESGCM(key).encrypt(nonce, file, None)
    return salt + nonce + ciphered


def decrypt(ciphered, password): 

    salt = ciphered[:SaltSize]
    nonce = ciphered[SaltSize:SaltSize + 12]
    ciphertext = ciphered[SaltSize + 12:]
    key = password2key(password, salt)
    file = AESGCM(key).decrypt(nonce, ciphertext, None)
    return file

#INITIALIZATION OF SERVER, DB, AND LOGS

def init_db():
    os.makedirs(os.path.dirname(db), exist_ok=True)
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pwhash BLOB NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS files (
        file_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        filename TEXT NOT NULL,
        date_added TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_download TEXT)""")
    con.commit()
    con.close()

def init_fs():
    os.makedirs(fs, exist_ok=True)

def init_lg():
    pass

#ACTUAL WEBSITE

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024 * 1024 #maximum file size 16GB

usrkeys = {}
def login_required(view):
    @wraps(view)
    def logincheck(*args, **kwargs):
        if  "user_id" not in session or session["user_id"] not in usrkeys:
            return redirect(url_for('loginPage'))
        return view(*args, **kwargs)
    return logincheck

def get_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]

@app.context_processor
def add_csrf():
    return {"csrf_token": get_csrf}

@app.before_request
def check_csrf():
    if request.method != "POST":
        return
    sent = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400)

@app.after_request
def set_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.route("/", methods=["GET"])
def welcomePage():
    return render_template("mainpage.html") #tell the user what this whole project is, two links -> sign in or register

# REGISTRATION

@app.route("/register", methods=["GET"])
def registerPage():
    return render_template("register.html") #registration page username and pw form + confirm password

@app.route("/register", methods=["POST"])
def register(): 
    usrn = request.form.get("username", "") #TO BE IMPLEMENTED: input sanitazation, will be done in checkpoint 3
    pw = request.form.get("password", "")
    pwconf = request.form.get("confirm password", "")
    if len(usrn) < minusrnL or len(usrn) > maxusrnL or not usrn.isalnum():
        return render_template("register.html", error="Invalid username"), 400
    if len(pw) < minpwL or len(pw) > maxpwL:
        return render_template("register.html", error="Invalid password"), 400
    if pw != pwconf:
        return render_template("register.html", error="Passwords do not match"), 400
    hashedPassword = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)) 
    con = sqlite3.connect(db)
    try:
        con.execute("INSERT INTO users (username, pwhash) VALUES (?, ?)",(usrn, hashedPassword),)
        con.commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", error="Username already exists"), 400
    finally:
        con.close()
    return redirect(url_for("loginPage"))

# LOGIN and LOGOUT

@app.route("/login", methods=["GET"])
def loginPage():
    return render_template("login.html") #login page, username and pw form

@app.route("/login", methods=["POST"])
def login(): #to implement: check if user needs to change pw (had pw for over 4 months) if yes redirect to password change
    usrn = request.form.get("username", "") #TO BE IMPLEMENTED: input sanitazation, will be done in checkpoint 3
    pw = request.form.get("password", "")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    check = con.execute("SELECT user_id, pwhash FROM users WHERE username = ?",(usrn,)).fetchone()
    if (check is None or not bcrypt.checkpw(pw.encode("utf-8"), check["pwhash"])):
        con.close()
        return render_template("login.html", error="Invalid username or password."), 400
    user_id = check["user_id"]
    con.close()
    session["user_id"] = user_id
    usrkeys[user_id] = password2key(pw.encode("utf-8"), check["pwhash"])
    return redirect(url_for("userPage"))    

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    usrkeys.pop(session["user_id"], None)
    session.clear()
    return redirect(url_for("welcomePage"))

# PW CHANGE, to be implemented checkpoint 3

@app.route("/password_update", methods=["GET"])
@login_required
def pwchangePage():
    return render_template("pwchange.html") #when user decides OR is forced to change password, asks for usrname, old pw, new pw, new pw confirmation
@app.route("/password_update", methods=["POST"])
@login_required
def pwchange():
    pass #mix of login and registration checks will be necessary

#UPLOAD

@app.route("/files", methods=["GET"])
@login_required
def userPage():
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        filelist = con.execute("SELECT file_id, filename, date_added, last_download FROM files WHERE user_id = ? ORDER BY date_added DESC", (session["user_id"],)).fetchall()
    finally:
        con.close()
    return render_template("files.html", files=filelist)

@app.route("/files", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if file is None or file.filename == "" or file.filename == None:
        return "No file selected", 400
    filename = secure_filename(file.filename)
    if not filename or len(filename) > maxnameL or len(filename) < 2:
        return "Invalid file name", 400
    if "." not in filename or filename.rsplit(".", 1)[1].lower() not in allowedExt:
        return "File type not allowed", 400
    data = file.read()
    if len(data) == 0:
        return "File is empty", 400
    if len(data) > maxsize:
        return "File too large", 400
    hash = usrkeys[session["user_id"]]
    cipher = encrypt(data, hash)
    con = sqlite3.connect(db)
    path = None
    try:
        count = con.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (session["user_id"],)).fetchone()[0]
        if count >= maxfiles:
            return "File limit reached", 400
        nsrt = con.execute("INSERT INTO files (user_id, filename, date_added) VALUES (?, ?, CURRENT_TIMESTAMP)", (session["user_id"], filename))
        file_id = nsrt.lastrowid
        path = os.path.join(fs, str(file_id))
        with open(os.path.join(fs, str(file_id)), "wb") as f:
            f.write(cipher) #there will be try except cases here, it simulates a configured server, but I wanna avoid OS issues when uploading files, so an error needs to be handled
        con.commit()
    except Exception:
        if path and os.path.exists(path):
            os.remove(path) #files to be removed in case of an error while uploading
        raise
    finally:
        con.close()
    return redirect(url_for("userPage"))
#DOWNLOAD

@app.route("/files/<int:file_id>", methods=["GET"])
@login_required
def download(file_id):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT filename FROM files WHERE file_id = ? AND user_id = ?", (file_id, session["user_id"])).fetchone()
        if row is None:
            return "File not found", 400
        hash = usrkeys[session["user_id"]]
        path =  os.path.join(fs, str(file_id))
        with open(path, "rb") as f:
            cipher = f.read()
        try:
            file = decrypt(cipher, hash)
        except InvalidTag:
            return "File could not be decrypted", 500
        con.execute("UPDATE files SET last_download = CURRENT_TIMESTAMP WHERE file_id = ?", (file_id,))
        con.commit()
    finally:
            con.close()
    return send_file(io.BytesIO(file), as_attachment=True, download_name=row["filename"])

#DELETE

@app.route("/files/<int:file_id>/delete", methods=["POST"])
@login_required
def delete(file_id):
    con = sqlite3.connect(db)
    try:
        row2dlt = con.execute("DELETE FROM files WHERE file_id = ? AND user_id = ?", (file_id, session["user_id"]))
        if row2dlt.rowcount == 0:
            return "File not found", 400
        con.commit()
    finally:
        con.close()
    path = os.path.join(fs, str(file_id))
    if os.path.exists(path):
        os.remove(path)
    return redirect(url_for("userPage"))

#Main

if __name__ == "__main__":
    if not os.path.exists(db):
        init_db() #running app for the first time may end up 
    if not os.path.exists(fs):
        init_fs() #maybe not even needed, it just has to be a folder
    if not os.path.exists(lg):
        init_lg() #checkpoint 3 problem

    app.run(port=5000, debug=False, ssl_context="adhoc")