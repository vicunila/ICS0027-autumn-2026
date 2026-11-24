#Made by Victor Laino
#student number 251773ICVM
import os
import logging
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, send_file
from functools import wraps
import bcrypt
import io
import secrets
import hmac
import re
import time
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

#TODO before final handout: gitignore, pw change, multisession blocking, secure deletion (not just os.remove)


# directories, locally simulates having some server structure
MainDir = os.path.dirname(os.path.abspath(__file__)) #secure directory used
db = os.path.join(MainDir, "databases", "main.db") #database
fs = os.path.join(MainDir, "files_storage") #file storage server object
lg = os.path.join(MainDir, "logging.log") #logging

#logging in variables
maxpwL = 20 #max password length
minpwL = 8 #min password length
maxusrnL = 20 #max username length
minusrnL = 5 #min username length
AllowedCharsusrn = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" #only alphanumerics in the username
AllowedCharspw = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*" #only alphanumerics and special chars in pw
IdleTimeout = 30 * 60 #30min
AuthTimeout = 10 * 60 #10min
AbsoluteTimeout = 10 * 60 * 60 #10hrs
AllowedCharsid = "0123456789abcdef" #needed for userIds or fileIds: HEX only
IdLength = 32

#upload limits
maxnameL = 100 #max 100 chars in filename
maxfiles = 1000 #max 1000 files per user
maxsize = 50 * 1024 * 1024 #50MB max upload size, forced by flask
allowedExt = {"txt", "pdf", "png", "jpg", "gif", "docx"} #allowed extensions

#user block limits
loginMaxFails = 5 #failed logins allowed from one ip
loginWindow = 30 #30 min window for ip limit to reset (changed to 30s for testing)
ipBlockTime = 1 * 60 #1 hr ip block time (changed to 1 min for testing)

#cryptography
SaltSize = 32
itrtns = 999999
def password2key(password, salt):
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=salt, length=32, iterations=itrtns)
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

logger = logging.getLogger("SecureFileManager")
def init_lg():
    if logger.handlers: #if logger already exist, do nothing
        return
    logger.setLevel(logging.INFO)
    fileHandling = logging.FileHandler(lg, mode='a', maxBytes= 5 * 1024 * 1024)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fileHandling.setFormatter(formatter)
    logger.addHandler(fileHandling)
    logger.info("logger_initialized")

def cleanusername(value):
    return "".join(c if c in AllowedCharsusrn else "?" for c in str(value)[:maxusrnL+20])

def init_db():
    os.makedirs(os.path.dirname(db), exist_ok=True)
    con = sqlite3.connect(db)
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY NOT NULL,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        pwhash BLOB NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS files (
        file_id TEXT PRIMARY KEY NOT NULL,
        user_id TEXT NOT NULL REFERENCES users(user_id),
        filename TEXT NOT NULL,
        date_added TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_download TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS login_blocks (
        ip TEXT PRIMARY KEY NOT NULL,
        failures INTEGER NOT NULL DEFAULT 0,
        window_start REAL NOT NULL,
        blocked_until REAL NOT NULL DEFAULT 0)""")
    con.commit()
    con.close()

def new_user_id(con):
    for _ in range(3): #if, very unluckily, the userId/fileId happens to already exist, it tries again, up to 3 times
        uid = secrets.token_hex(IdLength // 2)
        if con.execute("SELECT 1 FROM users WHERE user_id = ?", (uid,)).fetchone() is None:
            return uid
    logger.error(f"ip={request.remote_addr} could_not_generate_unique_userid")
    raise RuntimeError("Could not generate a unique user id")

def new_file_id(con):
    for _ in range(3):
        fid = secrets.token_hex(IdLength // 2)
        if con.execute("SELECT 1 FROM files WHERE file_id = ?", (fid,)).fetchone() is None:
            return fid
    logger.error(f"ip={request.remote_addr} could_not_generate_unique_fileid")
    raise RuntimeError("Could not generate a unique file id")

def valid_id(value):
    return len(value) == IdLength and all(c in AllowedCharsid for c in value)

def init_fs():
    os.makedirs(fs, exist_ok=True)

#ACTUAL WEBSITE

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024 #maximum file size 50MB

usrkeys = {}
def login_required(view):
    @wraps(view)
    def logincheck(*args, **kwargs):
        if  "user_id" not in session or session["user_id"] not in usrkeys:
            logger.info(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=unauthenticated_access")
            return redirect(url_for('loginPage'))
        return view(*args, **kwargs)
    return logincheck

@app.before_request
def check_timeout():
    now = time.time()
    if "last_seen" in session:
        if "user_id" in session:
            expired = now - session["last_seen"] > IdleTimeout or now - session.get("created", 0) > AbsoluteTimeout
        else:
            expired = now - session["last_seen"] > AuthTimeout
        if expired:
            logger.info(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=session_expired")
            usrkeys.pop(session.get("user_id"), None)
            session.clear()
            return redirect(url_for("loginPage"))
    session["last_seen"] = now

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
    sent = request.form.get("csrf_token", "").encode()
    expected = session.get("csrf_token", "").encode()
    if not expected or not hmac.compare_digest(sent, expected):
        logger.warning(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=csrf_failed")
        usrkeys.pop(session.get("user_id"), None)
        session.clear()
        return redirect(url_for("loginPage"))

@app.after_request
def set_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

@app.errorhandler(Exception)
def serverError(e):
    code = e.code if isinstance(e, HTTPException) else 500
    if request.endpoint == "register":
        logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=server_error endpoint={request.endpoint} status={code}", exc_info=True)
        return render_template("register.html", error="Something went wrong"), code
    if request.endpoint in ("upload", "download", "delete", "userPage"):
        logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=server_error endpoint={request.endpoint} status={code}", exc_info=True) 
        return userPage("Something went wrong"), code
    if request.endpoint in ("login", "pwchange"):
        logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=server_error endpoint={request.endpoint} status={code}", exc_info=True)
        usrkeys.pop(session.get("user_id"), None)
        session.clear()
        return render_template("login.html", error="Something went wrong"), code
    else:
        logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=server_error endpoint={request.endpoint} status={code}", exc_info=True)
        return render_template("mainpage.html", error="Something went wrong"), code

@app.route("/", methods=["GET"])
def welcomePage():
    return render_template("mainpage.html") #tell the user what this whole project is, two links -> sign in or register

# REGISTRATION

@app.route("/register", methods=["GET"])
def registerPage():
    return render_template("register.html") #registration page username and pw form + confirm password

@app.route("/register", methods=["POST"])
def register(): 
    usrn = request.form.get("username", "")
    pw = request.form.get("password", "")
    pwconf = request.form.get("confirm password", "")

    if len(usrn) < minusrnL or len(usrn) > maxusrnL or any(c not in AllowedCharsusrn for c in usrn):
        logger.info(f"user={cleanusername(usrn)} event=invalid_username")
        return render_template("register.html", error="Invalid username"), 400
    if len(pw) < minpwL or len(pw) > maxpwL or any(c not in AllowedCharspw for c in pw):
        logger.info(f"user={cleanusername(usrn)} event=invalid_password_size")
        return render_template("register.html", error="Invalid password"), 400
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw) and re.search(r"[0-9]", pw) and re.search(r"[!@#$%^&*]", pw)):
        logger.info(f"user={cleanusername(usrn)} event=weak_password")
        return render_template("register.html", error="Invalid password"), 400
    if pw != pwconf:
        logger.info(f"user={cleanusername(usrn)} event=passwords_dont_match")
        return render_template("register.html", error="Passwords do not match"), 400
    
    hashedPassword = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)) 
    con = sqlite3.connect(db)
    try:
        user_id = new_user_id(con)
        con.execute("INSERT INTO users (user_id, username, pwhash) VALUES (?, ?, ?)", (user_id, usrn, hashedPassword))
        con.commit()
        logger.info(f"user={cleanusername(usrn)} event=user_successfully_created")
    except sqlite3.IntegrityError:
        logger.warning(f"user={cleanusername(usrn)} ip={request.remote_addr} event=username_exists_already")
        return render_template("register.html", error="Username already exists"), 409
    finally:
        con.close()
    return redirect(url_for("loginPage"))

# LOGIN and LOGOUT

@app.route("/login", methods=["GET"])
def loginPage():
    return render_template("login.html") #login page, username and pw form

@app.route("/login", methods=["POST"])
def login(): #to implement: check if user needs to change pw (had pw for over 4 months) if yes redirect to password change

    usrn = request.form.get("username", "")
    pw = request.form.get("password", "")
    if len(usrn) < minusrnL or len(usrn) > maxusrnL or any(c not in AllowedCharsusrn for c in usrn):
            logger.warning(f"user={cleanusername(usrn)} ip={request.remote_addr} event=invalid_username_format")
            return render_template("login.html", error="Invalid username or password"), 401
    if len(pw) < minpwL or len(pw) > maxpwL or any(c not in AllowedCharspw for c in pw):
            logger.warning(f"user={cleanusername(usrn)} ip={request.remote_addr} event=invalid_password_format")
            return render_template("login.html", error="Invalid username or password"), 401
    
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    block = con.execute("SELECT failures, window_start, blocked_until FROM login_blocks WHERE ip = ?", (request.remote_addr,)).fetchone()
    if block is not None and block["blocked_until"] > time.time():
        con.close()
        logger.warning(f"user={cleanusername(usrn)} ip={request.remote_addr} event=login_blocked_ip")
        return render_template("login.html", error="Too many failed attempts, try again later"), 429
    
    check = con.execute("SELECT user_id, pwhash FROM users WHERE username = ?",(usrn,)).fetchone()
    if (check is None or not bcrypt.checkpw(pw.encode("utf-8"), check["pwhash"])):
        if block is None or time.time() - block["window_start"] > loginWindow:
            con.execute("INSERT OR REPLACE INTO login_blocks (ip, failures, window_start, blocked_until) VALUES (?, 1, ?, 0)", (request.remote_addr, time.time()))
        else:
            fails = block["failures"] + 1
            blockUser = time.time() + ipBlockTime if fails >= loginMaxFails else 0
            con.execute("UPDATE login_blocks SET failures = ?, blocked_until = ? WHERE ip = ?", (fails, blockUser, request.remote_addr))
            if blockUser:
                logger.warning(f"user={cleanusername(usrn)} ip={request.remote_addr} event=ip_blocked")
        con.commit()
        con.close()
        logger.warning(f"user={cleanusername(usrn)} ip={request.remote_addr} event=incorrect_credentials")
        return render_template("login.html", error="Invalid username or password"), 401
    user_id = check["user_id"]
    con.close()

    if "user_id" in session:
        usrkeys.pop(session.get("user_id"), None)
    session.clear()
    session["user_id"] = user_id
    usrkeys[user_id] = password2key(pw.encode("utf-8"), check["pwhash"])
    session["created"] = time.time()
    session["last_seen"] = time.time()
    session["username"] = cleanusername(usrn)
    logger.info(f"user={cleanusername(usrn)} event=user_logged_in")
    return redirect(url_for("userPage"))    

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logger.info(f"user={cleanusername(session.get("username", "?"))} event=user_logged_out")
    usrkeys.pop(session["user_id"], None)
    session.clear()
    return redirect(url_for("welcomePage"))

# PW CHANGE, to be implemented checkpoint 3

@app.route("/password_update", methods=["GET"])
@login_required
def pwchangePage():
    logger.error(f"user={cleanusername(session.get("username", "?"))} event=user_got_in_password_change")
    return render_template("pwchange.html") #when user decides OR is forced to change password, asks for usrname, old pw, new pw, new pw confirmation
@app.route("/password_update", methods=["POST"])
@login_required
def pwchange():
    usrkeys.pop(session["user_id"], None)
    session.clear()
    return redirect(url_for("welcomePage")) #temporary code, if triggered they will just log out user

#UPLOAD

@app.route("/files", methods=["GET"])
@login_required
def userPage(error=""):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        filelist = con.execute("SELECT file_id, filename, date_added, last_download FROM files WHERE user_id = ? ORDER BY date_added DESC", (session["user_id"],)).fetchall()
    finally:
        con.close()
    return render_template("files.html", files=filelist, error=error)

@app.route("/files", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    if file is None or file.filename == "" or file.filename == None:
        logger.info(f"user={cleanusername(session.get("username","?"))} event=empty_file_uploaded")
        return userPage("No file selected"), 400
    filename = secure_filename(file.filename)
    if not filename or len(filename) > maxnameL or len(filename) < 2:
        logger.info(f"user={cleanusername(session.get("username","?"))} event=filename_with_invalid_length")
        return userPage("Invalid file name"), 400
    if "." not in filename or filename.rsplit(".", 1)[1].lower() not in allowedExt:
        logger.warning(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=unallowed_file_extension")
        return userPage("File type not allowed"), 415
    data = file.read()
    if len(data) == 0:
        logger.info(f"user={cleanusername(session.get("username","?"))} event=empty_file")
        return userPage("File is empty"), 400
    if len(data) > maxsize:
        logger.info(f"user={cleanusername(session.get("username","?"))} event=file_is_too_big")
        return userPage("File too large"), 413
    hash = usrkeys[session["user_id"]]
    cipher = encrypt(data, hash)
    con = sqlite3.connect(db)
    path = None
    try:
        count = con.execute("SELECT COUNT(*) FROM files WHERE user_id = ?", (session["user_id"],)).fetchone()[0]
        if count >= maxfiles:
            logger.info(f"user={cleanusername(session.get("username","?"))} event=upload_file_limit_reached")
            return userPage("File limit reached"), 409
        file_id = new_file_id(con)
        con.execute("INSERT INTO files (file_id, user_id, filename) VALUES (?, ?, ?)", (file_id, session["user_id"], filename))
        path = os.path.join(fs, file_id)
        try:
            with open(path, "wb") as f:
                f.write(cipher)
        except OSError:
            if path and os.path.exists(path):
                os.remove(path)
            logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=server_error_upload reason=os_error", exc_info=True)
            return userPage("Server error"), 500
        con.commit()
        logger.info(f"user={cleanusername(session.get("username","?"))} event=file_uploaded_successfully")
    except Exception:
        if path and os.path.exists(path):
            os.remove(path) #files to be removed in case of an error while uploading
        logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} event=server_error_upload reason=other", exc_info=True)
        return userPage("Server error"), 500
    finally:
        con.close()
    return redirect(url_for("userPage"))
#DOWNLOAD

@app.route("/files/<file_id>", methods=["GET"])
@login_required
def download(file_id):
    if not valid_id(file_id):
        logger.warning(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} file_id={cleanusername(file_id)} event=invalid_fileid_format")
        return userPage("File not found"), 404
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT filename FROM files WHERE file_id = ? AND user_id = ?", (file_id, session["user_id"])).fetchone()
        if row is None:
            logger.warning(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} file_id={file_id} event=fileid_doesnt_exist_or_doesnt_belong_to_user")
            return userPage("File not found"), 404
        hash = usrkeys[session["user_id"]]
        path =  os.path.join(fs, str(file_id))
        try:
            with open(path, "rb") as f:
                cipher = f.read()
        except FileNotFoundError:
            logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} file_id={file_id} event=file_not_found_in_server", exc_info=True)
            return userPage("File not found"), 404
        try:
            file = decrypt(cipher, hash)
        except(InvalidTag, ValueError):
            logger.error(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} file_id={file_id} event=file_cannot_be_decrypted", exc_info=True)
            return userPage("File could not be decrypted"), 500
        con.execute("UPDATE files SET last_download = CURRENT_TIMESTAMP WHERE file_id = ?", (file_id,))
        con.commit()
        logger.info(f"user={cleanusername(session.get("username","?"))} event=file_downloaded_successfully")
    finally:
            con.close()
    return send_file(io.BytesIO(file), as_attachment=True, download_name=row["filename"])

#DELETE

@app.route("/files/<file_id>/delete", methods=["POST"])
@login_required
def delete(file_id):
    if not valid_id(file_id):
            logger.warning(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} file_id={cleanusername(file_id)} event=invalid_file_id_format")
            return userPage("File not found"), 404
    con = sqlite3.connect(db)
    try:
        row2dlt = con.execute("DELETE FROM files WHERE file_id = ? AND user_id = ?", (file_id, session["user_id"]))
        if row2dlt.rowcount == 0:
            logger.warning(f"user={cleanusername(session.get("username","?"))} ip={request.remote_addr} file_id={file_id} event=file_id_doesnt_exist_or_doesnt_belong_to_user")
            return userPage("File not found"), 404
        con.commit()
        logger.info(f"user={cleanusername(session.get("username","?"))} event=file_deleted_correctly_from_db")
    finally:
        con.close()
    path = os.path.join(fs, str(file_id))
    if os.path.exists(path):
        os.remove(path)
        logger.info(f"user={cleanusername(session.get("username","?"))} event=file_deleted_correctly_on_server")
    return redirect(url_for("userPage"))

#Main

if __name__ == "__main__":

    init_lg()
    if not os.path.exists(db):
        logger.warning(f"db_does_not_exist_a_new_db_is_created")
        init_db()
    if not os.path.exists(fs):
        logger.warning(f"server_does_not_exist_a_new_server_is_created")
        init_fs()

    app.run(port=5000, debug=False, ssl_context="adhoc")