#Made by Victor Laino
#student number 251773iCVM
import os
import getpass
import logging
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, send_file
from functools import wraps
import bcrypt
import io
from cryptography.hazmat.primitives.ciphers.aead import AESGCM #I will use CBC for now because I had implemented it in the past. will switch to GCM in checkpoint 3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

#TODO checkpoint 2: html pages, tls, delete dead code, rename project
#TODO checkpoint 3: session timeout, logging, gitignore, getting pw from db for encryption and decryption, delete, pw change, user blocking, input sanitazation, change CBC to GCM


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

#crypto stuff
SaltSize = 32
def password2key(password, salt):
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), salt=salt, length=32, iterations=9999)
    return key.derive(password)

def encrypt(file, password):

    key = b'\x00'
    salt = os.urandom(SaltSize)
    iv = os.urandom(16)

    key = password2key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    padder= padding.PKCS7(16*8).padder()
    padded = padder.update(file) + padder.finalize()

    ciphered = encryptor.update(padded) + encryptor.finalize()
    return salt + iv + ciphered


def decrypt(ciphered, password): 

    salt = ciphered[:SaltSize]
    iv = ciphered[SaltSize:(SaltSize + 16)]
    ciphertext = ciphered[SaltSize + 16:]

    key = password2key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphered) + decryptor.finalize()

    unpadder = padding.PKCS7(16*8).unpadder()
    file = unpadder.update(padded) + unpadder.finalize()
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

def login_required(view):
    @wraps(view)
    def logincheck(*args, **kwargs):
        if  "user_id" not in session:
            return redirect(url_for('loginPage'))
        return view(*args, **kwargs)
    return logincheck

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
    return redirect(url_for("userPage"))    

@app.route("/logout", methods=["POST"])
@login_required
def logout():
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

@app.route("/files", methods=["GET"]) #this GET is harder because it needs to show files PERSONALIZED to user
@login_required
def userPage():
    pass #personal user space, will show all user files

@app.route("/files", methods=["POST"])
@login_required
def upload():
    file = request.files.get("file")
    con = sqlite3.connect(db)
    hash = bcrypt.hashpw("password123", bcrypt.gensalt(rounds=12)) # will be replaced with hash from db
    #add checks for upload, absent file, unsafe file name, user has too many files etc (hard limit on filesize, filename length, files per user)
    #some ui update that uploading is in progress after checks
    cipher = encrypt(file.read(), hash)
    try:
        nsrt = con.execute("INSERT INTO files (user_id, filename) VALUES (?, ?)", (session["user_id"], file.filename))
        file_id = nsrt.lastrowid
        with open(os.path.join(fs, str(file_id)), "wb") as f:
            f.write(cipher) #there will be try except cases here, it simulates a configured server, but I wanna avoid OS issues when uploading files, so an error needs to be handled
        con.commit()
    finally:
        con.close()
    return redirect(url_for("userPage"))
#DOWNLOAD

@app.route("/files/<file_id>", methods=["GET"])
@login_required
def download(file_id):
    if False: 
        pass #does file belong to user??? Is file a valid file??? does file exist???
    hash = bcrypt.hashpw("password123", bcrypt.gensalt(rounds=12)) # will be replaced with hash from db
    path =  os.path.join(fs, str(file_id))
    with open(path, "rb") as f:
        cipher = f.read()
    file = decrypt(cipher, hash)
    return send_file(io.BytesIO(file), as_attachment=True, download_name=file_id)

#DELETE

@app.route("/files/<file_id>/delete", methods=["GET"])
@login_required
def deletePage():
    pass #are you sure you wanna delete this???? text appears somehow
@app.route("/files/<file_id>/delete", methods=["DELETE"])
@login_required
def delete():
    pass #file gets deleted from server, db is updated

if __name__ == "__main__":
    if not os.path.exists(db):
        init_db() #running app for the first time may end up 
    if not os.path.exists(fs):
        init_fs() #maybe not even needed, it just has to be a folder
    if not os.path.exists(lg):
        init_lg() #checkpoint 3 problem

    app.run(port=5000, debug=False)
# EVERYTHING AFTER THIS POINT IS OLD
"""
# salting
SaltSize = 32

#creating the logger
logger = logging.getLogger('SecureFileManager')

# LOGGING

def setupLogging():
    # Ensure the secure directory exists before setting up logging
    try:
        os.mkdir(SecDir, mode=0o744)
    except FileExistsError:
        # if directory already exists
        try:
            os.chmod(SecDir, 0o744) #override the directory permissions to ensure it is secure (forcing it)
        except Exception as e: #if directory cant be set to right privileges it is unsafe to use the program, a basic error will be just ignored by users
            print(f"Directory {SecDir} exists but failed to secure permissions via chmod. Aborting {e}", file=sys.stderr)
            sys.exit(1)
    except Exception as e: #other errors
        print(f"Cannnot create directory at {SecDir}. {e}", file=sys.stderr)
        sys.exit(1)

    #file handler for logging       

    logger.setLevel(logging.INFO)
    
    try:
        fileHandling = logging.FileHandler(LPath, mode='a') #append mode,handle files for logging
        os.chmod(LPath, 0o644) #for security making the logs only writable by the owner

    except IOError as e:
        print(f"Cannot open log file for writing at {LPath}. {e}", file=sys.stderr)
        sys.exit(1)

    #format of log
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fileHandling.setFormatter(formatter)

    #putting the handler
    logger.addHandler(fileHandling)
    
    logger.info("Logger initialized.")


# ---- Input validation ----

def PathCheck(filepath):
    
    if not filepath:
        print("Filepath is empty")
        logger.critical("Security Validation Failed: Filepath is empty.")
        sys.exit(1)
        
    if '\x00' in filepath: #null bytes are also unsafe in python
        logger.critical(f"Security Validation Failed: Null byte detected")#this is entered in logs without notifying a potential attacker
        sys.exit(1)
        
    # Normalize the path to avoid length problems
    norm_path = os.path.normpath(filepath)
    
    # checking for '..', avoiding path traversal attacks
    if '..' in norm_path.split(os.sep):
        logger.critical(f"Security Validation Failed: Path traversal ('..') is not allowed. file path: {filepath}")
        sys.exit(1)


# --- Authentication  ---

AllowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
MaxPwSize = 100

def startInit():
    
    print(f"Initializing secure storage in: {SecDir}")
    
    if os.path.exists(MPath):
        print("!!!WARNING!!!", file=sys.stderr)
        print("A master password is already set. Re-running 'init' will", file=sys.stderr)
        print("overwrite it, and you will lose access to files encrypted", file=sys.stderr)
        print("unless the new password is the same as the old one.", file=sys.stderr)
        choice = input("Proceed anyway? Type YES or NO (full capitalisation!)")
        if choice != 'YES':
            print("Initialization cancelled.")
            logger.warning(f"Initialization cancelled by user '{getpass.getuser()}' (hash file already exists)")
            return

    print("Password can only contain alphanumerics and the following symbols: !@#$%^&* . Maximum length: 100 characters")
    pass1 = getpass.getpass("Set master password: ")

    if len(pass1) > 100:
        print(f"Password exceeded maximum allowed length of 100 characters. Aborting", file=sys.stderr)
        logger.error("Initialization failed: Password too long")
        return

    if pass1 == "":
        print("Password cannot be empty. Abort", file=sys.stderr)
        logger.error("Initialization failed: Empty password")
        return

    if any(char not in set(AllowedChars) for char in pass1):
        print("Password contains unpermitted characters, you can use only alphanumeric and these symbols: !@#$%^&* Aborting", file=sys.stderr)
        logger.error("Initialization failed: Password failed character check")
        return

    pass2 = getpass.getpass("Confirm master password: ")
        
    if pass1 != pass2:
        print("Passwords do not match. Abort", file=sys.stderr)
        logger.error("Initialization failed: Passwords not matching")
        return
        
    PasswordBytes = bytearray(pass1.encode('utf-8')) #encodes the password as bytes
    
    try:
        print("Hashing master password...")
        hashedPassword = bcrypt.hashpw(bytes(PasswordBytes), bcrypt.gensalt(rounds=12))
        
        with open(MPath, 'wb') as f: #wb = write mode + binary mode. This way of writing also ensures the file is autoclosed after use
            f.write(hashedPassword)
            
        os.chmod(MPath, 0o600)
           
        print(f"Master password successfully saved to {MPath}")
        logger.info("System initialization complete, master password is set")
        
    except Exception as e:
        print(f"An error occurred during initialisation", file=sys.stderr)
        logger.error("Some exception occurred during start_init", exc_info=True)
    finally:
        PasswordBytes[:] = b'\x00' * len(PasswordBytes) #scrubs all the info so that it doesn't appear in memory
        pass1 = '0' * ( len(pass1) + 1)
        pass2 = '0' * ( len(pass2) + 1)
        del PasswordBytes 
        del pass1, pass2 

def checkMasterPassword(password):
   
    if os.path.isfile(MPath) == False:
        print("error system not initialized, please run 'init' first", file=sys.stderr)
        logger.error("authentication check failed: master hash file not found.")
        return False

    try:
        os.chmod(MPath, 0o600)

    except Exception as e: #for safety, i want to enforce this to 600 priviledge
        logger.critical(f"failed to put 0o600 permissions on hash file {MPath} aborting {e}")
        return False
        
    PasswordBytes = bytearray(password.encode('utf-8'))
    
    try:
        with open(MPath, 'rb') as f: #read + bytes mode
            storedHash = f.read()
            
        return bcrypt.checkpw(bytes(PasswordBytes), storedHash)
        
    except Exception as e:
        print(f"An error during authentication", file=sys.stderr)
        logger.error("Some error has occurred during checkMasterPassword" , exc_info=True)
        return False
    finally:
        PasswordBytes[:] = b'\x00' * len(PasswordBytes)
        del PasswordBytes

# --- Encryption  ---

def password2key(PasswordBytes, salt):
    key = PBKDF2(PasswordBytes, salt, dkLen=32)
    return bytearray(key)

def encrypt(inputpath, outputpath, password):

    logger.info(f"Encryption started for {inputpath}")
    key = b'\x00'
    passwordBytes = b'\x00'
    
    try:
        if not outputpath:
            outputpath = f"{inputpath}.enc"
        print(f"Output file: {outputpath}")

    except:

        if os.path.isfile(inputpath) == False:
            print(f"Input file not found at {inputpath}. Aborting encryption")
            logging.error("Encryption aborted because input file was missing. Input name: {inputpath}", exc_info=True)
            sys.exit(1)
        if os.path.exists(outputpath) == True:
            print("Output file {outputpath} already exists. Aborting encryption")
            logging.error("Encryption aborted because output file already exists. Output name: {outputpath}", exc_info=True)
            sys.exit(1)

    try:
        passwordBytes = bytearray(password.encode('utf-8'))
        salt = get_random_bytes(SaltSize)
        key = password2key(passwordBytes, salt)

        with open(inputpath, 'rb') as f_in:
            content = f_in.read()
        padded = pad(content, AES.block_size) #padding is needed to fit the block sizes for AES

        cipher = AES.new(key, AES.MODE_CBC) #Cipher Block Chaining mode for AES algo
        ciphered = cipher.encrypt(padded)
        
        with open(outputpath, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(cipher.iv)
            f_out.write(ciphered) #write all the content needed to be able to decrypt (except the password of course)
             
        print(f"Encrypted {inputpath} to {outputpath} successfully")
        logger.info(f"Encryption Successful. {inputpath} TO {outputpath}")
        
    except Exception as e:
        print(f"Error during encryption", file=sys.stderr)
        logger.error(f"Encryption failed for {inputpath} Error: {e}", exc_info=True)
        if os.path.exists(outputpath):
            os.remove(outputpath) # Cleaning up partial files
    finally:
        key[:] = b'\x00' * len(key)
        del key
        passwordBytes[:] = b'\x00' * len(passwordBytes)
        del passwordBytes

def decrypt(inputpath, outputpath, password): #input = encrypted file .  output = decrypted file

    logger.info(f"Decryption started for {inputpath}")
    key = b'\x00'
    passwordBytes = b'\x00'

    try:
        if not outputpath:
            if inputpath.endswith('.enc'):
                outputpath = inputpath[:-4] #remove the .enc part
            else:
                outputpath = f"{inputpath}.dec"
        print(f"Output File: {outputpath}")

        if os.path.isfile(inputpath) == False:
            print(f"Input file not found at '{inputpath}'")
            logger.error(f"Decryption failed because input file doesn't exist. Input: {inputpath}", exc_info=True)
            sys.exit(1)
        if os.path.exists(outputpath):
            print(f"Output file '{outputpath}' already exists")
            logger.error(f"Decryption failed because output file already exists. Output: {outputpath}", exc_info=True)
            sys.exit(1)

        with open(inputpath, 'rb') as f_in:
            salt = f_in.read(SaltSize)
            if len(salt) != SaltSize:
                print("Invalid file: too short to contain salt.")
                logger.error(f"Decryption failed because input file is too short to contain salt. Input: {inputpath}", exc_info=True)
                sys.exit(1)
            iv = f_in.read(AES.block_size)
            if len(iv) != AES.block_size:
                raise ValueError("Invalid file: too short to contain IV.")
                logger.error(f"Decryption failed because input file is too short to contain IV. Input: {inputpath}", exc_info=True)
                sys.exit(1)
            ciphered = f_in.read()

        passwordBytes = bytearray(password.encode('utf-8'))
        key = password2key(passwordBytes, salt)
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(ciphered)
        
        content = unpad(padded, AES.block_size)

        with open(outputpath, 'wb') as f_out:
            f_out.write(content)
            
        print(f"Decrypted {inputpath} TO {outputpath} successfully")
        logger.info(f"Decryption successful. {inputpath} TO {outputpath}")
        
    except Exception as e:
        print(f"Error during decryption. Ensure that the master password is correct", file=sys.stderr)
        logger.error(f"Decryption failed for {inputpath} Error: {e}", exc_info=True)
        if os.path.exists(outputpath):
            os.remove(outputpath)
    finally:
            key[:] = b'\x00' * len(key)
            del key
            passwordBytes[:] = b'\x00' * len(passwordBytes)
            del passwordBytes

# --- Secure Delete ---

SecDelSize = 1000000 #size of chunk for secure delete, done in chunks because one by one just doesn't work well

def secureDelete(inputpath):
    logger.info(f"Secure-delete started for {inputpath}")
    print(f"Target File: {inputpath}")

    if os.path.isfile(inputpath) == False:
        print(f"Error. File not found. Input: {inputpath}", file=sys.stderr)
        logger.error(f"Secure-delete failed. File not found at {inputpath}.")
        sys.exit(1)
    try:
        fileSize = os.path.getsize(inputpath)
        if fileSize == 0:
            logger.info(f"File '{inputpath}' is empty. Simply Removed")
        else:
            with open(inputpath, 'r+b') as f:
                print(f"Overwriting {fileSize} bytes")
                logger.info(f"Overwriting {fileSize} bytes in {inputpath}")
                WrittenBytes = 0
                while WrittenBytes < fileSize:
                    chunksize = min(SecDelSize, fileSize - WrittenBytes) #will delete a piece of 1mb at a time but wont crash at the end
                    EmptyChunk = b'\x00' * chunksize 
                    f.write(EmptyChunk) 
                    del EmptyChunk
                    WrittenBytes += chunksize
                f.flush()
                os.fsync(f.fileno()) #syncs up the file so that if the process fails we will have a partially overwritten file (avoids corruption)
        os.remove(inputpath)
        print(f"{inputpath} securely deleted.")
        logger.info(f"Secure-delete successful for {inputpath}")
        
    except Exception as e:
        print(f"Error during secure delete. Please try again", file=sys.stderr)
        logger.error(f"Secure-delete has failed for {inputpath} Error: {e}", exc_info=True)

# --- Main ---

def main():
    setupLogging()

    cli = argparse.ArgumentParser(
        description="Secure File Encryption and Management System",
        epilog="Run python SecureFileManager.py init to start"
    )
    
    commands = cli.add_subparsers(dest='command', required=True)
    
    initP = commands.add_parser('init', help='Initialisation, sets up the password (NOTE: this must be used before encrypt and decrypt commands')
    encryptP = commands.add_parser('encrypt', help='Format: python SecureFileManager.py encrypt <file path to encrypt> [-o <optional path of output file>]')
    encryptP.add_argument('inputpath', type=str)
    encryptP.add_argument('-o', '--output', type=str)
    decryptP = commands.add_parser('decrypt', help='Format: python SecureFileManager.py decrypt <file path to decrypt> [-o <optional path of output file>]')
    decryptP.add_argument('inputpath', type=str)
    decryptP.add_argument('-o', '--output', type=str)
    securedeleteP = commands.add_parser('secure-delete', help='Format: python SecureFileManager.py secure-delete <file path to encrypt>')
    securedeleteP.add_argument('inputpath', type=str)

    if len(sys.argv) == 1:
        print()
        sys.exit(1)
        
    args = cli.parse_args()                                                                                                                                             #AAAAAAAAAAAAAAAAAAAAA

    password = None

    try:
        if hasattr(args, 'inputpath'): #input validation
            PathCheck(args.inputpath)
            
        if hasattr(args, 'output') and args.output:
            PathCheck(args.output)
            
        if args.command == 'init':
            startInit()
            
        elif args.command == 'secure-delete':
            secureDelete(args.inputpath)
            
        elif args.command == 'encrypt' or args.command == 'decrypt':
            if os.path.exists(MPath) == False:
                print("Error. Program wasn't initialized yet. Please run 'init' ", file=sys.stderr)
                logger.error("Error. Encryption/Decryption attempted before initialisation")
                sys.exit(1)
                
            password = getpass.getpass("Enter master password: ")
            
            if not checkMasterPassword(password):
                print("Authentication Failed. Aborting", file=sys.stderr)
                logger.warning(f"Authenticating failed for {args.command}")
                sys.exit(1)
            
            print("Authentication successful")
            logger.info(f"Authenticating successful for {args.command}")
            
            if args.command == 'encrypt':
                encrypt(args.inputpath, args.output, password)
            elif args.command == 'decrypt':
                decrypt(args.inputpath, args.output, password)
    
    except Exception as e:
        print(f"An error occurred", file=sys.stderr)
        logger.critical(f"Unhandled error in main {e}", exc_info=True)
        sys.exit(1)
                
    finally:
        if password:
            password = '0' * ( len(password) + 1 )
            del password

if __name__ == "__main__":
    main()
"""