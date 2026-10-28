# Secure Web-Based File Encryption and Management System

## Scope

Web-based application that stores files safely with user authentication features. To ensure safety of files they are encrypted and only the ciphered data is written to server.

## Project layout

```text
SecureFileManager.py
requirements.txt
templates/
    mainpage.html
    register.html
    login.html
    files.html
    pwchange.html
```

## Routes and features

- `GET /` Main page
- `POST /login` Login endpoint
- `GET /login` Login page
- `POST /logout` Logout endpoint
- `GET /register` Registration page
- `POST /register` Endpoint for creating an account
- `POST /files` Endpoint for uploading new files, needs to handle file size check and file "safety" check, include an error response for maximum files amount reached
- `GET /files/<file_id>` Endpoint for downloading files, needs to handle ownership check
- `GET /files` Endpoint for listing files, needs to handle empty case, only lists user's files
- `GET /files/<file_id>/delete` Confirmation page before deleting a file
- `DELETE /files/<file_id>/delete` Endpoint for deleting files from server, needs to handle ownership check
- `GET /password_update` Password change page
- `POST /password_update` Endpoint for changing password, needs to check old password and new password confirmation

AES-GCM encryption in the server with key generated from password, currently implemented with AES-CBC\
Session based auth with user input/upload cleaning\
Users will have a unique id for verifying ownership alongside session tokens

## how to run locally

### on Linux/MacOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 SecureFIleManager.py
```

### on Windows

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python SecureFIleManager.py
```

Open [https://localhost:5000](https://localhost:5000). The app uses a self-signed certificate, so accept the browser warning
