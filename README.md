# Secure Web-Based File Encryption and Management System

## Scope
Web-based application that stores files safely with user authentication features. To ensure safety of files they are encrypted and only the ciphered data is written to server.

## Planned routes and features

- `POST /login` Login endpoint\
- `POST /logout` Logout endpoint\
- `POST /newaccount` Endpoint for creating an account\
- `POST /files` Endpoint for uploading new files, needs to handle file size check and file "safety" check, include an error response for maximum files amount reached\
- `GET /files/<file_id>` Endpoint for downloading new files, needs to handle ownership check\
- `GET /files` Endpoint for listing files, needs to handle empty case, only lists user's files\
- `DELETE /files/<file_id>` Endpoint for deleting files from server, needs to handle ownership check\

AES-GCM encryption in the server with key generated from password\
Session based auth with user input/upload cleaning\
Users will have a unique id for verifying ownership alongside session tokens

## how to run locally

### on Linux/MacOS
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 [whatever the app will be called].py
```
### on Windows
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python [whatever the app will be called].py
```

## Note for checkpoint 1 review

Some info of this may be changed with time, I don't want to limit myself by choices I made earlier.
Features and routes will be added and removed according to what I end up coding
