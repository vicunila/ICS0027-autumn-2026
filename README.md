Secure Web-Based File Encryption and Management System

## Scope
blablabla

## Planned routes and features

POST /stuff
GET /stuff2
DELETE /stuff3

Login
Logout
Create account
Upload file that will be encrypted in server
Download file that will be decrypted before download
Delete files from server
Show all files user has in the server --> needs to handle when user has no files 
(notes for future me: error handling necessary includes: hard limit on file size uploaded, and amount of total files)

AES-GCM encryption in the server
Session based auth --> with input cleaning
some way to show users what files they got

## how to run locally

# on Linux/MacOS
python3 -m venv venv
source venv/bin/activate
python3 \[whatever the app will be called\].py

# on Windows
python -m venv venv
venv\Scripts\activate
python3 \[whatever the app will be called\].py

## Note for checkpoint 1 review

Some info of this may be changed with time, I don't want to limit myself by choices I made earlier.
Features and routes will be added and removed according to what I end up coding
