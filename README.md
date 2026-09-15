# Secure File Storage System

Flask web app for secure file upload, encryption, and decryption using AES + RSA (Hybrid Encryption).

## 1. Create Virtual Environment

### Windows

python -m venv venv

venv\Scripts\activate

### Mac / Linux

python3 -m venv venv

source venv/bin/activate

## 2. Install Dependencies

pip install -r requirements.txt

### 3. Run the Project

python app.py

Open:

http://127.0.0.1:5000/

### 4. Required Folders

The application automatically creates the uploads/ and encrypted/ directories at startup. SQLite creates instance/database.db when the application initializes.

### 5. Notes

SQLite database will be created automatically

RSA keys are generated during user registration

Original uploaded files are deleted after encryption

### VS Code Fix

If Flask import is still red in VS Code:

1. Press `CTRL + SHIFT + P`

2. Select `Python: Select Interpreter`

3. Choose the `venv` interpreter

## Project Members

- **Natchanon Meechana** — [@natchatn](https://github.com/natchatn)
- **Phutharit Promin** — [@phutharitpromin-sys](https://github.com/phutharitpromin-sys)
- **Piyathida Sukniran** — [@chococatza](https://github.com/chococatza)
