from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file,
    flash,
    url_for
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from crypto.rsa_utils import (
    generate_keys,
    encrypt_aes_key,
    decrypt_aes_key
)
from crypto.aes_utils import (
    generate_aes_key,
    encrypt_file,
    decrypt_file
)

ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "docx"
}

def allowed_file(filename):

    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS

app = Flask(__name__)

os.makedirs("uploads", exist_ok=True)
os.makedirs("encrypted", exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

app.config["SECRET_KEY"] = os.urandom(24)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db = SQLAlchemy(app)


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)

    public_key = db.Column(db.Text)

    private_key = db.Column(db.Text)

class EncryptedFile(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(db.String(200))

    encrypted_path = db.Column(db.String(300))

    encrypted_aes_key = db.Column(db.Text)

    owner = db.Column(db.String(100))

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:

            flash("Username already exists")

            return redirect("/register")


        hashed_password = generate_password_hash(password)
        public_key, private_key = generate_keys()
        
        new_user = User(
            username=username,
            password=hashed_password,
            public_key=public_key,
            private_key=private_key
        )

        db.session.add(new_user)

        db.session.commit()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):

            session["user"] = user.username

            return redirect("/dashboard")
        
        flash("Invalid username or password")

        return redirect("/login")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    user_files = EncryptedFile.query.filter_by(
        owner=session["user"]
    ).all()

    return render_template(
        "dashboard.html",
        username=session["user"],
        files=user_files
    )

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":

        file = request.files["file"]

        if file.filename == "":

            flash("Please select a file")

            return redirect("/upload")

        if not allowed_file(file.filename):

            flash("Invalid file type")

            return redirect("/upload")

        if file:

            file_path = "uploads/" + file.filename

            file.save(file_path)

            aes_key = generate_aes_key()

            encrypted_path = encrypt_file(file_path, aes_key)

            if os.path.exists(file_path):
                os.remove(file_path)

            user = User.query.filter_by(username=session["user"]).first()

            encrypted_aes_key = encrypt_aes_key(
                aes_key,
                user.public_key
            )

            new_file = EncryptedFile(
            filename=file.filename,
            encrypted_path=encrypted_path,
            encrypted_aes_key=encrypted_aes_key,
            owner=user.username
        )

            db.session.add(new_file)

            db.session.commit()

            flash("File encrypted successfully!")

            return redirect("/dashboard")

    return render_template("upload.html")

@app.route("/download/encrypted/<int:file_id>")
def download_encrypted(file_id):

    if "user" not in session:
        return redirect("/login")

    encrypted_file = EncryptedFile.query.get(file_id)

    if not encrypted_file:
        flash("File not found")

        return redirect("/dashboard")
    
    if encrypted_file.owner != session["user"]:
        flash("Access denied")

        return redirect("/dashboard")

    return send_file(
        encrypted_file.encrypted_path,
        as_attachment=True
    )

@app.route("/delete/<int:file_id>")
def delete_file(file_id):

    if "user" not in session:
        return redirect("/login")

    encrypted_file = EncryptedFile.query.get(file_id)

    if not encrypted_file:
        flash("File not found")

        return redirect("/dashboard")
    
    if encrypted_file.owner != session["user"]:
        flash("Access denied")

        return redirect("/dashboard")

    import os

    if os.path.exists(encrypted_file.encrypted_path):
        os.remove(encrypted_file.encrypted_path)

    db.session.delete(encrypted_file)

    db.session.commit()

    return redirect("/dashboard")

@app.route("/decrypt/<int:file_id>")
def decrypt(file_id):

    if "user" not in session:
        return redirect("/login")

    encrypted_file = EncryptedFile.query.get(file_id)

    if not encrypted_file:
        flash("File not found")

        return redirect("/dashboard")

    if encrypted_file.owner != session["user"]:
        flash("Access denied")

        return redirect("/dashboard")

    user = User.query.filter_by(
        username=session["user"]
    ).first()

    aes_key = decrypt_aes_key(
        encrypted_file.encrypted_aes_key,
        user.private_key
    )

    decrypted_data = decrypt_file(
        encrypted_file.encrypted_path,
        aes_key
    )

    from flask import Response

    return Response(
        decrypted_data,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition":
            f"attachment;filename={encrypted_file.filename}"
        }
    )

@app.route("/logout")
def logout():

    session.pop("user", None)

    return redirect("/login")

@app.errorhandler(413)
def file_too_large(error):

    flash("File is too large (max 16 MB)")

    return redirect(url_for("upload"))

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)
