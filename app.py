import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from mapreduce import run_mapreduce

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///logs.db")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ALLOWED_EXTENSIONS"] = {"log", "txt"}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class AnalysisResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    results = db.Column(db.Text)
    uploaded_by = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def initialize_db():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                password=generate_password_hash("admin123"),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

initialize_db()

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password", "error")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm = request.form["confirm_password"]
        if len(username) < 3:
            flash("Username must be at least 3 characters", "error")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match", "error")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("Username already taken", "error")
            return render_template("register.html")
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! Please sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    results = AnalysisResult.query.order_by(AnalysisResult.created_at.desc()).all()
    parsed = []
    for r in results:
        parsed.append({
            "id": r.id,
            "filename": r.filename,
            "uploaded_by": r.uploaded_by,
            "created_at": r.created_at,
            "results": json.loads(r.results)
        })
    return render_template("dashboard.html", results=parsed, user=current_user)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "logfile" not in request.files:
        flash("No file selected", "error")
        return redirect(url_for("dashboard"))
    file = request.files["logfile"]
    if file.filename == "" or not allowed_file(file.filename):
        flash("Please upload a valid .log or .txt file", "error")
        return redirect(url_for("dashboard"))
    filename = secure_filename(file.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(path)
    output = run_mapreduce(path)
    record = AnalysisResult(
        filename=filename,
        results=json.dumps(output),
        uploaded_by=current_user.username
    )
    db.session.add(record)
    db.session.commit()
    flash("File analyzed successfully!", "success")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))