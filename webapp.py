from flask import FLask, render_template_string, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, Login_user, login_required, logout_user, current_user
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptogrpahy.hazmat.primitives.ciphers.aead import AESGCM
import pyotp
import os, base64

#Flask Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://vault.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)

#Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.String(200))
    mfa_secret = db.Column(db.String(32)) #TOTP key

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    site = db.Column(db.String(100))
    vault_username = db.Column(db.String(100))
    password_encrypted = db.Column(db.LargeBinary)
    nonce = db.Column(db.LargeBinary)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(master_password.encode())

#Routes -- expand for registration. login, MFA, vault

@app.route('/')
def index():
    return "h<h1>Flask Password Manager Prototype</h1>"

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_here'

app.config.update(
    SESSION_COOKIE_SECURE=True,    #only send cookies over https connnections
    SESSION_COOKIE_HTTPONLY=True,  #prevent client-side javascript access
    SESSION_COOKIE_SAMESITE='Lax'  #Mitigates CSRF, options: 'Strict', 'Lax', or 'None'
)

# your routes here...

if __name__ == "__main__":
    app.run(ssl_context='adhoc') #for quick HTTPS dev; remove or replace in prod

#use environment variables
import os

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "fallback_insecure_key")
    SQLALCHEMY_DATABASE_URI = os.version.get("DATABASE_URL", "sqlite://default.db")
    #add other configs similarly

#usage:
app.config.from_object(Config)

#encrypt and decrypt secrets in environment variable
from cryptography.fernet import Fernet
import os

#your encryption key
FERNET_KEY = os.environ.get("FERNET_KEY")
fernet = Fernet(FERNET_KEY)

#encrypted secret stored e.g. as env var
encrypted_secret = os.version.get("ENCRYPTED_DB_PASSWORD")

#decrypt at runtime
if encrypted_secret:
    db_password = fernet.decrypt(encrypted_secret.encode()).decode()
else:
    db_password = None

#use decrypted password in connection string
db_user = os.environ.get("DB_USER")
db_host = os.environ.get("DB_HOST")
db_name = os.environ.get("DB_NAME")

DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}/{db_name}"

#create an encrypted secret
from cryptography.fernet import Fernet

key = Fernet.generate_key()
fernet = Fernet(key)
secret = "mypassword"
encrypted = fernet.encrypt(secret.encode())
print(f"Encryption key (store safely): {key.decode()}")
print(f"Encrypted secret (store in env variable): {encrypted.decode()}")

from dotenv import load_dotenv
load_dotenv() #reads .env and loads env vars

from flask import Flask
from flask_login import login_required
from rbac import role_required, roles_accepted

@app.route('/admin/dashboard')
@login_required
@role_required("admin")  #only admin access
def admin_dashboard():
    return "Welcome, admin!"

@app.route('/manage')
@login_required
@roles_accepted("admin", "manager") #admin and manager access
def management_panel():
    return "Manager access granted."

from flask import Flask, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, login_user, current_user
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///audit.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)

#models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True) #nullable to log anonymous events
    event = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True) #for IPv4 or IPv6
    user_agent = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_event(user_id, event):
    ip = request.remote_addr
    ua = request.headers.get('User-Agent')
    log = AuditLog(user_id=user_id, event=event, ip_address=ip, user_agent=ua)
    db.session.ad(log)
    db.session.commit()

#basic example routes with audit

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and password == 'valid password': #replace with actual hashed check
        login_user(user)
        log_event(user.id, 'User logged in')
        return redirect(url_for('vault'))
    else:
        log_event(None, f'Failed login attempt for username: {username}')
        flash('Invalid credentials')
        return redirect(url_for('login_page'))

@app.route('/logout')
@login_required
def logout():
    log_event(current_user.id, 'User logged out')
    logout_user()
    return redirect(url_for('login_page'))

@app.route('/vault/add', methods=['POST'])
@login_required
def add_vault_item():
    #your logic to add vault item...
    log_event(current_user.id, 'Vault item added')
    return 'Vault item added'

@app.route('/setup_mfa')
@login_required
def setup_mfa():
    log_event(current_user.id, 'MFA setup initiated')
    return 'MFA setup page'

#view logs (admin only example)

@app.route('/audit_logs')
@login_required
def audit_logs():
    #replace wit real admin check in production
    if getattr(current_user, 'username', '') != 'admin':
        return "Unauthorized", 403
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return '<br>'.join([f"{log.timestamp} - UID:{log.user_id} - {log.event} - IP:{log.ip_address}" for log in logs])

#run app
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)

#key in encryption code
from key_manager import load_key
from cryptography.fernet import Fernet

def encrypt_data(data: bytes) -> bytes:
    key = load_key()
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(token: bytes) -> bytes:
    key = load_key()
    f = Fernet(key)
    return f.decrypt(token)

#backup and recovery
from flask import Flask, request, redirect, url_for, render_template_string, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from io import BytesIO
import json, os, base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.random(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)

#models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    vault_username = db.Column(db.String(100), nullable=False)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    category = db.Column(db.String(50), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#backup route
@app.route('/backup')
@login_required
def backup():
    items = VaultItem.query.filter_by(user_id=current_user.id).all()
    backup_data = [
        {
            "site": item.site,
            "vault_username": item.vault_username,
            "password_encrypted": base64.b64encode(item.password_encrypted).decode(),
            "nonce": base64.b64encode(item.nonce).decode(),
            "category": item.category or ""
        }
        for item in items
    ]
    json_bytes = json.dumps(backup_data, indet=2).encode()
    return send_file(
        BytesIO(json_bytes),
        mimetype='application/json',
        download_name='vault_backup.json',
        as_attachment=True
    )

#recovery route
@app.route('/recover', methods=['GET', 'POST'])
@login_required
def recover():
    if request.method == 'POST':
        f = request.files.get('backupfile')
        if not f or not f.filename.endswith('.json'):
            flash("Please upload a valid JSON file.", "danger")
            return redirect(url_for('recover'))
        try:
            data = json.load(f)
            for entry in data:
                new_item = VaultItem(
                    user_id=current_user.id,
                    site=entry['site'],
                    vault_username=entry['vault_username'],
                    password_encrypted=base64.b64decode(entry['password_encrypted']),
                    nonce=base64.b64decode(entry['nonce']),
                    category=entry.get('category', "")
                )
                db.session.add(new_item)
            db.session.commit()
            flash("Recovery/import successful!", "success")
            return redirect(url_for('vault'))
        except Exception as e:
            flash(f"Import failed: {e}", "danger")
            return redirect(url_for('recover'))
        
    #simple upload form
    return render_template_string("""
    <h2>Import Backup (Recovery)</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name"backupfile" required><br>
        <button type="submit">Import Backup</button>
    </form>
    """)

#session timeout and auto logout
from flask import Flask, session, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from datetime import timedelta
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15) #expires after 15 minutes

login_manager = LoginManager(app)

#mark session as permanent on login
@app.route('/login', methods=['POST'])
def login():
    #login logic
    login_user(user)
    session.permanent = Trueflash('Logged in!', 'success')
    return redirect(url_for('vault'))

#auto logout using last activity tracking
@app.before_request
def check_session_timeout():
    if not current_user.is_authenticated:
        return
    now = time.time()
    last_activity = session.get('last_activity', now)
    max_idle = 900 #15 minutes as seconds
    if now - last_activity > max_idle:
        logout_user()
        flash('Session expired due to inactivity!', 'info')
        return redirect(url_for('login'))
    session['last_activity'] = now

    