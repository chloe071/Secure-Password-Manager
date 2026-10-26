from flask import Flask, render_template_string, request, redirect, url_for, session
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

from flask import Flask, render_template, request, jsonify
from password_generator import password_generator

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    try:
        length = int(request.form.get('length', 12))
        length = max(8, min(length,64)) #clamp length between 8 and 64
        use_symbols = request.form.get('use symbols', 'false').lower() == 'true'
        pwd = password_generator(length, use_symbols)
        return jsonify(password=pwd)
    except Exception as e:
        return jsonify(error=str(e)), 400
    
if __name__ == '__main__':
    app.run(debug=True)