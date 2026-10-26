"""Secure Password Manager — a Flask vault with AES-GCM encryption,
PBKDF2 key derivation, optional TOTP MFA, rate limiting, and CSRF protection.

Built from the prototype snippets in prototypes/.
"""
import base64
import csv
import io
import os
import secrets
import string
from datetime import datetime, timezone

import pyotp
import qrcode
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import (Flask, Response, abort, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

# ---------- App setup ---------- #

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///vault.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
    # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
    KDF_ITERATIONS=int(os.environ.get("KDF_ITERATIONS", 600_000)),
    RATELIMIT_STORAGE_URI=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])
login_manager = LoginManager(app)
login_manager.login_view = "login"

USERNAME_CHARS = set(string.ascii_letters + string.digits + "_.-")
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

# Derived vault keys live only in server memory, keyed by a random token
# stored in the session. The master password itself is never stored.
# Restarting the server (or logging out) clears every key.
_vault_keys = {}


# ---------- Models ---------- #

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    kdf_salt = db.Column(db.LargeBinary(16), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=True)
    items = db.relationship("VaultItem", backref="owner", cascade="all, delete-orphan")


class VaultItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    site = db.Column(db.String(100), nullable=False)
    vault_username = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    event = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------- Crypto helpers ---------- #

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=app.config["KDF_ITERATIONS"])
    return kdf.derive(master_password.encode())


def _aad(user_id: int) -> bytes:
    # Binds ciphertext to its owner so rows can't be swapped between users.
    return f"user:{user_id}".encode()


def encrypt_password(key: bytes, user_id: int, plaintext: str):
    nonce = os.urandom(12)  # fresh nonce for every encryption
    return AESGCM(key).encrypt(nonce, plaintext.encode(), _aad(user_id)), nonce


def decrypt_password(key: bytes, item: VaultItem) -> str:
    return AESGCM(key).decrypt(item.nonce, item.password_encrypted, _aad(item.user_id)).decode()


def generate_password(length=16, use_symbols=True) -> str:
    """Cryptographically secure generator (uses `secrets`, not `random`)."""
    length = max(8, min(int(length), 64))
    alphabet = string.ascii_letters + string.digits + (SYMBOLS if use_symbols else "")
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and (not use_symbols or any(c in SYMBOLS for c in pwd))):
            return pwd


def current_key():
    token = session.get("vault_token")
    return _vault_keys.get(token) if token else None


def unlock_vault(user: User, master_password: str):
    token = secrets.token_urlsafe(32)
    _vault_keys[token] = derive_key(master_password, user.kdf_salt)
    session["vault_token"] = token


def lock_vault():
    token = session.pop("vault_token", None)
    _vault_keys.pop(token, None)


def log_event(user_id, event):
    db.session.add(AuditLog(user_id=user_id, event=event, ip_address=request.remote_addr))
    db.session.commit()


def own_item_or_404(item_id) -> VaultItem:
    item = db.session.get(VaultItem, item_id)
    if item is None or item.user_id != current_user.id:
        abort(404)  # don't reveal whether other users' items exist
    return item


def require_unlocked():
    key = current_key()
    if key is None:
        logout_user()
        session.clear()
        flash("Your vault was locked. Please log in again.", "info")
    return key


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'"
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- Auth routes ---------- #

@app.route("/")
def index():
    return redirect(url_for("vault" if current_user.is_authenticated else "login"))


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("vault"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not (3 <= len(username) <= 80) or not set(username) <= USERNAME_CHARS:
            flash("Username must be 3–80 letters, numbers, underscores, dots, or dashes.", "danger")
        elif not (12 <= len(password) <= 128):
            flash("Master password must be 12–128 characters.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("That username is taken.", "danger")
        else:
            user = User(username=username, password_hash=generate_password_hash(password),
                        kdf_salt=os.urandom(16))
            db.session.add(user)
            db.session.commit()
            log_event(user.id, "Registered")
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("vault"))
    if request.method == "POST":
        username = request.form.get("username") or ""
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            unlock_vault(user, password)
            if user.mfa_secret:
                session["mfa_user_id"] = user.id  # not logged in until TOTP verified
                return redirect(url_for("verify_mfa"))
            login_user(user)
            log_event(user.id, "Logged in")
            return redirect(url_for("vault"))
        log_event(None, "Failed login")
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/verify_mfa", methods=["GET", "POST"])
@limiter.limit("6 per minute", methods=["POST"])
def verify_mfa():
    user_id = session.get("mfa_user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user or not user.mfa_secret:
        return redirect(url_for("login"))
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        if pyotp.TOTP(user.mfa_secret).verify(token, valid_window=1):
            session.pop("mfa_user_id")
            login_user(user)
            log_event(user.id, "Logged in with MFA")
            return redirect(url_for("vault"))
        log_event(user.id, "Failed MFA")
        flash("Invalid code. Try again.", "danger")
    return render_template("verify_mfa.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event(current_user.id, "Logged out")
    lock_vault()
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/setup_mfa", methods=["GET", "POST"])
@login_required
@limiter.limit("3 per minute", methods=["POST"])
def setup_mfa():
    if current_user.mfa_secret:
        flash("MFA is already enabled.", "info")
        return redirect(url_for("vault"))
    secret = session.get("pending_mfa_secret") or pyotp.random_base32()
    session["pending_mfa_secret"] = secret
    if request.method == "POST":
        # Only enable MFA once the user proves their app is set up correctly.
        if pyotp.TOTP(secret).verify((request.form.get("token") or "").strip(), valid_window=1):
            current_user.mfa_secret = secret
            session.pop("pending_mfa_secret")
            db.session.commit()
            log_event(current_user.id, "MFA enabled")
            flash("MFA enabled.", "success")
            return redirect(url_for("vault"))
        flash("That code didn't match. Try again.", "danger")
    uri = pyotp.TOTP(secret).provisioning_uri(current_user.username, issuer_name="SecurePM")
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    qr = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_mfa.html", qr=qr, secret=secret)


# ---------- Vault routes ---------- #

@app.route("/vault")
@login_required
def vault():
    if require_unlocked() is None:
        return redirect(url_for("login"))
    q = (request.args.get("q") or "").strip()
    category = request.args.get("category") or ""
    query = VaultItem.query.filter_by(user_id=current_user.id)
    if q:
        query = query.filter(VaultItem.site.ilike(f"%{q}%"))
    if category:
        query = query.filter_by(category=category)
    items = query.order_by(VaultItem.site).all()
    categories = sorted({i.category for i in current_user.items if i.category})
    return render_template("vault.html", items=items, categories=categories,
                           search_query=q, current_category=category)


@app.route("/vault/<int:item_id>/reveal", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def reveal(item_id):
    key = current_key()
    if key is None:
        return jsonify(error="Vault locked"), 401
    item = own_item_or_404(item_id)
    try:
        return jsonify(password=decrypt_password(key, item))
    except InvalidTag:
        return jsonify(error="Could not decrypt item"), 500


def _item_from_form():
    site = (request.form.get("site") or "").strip()[:100]
    vault_username = (request.form.get("vault_username") or "").strip()[:100]
    category = (request.form.get("category") or "").strip()[:50] or None
    password = request.form.get("password") or ""
    return site, vault_username, category, password


@app.route("/add", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per minute", methods=["POST"])
def add_item():
    key = require_unlocked()
    if key is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        site, vault_username, category, password = _item_from_form()
        if not site or not vault_username or not password:
            flash("Site, username, and password are required.", "danger")
        else:
            ct, nonce = encrypt_password(key, current_user.id, password)
            db.session.add(VaultItem(user_id=current_user.id, site=site, vault_username=vault_username,
                                     category=category, password_encrypted=ct, nonce=nonce))
            db.session.commit()
            log_event(current_user.id, "Vault item added")
            return redirect(url_for("vault"))
    return render_template("item_form.html", item=None)


@app.route("/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def edit_item(item_id):
    key = require_unlocked()
    if key is None:
        return redirect(url_for("login"))
    item = own_item_or_404(item_id)
    if request.method == "POST":
        site, vault_username, category, password = _item_from_form()
        if not site or not vault_username:
            flash("Site and username are required.", "danger")
        else:
            item.site, item.vault_username, item.category = site, vault_username, category
            if password:  # blank = keep current password
                item.password_encrypted, item.nonce = encrypt_password(key, current_user.id, password)
            db.session.commit()
            log_event(current_user.id, "Vault item edited")
            return redirect(url_for("vault"))
    return render_template("item_form.html", item=item)


@app.route("/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_item(item_id):
    item = own_item_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    log_event(current_user.id, "Vault item deleted")
    return redirect(url_for("vault"))


@app.route("/export")
@login_required
@limiter.limit("2 per minute")
def export_vault():
    """Export still-encrypted items (useless without the master password)."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["site", "vault_username", "category", "nonce_b64", "password_encrypted_b64"])
    for i in current_user.items:
        w.writerow([i.site, i.vault_username, i.category or "",
                    base64.b64encode(i.nonce).decode(), base64.b64encode(i.password_encrypted).decode()])
    log_event(current_user.id, "Vault exported")
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=vault_export.csv"})


@app.route("/generate", methods=["GET", "POST"])
@login_required
def generate():
    if request.method == "POST":
        try:
            length = int(request.form.get("length", 16))
        except ValueError:
            return jsonify(error="Length must be a number"), 400
        use_symbols = request.form.get("use_symbols") in ("on", "true", "1")
        return jsonify(password=generate_password(length, use_symbols))
    return render_template("generate.html")


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
