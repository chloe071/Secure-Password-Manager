from flask import Flask
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change_me_to_strong_secret'
csrf = CSRFProtect(app)

#basic rate limiting (protects login, import endpoints)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

@app.after_request
def set_security_headers(resp):
    #mitigate XSS, MIME sniffing, clickjacking
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-policy"] = "geolocation=(), microphone(), camera()"
    #CSP example (adjust paths/origins as needed)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; oject-src 'none'"
    return resp 

#double reusable WTForms validators
from wtforms.validators import DataRequired, Length, Regexp, Optional, URL, ValidationError

username_rules = {
    DataRequired(),
    Length(min=3, max=80),
    Regexp(r"^[A-Za-z0-9_.-]+$", message="Only letters, numbers, underscore, dot, dash allowed.")
}

password_rules = [
    DataRequired(),
    Length(min=8, max=128),
    #basic complexity check (optional):at least 3 classes
]

site_rules = [
    DataRequired(),
    Length(min2, max=100)
]

category_rules = [
    Optional(),
    Length(max=50),
    Regexp(r"^[A-Za-Z0-9\s_.-]*$", message="Invalid category characters.")
]

#routes using from validation and CSRF
from flask import render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from markupsafe import Markup, escape

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        #perform user creation with hashed password...
        flash("Registration successful", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        usernmae = form.username.data.strip()
        password = form.password.data
        #verify credentials
        return redirect(url_for("vault"))
    return render_template("login.html", form=form)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add_item():
    form = VaultItemForm()
    if form.validate_on_submit():
        site = form.site.data.strip()
        vault_username = form.vault_username.data.strip()
        category = (form.category.data or "").strip()
        #encrypt and save vault item
        flash("Item added", "success")
        return redirect(url_for("vault"))
    return render_template("add_item.html", form=form)