from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.utl import get_remote_address

app = Flask(__name__)

#development: in-memory storage; Production: useRedis or similar
USE_REDIS = False  #set True in prod
STORAGE_URI = "memory://" if not USE_REDIS else "redis://localhost:6379/0"

limiter = Limiter(
    get_remote_address,   #key function
    app=app,
    default_limiters=["200 per day", "50 per hour"], #global defaults
    storage_uri=STORAGE_URI,  #swap to Redis in prod
    strategy="fixed-window",  # or moving window/sliding window counter
)

#per-route limits
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    # login logic
    return jsonify(ok=True)

@app.route("/setup_mfa", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def setup_mfa():
    #MFA provisioning
    return jsonify(ok=True)

@app.route("/verify_mfa", methods=["POST"])
@limiter.limit("6 per minute")
def verify_mfa():
    #TOTP verify
    return jsonify(ok=True)

@app.route("/add", methods=["POST"])
@limiter.limit("30 per minute")
def add_item():
    #add vault item
    return jsonify(ok=True)

@app.route("/export", methods=["GET"])
@limiter.limit("2 per minute")
def export_vault():
    #export logic
    return jsonify(ok=True)

@app.route("/ping")
@limiter.exempt
def ping():
    return "PONG"
#per user limits
from flask_login import current_user

def user_or_ip():
    #if authenticated, key by username; else IP
    if getattr(current_user, "is_authenticated", False):
        return f"user:{current_user.get_id()}"
user_limiter = Limiter(
    key_func=user_or_ip,
    app=app,
    storage_uri=STORAGE_URI,
)

@app.route("/vault")
@user_limiter.limit("120 per hour") #per user 1 limit
def vault():
    #fetch vault
    return jsonify(ok=True)

#blueprints and defaults
from flask import Blueprint

api = Blueprint("api", __name__)
limiter.limit("60 per minute")(api) #default for all routes in this blueprint

@api.route("/search")
def search():
    return jsonify(ok=True)

app.register_blueprint(api, url_prefix="/api")
