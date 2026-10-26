class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user") #role field

from functools import wraps
from flask import abort
from flask_login import current_user

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  #unauthorized
            user_role = getattr(current_user, "role", None)
            if user_role != required_role:
                abort(403) #forbidden
            return f(*args, *kwargs)
        return wrapped
    return decorator

def roles_accepted(*accepted_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            user_role = getattr(current_user, "role", None)
            if user_role not in accepted_roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator