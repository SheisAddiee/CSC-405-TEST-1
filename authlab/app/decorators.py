from functools import wraps
import jwt
from flask import g, jsonify, request

from . import db
from .security import decode_token

def _unauthenticated():
    return jsonify(error="Unauthenticated"), 401

def login_required(fn):
    """Authentication: who are you? 401 if the token is missing, forged, expired or revoked."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return _unauthenticated()
        
        try:
            claims = decode_token(header[7:])
        except jwt.InvalidTokenError:  # bad signature, expired, wrong alg
            return _unauthenticated()
            
        username = claims.get("sub")
        if claims.get("jti") in db.REVOKED or username not in db.USERS:
            return _unauthenticated()
            
        g.user = username
        g.role = db.USERS[username]["role"]  # role comes from the DB, not from the token
        g.jti = claims["jti"]
        return fn(*args, **kwargs)
    return wrapper

def roles_required(*roles):
    """Authorization: are you allowed? Authenticates first (401), then checks the role (403)."""
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if g.role not in roles:
                return jsonify(error="Forbidden"), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def is_owner_or_admin(username: str) -> bool:
    """Object-level check: you may touch your own data, or you are an admin."""
    return g.user == username or g.role == "admin"