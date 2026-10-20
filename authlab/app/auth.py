import re
import time

from flask import Blueprint, g, jsonify, request

from . import db
from .decorators import login_required
from .security import create_token, password_problems, verify_password

bp = Blueprint("auth", __name__)

MAX_FAILS = 3
LOCK_SECONDS = 30
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


@bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password are required"), 400
        
    if not USERNAME_RE.match(username):
        return jsonify(error="username must be 3-20 letters, digits or underscores"), 400

    problems = password_problems(password)
    if problems:
        return jsonify(error="weak password", must_include=problems), 400

    try:
        # The role is NEVER read from the request. Everyone registers as a student.
        db.create_user(username, password, role="student")
    except ValueError:
        return jsonify(error="username already exists"), 409

    return jsonify(username=username, role="student"), 201


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username, password = data.get("username"), data.get("password")
    
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="username and password are required"), 400

    fails = db.FAILS.setdefault(username, {"n": 0, "until": 0.0})
    
    if fails["until"] > time.time():
        return jsonify(error="Account temporarily locked"), 423

    user = db.USERS.get(username)
    if not user or not verify_password(password, user["hash"]):
        fails["n"] += 1
        if fails["n"] >= MAX_FAILS:
            fails["until"] = time.time() + LOCK_SECONDS
            fails["n"] = 0
        # Same message for unknown user and wrong password: no user enumeration.
        return jsonify(error="Invalid credentials"), 401

    fails["n"] = 0
    return jsonify(token=create_token(username, user["role"]))


@bp.post("/logout")
@login_required
def logout():
    db.REVOKED.add(g.jti)  # this exact token can no longer be used
    return jsonify(message="Logged out")


@bp.get("/me")
@login_required
def me():
    return jsonify(user=g.user, role=g.role)