from flask import Blueprint, jsonify, request
from . import db
from .decorators import login_required, roles_required, is_owner_or_admin

bp = Blueprint("api", __name__)

@bp.get("/grades/<username>")
@login_required
def get_grades(username):
    if not is_owner_or_admin(username):
        return jsonify(error="Forbidden"), 403
        
    if username not in db.USERS:
        return jsonify(error="Not found"), 404
        
    return jsonify(user=username, grade=db.GRADES.get(username, "N/A")), 200

@bp.post("/courses")
@roles_required("editor", "admin")
def create_course():
    data = request.get_json(silent=True) or {}
    title = data.get("title")
    
    if not title or not isinstance(title, str) or not title.strip():
        return jsonify(error="Title is missing or blank"), 400
        
    db.COURSES.append(title)
    return jsonify(created=title), 201

@bp.delete("/users/<username>")
@roles_required("admin")
def delete_user(username):
    if username not in db.USERS:
        return jsonify(error="Not found"), 404
        
    del db.USERS[username]
    if username in db.GRADES:
        del db.GRADES[username]
        
    return jsonify(deleted=username), 200