import base64
import json
import jwt
from app.security import create_token, SECRET, ALGO
from tests.conftest import PASSWORDS

def login(client, user, pw):
    return client.post("/login", json={"username": user, "password": pw})

def test_valid_login_returns_token(client):
    r = login(client, "alice", PASSWORDS["alice"])
    assert r.status_code == 200
    assert r.get_json()["token"].count(".") == 2

def test_no_token_401(client):
    assert client.get("/me").status_code == 401

def test_wrong_password_401(client):
    assert login(client, "alice", "wrongpass").status_code == 401

def test_unknown_user_wrong_password_same_error(client):
    r1 = login(client, "alice", "wrongpass")
    r2 = login(client, "unknown", "wrongpass")
    assert r1.status_code == 401 and r2.status_code == 401
    assert r1.get_json() == r2.get_json()

def test_no_real_password_in_db():
    from app import db
    assert "Admin!pass" not in db.USERS["alice"]["hash"]

def test_three_wrong_passwords_lockout(client):
    for _ in range(3):
        login(client, "alice", "wrong")
    r = login(client, "alice", PASSWORDS["alice"])
    assert r.status_code == 423

def test_tampered_token_401(client, auth):
    headers = auth("carol")
    token = headers["Authorization"].split(" ")[1]
    header_b64, payload_b64, sig = token.split(".")
    
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    payload["role"] = "admin"
    new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    
    tampered_token = f"{header_b64}.{new_payload_b64}.{sig}"
    assert client.get("/me", headers={"Authorization": f"Bearer {tampered_token}"}).status_code == 401

def test_expired_token_401(client):
    token = create_token("carol", "student", minutes=-5)
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

def test_alg_none_token_401(client):
    token = jwt.encode({"sub": "alice", "role": "admin", "jti": "x"}, None, algorithm="none")
    assert client.get("/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

def test_logout_invalidates_token(client, auth):
    headers = auth("carol")
    client.post("/logout", headers=headers)
    assert client.get("/me", headers=headers).status_code == 401

def test_weak_password_registration_400(client):
    r = client.post("/register", json={"username": "dave", "password": "abc"})
    assert r.status_code == 400

def test_successful_registration_201(client):
    r = client.post("/register", json={"username": "dave", "password": "Strong!password1"})
    assert r.status_code == 201
    assert r.get_json()["role"] == "student"

def test_duplicate_username_409(client):
    client.post("/register", json={"username": "dave", "password": "Strong!password1"})
    r = client.post("/register", json={"username": "dave", "password": "Strong!password1"})
    assert r.status_code == 409

def test_mass_assignment_student_role(client):
    r = client.post("/register", json={"username": "eve", "password": "Strong!password1", "role": "admin"})
    assert r.get_json()["role"] == "student"