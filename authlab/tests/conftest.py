import pytest
from app import create_app, db

PASSWORDS = {
    "alice": "Admin!pass",
    "bob": "Editor!pass",
    "carol": "Stud3nt!pass"
}

@pytest.fixture(autouse=True)
def reset_db():
    db.reset()

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()

@pytest.fixture
def auth(client):
    def _auth(username):
        password = PASSWORDS.get(username)
        r = client.post("/login", json={"username": username, "password": password})
        token = r.get_json()["token"]
        return {"Authorization": f"Bearer {token}"}
    return _auth