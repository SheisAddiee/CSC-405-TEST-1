import pytest

matrix = [
    (None, "GET", "/me", 401),
    (None, "GET", "/grades/carol", 401),
    (None, "GET", "/grades/bob", 401),
    (None, "POST", "/courses", 401),
    (None, "DELETE", "/users/carol", 401),
    ("carol", "GET", "/me", 200),
    ("carol", "GET", "/grades/carol", 200),
    ("carol", "GET", "/grades/bob", 403),
    ("carol", "POST", "/courses", 403),
    ("carol", "DELETE", "/users/bob", 403),
    ("bob", "GET", "/me", 200),
    ("bob", "GET", "/grades/bob", 200),
    ("bob", "GET", "/grades/carol", 403),
    ("bob", "POST", "/courses", 201),
    ("bob", "DELETE", "/users/carol", 403),
    ("alice", "GET", "/me", 200),
    ("alice", "GET", "/grades/alice", 200),
    ("alice", "GET", "/grades/carol", 200),
    ("alice", "POST", "/courses", 201),
    ("alice", "DELETE", "/users/carol", 200),
]

@pytest.mark.parametrize("user, method, path, expected_status", matrix)
def test_authorization_matrix(client, auth, user, method, path, expected_status):
    headers = auth(user) if user else {}
    body = {"title": "New Course"} if method == "POST" else None
    r = client.open(path, method=method, headers=headers, json=body)
    assert r.status_code == expected_status

def test_blank_course_title_400(client, auth):
    r = client.post("/courses", headers=auth("bob"), json={"title": ""})
    assert r.status_code == 400

def test_deleted_user_token_fails(client, auth):
    bob_headers = auth("bob")
    client.delete("/users/bob", headers=auth("alice"))
    assert client.get("/me", headers=bob_headers).status_code == 401