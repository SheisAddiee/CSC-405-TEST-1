from .security import hash_password 
 
USERS: dict[str, dict] = {}     # username -> {"hash": ..., "role": ...} 
GRADES: dict[str, str] = {}     # username -> grade 
FAILS: dict[str, dict] = {}     # username -> {"n": int, "until": float} 
REVOKED: set[str] = set()       # revoked token ids (jti) 
COURSES: list[str] = [] 
 
SEED = [
    ("alice", "Admin!pass", "admin", "A"),
    ("bob", "Editor!pass", "editor", "B+"),
    ("carol", "Stud3nt!pass", "student", "A-"),
]
 
 
def create_user(username: str, password: str, role: str = "student") -> None: 
    if username in USERS: 
        raise ValueError("username already exists") 
    USERS[username] = {"hash": hash_password(password), "role": role} 
    GRADES.setdefault(username, "N/A") 
 
 
def reset() -> None: 
    """Wipe everything and re-seed. Tests call this before every test.""" 
    for store in (USERS, GRADES, FAILS): 
        store.clear() 
    REVOKED.clear() 
    COURSES.clear() 
    for username, password, role, grade in SEED: 
        create_user(username, password, role) 
        GRADES[username] = grade


reset()