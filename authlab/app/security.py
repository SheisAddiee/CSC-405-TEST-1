import os 
import re 
import uuid 
from datetime import datetime, timedelta, timezone 
 
import jwt 
from werkzeug.security import check_password_hash, generate_password_hash 
 
SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me-0123456789abcdef") 
ALGO = "HS256" 
 
 
def hash_password(password: str) -> str: 
    return generate_password_hash(password)          # salted scrypt by default 
 
 
def verify_password(password: str, hashed: str) -> bool: 
    return check_password_hash(hashed, password) 
 
 
def password_problems(password: str) -> list[str]: 
    """Return the policy rules that are broken (empty list means the password is 
OK).""" 
    problems = [] 
    if len(password) < 8: 
        problems.append("at least 8 characters") 
    if not re.search(r"[a-z]", password): 
        problems.append("a lowercase letter") 
    if not re.search(r"[A-Z]", password): 
        problems.append("an uppercase letter") 
    if not re.search(r"\d", password): 
        problems.append("a digit") 
    if not re.search(r"[^\w\s]", password): 
        problems.append("a symbol") 
    return problems 
 
 
def create_token(sub: str, role: str, minutes: int = 15) -> str: 
    now = datetime.now(timezone.utc) 
    payload = { 
        "sub": sub, 
        "role": role, 
        "jti": uuid.uuid4().hex,      # unique id, lets us revoke on logout 
        "iat": now, 
        "exp": now + timedelta(minutes=minutes), 
    } 
    return jwt.encode(payload, SECRET, algorithm=ALGO) 
 
 
def decode_token(token: str) -> dict: 
    # Pinning algorithms=[ALGO] rejects alg:none forgeries. 
    # PyJWT also verifies the signature and the exp (expiry) claim. 
    return jwt.decode(token, SECRET, algorithms=[ALGO])