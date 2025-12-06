"""
Security Testing Script

Tests password hashing and verification functionality.
"""
from app.core.security import get_password_hash, verify_password

# Test password hashing
password = "123456"
hashed = get_password_hash(password)

print(f"Password: {password}")
print(f"Hashed: {hashed}")
print(f"Verify: {verify_password(password, hashed)}")

# Test with existing hash from database
from app.core.database import SessionLocal
from app.models import User

db = SessionLocal()
user = db.query(User).filter(User.username == "admin").first()
if user:
    print(f"\nDB Hash: {user.hashed_password}")
    print(f"Match: {verify_password('123456', user.hashed_password)}")
db.close()
