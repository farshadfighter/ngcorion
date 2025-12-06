"""
User Creation/Update Script

Creates or updates the admin user with default password.
WARNING: For development/testing only. Use secure passwords in production.
"""
from app.core.database import SessionLocal
from app.models import User, UserRole
from app.core.security import get_password_hash

db = SessionLocal()

try:
    # Only update password (without deletion!)
    user = db.query(User).filter(User.username == "admin").first()

    if user:
        # Update existing user password
        user.hashed_password = get_password_hash("123456")
        db.commit()
        print(f"✅ Password updated for: {user.username}")
    else:
        # Create new admin user
        user = User(
            username="admin",
            email="admin@test.com",
            hashed_password=get_password_hash("123456"),
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(user)
        db.commit()
        print(f"✅ User created: {user.username}")

except Exception as e:
    print(f"❌ Error: {e}")
    db.rollback()
finally:
    db.close()