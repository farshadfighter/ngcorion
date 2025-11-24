from app.core.database import SessionLocal
from app.models import User, UserRole
from app.core.security import get_password_hash

db = SessionLocal()

try:
    # فقط آپدیت پسورد (بدون حذف!)
    user = db.query(User).filter(User.username == "admin").first()
    
    if user:
        # آپدیت پسورد
        user.hashed_password = get_password_hash("123456")
        db.commit()
        print(f"✅ Password updated for: {user.username}")
    else:
        # ساخت یوزر جدید
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