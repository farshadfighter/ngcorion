from app.core.database import SessionLocal
from app.models import User, UserRole
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

db = SessionLocal()

try:
    password = "123456"
    hashed = pwd_context.hash(password)
    
    # بدون full_name
    user = User(
        username="Sina_Bimesl",
        email="sina@gmail.com",
        hashed_password=hashed,
        role=UserRole.ADMIN,
        is_active=True
    )
    db.add(user)
    db.commit()
    
    print(f"✅ Created user: {user.username} (id={user.id})")
    
except Exception as e:
    print(f"❌ Error: {e}")
finally:
    db.close()