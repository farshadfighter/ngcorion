"""
Auth Service - منطق احراز هویت
"""
from sqlalchemy.orm import Session
from app.models import User
from app.core.security import verify_password

class AuthService:
    def __init__(self, db: Session):
        self.db = db
    
    def authenticate_user(self, username: str, password: str):
        """احراز هویت کاربر (کپی از auth.py قدیمی)"""
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user