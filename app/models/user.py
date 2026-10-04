"""Application user accounts and their roles."""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base
import enum

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    MANAGER = "manager"
    GUEST = "guest"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True)
    # Mobile number for SMS alerts (optional). Digits with an optional leading +.
    phone = Column(String(20), nullable=True)
    # Interface language ("en" | "fa"); empty = the system default (System Configuration).
    language = Column(String(5), nullable=True)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    # Set when someone other than the user chose the password (the first admin
    # from scripts/init_db.py, an account created by an administrator). Until
    # the user picks their own, get_current_user lets them reach only the
    # password-change and session endpoints (PASSWORD_CHANGE_ALLOWED).
    must_change_password = Column(Boolean, nullable=False, default=False, server_default="false")
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship to permissions - cascade delete ensures permissions are deleted when user is deleted
    permissions = relationship("UserPermission", back_populates="user", cascade="all, delete-orphan")