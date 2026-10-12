"""Application user accounts and their roles."""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base
import enum

class UserRole(str, enum.Enum):
    """Roles: admin (everything), manager and user (what their module permissions allow), guest
    (read-only by default).
    """
    ADMIN = "admin"
    USER = "user"
    MANAGER = "manager"
    GUEST = "guest"

class User(Base):
    """An account of NGCorion: identity, bcrypt password hash, role, language, and whether the password
    must be changed at the next login. Per-module permissions are in UserPermission.
    """
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
    # Where the password is checked: "local" (hashed_password) or "ldap" (Active Directory / LDAP,
    # app/modules/directory). A directory account is made at its first sign-in; its role and
    # permissions follow its directory groups, and hashed_password holds a random value nobody knows.
    auth_source = Column(String(10), nullable=False, default="local", server_default="local")
    external_dn = Column(Text, nullable=True)
    # Turned off by the directory check (disabled, deleted or out of every mapped group there), not
    # by an administrator: the next successful directory sign-in turns it back on.
    disabled_by_directory = Column(Boolean, nullable=False, default=False, server_default="false")
    directory_synced_at = Column(DateTime(timezone=True), nullable=True)

    # Relationship to permissions - cascade delete ensures permissions are deleted when user is deleted
    permissions = relationship("UserPermission", back_populates="user", cascade="all, delete-orphan")