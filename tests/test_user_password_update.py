"""
Password changes through UserService.update_user.

Policy (5f147c8): setting a new password always requires the target user's
current password - for admins too. A user who has forgotten it resets it via
the emailed-OTP flow instead (/auth/forgot-password + /auth/reset-password).
"""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.security import get_password_hash, verify_password
from app.models import User, UserRole
from app.models.security_audit_log import AuditLog
from app.models.user_permission import UserPermission
from app.modules.users.service import UserService
from app.schemas.user import UserUpdate

OLD_PASSWORD = "Old-Passw0rd!"
NEW_PASSWORD = "New-Passw0rd!"


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [User.__table__, UserPermission.__table__, AuditLog.__table__]
    Base.metadata.create_all(bind=engine, tables=tables)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))


def create_test_user(db_session, user_id=1, username="alice", role=UserRole.USER):
    user = User(
        id=user_id,
        username=username,
        email=f"{username}@example.com",
        hashed_password=get_password_hash(OLD_PASSWORD),
        role=role,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_self_password_change_requires_current_password(db_session):
    create_test_user(db_session)

    with pytest.raises(HTTPException) as exc_info:
        UserService(db_session).update_user(1, UserUpdate(password=NEW_PASSWORD), current_user_id=1)

    assert exc_info.value.status_code == 400
    assert "current password is required" in exc_info.value.detail


def test_self_password_change_rejects_wrong_current_password(db_session):
    create_test_user(db_session)

    with pytest.raises(HTTPException) as exc_info:
        UserService(db_session).update_user(
            1, UserUpdate(password=NEW_PASSWORD, current_password="Wr0ng-Password!"), current_user_id=1,
        )

    assert exc_info.value.status_code == 401
    assert verify_password(OLD_PASSWORD, db_session.get(User, 1).hashed_password)


def test_self_password_change_accepts_correct_current_password(db_session):
    user = create_test_user(db_session)

    updated = UserService(db_session).update_user(
        1, UserUpdate(password=NEW_PASSWORD, current_password=OLD_PASSWORD), current_user_id=1,
    )

    assert updated.id == user.id
    assert verify_password(NEW_PASSWORD, updated.hashed_password)


def test_admin_also_needs_the_users_current_password(db_session):
    create_test_user(db_session, user_id=1, username="root", role=UserRole.ADMIN)
    create_test_user(db_session, user_id=2, username="bob")
    service = UserService(db_session)

    with pytest.raises(HTTPException) as exc_info:
        service.update_user(2, UserUpdate(password=NEW_PASSWORD), current_user_id=1)
    assert exc_info.value.status_code == 400

    updated = service.update_user(
        2, UserUpdate(password=NEW_PASSWORD, current_password=OLD_PASSWORD), current_user_id=1,
    )
    assert verify_password(NEW_PASSWORD, updated.hashed_password)


def test_weak_new_password_is_rejected_by_policy():
    with pytest.raises(ValueError):
        UserUpdate(password="new-password")
