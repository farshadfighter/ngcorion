import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.security import get_password_hash, verify_password
from app.models import User, UserRole
from app.models.user_permission import UserPermission
from app.modules.users.service import UserService
from app.schemas.user import UserUpdate


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine, tables=[User.__table__, UserPermission.__table__])
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine, tables=[UserPermission.__table__, User.__table__])


def create_test_user(db_session, user_id=1, username="alice", password="old-password"):
    user = User(
        id=user_id,
        username=username,
        email=f"{username}@example.com",
        hashed_password=get_password_hash(password),
        role=UserRole.USER,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    return user


def test_self_password_change_requires_current_password(db_session):
    create_test_user(db_session)
    service = UserService(db_session)

    with pytest.raises(HTTPException) as exc_info:
        service.update_user(
            1,
            UserUpdate(password="new-password"),
            current_user_id=1,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Current password is required to change your password"


def test_self_password_change_rejects_wrong_current_password(db_session):
    create_test_user(db_session)
    service = UserService(db_session)

    with pytest.raises(HTTPException) as exc_info:
        service.update_user(
            1,
            UserUpdate(password="new-password", current_password="wrong-password"),
            current_user_id=1,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Current password is incorrect"


def test_self_password_change_accepts_correct_current_password(db_session):
    user = create_test_user(db_session)
    service = UserService(db_session)

    updated_user = service.update_user(
        1,
        UserUpdate(password="new-password", current_password="old-password"),
        current_user_id=1,
    )

    assert updated_user.id == user.id
    assert verify_password("new-password", updated_user.hashed_password)


def test_admin_can_reset_another_users_password_without_current_password(db_session):
    target_user = create_test_user(db_session, user_id=2, username="bob")
    service = UserService(db_session)

    updated_user = service.update_user(
        target_user.id,
        UserUpdate(password="reset-password"),
        current_user_id=1,
    )

    assert verify_password("reset-password", updated_user.hashed_password)
