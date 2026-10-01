"""Interface language: per-user choice, system default, and what /auth/me reports."""
import importlib

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.database import engine
from app.core.locale import default_language, user_language
from app.models import User, UserRole
from app.models.system_config import SECTION_LOCALE, SystemConfigSetting

auth = importlib.import_module("app.modules.auth.router")
sysconf = importlib.import_module("app.modules.system_config.router")


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture
def user(db):
    db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION_LOCALE).delete()
    u = User(username="locale_user", email="locale@example.com", hashed_password="x", role=UserRole.ADMIN)
    db.add(u)
    db.flush()
    return u


def test_falls_back_to_english(db, user):
    assert default_language(db) == "en"
    assert user_language(db, user) == "en"
    assert auth.read_current_user(current_user=user, db=db)["language"] == "en"


def test_system_default_applies_until_user_chooses(db, user):
    sysconf.update_locale_config(sysconf.LocaleConfig(default_language="fa"), current_user=user, db=db)
    assert sysconf.get_locale_config(_current_user=user, db=db)["config"] == {"default_language": "fa"}
    assert auth.read_current_user(current_user=user, db=db)["language"] == "fa"
    auth.set_my_language(auth.LanguageUpdate(language="en"), current_user=user, db=db)
    assert user.language == "en"
    assert auth.read_current_user(current_user=user, db=db)["language"] == "en"


def test_only_supported_languages():
    with pytest.raises(ValidationError):
        auth.LanguageUpdate(language="de")
    with pytest.raises(ValidationError):
        sysconf.LocaleConfig(default_language="xx")
    from app.schemas.user import UserUpdate
    assert UserUpdate(language="fa").language == "fa"
    with pytest.raises(ValidationError):
        UserUpdate(language="english")
