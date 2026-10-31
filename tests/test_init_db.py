"""
scripts/init_db.py makes the first web administrator: on the appliance's first start
(appliance/ngcorion_appliance/system.py create_admin) and from the console's password reset when
there is none yet. It imported a model the one zone list removed (NetworkZone), so it stopped before
making the account and no password the operator chose could sign in.

Needs a migrated PostgreSQL database; the test runs in a transaction that is rolled back.
"""
import importlib.util
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.core.security import verify_password
from app.models import User, UserPermission

ROOT = Path(__file__).resolve().parent.parent
GOOD = "Ngc-Admin-2026!x"


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


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)        # every import resolves
    return module


def test_init_db_makes_the_administrator_with_the_password_given(db, monkeypatch):
    init_db = _load("init_db_under_test", ROOT / "scripts" / "init_db.py")
    monkeypatch.setenv("NGCORION_ADMIN_PASSWORD", GOOD)
    db.query(User).filter(User.username == "admin").delete()
    db.flush()

    admin = init_db.create_admin_user(db)
    init_db.create_admin_permissions(db, admin)
    init_db.create_default_asset_types(db)
    init_db.create_default_os_catalog(db)
    init_db.create_default_vendors(db)

    row = db.query(User).filter(User.username == "admin").one()
    assert verify_password(GOOD, row.hashed_password) and row.is_active and row.must_change_password
    assert db.query(UserPermission).filter(UserPermission.user_id == row.id).count() > 0


def test_a_weak_password_is_refused(monkeypatch):
    init_db = _load("init_db_under_test", ROOT / "scripts" / "init_db.py")
    monkeypatch.setenv("NGCORION_ADMIN_PASSWORD", "admin")
    with pytest.raises(ValueError):
        init_db._admin_password()


def test_the_appliance_password_reset_compiles_and_its_imports_resolve():
    sys.path.insert(0, str(ROOT / "appliance"))
    try:
        from ngcorion_appliance.system import _RESET_PASSWORD_PY
    finally:
        sys.path.remove(str(ROOT / "appliance"))
    compile(_RESET_PASSWORD_PY, "<reset>", "exec")
    imports = "\n".join(line for line in _RESET_PASSWORD_PY.splitlines() if line.startswith(("import ", "from ")))
    exec(compile(imports, "<reset-imports>", "exec"), {})
    assert 'runpy.run_path("scripts/init_db.py"' in _RESET_PASSWORD_PY      # no admin yet: make one
