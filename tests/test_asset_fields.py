"""
Asset fields that are optional, and the dates NGCorion keeps itself.

Reported from a server: an asset could not be saved without a serial number, a value, or the last audit
and hardening dates. The edit forms sent those as "", which the API refused for a date or a number
(422), and stored for the serial - unique, so the next asset without one collided (500). And the last
audit date was only ever typed in: no audit set it, and nothing at all kept a last hardening date.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
from datetime import date, datetime

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.hardening import HardeningAction
from app.modules.assets.schemas import AssetCreate, AssetUpdate


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


_seq = [0]


def _n():
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def kind(db):
    t = AssetType(type_name=f"Fields type {_n()}", category="server")
    db.add(t)
    db.flush()
    return t


def test_an_empty_field_is_not_set():
    body = AssetUpdate(**{"serial_number": "", "last_audit_date": "", "last_patch_date": " ", "asset_value": "",
                          "confidentiality_level": "", "description": ""})
    assert body.model_dump(exclude_unset=True) == {
        "serial_number": None, "last_audit_date": None, "last_patch_date": None, "asset_value": None,
        "confidentiality_level": None, "description": None}
    created = AssetCreate(asset_name="web-02", asset_type_id=1, serial_number="", asset_value="", last_audit_date="")
    assert (created.serial_number, created.asset_value, created.last_audit_date) == (None, None, None)


def test_two_assets_without_a_serial(db, kind):
    """The serial is unique: "" for both collided; empty means none."""
    a = Asset(asset_name=f"nos-{_n()}", asset_type_id=kind.id, serial_number="")
    b = Asset(asset_name=f"nos-{_n()}", asset_type_id=kind.id, serial_number="  ")
    db.add_all([a, b])
    db.flush()
    assert a.serial_number is None and b.serial_number is None
    a.serial_number = " SN-1 "
    db.flush()
    assert a.serial_number == "SN-1"


def test_audit_and_hardening_set_the_asset_dates(db, kind):
    user = User(username=f"fld_{_n()}", email=f"fld{_seq[0]}@corp.example", hashed_password="x",
                role=UserRole.ADMIN, is_active=True)
    asset = Asset(asset_name=f"dated-{_seq[0]}", asset_type_id=kind.id, ip_address="10.46.0.1",
                  last_audit_date=date(2026, 1, 5))
    db.add_all([user, asset])
    db.flush()

    session = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address,
                           device_type=DeviceType.LINUX, status="running", started_at=datetime(2026, 3, 1, 9))
    db.add(session)
    db.flush()
    assert asset.last_audit_date == date(2026, 1, 5)              # running: not yet
    session.status, session.completed_at = "completed", datetime(2026, 3, 1, 9, 30)
    db.flush()
    assert asset.last_audit_date == date(2026, 3, 1)

    result = AuditResult(session_id=session.id, check_number="1.1", check_title="Check", severity="high",
                         level="L1", status=CheckStatus.FAIL)
    db.add(result)
    db.flush()

    def action(status, action_type, when):
        return HardeningAction(audit_result_id=result.id, user_id=user.id, asset_id=asset.id,
                               audit_session_id=session.id, check_number="1.1", check_title="Check",
                               action_type=action_type, status=status, commands_json="[]",
                               executed_at=when, completed_at=when)

    db.add(action("success", "preview", datetime(2026, 3, 2)))
    db.add(action("failed", "execute", datetime(2026, 3, 3)))
    db.flush()
    assert asset.last_hardening_date is None                       # a preview or a failure is not hardening
    db.add(action("success", "execute", datetime(2026, 3, 4, 23, 50)))
    db.flush()
    assert asset.last_hardening_date == date(2026, 3, 4)

    asset.last_audit_date = date(2026, 6, 1)                       # an audit done outside NGCorion, later
    old = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address,
                       device_type=DeviceType.LINUX, status="completed", started_at=datetime(2026, 4, 1))
    db.add(old)
    db.flush()
    assert asset.last_audit_date == date(2026, 6, 1)               # dates only move forward
