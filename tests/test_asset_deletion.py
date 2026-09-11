"""Regression tests for deleting an asset (Asset List -> Delete).

Deleting an asset touches a dozen child tables. Every FK is ON DELETE CASCADE
or SET NULL, and every ORM relationship on Asset is passive_deletes, so the
delete has to be one statement Postgres resolves — not a sweep that loads each
child to null it out (which is what made the operation slow and, for a NOT NULL
child column, fail outright).

Needs a migrated PostgreSQL database; each test runs inside a transaction that
is rolled back, so nothing here touches real rows. The service commits
internally, which lands on a savepoint here — never point these at a database
whose contents matter.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy import event, inspect, text
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.audit import AuditSession, DeviceType
from app.models.hardening_log import HardeningLog
from app.models.port import Port, Protocol
from app.models.risk import AssetOpenPort, AssetRiskHistory, AssetRiskScore
from app.models.user import User
from app.modules.assets.service import AssetService


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection)
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, transaction):
        if transaction.nested and not transaction._parent.nested:
            sess.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", _restart_savepoint)
        session.close()
        trans.rollback()
        connection.close()


_seq = [0]


def _next() -> int:
    _seq[0] += 1
    return _seq[0]


@pytest.fixture
def user(db) -> User:
    row = User(username=f"del_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def asset(db, user) -> Asset:
    asset_type = AssetType(type_name=f"DelTestType_{_next()}", category="server")
    db.add(asset_type)
    db.flush()
    row = Asset(
        asset_name=f"del-test-{_next()}",
        asset_type_id=asset_type.id,
        user_id=user.id,
    )
    db.add(row)
    db.flush()
    return row


def _protocol(db) -> Protocol:
    row = db.query(Protocol).first()
    if row is None:
        row = Protocol(protocol_name=f"TCP{_next()}")
        db.add(row)
        db.flush()
    return row



def test_delete_removes_the_asset(db, asset):
    asset_id = asset.id
    assert AssetService.delete_asset(db, asset_id) is True
    assert db.query(Asset).filter(Asset.id == asset_id).first() is None


def test_delete_missing_asset_reports_false(db):
    """The router turns this into a 404 rather than a silent success."""
    assert AssetService.delete_asset(db, 2_000_000_000) is False


def test_delete_cascades_to_child_rows(db, asset):
    """Children with ON DELETE CASCADE go with the asset, not before it."""
    asset_id = asset.id
    db.add(Port(asset_id=asset_id, port_number=22, protocol_id=_protocol(db).id))
    db.add(AssetOpenPort(
        asset_id=asset_id, ip_address="10.0.0.9", port=22,
        protocol="tcp", severity="high", severity_score=7,
    ))
    db.add(AssetRiskScore(asset_id=asset_id, final_risk_score=50, risk_level="high"))
    db.add(AssetRiskHistory(asset_id=asset_id, risk_score=50, risk_level="high"))
    db.flush()

    assert AssetService.delete_asset(db, asset_id) is True

    for model in (Port, AssetOpenPort, AssetRiskScore, AssetRiskHistory):
        remaining = (
            db.query(model).filter(model.asset_id == asset_id).count()
        )
        assert remaining == 0, f"{model.__name__} rows survived the delete"


def test_delete_detaches_set_null_children(db, asset, user):
    """History rows outlive the asset with a NULL asset_id — they are a record
    of what happened, not a part of the asset."""
    asset_id = asset.id
    session = AuditSession(
        asset_id=asset_id, user_id=user.id,
        device_type=DeviceType.CISCO, target_ip="10.0.0.9",
    )
    log = HardeningLog(
        asset_id=asset_id, user_id=user.id, action="delete-test", status="success"
    )
    db.add_all([session, log])
    db.flush()
    session_id, log_id = session.id, log.id

    assert AssetService.delete_asset(db, asset_id) is True

    assert db.get(AuditSession, session_id).asset_id is None
    assert db.get(HardeningLog, log_id).asset_id is None


def test_every_asset_child_relationship_is_passive(db):
    """Guards the fix directly.

    A one-to-many on Asset without passive_deletes makes SQLAlchemy load the
    whole collection and UPDATE each row on delete, which fails outright when
    the child's asset_id is NOT NULL. Adding a relationship without it would
    reintroduce the bug silently, so assert the property rather than only its
    symptom.
    """
    offenders = [
        rel.key
        for rel in inspect(Asset).relationships
        if rel.direction.name == "ONETOMANY" and not rel.passive_deletes
    ]
    assert offenders == []


def test_every_asset_fk_has_an_ondelete_rule(db):
    """A child FK without ON DELETE would make the asset undeletable."""
    rows = db.execute(text(
        """
        SELECT c.conrelid::regclass::text, c.conname, pg_get_constraintdef(c.oid)
        FROM pg_constraint c
        WHERE c.confrelid = 'asset_inventory'::regclass AND c.contype = 'f'
        """
    )).fetchall()
    assert rows, "expected child tables referencing asset_inventory"
    missing = [
        (table, name)
        for table, name, definition in rows
        if "ON DELETE" not in definition
    ]
    assert missing == [], f"FKs with no ON DELETE rule: {missing}"


# ======================================================================
# Route behaviour
# ======================================================================

def test_route_returns_the_deleted_id(db, asset, user):
    """The frontend filters the row out by id, so the id has to come back."""
    from app.modules.assets.router_with_auth import delete_asset as route

    asset_id = asset.id
    result = route(asset_id=asset_id, current_user=user, db=db)
    assert result["id"] == asset_id
    assert "Deleted" in result["message"]


def test_route_404s_for_a_missing_asset(db, user):
    from app.modules.assets.router_with_auth import delete_asset as route

    with pytest.raises(HTTPException) as exc_info:
        route(asset_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404
