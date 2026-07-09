"""
Schema/value length regression tests.

Background: hardening_actions.action_type was VARCHAR(10) while the manual
"View Fix" path wrote 'manual-execute' (14 chars), so EVERY manual execution
died with StringDataRightTruncation. These tests pin the fix from two sides:

1. Unit (always runs): every literal the code writes into a constrained
   String(N) column fits, including every check id defined by ANY vendor
   module (scanned from source so new checks are covered automatically).
2. Integration (runs when the configured PostgreSQL is reachable): inserts a
   real HardeningAction row for every action_type/status literal — including
   action_type='manual-execute' — into a scratch schema and commits.
"""

import glob
import re

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.audit import AuditCheck, AuditResult, AuditSession
from app.models.hardening import HardeningAction

# Every value the code writes to these columns (see the vendor hardening
# services and shared/hardening_router.py).
ACTION_TYPES = ["preview", "execute", "manual-execute"]
ACTION_STATUSES = ["pending", "executing", "success", "failed", "blocked"]
SESSION_STATUSES = ["running", "completed", "failed"]

# Longest check id currently defined anywhere (linux RHEL numbering).
LONGEST_KNOWN_CHECK_ID = "LNX-RHEL-L1-5.3.1.1"


# ---------------------------------------------------------------------------
# 1. Unit: model column sizes vs the values the code writes
# ---------------------------------------------------------------------------
def test_action_type_column_fits_all_action_types():
    size = HardeningAction.__table__.c.action_type.type.length
    for value in ACTION_TYPES:
        assert len(value) <= size, (
            f"action_type '{value}' ({len(value)} chars) exceeds VARCHAR({size})"
        )


def test_status_columns_fit_all_statuses():
    size = HardeningAction.__table__.c.status.type.length
    for value in ACTION_STATUSES:
        assert len(value) <= size
    size = AuditSession.__table__.c.status.type.length
    for value in SESSION_STATUSES:
        assert len(value) <= size


def _all_defined_check_ids():
    """Scan every module's source for check-id-shaped strings (FG-*, IOS-*,
    LNX-*, WIN-*, APACHE-*, MONGO-*, MSSQL-*, ...) so newly added checks are
    length-tested without registering them here."""
    pat = re.compile(
        r'''["']((?:FG|IOS|LNX|LINUX|APACHE|MONGO|MDB|MSSQL|WIN|WN)'''
        r'''(?:-[A-Za-z0-9.]+){1,6})["']'''
    )
    ids = set()
    for f in glob.glob("app/modules/**/*.py", recursive=True):
        with open(f, encoding="utf-8", errors="ignore") as fh:
            for m in pat.finditer(fh.read()):
                s = m.group(1)
                if any(c.isdigit() for c in s):
                    ids.add(s)
    return ids


def test_every_vendor_check_id_fits_check_number_columns():
    ids = _all_defined_check_ids()
    assert LONGEST_KNOWN_CHECK_ID in ids  # scanner sanity check
    for column in (
        HardeningAction.__table__.c.check_number,
        AuditResult.__table__.c.check_number,
        AuditCheck.__table__.c.check_number,
    ):
        size = column.type.length
        too_long = sorted(i for i in ids if len(i) > size)
        assert not too_long, (
            f"{column.table.name}.{column.name} is VARCHAR({size}); "
            f"these check ids overflow it: {too_long}"
        )


# ---------------------------------------------------------------------------
# 2. Integration: real INSERTs against PostgreSQL (scratch schema)
# ---------------------------------------------------------------------------
_SCHEMA = "test_varchar_lengths"


@pytest.fixture(scope="module")
def pg_db():
    from app.core.config import settings
    from app.core.database import Base

    engine = create_engine(settings.DATABASE_URL)
    try:
        conn = engine.connect()
    except Exception:
        pytest.skip("PostgreSQL not reachable — skipping DB length regression test")

    conn.execute(text(f'DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE'))
    conn.execute(text(f'CREATE SCHEMA {_SCHEMA}'))
    conn.execute(text(f'SET search_path TO {_SCHEMA}'))
    conn.commit()
    conn.execute(text(f'SET search_path TO {_SCHEMA}'))
    Base.metadata.create_all(bind=conn)
    conn.commit()

    session = sessionmaker(bind=conn)()
    try:
        yield session
    finally:
        session.close()
        conn.rollback()
        conn.execute(text(f'DROP SCHEMA IF EXISTS {_SCHEMA} CASCADE'))
        conn.commit()
        conn.close()
        engine.dispose()


def _seed_fk_chain(db):
    """Minimal user -> asset-type -> asset -> session -> result chain that
    HardeningAction's NOT NULL FKs require."""
    from app.models import Asset, AssetType, User
    from app.models.audit import CheckStatus, DeviceType

    user = User(username="len-test", email="len-test@example.com",
                hashed_password="x")
    db.add(user)
    db.flush()

    asset_type = AssetType(type_name="len-test-type", category="Network")
    db.add(asset_type)
    db.flush()

    asset = Asset(asset_name="len-test-asset", asset_type_id=asset_type.id)
    db.add(asset)
    db.flush()

    session = AuditSession(
        user_id=user.id, asset_id=asset.id, target_ip="192.0.2.1",
        device_type=DeviceType.FORTINET, status="completed",
    )
    db.add(session)
    db.flush()

    result = AuditResult(
        session_id=session.id,
        check_number=LONGEST_KNOWN_CHECK_ID,  # longest id must store, too
        check_title="length regression",
        status=CheckStatus.FAIL,
    )
    db.add(result)
    db.flush()
    return user, asset, session, result


def test_hardening_action_accepts_every_literal(pg_db):
    """The exact insert that used to raise StringDataRightTruncation."""
    user, asset, session, result = _seed_fk_chain(pg_db)

    for action_type in ACTION_TYPES:
        for status_value in ACTION_STATUSES:
            pg_db.add(HardeningAction(
                audit_result_id=result.id,
                user_id=user.id,
                asset_id=asset.id,
                audit_session_id=session.id,
                check_number=LONGEST_KNOWN_CHECK_ID,
                check_title="length regression",
                action_type=action_type,
                status=status_value,
                commands_json="[]",
            ))
    pg_db.commit()  # must not raise (was: value too long for varchar(10))

    stored = pg_db.query(HardeningAction).filter(
        HardeningAction.action_type == "manual-execute"
    ).count()
    assert stored == len(ACTION_STATUSES)
