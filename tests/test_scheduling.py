"""Tests for the Scheduled Jobs module (recurrence computation, job
validation, run execution with the underlying discovery/audit I/O mocked,
and router behaviour).

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_drift.py / test_cve.py).
"""

import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.core.credential_crypto import encrypt_json, decrypt_json
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.user import User
from app.models.scheduling import ScheduledJob, ScheduledJobRun
from app.modules.scheduling.recurrence import compute_next_run_at
from app.modules.scheduling.audit_dispatch import REQUIRED_PARAMS, SUPPORTED_TECHNOLOGIES
from app.modules.scheduling.service import SchedulingService
from app.modules.scheduling.schemas import ScheduledJobCreate, ScheduledJobUpdate


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
    row = User(username=f"sched_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db) -> Asset:
    asset_type = AssetType(type_name=f"Cisco Router_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(asset_name=f"sched-asset-{_next()}", asset_type_id=asset_type.id, ip_address="10.0.0.9")
    db.add(row)
    db.flush()
    return row


# ======================================================================
# recurrence.compute_next_run_at
# ======================================================================

def test_daily_not_yet_passed_runs_today():
    now = datetime(2026, 9, 20, 10, 30)
    assert compute_next_run_at("daily", 14, 0, None, now) == datetime(2026, 9, 20, 14, 0)


def test_daily_already_passed_runs_tomorrow():
    now = datetime(2026, 9, 20, 10, 30)
    assert compute_next_run_at("daily", 9, 0, None, now) == datetime(2026, 9, 21, 9, 0)


def test_hourly_uses_next_top_of_minute():
    now = datetime(2026, 9, 20, 10, 30)
    assert compute_next_run_at("hourly", None, 45, None, now) == datetime(2026, 9, 20, 10, 45)
    assert compute_next_run_at("hourly", None, 15, None, now) == datetime(2026, 9, 20, 11, 15)


def test_weekly_picks_next_matching_weekday():
    now = datetime(2026, 9, 20, 10, 30)  # a Sunday
    assert compute_next_run_at("weekly", 8, 0, 0, now) == datetime(2026, 9, 21, 8, 0)  # next Monday


def test_weekly_same_day_later_time_runs_today():
    now = datetime(2026, 9, 20, 10, 30)
    assert compute_next_run_at("weekly", 14, 0, now.weekday(), now) == datetime(2026, 9, 20, 14, 0)


def test_unknown_recurrence_raises():
    with pytest.raises(ValueError):
        compute_next_run_at("monthly", 0, 0, None, datetime.utcnow())


# ======================================================================
# credential_crypto round-trip
# ======================================================================

def test_encrypt_decrypt_round_trip():
    ciphertext = encrypt_json('{"a": 1}')
    assert ciphertext != '{"a": 1}'
    assert decrypt_json(ciphertext) == '{"a": 1}'


def test_decrypt_garbage_raises_value_error():
    with pytest.raises(ValueError):
        decrypt_json("not-a-real-token")


# ======================================================================
# SchedulingService.create_job
# ======================================================================

def test_create_discovery_job(db, user):
    data = ScheduledJobCreate(job_name="nightly scan", job_type="discovery", recurrence="daily", hour=2, target="192.168.1.0/24")
    job = SchedulingService.create_job(db, data, user.id)
    assert job.id is not None
    assert job.job_type == "discovery"
    assert job.technology is None
    params = decrypt_json(job.params_encrypted)
    assert "192.168.1.0/24" in params


def test_create_discovery_job_without_target_fails(db, user):
    data = ScheduledJobCreate(job_name="bad", job_type="discovery")
    with pytest.raises(ValueError, match="target"):
        SchedulingService.create_job(db, data, user.id)


def test_create_audit_job_with_all_required_params(db, user):
    asset = _make_asset(db)
    data = ScheduledJobCreate(
        job_name="nightly cisco audit", job_type="audit", technology="cisco", asset_id=asset.id,
        audit_params={"ssh_username": "admin", "ssh_password": "secret"},
    )
    job = SchedulingService.create_job(db, data, user.id)
    assert job.technology == "cisco"
    assert job.asset_id == asset.id
    params = decrypt_json(job.params_encrypted)
    assert "secret" in params  # confirms it's really encoded, not that plaintext DB storage is fine


def test_create_audit_job_missing_required_param_fails(db, user):
    asset = _make_asset(db)
    data = ScheduledJobCreate(
        job_name="bad", job_type="audit", technology="mssql", asset_id=asset.id,
        audit_params={"mssql_username": "sa"},
    )
    with pytest.raises(ValueError, match="mssql_password"):
        SchedulingService.create_job(db, data, user.id)


def test_create_audit_job_unknown_technology_fails(db, user):
    asset = _make_asset(db)
    data = ScheduledJobCreate(job_name="bad", job_type="audit", technology="juniper", asset_id=asset.id, audit_params={})
    with pytest.raises(ValueError, match="technology"):
        SchedulingService.create_job(db, data, user.id)


def test_create_weekly_job_without_day_of_week_fails(db, user):
    data = ScheduledJobCreate(job_name="bad", job_type="discovery", recurrence="weekly", target="10.0.0.0/24")
    with pytest.raises(ValueError, match="day_of_week"):
        SchedulingService.create_job(db, data, user.id)


def test_all_supported_technologies_have_required_params_defined():
    assert set(REQUIRED_PARAMS.keys()) == set(SUPPORTED_TECHNOLOGIES)


# ======================================================================
# SchedulingService.update_job
# ======================================================================

def test_update_job_toggle_enabled(db, user):
    data = ScheduledJobCreate(job_name="j", job_type="discovery", target="10.0.0.0/24")
    job = SchedulingService.create_job(db, data, user.id)
    updated = SchedulingService.update_job(db, job, ScheduledJobUpdate(enabled=False))
    assert updated.enabled is False


def test_update_job_recurrence_recomputes_next_run_at(db, user):
    data = ScheduledJobCreate(job_name="j", job_type="discovery", recurrence="daily", hour=2, target="10.0.0.0/24")
    job = SchedulingService.create_job(db, data, user.id)
    original_next_run = job.next_run_at
    updated = SchedulingService.update_job(db, job, ScheduledJobUpdate(recurrence="hourly", minute=5))
    assert updated.next_run_at != original_next_run


def test_update_audit_params_merges_and_validates(db, user):
    asset = _make_asset(db)
    data = ScheduledJobCreate(
        job_name="j", job_type="audit", technology="cisco", asset_id=asset.id,
        audit_params={"ssh_username": "admin", "ssh_password": "old"},
    )
    job = SchedulingService.create_job(db, data, user.id)
    updated = SchedulingService.update_job(db, job, ScheduledJobUpdate(audit_params={"ssh_password": "new"}))
    params = decrypt_json(updated.params_encrypted)
    assert "new" in params and "admin" in params  # username preserved, password replaced


# ======================================================================
# SchedulingService.due_jobs
# ======================================================================

def test_due_jobs_only_returns_enabled_and_past_due(db, user):
    past = SchedulingService.create_job(
        db, ScheduledJobCreate(job_name="past", job_type="discovery", recurrence="once", hour=0, target="10.0.0.0/24"), user.id
    )
    past.next_run_at = datetime(2000, 1, 1)
    future = SchedulingService.create_job(
        db, ScheduledJobCreate(job_name="future", job_type="discovery", recurrence="once", hour=23, target="10.0.0.0/24"), user.id
    )
    future.next_run_at = datetime(2999, 1, 1)
    disabled = SchedulingService.create_job(
        db, ScheduledJobCreate(job_name="disabled", job_type="discovery", recurrence="once", hour=0, target="10.0.0.0/24", enabled=False), user.id
    )
    disabled.next_run_at = datetime(2000, 1, 1)
    db.flush()

    due = SchedulingService.due_jobs(db, datetime(2026, 1, 1))
    due_ids = {j.id for j in due}
    assert past.id in due_ids
    assert future.id not in due_ids
    assert disabled.id not in due_ids


# ======================================================================
# SchedulingService.run_job_now
# ======================================================================

def test_run_discovery_job_success(db, user):
    data = ScheduledJobCreate(job_name="j", job_type="discovery", recurrence="daily", hour=3, target="10.0.0.0/24")
    job = SchedulingService.create_job(db, data, user.id)

    with patch("app.modules.scheduling.service.DiscoveryService") as mock_service:
        mock_service.start_scan.return_value = {"scan_id": "abc123"}
        run = SchedulingService.run_job_now(db, job)

    assert run.status == "success"
    assert run.result_ref == "scan:abc123"
    assert job.last_run_status == "success"
    assert job.last_run_at is not None


def test_run_discovery_job_once_disables_after_running(db, user):
    data = ScheduledJobCreate(job_name="j", job_type="discovery", recurrence="once", hour=3, target="10.0.0.0/24")
    job = SchedulingService.create_job(db, data, user.id)

    with patch("app.modules.scheduling.service.DiscoveryService") as mock_service:
        mock_service.start_scan.return_value = {"scan_id": "abc123"}
        SchedulingService.run_job_now(db, job)

    assert job.enabled is False


def test_run_audit_job_success(db, user):
    asset = _make_asset(db)
    data = ScheduledJobCreate(
        job_name="j", job_type="audit", technology="cisco", asset_id=asset.id,
        audit_params={"ssh_username": "admin", "ssh_password": "secret"},
    )
    job = SchedulingService.create_job(db, data, user.id)
    fake_session = MagicMock(id=999)

    with patch("app.modules.scheduling.service.run_audit", return_value=fake_session) as mock_run:
        run = SchedulingService.run_job_now(db, job)

    assert run.status == "success"
    assert run.result_ref == "audit_session:999"
    mock_run.assert_called_once()
    call_kwargs = mock_run.call_args
    assert call_kwargs[0][0] == "cisco"
    assert call_kwargs[0][2] == asset.id


def test_run_job_failure_is_recorded_not_raised(db, user):
    data = ScheduledJobCreate(job_name="j", job_type="discovery", recurrence="daily", hour=3, target="10.0.0.0/24")
    job = SchedulingService.create_job(db, data, user.id)

    with patch("app.modules.scheduling.service.DiscoveryService") as mock_service:
        mock_service.start_scan.side_effect = RuntimeError("nmap not found")
        run = SchedulingService.run_job_now(db, job)

    assert run.status == "failed"
    assert "nmap not found" in run.message
    assert job.last_run_status == "failed"
    # A failed run still reschedules - it does not get stuck retrying instantly.
    assert job.next_run_at > datetime.utcnow()


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_get_job_404s_for_missing_job(db, user):
    from app.modules.scheduling.router import get_job as route

    with pytest.raises(HTTPException) as exc_info:
        route(job_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_create_job_requires_permission(db, user):
    from app.modules.scheduling.router import create_job as route

    with pytest.raises(HTTPException) as exc_info:
        route(
            data=ScheduledJobCreate(job_name="j", job_type="discovery", target="10.0.0.0/24"),
            current_user=user, db=db,
        )
    assert exc_info.value.status_code == 403


def test_route_create_job_succeeds_for_admin(db):
    from app.modules.scheduling.router import create_job as route
    from app.models.user import UserRole

    admin = User(username=f"sched_admin_{_next()}", hashed_password="x", role=UserRole.ADMIN)
    db.add(admin)
    db.flush()

    result = route(
        data=ScheduledJobCreate(job_name="j", job_type="discovery", target="10.0.0.0/24"),
        current_user=admin, db=db,
    )
    assert result.job_name == "j"


def test_route_run_job_now_with_mocked_discovery(db):
    from app.modules.scheduling.router import create_job as create_route, run_job_now as run_route
    from app.models.user import UserRole

    admin = User(username=f"sched_admin_{_next()}", hashed_password="x", role=UserRole.ADMIN)
    db.add(admin)
    db.flush()

    created = create_route(
        data=ScheduledJobCreate(job_name="j", job_type="discovery", target="10.0.0.0/24"),
        current_user=admin, db=db,
    )

    with patch("app.modules.scheduling.service.DiscoveryService") as mock_service:
        mock_service.start_scan.return_value = {"scan_id": "xyz"}
        run = run_route(job_id=created.id, current_user=admin, db=db)

    assert run.status == "success"
