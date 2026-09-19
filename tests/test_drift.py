"""Tests for the Configuration Drift module (live-vs-baseline diff analysis
and the resulting findings workflow). No real hardware is available in this
environment, so the per-tech executors are mocked - the same way NGFabric's
own drivers are documented as hardware-untested.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_asset_deletion.py / test_topology.py / test_deployment.py).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.asset import Asset
from app.models.asset_types import AssetType
from app.models.backup import DeviceBackup
from app.models.drift import DriftRun, DriftResult
from app.models.user import User
from app.modules.drift.service import DriftService, _severity_for


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
    row = User(username=f"drift_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, type_name="Cisco Router", with_ip=True) -> Asset:
    asset_type = AssetType(type_name=f"{type_name}_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(
        asset_name=f"drift-asset-{_next()}",
        asset_type_id=asset_type.id,
        ip_address="10.0.0.9" if with_ip else None,
    )
    db.add(row)
    db.flush()
    return row


def _make_backup(db, asset, user, content="hostname R1\ninterface Gi0/0\n no shutdown"):
    backup = DeviceBackup(
        asset_id=asset.id, asset_name=asset.asset_name, device_ip=asset.ip_address,
        device_type="cisco", config_content=content, source="manual", created_by=user.id,
    )
    db.add(backup)
    db.flush()
    return backup


def _mock_executor(*, live_config="hostname R1\ninterface Gi0/0\n no shutdown"):
    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.__exit__.return_value = False
    instance.backup_config.return_value = live_config
    factory = MagicMock(return_value=instance)
    return factory, instance


# ======================================================================
# Severity heuristic (pure function)
# ======================================================================

def test_severity_thresholds():
    assert _severity_for(0) == "low"
    assert _severity_for(5) == "low"
    assert _severity_for(6) == "medium"
    assert _severity_for(20) == "medium"
    assert _severity_for(21) == "high"


# ======================================================================
# analyze_asset
# ======================================================================

def test_analyze_fails_without_a_baseline_backup(db, user):
    asset = _make_asset(db)
    run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)
    assert run.status == "failed"
    assert "backup baseline" in run.error_message.lower()
    assert run.drift_found_count == 0


def test_analyze_fails_without_an_ip_address(db, user):
    asset = _make_asset(db, with_ip=False)
    _make_backup(db, asset, user)
    run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)
    assert run.status == "failed"
    assert "IP address" in run.error_message


def test_analyze_finds_no_drift_when_config_is_unchanged(db, user):
    asset = _make_asset(db)
    _make_backup(db, asset, user, content="hostname R1\ninterface Gi0/0\n no shutdown")
    factory, _instance = _mock_executor(live_config="hostname R1\ninterface Gi0/0\n no shutdown")

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)

    assert run.status == "completed"
    assert run.drift_found_count == 0
    assert db.query(DriftResult).filter(DriftResult.run_id == run.id).count() == 0


def test_analyze_creates_a_result_when_live_config_differs(db, user):
    asset = _make_asset(db)
    baseline = _make_backup(db, asset, user, content="hostname R1\ninterface Gi0/0\n no shutdown")
    factory, _instance = _mock_executor(
        live_config="hostname R1\ninterface Gi0/0\n shutdown\ninterface Gi0/1\n no shutdown"
    )

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)

    assert run.status == "completed"
    assert run.drift_found_count == 1
    result = db.query(DriftResult).filter(DriftResult.run_id == run.id).first()
    assert result is not None
    assert result.baseline_backup_id == baseline.id
    assert result.lines_changed > 0
    assert result.status == "open"
    assert "diff" in result.diff.lower() or "+" in result.diff


def test_analyze_unsupported_device_type_fails_gracefully(db, user):
    asset = _make_asset(db, type_name="Ubuntu Linux Server")
    _make_backup(db, asset, user)
    run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)
    assert run.status == "failed"
    assert "not supported" in run.error_message


def test_analyze_handles_executor_exception(db, user):
    asset = _make_asset(db)
    _make_backup(db, asset, user)
    factory = MagicMock(side_effect=RuntimeError("connection refused"))

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)

    assert run.status == "failed"
    assert "connection refused" in run.error_message


# ======================================================================
# Findings workflow
# ======================================================================

def test_resolve_result_marks_accepted(db, user):
    asset = _make_asset(db)
    _make_backup(db, asset, user, content="hostname R1")
    factory, _instance = _mock_executor(live_config="hostname R2")

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        run = DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)

    result = db.query(DriftResult).filter(DriftResult.run_id == run.id).first()
    resolved = DriftService.resolve_result(db, result, "accepted", user.id)
    assert resolved.status == "accepted"
    assert resolved.resolved_at is not None


def test_list_results_filters_by_status(db, user):
    asset = _make_asset(db)
    _make_backup(db, asset, user, content="hostname R1")
    factory, _instance = _mock_executor(live_config="hostname R2")

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        DriftService.analyze_asset(db, asset, "u", "p", None, 22, user.id)

    open_results = DriftService.list_results(db, status="open")
    assert len(open_results) >= 1
    accepted_results = DriftService.list_results(db, status="accepted")
    assert all(r.status == "accepted" for r in accepted_results)


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_analyze_404s_for_missing_asset(db, user):
    from app.modules.drift.router import analyze as route
    from app.modules.drift.schemas import AnalyzeAssetRequest

    with pytest.raises(HTTPException) as exc_info:
        route(
            request=AnalyzeAssetRequest(asset_id=2_000_000_000, ssh_username="u", ssh_password="p"),
            current_user=user, db=db,
        )
    assert exc_info.value.status_code == 404


def test_route_accept_404s_for_missing_result(db, user):
    from app.modules.drift.router import accept_result as route

    with pytest.raises(HTTPException) as exc_info:
        route(result_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404
