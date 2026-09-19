"""Tests for the Deployment module (precheck -> backup -> apply -> verify
pipeline, and rollback). No real hardware is available in this environment,
so the per-tech executors are mocked - the same way NGFabric's own drivers
are documented as hardware-untested.

Needs a migrated PostgreSQL database; each test runs inside a transaction
that is rolled back, so nothing here touches real rows (same pattern as
test_asset_deletion.py / test_topology.py).
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
from app.models.configuration import ConfigurationJob, ConfigurationObject
from app.models.deployment import DeploymentJob
from app.models.user import User
from app.modules.deployment.service import DeploymentService


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
    row = User(username=f"deploy_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, type_name="Cisco Router") -> Asset:
    asset_type = AssetType(type_name=f"{type_name}_{_next()}", category="network")
    db.add(asset_type)
    db.flush()
    row = Asset(asset_name=f"deploy-asset-{_next()}", asset_type_id=asset_type.id, ip_address="10.0.0.9")
    db.add(row)
    db.flush()
    return row


@pytest.fixture
def config_object(db, user):
    asset = _make_asset(db)
    job = ConfigurationJob(name="job", status="generated", created_by=user.id)
    db.add(job)
    db.flush()
    obj = ConfigurationObject(
        configuration_job_id=job.id,
        asset_id=asset.id,
        asset_name=asset.asset_name,
        device_type="cisco",
        generated_config="interface Gi0/0\n no shutdown",
        apply_status="pending",
    )
    db.add(obj)
    db.flush()
    return obj


def _mock_executor(*, connectivity_sequence=None, backup_text="hostname R1", apply_success=True, apply_errors=None):
    """A context-manager mock standing in for Cisco/FortiGateHardeningExecutor."""
    instance = MagicMock()
    instance.__enter__.return_value = instance
    instance.__exit__.return_value = False
    if connectivity_sequence is not None:
        instance.test_connectivity.side_effect = connectivity_sequence
    else:
        instance.test_connectivity.return_value = True
    instance.backup_config.return_value = backup_text
    instance.execute_commands.return_value = {
        "success": apply_success,
        "output": "ok" if apply_success else "",
        "errors": apply_errors or [],
    }
    factory = MagicMock(return_value=instance)
    return factory, instance


# ======================================================================
# create_job
# ======================================================================

def test_create_job_rejects_unsupported_device_type(db, user):
    asset = _make_asset(db, type_name="Ubuntu Linux Server")
    job = ConfigurationJob(name="job", status="generated", created_by=user.id)
    db.add(job)
    db.flush()
    obj = ConfigurationObject(
        configuration_job_id=job.id, asset_id=asset.id, asset_name=asset.asset_name,
        device_type="linux", generated_config="echo hi", apply_status="pending",
    )
    db.add(obj)
    db.flush()

    with pytest.raises(ValueError):
        DeploymentService.create_job(db, obj, user.id)


def test_create_job_succeeds_for_cisco(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    assert job.status == "queued"
    assert job.asset_id == config_object.asset_id
    assert job.device_type == "cisco"


# ======================================================================
# start_job: full pipeline
# ======================================================================

def test_start_job_happy_path_reaches_success(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    factory, _instance = _mock_executor()

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        result = DeploymentService.start_job(db, job, "u", "p", None, 22, user.id)

    assert result.status == "success"
    assert result.backup_id is not None
    assert db.query(DeviceBackup).filter(DeviceBackup.id == result.backup_id).first() is not None
    assert result.completed_at is not None


def test_start_job_precheck_failure_stops_before_backup(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    factory, _instance = _mock_executor(connectivity_sequence=[False])

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        result = DeploymentService.start_job(db, job, "u", "p", None, 22, user.id)

    assert result.status == "precheck_failed"
    assert result.backup_id is None


def test_start_job_apply_failure_keeps_the_backup(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    factory, _instance = _mock_executor(apply_success=False, apply_errors=["syntax error"])

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        result = DeploymentService.start_job(db, job, "u", "p", None, 22, user.id)

    assert result.status == "apply_failed"
    assert result.backup_id is not None  # backup was taken before the failing apply


def test_start_job_verify_failure_after_successful_apply(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    # First connectivity check (precheck) succeeds, second (post-apply verify) fails.
    factory, _instance = _mock_executor(connectivity_sequence=[True, False])

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        result = DeploymentService.start_job(db, job, "u", "p", None, 22, user.id)

    assert result.status == "verify_failed"
    assert result.backup_id is not None


def test_start_job_handles_executor_exception(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    factory = MagicMock(side_effect=RuntimeError("connection refused"))

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        result = DeploymentService.start_job(db, job, "u", "p", None, 22, user.id)

    assert result.status == "precheck_failed"
    assert "connection refused" in result.error_message


# ======================================================================
# rollback_job
# ======================================================================

def test_rollback_requires_a_backup(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    with pytest.raises(ValueError):
        DeploymentService.rollback_job(db, job, "u", "p", None, 22)


def test_rollback_pushes_backup_content_and_marks_rolled_back(db, user, config_object):
    job = DeploymentService.create_job(db, config_object, user.id)
    factory, _instance = _mock_executor(apply_success=False)  # force apply_failed so a backup exists

    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", factory):
        job = DeploymentService.start_job(db, job, "u", "p", None, 22, user.id)
    assert job.status == "apply_failed"
    assert job.backup_id is not None

    rollback_factory, rollback_instance = _mock_executor(apply_success=True)
    with patch("app.modules.cisco.hardening.ssh_executor.CiscoHardeningExecutor", rollback_factory):
        result = DeploymentService.rollback_job(db, job, "u", "p", None, 22)

    assert result.status == "rolled_back"
    rollback_instance.execute_commands.assert_called_once()


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_create_job_404s_for_missing_configuration_object(db, user):
    from app.modules.deployment.router import create_job as route
    from app.modules.deployment.schemas import CreateJobRequest

    with pytest.raises(HTTPException) as exc_info:
        route(request=CreateJobRequest(configuration_object_id=2_000_000_000), current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_start_job_rejects_non_queued_job(db, user, config_object):
    from app.modules.deployment.router import start_job as route
    from app.modules.deployment.schemas import DeviceCredentialsRequest

    job = DeploymentService.create_job(db, config_object, user.id)
    job.status = "success"
    db.commit()

    with pytest.raises(HTTPException) as exc_info:
        route(job_id=job.id, request=DeviceCredentialsRequest(ssh_username="u", ssh_password="p"), current_user=user, db=db)
    assert exc_info.value.status_code == 400


def test_route_rollback_rejects_job_with_nothing_to_roll_back(db, user, config_object):
    from app.modules.deployment.router import rollback_job as route
    from app.modules.deployment.schemas import DeviceCredentialsRequest

    job = DeploymentService.create_job(db, config_object, user.id)  # still "queued"

    with pytest.raises(HTTPException) as exc_info:
        route(job_id=job.id, request=DeviceCredentialsRequest(ssh_username="u", ssh_password="p"), current_user=user, db=db)
    assert exc_info.value.status_code == 400
