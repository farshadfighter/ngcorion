"""
Hardening records of the family services (app/modules/shared/hardening_record.py) and what the risk score
reads from them.

Reported from a server: after an audit and a Linux hardening, the risk page said nothing had been
hardened. The Linux service (like Windows, SQL Server, Apache, MongoDB and the benchmark modules) set the
fixed findings to PASS but wrote no hardening_actions row, and the risk score counted "fixed by
hardening" only among findings still FAIL.

Needs a migrated PostgreSQL database; every test runs in a transaction that is rolled back.
"""
import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.models import Asset, AssetType, User, UserRole
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.hardening import HardeningAction
from app.modules.linux.hardening import service as linux_service
from app.modules.risk.service import risk_calculation_service
from app.modules.shared.hardening_record import record_fix_results

SECRET = "S3cret-Value!"


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
def audit(db):
    """A user, a Linux asset and its audit with three failed controls."""
    user = User(username=f"hrec_{_n()}", email=f"hrec{_seq[0]}@corp.example", hashed_password="x",
                role=UserRole.ADMIN, is_active=True)
    kind = AssetType(type_name=f"Hrec type {_seq[0]}", category="server")
    db.add_all([user, kind])
    db.flush()
    asset = Asset(asset_name=f"hrec-{_seq[0]}", asset_type_id=kind.id, ip_address=f"10.45.{_seq[0] % 250}.1")
    db.add(asset)
    db.flush()
    session = AuditSession(user_id=user.id, asset_id=asset.id, target_ip=asset.ip_address,
                           device_type=DeviceType.LINUX, status="completed", compliance_pct=0)
    db.add(session)
    db.flush()
    for check, sev in (("LNX-1", "high"), ("LNX-2", "medium"), ("LNX-3", "low")):
        db.add(AuditResult(session_id=session.id, check_number=check, check_title=f"Check {check}", severity=sev,
                           level="L1", status=CheckStatus.FAIL))
    db.commit()
    return user, asset, session


def _fixed(check):
    return {"check_id": check, "check_title": "", "success": True, "commands_executed": [f"fix {check}"],
            "command_outputs": {f"fix {check}": "ok"}, "verification_result": "PASS", "error_message": None}


def _failed(check):
    return {"check_id": check, "check_title": "", "success": False,
            "commands_executed": [f"chpasswd <<< 'root:{SECRET}'"],
            "command_outputs": {f"chpasswd <<< 'root:{SECRET}'": f"rejected {SECRET}"},
            "verification_result": "FAIL", "error_message": f"verification reported FAIL ({SECRET})"}


class FakeExecutor:
    """Stands in for LinuxHardeningBatchExecutor: LNX-1 fixes and verifies, LNX-2 fails."""
    def __init__(self, **kw):
        pass

    def execute_selected(self, checks, create_backup=False):
        results = [_fixed(c["check_id"]) if c["check_id"] == "LNX-1" else _failed(c["check_id"]) for c in checks]
        return {"total": len(results), "successful": 1, "failed": len(results) - 1, "results": results}

    def execute_single(self, check_id, parameters):
        return _fixed(check_id)


def _actions(db, session):
    return {a.check_number: a for a in db.query(HardeningAction).filter(HardeningAction.audit_session_id == session.id)}


def test_linux_hardening_is_recorded_and_counted_by_the_risk_score(db, audit, monkeypatch):
    user, asset, session = audit
    monkeypatch.setattr(linux_service, "LinuxHardeningBatchExecutor", FakeExecutor)
    before = risk_calculation_service._audit_and_hardening_risk(db, asset.id, risk_calculation_service._load_settings(db))
    assert before["resolved_by_hardening"] == 0 and before["hardening_is_unknown"] is True

    linux_service.LinuxHardeningService.batch_execute_selected(
        db=db, session_id=session.id, asset_id=asset.id, ssh_username="u", ssh_password="p", sudo_password=None,
        checks=[{"check_id": "LNX-1", "parameters": {}}, {"check_id": "LNX-2", "parameters": {"root_password": SECRET}}],
        user_id=user.id)

    actions = _actions(db, session)
    assert set(actions) == {"LNX-1", "LNX-2"}
    ok, bad = actions["LNX-1"], actions["LNX-2"]
    assert (ok.action_type, ok.status, ok.verification_passed, ok.user_id, ok.asset_id) == \
        ("execute", "success", True, user.id, asset.id)
    assert ok.check_title == "Check LNX-1"                       # from the finding when the executor has none
    assert (bad.status, bad.verification_passed) == ("failed", False)
    for text in (bad.commands_json, bad.output, bad.error_message, bad.verification_evidence or ""):
        assert SECRET not in text                                # the parameter's value is redacted
    status = {r.check_number: r.status for r in db.query(AuditResult).filter(AuditResult.session_id == session.id)}
    assert status == {"LNX-1": CheckStatus.PASS, "LNX-2": CheckStatus.FAIL, "LNX-3": CheckStatus.FAIL}

    after = risk_calculation_service._audit_and_hardening_risk(db, asset.id, risk_calculation_service._load_settings(db))
    assert after["resolved_by_hardening"] == 1                    # LNX-1, already PASS
    assert after["hardening_is_unknown"] is False                 # the asset has hardening data now
    assert after["fixes_found"] == 1                              # LNX-2: still failing, a fix was tried


def test_a_single_linux_fix_is_recorded(db, audit, monkeypatch):
    user, asset, session = audit
    monkeypatch.setattr(linux_service, "LinuxHardeningBatchExecutor", FakeExecutor)
    linux_service.LinuxHardeningService.execute_single_fix(
        db=db, asset_id=asset.id, ssh_username="u", ssh_password="p", sudo_password=None, check_id="LNX-3",
        session_id=session.id, sub_device_type="linux-ubuntu-22", user_id=user.id)
    assert _actions(db, session)["LNX-3"].verification_passed is True


def test_what_is_not_recorded(db, audit):
    user, asset, session = audit
    unverified = dict(_fixed("LNX-1"), verification_result=None)
    manual = dict(_fixed("LNX-2"), manual_only=True)
    unknown = _fixed("NOT-IN-THE-AUDIT")
    assert record_fix_results(db, session_id=session.id, asset_id=asset.id, user_id=None, results=[unverified]) == 0
    assert record_fix_results(db, session_id=session.id, asset_id=asset.id, user_id=user.id,
                              results=[unverified, manual, unknown]) == 1
    action = _actions(db, session)["LNX-1"]
    assert (action.status, action.verification_passed) == ("success", None)   # ran, but nothing verified it


def _impact(db, asset):
    from app.models.risk import AssetRiskScore
    from app.modules.risk.router import _hardening_impact
    score = db.query(AssetRiskScore).filter(AssetRiskScore.asset_id == asset.id).one()
    return _hardening_impact(db, asset.id, score)


def test_hardening_impact_before_and_now(db, audit, monkeypatch):
    """The risk detail's Hardening Impact: findings and audit risk just after the audit and now, the risk score
    before the first change and now."""
    user, asset, session = audit
    risk_calculation_service.calculate(asset_id=asset.id, db=db, trigger_type="audit_completed")
    db.commit()
    assert _impact(db, asset)["hardened"] is False

    monkeypatch.setattr(linux_service, "LinuxHardeningBatchExecutor", FakeExecutor)
    linux_service.LinuxHardeningService.batch_execute_selected(
        db=db, session_id=session.id, asset_id=asset.id, ssh_username="u", ssh_password="p", sudo_password=None,
        checks=[{"check_id": "LNX-1", "parameters": {}}, {"check_id": "LNX-2", "parameters": {}}], user_id=user.id)
    risk_calculation_service.calculate(asset_id=asset.id, db=db, trigger_type="hardening_verified")
    db.commit()

    impact = _impact(db, asset)
    assert impact["hardened"] is True and impact["audit_session_id"] == session.id
    assert (impact["changes"], impact["verified"], impact["failed"], impact["awaiting_reaudit"]) == (2, 1, 1, 0)
    assert (impact["findings_before"], impact["findings_now"]) == (3, 2)        # LNX-1 now passes
    assert impact["audit_risk_before"] == 100.0
    assert 0 < impact["audit_risk_now"] < 100.0                                 # the high one is fixed
    assert impact["risk_before"] is not None and impact["risk_now"] < impact["risk_before"]
    assert impact["first_change_at"] and impact["last_hardened_at"]


def test_a_verified_fix_still_failing_waits_for_the_reaudit(db, audit):
    """Cisco and FortiGate fixes leave the finding FAIL until the next audit: it counts in both, and is named."""
    user, asset, session = audit
    risk_calculation_service.calculate(asset_id=asset.id, db=db, trigger_type="audit_completed")
    record_fix_results(db, session_id=session.id, asset_id=asset.id, user_id=user.id, results=[_fixed("LNX-3")])
    risk_calculation_service.calculate(asset_id=asset.id, db=db, trigger_type="hardening_verified")
    db.commit()
    impact = _impact(db, asset)
    assert (impact["findings_before"], impact["findings_now"], impact["awaiting_reaudit"]) == (3, 3, 1)
