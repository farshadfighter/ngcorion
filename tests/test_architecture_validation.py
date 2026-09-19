"""Tests for the Architecture Validation module (rule engine + findings workflow).

Needs a migrated PostgreSQL database; each test runs inside a transaction that
is rolled back, so nothing here touches real rows (same pattern as
test_asset_deletion.py / test_topology.py).
"""

import sys
from pathlib import Path

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
from app.models.architecture_finding import ArchitectureFinding
from app.models.backup import DeviceBackup
from app.models.user import User
from app.modules.architecture_validation.engine import (
    evaluate_condition,
    run_rules,
    load_rules,
    RuleConditionError,
)
from app.modules.architecture_validation.service import ArchitectureValidationService
from app.modules.topology.service import TopologyService


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
    row = User(username=f"av_test_user_{_next()}", hashed_password="x")
    db.add(row)
    db.flush()
    return row


def _make_asset(db, **overrides) -> Asset:
    asset_type = AssetType(type_name=f"AVType_{_next()}", category="server")
    db.add(asset_type)
    db.flush()
    defaults = dict(asset_name=f"av-asset-{_next()}", asset_type_id=asset_type.id)
    defaults.update(overrides)
    row = Asset(**defaults)
    db.add(row)
    db.flush()
    return row


# ======================================================================
# Engine: condition evaluation
# ======================================================================

def test_evaluate_condition_basic_comparison():
    assert evaluate_condition("topology_degree == 0", {"topology_degree": 0}) is True
    assert evaluate_condition("topology_degree == 0", {"topology_degree": 2}) is False


def test_evaluate_condition_boolean_ops():
    ctx = {"is_critical": True, "has_backup": False}
    assert evaluate_condition("is_critical and not has_backup", ctx) is True
    assert evaluate_condition("is_critical and has_backup", ctx) is False


def test_evaluate_condition_in_operator():
    assert evaluate_condition('risk_level in ("high", "critical")', {"risk_level": "high"}) is True
    assert evaluate_condition('risk_level in ("high", "critical")', {"risk_level": "low"}) is False


def test_evaluate_condition_rejects_unknown_name():
    with pytest.raises(RuleConditionError):
        evaluate_condition("nonexistent_field == 1", {})


def test_evaluate_condition_rejects_arbitrary_code():
    """The whole point of the AST walker: no function calls, no imports."""
    with pytest.raises(RuleConditionError):
        evaluate_condition("__import__('os').system('echo hi')", {})


def test_load_rules_are_all_unique_and_valid():
    rules = load_rules()
    codes = [r["code"] for r in rules]
    assert len(codes) == len(set(codes)), "duplicate rule codes"
    for rule in rules:
        assert rule["severity"] in ("low", "medium", "high")
        # Every condition must at least parse.
        import ast as _ast
        _ast.parse(rule["condition"], mode="eval")


def test_run_rules_returns_only_matching_rules():
    rules = [
        {"code": "X-1", "title": "t", "severity": "low", "condition": "flag"},
        {"code": "X-2", "title": "t", "severity": "low", "condition": "not flag"},
    ]
    findings = run_rules({"flag": True}, rules)
    assert [f["code"] for f in findings] == ["X-1"]


# ======================================================================
# Service: context building
# ======================================================================

def test_build_asset_context_no_ip_flags_missing(db):
    asset = _make_asset(db, ip_address=None)
    ctx = ArchitectureValidationService.build_asset_context(asset, 0, False, None)
    assert ctx["ip_address"] is None
    assert ctx["topology_degree"] == 0
    assert ctx["has_backup"] is False
    assert ctx["last_audit_status"] is None
    assert ctx["days_since_audit"] is None


# ======================================================================
# Service: full analyze() run
# ======================================================================

def test_analyze_flags_orphan_asset_with_no_ip(db):
    _make_asset(db, ip_address=None)
    findings = ArchitectureValidationService.analyze(db)
    codes = {f.rule_code for f in findings}
    assert "AV-001" in codes  # no IP
    assert "AV-010" in codes  # no topology links


def test_analyze_flags_critical_asset_without_backup(db, user):
    from app.models.enums import RiskLevelEnum

    asset = _make_asset(db, ip_address="10.0.0.5", risk_level=RiskLevelEnum.CRITICAL)
    findings = ArchitectureValidationService.analyze(db)
    codes = {f.rule_code: f for f in findings if f.asset_id == asset.id}
    assert "AV-020" in codes

    # Adding a backup and re-running should clear AV-020 for this asset.
    db.add(DeviceBackup(asset_id=asset.id, config_content="hostname x", source="manual"))
    db.flush()
    findings2 = ArchitectureValidationService.analyze(db)
    codes2 = {f.rule_code for f in findings2 if f.asset_id == asset.id}
    assert "AV-020" not in codes2


def test_analyze_respects_topology_redundancy(db, user):
    a = _make_asset(db, ip_address="10.0.0.1")
    b = _make_asset(db, ip_address="10.0.0.2")
    TopologyService.create_link(db, {"source_asset_id": a.id, "destination_asset_id": b.id}, user.id)

    findings = ArchitectureValidationService.analyze(db)
    codes_a = {f.rule_code for f in findings if f.asset_id == a.id}
    assert "AV-010" not in codes_a  # has a link
    assert "AV-011" in codes_a      # but only one -> no redundancy


def test_analyze_does_not_recreate_resolved_findings(db, user):
    _make_asset(db, ip_address=None)
    first_run = ArchitectureValidationService.analyze(db)
    av001 = next(f for f in first_run if f.rule_code == "AV-001")

    ArchitectureValidationService.resolve_finding(db, av001, "accepted", user.id)

    second_run = ArchitectureValidationService.analyze(db)
    assert all(f.rule_code != "AV-001" for f in second_run)

    # The accepted finding itself must still exist (not deleted).
    assert db.query(ArchitectureFinding).filter(ArchitectureFinding.id == av001.id).first() is not None


# ======================================================================
# Router behaviour
# ======================================================================

def test_route_accept_404s_for_missing_finding(db, user):
    from app.modules.architecture_validation.router import accept_finding as route

    with pytest.raises(HTTPException) as exc_info:
        route(finding_id=2_000_000_000, current_user=user, db=db)
    assert exc_info.value.status_code == 404


def test_route_accept_marks_status(db, user):
    from app.modules.architecture_validation.router import accept_finding as route

    _make_asset(db, ip_address=None)
    findings = ArchitectureValidationService.analyze(db)
    finding = findings[0]

    result = route(finding_id=finding.id, current_user=user, db=db)
    assert result.status == "accepted"
    assert result.resolved_at is not None
