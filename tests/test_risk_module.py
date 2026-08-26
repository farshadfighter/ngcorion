"""
Risk & Exposure Intelligence module tests (spec section 30).

These are integration-style tests that exercise the real
``AssetRiskCalculationService`` against a PostgreSQL database (the project
does not use SQLite — see DATABASE_URL).  Each test runs inside a single
database transaction that is rolled back on teardown, so tests are fully
independent and leave no rows behind — even though the service commits
internally (those commits become SAVEPOINT releases inside the outer
transaction).

Factors and their default weights (from risk_settings / service defaults):
    criticality 25%, zone 20%, open_port 15%, audit 40%
Severity weights: low=1, medium=3, high=7, critical=10; port normalization
factor = 4.  Fallback ("unknown") scores = 50 for zone/port/audit.
Risk-level bands (inclusive lower bound): medium=20, high=40, very_high=60,
critical=80.  The setting keys are offset from the band they open -- the
boundary at 60 is stored as risk_level_high_threshold but starts Very High.
"""

import sys
from pathlib import Path

# Make the project importable when pytest is run from anywhere.
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
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.enums import StatusEnum
from app.models.hardening import HardeningAction
from app.models.risk import (
    AssetOpenPort,
    AssetRiskProfile,
    AssetRiskScore,
    RiskSetting,
    RiskZone,
)
from app.models.user import User
from app.modules.risk.service import risk_calculation_service


# ======================================================================
# Database session fixture — transaction-per-test with rollback
# ======================================================================

@pytest.fixture
def db():
    """A Session bound to a connection-level transaction that is rolled
    back after the test.

    The service commits internally; the ``after_transaction_end`` listener
    reopens a SAVEPOINT each time so the outer transaction survives and the
    final rollback wipes everything the test created.
    """
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


# ======================================================================
# Factories
# ======================================================================

class RiskFactory:
    """Creates the minimal row graph each risk test needs, bound to one db."""

    _seq = 0

    def __init__(self, db: Session):
        self.db = db
        self._user = None
        self._asset_type = None

    def _next(self) -> int:
        RiskFactory._seq += 1
        return RiskFactory._seq

    def user(self) -> User:
        if self._user is None:
            self._user = User(
                username=f"risk_test_user_{self._next()}",
                hashed_password="x",
            )
            self.db.add(self._user)
            self.db.flush()
        return self._user

    def asset_type(self) -> AssetType:
        if self._asset_type is None:
            self._asset_type = AssetType(
                type_name=f"RiskTestType_{self._next()}", category="server"
            )
            self.db.add(self._asset_type)
            self.db.flush()
        return self._asset_type

    def asset(self, ip: str = "10.20.30.40") -> Asset:
        asset = Asset(
            asset_name=f"RiskTestAsset_{self._next()}",
            asset_type_id=self.asset_type().id,
            user_id=self.user().id,
            status=StatusEnum.ACTIVE,
            ip_address=ip,
        )
        self.db.add(asset)
        self.db.flush()
        return asset

    def zone(self, score: float, name: str = None) -> RiskZone:
        zone = RiskZone(
            name=name or f"RiskTestZone_{self._next()}",
            score=score,
            status="active",
        )
        self.db.add(zone)
        self.db.flush()
        return zone

    def profile(
        self,
        asset: Asset,
        criticality_level: str = "medium",
        criticality_score: float = 50,
        zone: RiskZone = None,
    ) -> AssetRiskProfile:
        profile = AssetRiskProfile(
            asset_id=asset.id,
            criticality_level=criticality_level,
            criticality_score=criticality_score,
            zone_id=zone.id if zone else None,
            criticality_is_default=False,
            zone_is_default=zone is None,
        )
        self.db.add(profile)
        self.db.flush()
        return profile

    _SEV_SCORE = {"low": 1, "medium": 3, "high": 7, "critical": 10}

    def port(
        self,
        asset: Asset,
        port: int,
        severity: str = "medium",
        status: str = "open",
        is_included_in_risk: bool = True,
        protocol: str = "tcp",
    ) -> AssetOpenPort:
        p = AssetOpenPort(
            asset_id=asset.id,
            ip_address=asset.ip_address,
            port=port,
            protocol=protocol,
            severity=severity,
            severity_score=self._SEV_SCORE.get(severity, 3),
            status=status,
            is_included_in_risk=is_included_in_risk,
        )
        self.db.add(p)
        self.db.flush()
        return p

    def audit_session(self, asset: Asset, status: str = "completed") -> AuditSession:
        s = AuditSession(
            user_id=self.user().id,
            asset_id=asset.id,
            target_ip=asset.ip_address,
            device_type=DeviceType.LINUX,
            status=status,
        )
        self.db.add(s)
        self.db.flush()
        return s

    def result(
        self,
        session: AuditSession,
        status: CheckStatus,
        severity: str = "medium",
        check_number: str = None,
    ) -> AuditResult:
        r = AuditResult(
            session_id=session.id,
            check_number=check_number or f"CHK-{self._next()}",
            check_title="risk test check",
            severity=severity,
            status=status,
        )
        self.db.add(r)
        self.db.flush()
        return r

    def hardening(
        self,
        result: AuditResult,
        session: AuditSession,
        asset: Asset,
        status: str = "success",
        verification_passed=True,
        action_type: str = "execute",
    ) -> HardeningAction:
        h = HardeningAction(
            audit_result_id=result.id,
            user_id=self.user().id,
            asset_id=asset.id,
            audit_session_id=session.id,
            check_number=result.check_number,
            check_title="risk test fix",
            action_type=action_type,
            status=status,
            commands_json="[]",
            verification_passed=verification_passed,
        )
        self.db.add(h)
        self.db.flush()
        return h


@pytest.fixture
def factory(db) -> RiskFactory:
    return RiskFactory(db)


@pytest.fixture
def settings(db) -> dict:
    """The effective risk settings as the service loads them."""
    return risk_calculation_service._load_settings(db)


def calc(db, asset) -> AssetRiskScore:
    return risk_calculation_service.calculate(asset.id, db, trigger_type="test")


def set_setting(db, key: str, value, value_type: str = "int"):
    """Override a risk setting in-session (rolled back after the test)."""
    row = db.query(RiskSetting).filter(RiskSetting.setting_key == key).first()
    if row is None:
        row = RiskSetting(setting_key=key, setting_value=str(value), value_type=value_type)
        db.add(row)
    else:
        row.setting_value = str(value)
    db.flush()


# ======================================================================
# 30.1 Criticality Tests
# ======================================================================

def _transient_profile(level):
    """Profile with no explicit score, so the service maps level -> score."""
    return AssetRiskProfile(criticality_level=level, criticality_score=None)


def test_criticality_low_score(settings):
    score = risk_calculation_service._criticality_score(_transient_profile("low"), settings)
    assert score == 25


def test_criticality_medium_score(settings):
    score = risk_calculation_service._criticality_score(_transient_profile("medium"), settings)
    assert score == 50


def test_criticality_high_score(settings):
    score = risk_calculation_service._criticality_score(_transient_profile("high"), settings)
    assert score == 75


def test_criticality_critical_score(settings):
    score = risk_calculation_service._criticality_score(_transient_profile("critical"), settings)
    assert score == 100


def test_criticality_change_triggers_recalculate(db, factory):
    asset = factory.asset()
    profile = factory.profile(asset, criticality_level="low", criticality_score=25)

    first = calc(db, asset)
    assert float(first.criticality_score) == 25
    low_final = float(first.final_risk_score)

    # Operator raises criticality to critical, then recalculate.
    profile.criticality_level = "critical"
    profile.criticality_score = 100
    db.flush()

    second = calc(db, asset)
    assert float(second.criticality_score) == 100
    # Higher criticality => higher final score (all other factors unchanged).
    assert float(second.final_risk_score) > low_final


# ======================================================================
# 30.2 Zone Tests
# ======================================================================

def test_zone_score_correct(db, factory):
    zone = factory.zone(score=80)
    asset = factory.asset()
    factory.profile(asset, zone=zone)

    score = calc(db, asset)
    assert float(score.zone_score) == 80
    assert score.zone_id == zone.id
    assert score.zone_name == zone.name


def test_zone_change_triggers_recalculate(db, factory):
    low_zone = factory.zone(score=20)
    high_zone = factory.zone(score=100)
    asset = factory.asset()
    profile = factory.profile(asset, zone=low_zone)

    first = calc(db, asset)
    assert float(first.zone_score) == 20
    # calc() upserts and returns the same row object, so snapshot the value.
    first_final = float(first.final_risk_score)

    profile.zone_id = high_zone.id
    db.flush()

    second = calc(db, asset)
    assert float(second.zone_score) == 100
    assert float(second.final_risk_score) > first_final


def test_deleted_zone_not_assignable(db, factory):
    """A zone that no longer exists cannot be assigned to an asset profile."""
    from app.modules.risk.router import update_asset_profile
    from app.modules.risk.schemas import ProfileUpdateRequest

    zone = factory.zone(score=80)
    asset = factory.asset()
    factory.profile(asset)

    deleted_zone_id = zone.id
    db.delete(zone)
    db.flush()

    with pytest.raises(HTTPException) as exc_info:
        update_asset_profile(
            asset_id=asset.id,
            data=ProfileUpdateRequest(zone_id=deleted_zone_id),
            current_user=factory.user(),
            db=db,
        )
    assert exc_info.value.status_code == 400
    assert "Zone not found" in exc_info.value.detail


# ======================================================================
# 30.3 Open Port Tests
# ======================================================================

def test_only_open_ports_calculated(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=22, severity="critical", status="open")
    factory.port(asset, port=23, severity="critical", status="closed")

    score = calc(db, asset)
    # open_ports_count reflects only the open port.
    assert score.open_ports_count == 1
    # raw score is only the single open critical port (weight 10).
    assert float(score.open_port_raw_score) == 10


def test_excluded_port_not_calculated(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=443, severity="critical", is_included_in_risk=True)
    factory.port(asset, port=8443, severity="critical", is_included_in_risk=False)

    score = calc(db, asset)
    # Only the included port (weight 10) contributes to the raw score.
    assert float(score.open_port_raw_score) == 10


def test_severity_weight_applied(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=3389, severity="critical")

    score = calc(db, asset)
    # critical severity weight = 10.
    assert float(score.open_port_raw_score) == 10
    # normalized: min(100, 10 * 4) = 40.
    assert float(score.open_port_score) == 40


def test_port_score_max_100(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    # 5 critical ports => raw 50 => 50 * 4 = 200 => capped at 100.
    for i, p in enumerate((21, 22, 23, 25, 80)):
        factory.port(asset, port=p, severity="critical")

    score = calc(db, asset)
    assert float(score.open_port_raw_score) == 50
    assert float(score.open_port_score) == 100


def test_closed_port_removed_from_risk(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    p1 = factory.port(asset, port=22, severity="critical")
    factory.port(asset, port=3389, severity="critical")

    first = calc(db, asset)
    # 2 critical ports => raw 20 => min(100, 80) = 80.
    assert float(first.open_port_score) == 80
    first_port_score = float(first.open_port_score)

    # Close one port; it should no longer count toward risk.
    p1.status = "closed"
    db.flush()

    second = calc(db, asset)
    assert second.open_ports_count == 1
    assert float(second.open_port_score) == 40
    assert float(second.open_port_score) < first_port_score


def test_excluding_port_requires_reason(db, factory):
    """PUT /ports/{id} must reject excluding a port with no exclusion_reason."""
    from app.modules.risk.router import update_port
    from app.modules.risk.schemas import PortUpdateRequest

    asset = factory.asset()
    factory.profile(asset)
    port = factory.port(asset, port=8080, severity="high", is_included_in_risk=True)

    with pytest.raises(HTTPException) as exc_info:
        update_port(
            port_id=port.id,
            data=PortUpdateRequest(is_included_in_risk=False),
            current_user=factory.user(),
            db=db,
        )
    assert exc_info.value.status_code == 400
    assert "exclusion_reason is required" in exc_info.value.detail


def test_excluding_port_with_reason_succeeds(db, factory):
    from app.modules.risk.router import update_port
    from app.modules.risk.schemas import PortUpdateRequest

    asset = factory.asset()
    factory.profile(asset)
    port = factory.port(asset, port=8080, severity="high", is_included_in_risk=True)

    result = update_port(
        port_id=port.id,
        data=PortUpdateRequest(
            is_included_in_risk=False, exclusion_reason="approved internal service"
        ),
        current_user=factory.user(),
        db=db,
    )
    assert result["port"]["is_included_in_risk"] is False
    assert result["port"]["exclusion_reason"] == "approved internal service"


# ======================================================================
# 30.4 Audit Tests
# ======================================================================

def test_only_applicable_controls_in_denominator(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    # Applicable: PASS(high=7) + FAIL(medium=3) = 10 applicable weight.
    factory.result(session, CheckStatus.PASS, severity="high")
    factory.result(session, CheckStatus.FAIL, severity="medium")
    # Not applicable / error must be excluded from the denominator.
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="critical")
    factory.result(session, CheckStatus.ERROR, severity="critical")

    score = calc(db, asset)
    assert float(score.audit_applicable_weight) == 10


def test_only_active_failures_in_numerator(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="high")   # 7
    factory.result(session, CheckStatus.FAIL, severity="medium")  # 3
    factory.result(session, CheckStatus.PASS, severity="critical")

    score = calc(db, asset)
    # numerator = only the two active failures = 7 + 3 = 10.
    assert float(score.audit_failed_weight) == 10
    assert score.active_audit_findings_count == 2


def test_pass_not_counted(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.PASS, severity="critical")
    factory.result(session, CheckStatus.PASS, severity="high")

    score = calc(db, asset)
    # All applicable but nothing failed => numerator 0 => audit risk 0.
    assert float(score.audit_failed_weight) == 0
    assert float(score.audit_risk_score) == 0


def test_resolved_not_counted(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    failed = factory.result(session, CheckStatus.FAIL, severity="high")  # 7
    # A verified successful hardening execute resolves the finding.
    factory.hardening(failed, session, asset, status="success", verification_passed=True)

    score = calc(db, asset)
    assert float(score.audit_failed_weight) == 0
    assert score.active_audit_findings_count == 0
    assert score.resolved_by_hardening_count == 1


def test_not_applicable_not_counted(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="medium")  # 3 applicable+failed
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="critical")

    score = calc(db, asset)
    # NOT_APPLICABLE excluded from both denominator and numerator.
    assert float(score.audit_applicable_weight) == 3
    assert float(score.audit_failed_weight) == 3


def test_division_by_zero_handled(db, factory, settings):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    # No applicable controls (all NOT_APPLICABLE) => no ZeroDivision.
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="high")
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="critical")

    score = calc(db, asset)
    assert float(score.audit_applicable_weight) == 0
    # Falls back to the configured unknown_audit_score.
    assert float(score.audit_risk_score) == float(settings["unknown_audit_score"])


# ======================================================================
# 30.5 Hardening Tests
# ======================================================================

def test_hardening_success_without_verification_not_resolved(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    failed = factory.result(session, CheckStatus.FAIL, severity="high")  # 7
    # Executed successfully but verification never passed => still active.
    factory.hardening(failed, session, asset, status="success", verification_passed=None)

    score = calc(db, asset)
    assert float(score.audit_failed_weight) == 7
    assert score.active_audit_findings_count == 1
    assert score.resolved_by_hardening_count == 0


def test_verification_pass_resolves_finding(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    failed = factory.result(session, CheckStatus.FAIL, severity="high")
    factory.hardening(failed, session, asset, status="success", verification_passed=True)

    score = calc(db, asset)
    assert score.resolved_by_hardening_count == 1
    assert score.active_audit_findings_count == 0


def test_resolved_finding_excluded_from_audit_risk(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    # Two fails; one resolved, one still active.
    resolved = factory.result(session, CheckStatus.FAIL, severity="high")   # 7
    active = factory.result(session, CheckStatus.FAIL, severity="medium")   # 3
    factory.hardening(resolved, session, asset, status="success", verification_passed=True)

    score = calc(db, asset)
    # Only the unresolved failure remains in the numerator.
    assert float(score.audit_failed_weight) == 3
    # Denominator still includes both applicable checks (7 + 3 = 10).
    assert float(score.audit_applicable_weight) == 10


def test_risk_score_decreases_after_resolution(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    failed = factory.result(session, CheckStatus.FAIL, severity="critical")

    before = calc(db, asset)
    # calc() upserts and returns the same row object, so snapshot the values.
    before_audit = float(before.audit_risk_score)
    before_final = float(before.final_risk_score)

    factory.hardening(failed, session, asset, status="success", verification_passed=True)

    after = calc(db, asset)
    assert float(after.audit_risk_score) < before_audit
    assert float(after.final_risk_score) < before_final


# ======================================================================
# 30.6 Formula Test
# ======================================================================

def test_exact_formula(db, factory):
    """C=100, Z=80, P=70, A=45 => 100*.25 + 80*.20 + 70*.15 + 45*.40 = 69.50."""
    # Make the open-port factor land exactly on 70: one low port (weight 1)
    # with the normalization factor set to 70 => min(100, 1 * 70) = 70.
    set_setting(db, "open_port_normalization_factor", 70)

    zone = factory.zone(score=80)                       # Z = 80
    asset = factory.asset()
    factory.profile(asset, criticality_level="critical",
                    criticality_score=100, zone=zone)   # C = 100
    factory.port(asset, port=22, severity="low")        # P = 70

    # A = 45  ->  failed_weight / applicable_weight = 9 / 20 = 0.45
    session = factory.audit_session(asset)
    for _ in range(3):
        factory.result(session, CheckStatus.FAIL, severity="medium")  # 3 x 3 = 9 failed
    factory.result(session, CheckStatus.PASS, severity="high")        # +7
    factory.result(session, CheckStatus.PASS, severity="medium")      # +3
    factory.result(session, CheckStatus.PASS, severity="low")         # +1  => applicable 20

    score = calc(db, asset)

    # Verify each factor first for a precise failure message.
    assert float(score.criticality_score) == 100
    assert float(score.zone_score) == 80
    assert float(score.open_port_score) == 70
    assert float(score.audit_risk_score) == 45
    assert float(score.final_risk_score) == 69.50


# ======================================================================
# 30.7 Boundary Tests (risk-level thresholds)
# ======================================================================

def _level(score, settings):
    return risk_calculation_service._risk_level(score, settings)


def test_risk_level_low(settings):
    assert _level(0, settings) == "low"
    assert _level(19.99, settings) == "low"


def test_risk_level_medium(settings):
    assert _level(20, settings) == "medium"
    assert _level(39.99, settings) == "medium"


def test_risk_level_high(settings):
    assert _level(40, settings) == "high"
    assert _level(59.99, settings) == "high"


def test_risk_level_very_high(settings):
    assert _level(60, settings) == "very_high"
    assert _level(79.99, settings) == "very_high"


def test_risk_level_critical(settings):
    assert _level(80, settings) == "critical"
    assert _level(100, settings) == "critical"


# ======================================================================
# Settings validation (thresholds / editable score settings)
# ======================================================================

def _ensure_threshold_rows(db):
    # The four boundaries between the five bands. There is no
    # *_very_high_threshold key: risk_level_high_threshold=60 opens Very High.
    set_setting(db, "risk_level_low_threshold", 20)
    set_setting(db, "risk_level_medium_threshold", 40)
    set_setting(db, "risk_level_high_threshold", 60)
    set_setting(db, "risk_level_critical_threshold", 80)


def test_thresholds_must_be_ascending(db, factory):
    from fastapi import BackgroundTasks
    from app.modules.risk.router import update_settings

    _ensure_threshold_rows(db)
    with pytest.raises(HTTPException) as exc_info:
        update_settings(
            updates={"risk_level_high_threshold": 90},  # >= critical (80)
            background_tasks=BackgroundTasks(),
            current_user=factory.user(),
            db=db,
        )
    assert exc_info.value.status_code == 400
    assert "ascending" in exc_info.value.detail


def test_thresholds_ascending_update_ok(db, factory):
    from fastapi import BackgroundTasks
    from app.modules.risk.router import update_settings

    _ensure_threshold_rows(db)
    result = update_settings(
        updates={"risk_level_medium_threshold": 25},
        background_tasks=BackgroundTasks(),
        current_user=factory.user(),
        db=db,
    )
    assert result["risk_level_medium_threshold"] == 25


def test_criticality_score_setting_editable(db, factory):
    """The criticality_*_score settings must be editable via PUT /settings."""
    from fastapi import BackgroundTasks
    from app.modules.risk.router import update_settings

    set_setting(db, "criticality_high_score", 75)
    result = update_settings(
        updates={"criticality_high_score": 90},
        background_tasks=BackgroundTasks(),
        current_user=factory.user(),
        db=db,
    )
    assert result["criticality_high_score"] == 90
