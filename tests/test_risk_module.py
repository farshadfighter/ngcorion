"""Risk & Exposure Intelligence — integration tests (NGCorion Risk Score PDF).

These exercise the real ``AssetRiskCalculationService`` against a PostgreSQL
database (the project does not use SQLite). Each test runs inside a single
transaction that is rolled back on teardown, so tests are independent even
though the service commits internally (those commits become SAVEPOINT releases
inside the outer transaction).

Requires a migrated database (``alembic upgrade head``) reachable via
``DATABASE_URL``. The database-independent arithmetic (weights, formula, risk
levels, OP cap, AF/HF raw math) is covered separately by
``tests/test_risk_score_formula.py``, which needs no database.

Factors and their default weights (from risk_settings / service defaults):
    criticality 25%, zone 20%, open_port 15%, audit 40%
Severity weights: low=1, medium=3, high=7, critical=10; port normalization
factor = 4.  Fallback ("unknown") scores = 50 for zone/port/audit.

Risk-level bands (inclusive lower bound): medium=20, high=40, very_high=60,
critical=80.  The setting keys are offset from the band they open -- the
boundary at 60 is stored as risk_level_high_threshold but starts Very High.

NOTE: the five levels here are low/medium/high/very_high/critical, not the
PDF's informational/low/medium/high/critical. The very_high scheme is a direct
client requirement and overrides the PDF on this point.
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
from app.models.audit import AuditResult, AuditSession, CheckStatus, DeviceType
from app.models.enums import RiskLevelEnum, StatusEnum
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

    def asset(self, ip: str = "10.20.30.40", risk_level=None) -> Asset:
        asset = Asset(
            asset_name=f"RiskTestAsset_{self._next()}",
            asset_type_id=self.asset_type().id,
            user_id=self.user().id,
            status=StatusEnum.ACTIVE,
            ip_address=ip,
            risk_level=risk_level,
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
            criticality_is_default=False,
            zone_id=zone.id if zone else None,
            zone_is_default=zone is None,
        )
        self.db.add(profile)
        self.db.flush()
        return profile

    # PDF section 6 open-port scale (1/3/5/10) — matches port_severity_* weights.
    _PORT_SCORE = {"low": 1, "medium": 3, "high": 5, "critical": 10}

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
            severity_score=self._PORT_SCORE.get(severity, 3),
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
    return risk_calculation_service._load_settings(db)


def calc(db, asset) -> AssetRiskScore:
    return risk_calculation_service.calculate(asset.id, db, trigger_type="test")


def set_setting(db, key: str, value, value_type: str = "int"):
    row = db.query(RiskSetting).filter(RiskSetting.setting_key == key).first()
    if row is None:
        row = RiskSetting(setting_key=key, setting_value=str(value), value_type=value_type)
        db.add(row)
    else:
        row.setting_value = str(value)
    db.flush()


# ======================================================================
# Criticality (AC)
# ======================================================================

def test_criticality_change_triggers_recalculate(db, factory):
    asset = factory.asset()
    profile = factory.profile(asset, criticality_level="low", criticality_score=25)

    first = calc(db, asset)
    assert float(first.criticality_score) == 25
    low_final = float(first.final_risk_score)

    profile.criticality_level = "critical"
    profile.criticality_score = 100
    db.flush()

    second = calc(db, asset)
    assert float(second.criticality_score) == 100
    assert float(second.final_risk_score) > low_final


# ======================================================================
# Asset Risk (AR) — PDF section 4
# ======================================================================

def test_asset_risk_from_asset_risk_level(db, factory):
    asset = factory.asset(risk_level=RiskLevelEnum.HIGH)
    factory.profile(asset)
    score = calc(db, asset)
    assert float(score.asset_risk_score) == 75          # High -> 75
    assert float(score.asset_risk_weight) == 20         # AR carries 20%


def test_missing_asset_risk_flagged_incomplete(db, factory):
    asset = factory.asset(risk_level=None)
    factory.profile(asset)
    score = calc(db, asset)
    assert score.incomplete_data is True
    assert "missing_asset_risk" in (score.incomplete_reasons_json or [])


# ======================================================================
# Zone (AZ)
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
    first_final = float(first.final_risk_score)

    profile.zone_id = high_zone.id
    db.flush()

    second = calc(db, asset)
    assert float(second.zone_score) == 100
    assert float(second.final_risk_score) > first_final


def test_deleted_zone_not_assignable(db, factory):
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
# Open Ports (OP) — PDF section 6: OP = min(100, sum of points)
# ======================================================================

def test_only_open_ports_calculated(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=22, severity="critical", status="open")
    factory.port(asset, port=23, severity="critical", status="closed")

    score = calc(db, asset)
    assert score.open_ports_count == 1
    assert float(score.open_port_raw_score) == 10


def test_excluded_port_not_calculated(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=443, severity="critical", is_included_in_risk=True)
    factory.port(asset, port=8443, severity="critical", is_included_in_risk=False)

    score = calc(db, asset)
    assert float(score.open_port_raw_score) == 10


def test_op_no_normalization_multiplier(db, factory):
    """OP = min(100, sum): one critical port (10 points) -> OP = 10, not 40."""
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=3389, severity="critical")

    score = calc(db, asset)
    assert float(score.open_port_raw_score) == 10
    assert float(score.open_port_score) == 10


def test_op_pdf_example_26(db, factory):
    """PDF section 6: SSH 3 + HTTP 3 + SMB 10 + RDP 10 = 26 -> OP = 26."""
    asset = factory.asset()
    factory.profile(asset)
    factory.port(asset, port=22, severity="medium")     # SSH -> 3
    factory.port(asset, port=80, severity="medium")     # HTTP -> 3
    factory.port(asset, port=445, severity="critical")  # SMB -> 10
    factory.port(asset, port=3389, severity="critical") # RDP -> 10

    score = calc(db, asset)
    assert float(score.open_port_raw_score) == 26
    assert float(score.open_port_score) == 26


def test_port_score_capped_at_100(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    # 12 critical ports -> raw 120 -> capped at 100.
    for p in (21, 22, 23, 25, 80, 110, 143, 445, 993, 995, 1433, 3389):
        factory.port(asset, port=p, severity="critical")

    score = calc(db, asset)
    assert float(score.open_port_raw_score) == 120
    assert float(score.open_port_score) == 100


def test_closed_port_removed_from_risk(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    p1 = factory.port(asset, port=22, severity="critical")
    factory.port(asset, port=3389, severity="critical")

    first = calc(db, asset)
    # 2 critical ports -> raw 20 -> OP = min(100, 20) = 20.
    assert float(first.open_port_score) == 20
    first_port_score = float(first.open_port_score)

    p1.status = "closed"
    db.flush()

    second = calc(db, asset)
    assert second.open_ports_count == 1
    assert float(second.open_port_score) == 10
    assert float(second.open_port_score) < first_port_score


def test_excluding_port_requires_reason(db, factory):
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
# Audit Failure (AF) — medium weight is now 4 (PDF section 7)
# ======================================================================

def test_only_applicable_controls_in_denominator(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    # Applicable: PASS(high=7) + FAIL(medium=4) = 11 applicable weight.
    factory.result(session, CheckStatus.PASS, severity="high")
    factory.result(session, CheckStatus.FAIL, severity="medium")
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="critical")
    factory.result(session, CheckStatus.ERROR, severity="critical")

    score = calc(db, asset)
    assert float(score.audit_applicable_weight) == 11


def test_failed_controls_in_numerator(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="high")    # 7
    factory.result(session, CheckStatus.FAIL, severity="medium")  # 4
    factory.result(session, CheckStatus.PASS, severity="critical")

    score = calc(db, asset)
    assert float(score.audit_failed_weight) == 11
    assert score.active_audit_findings_count == 2


def test_af_normalized_ratio(db, factory):
    """AF = 100 * failed/applicable. FAIL high(7) with PASS high(7) -> 50."""
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="high")   # 7 failed
    factory.result(session, CheckStatus.PASS, severity="high")   # +7 applicable

    score = calc(db, asset)
    assert float(score.audit_applicable_weight) == 14
    assert float(score.audit_failed_weight) == 7
    assert float(score.audit_risk_score) == 50


def test_pass_not_counted(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.PASS, severity="critical")
    factory.result(session, CheckStatus.PASS, severity="high")

    score = calc(db, asset)
    assert float(score.audit_failed_weight) == 0
    assert float(score.audit_risk_score) == 0


def test_not_applicable_not_counted(db, factory):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="medium")  # 4
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="critical")

    score = calc(db, asset)
    assert float(score.audit_applicable_weight) == 4
    assert float(score.audit_failed_weight) == 4


def test_division_by_zero_handled(db, factory, settings):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="high")
    factory.result(session, CheckStatus.NOT_APPLICABLE, severity="critical")

    score = calc(db, asset)
    assert float(score.audit_applicable_weight) == 0
    assert float(score.audit_risk_score) == float(settings["unknown_audit_score"])


# ======================================================================
# Hardening Fix Found (HF) — Strict PDF: additive term, does NOT lower AF
# ======================================================================

def test_fix_found_raises_hf_but_stays_in_af(db, factory):
    """A failed control with a fix found: HF > 0, and the finding still counts
    in AF (hardening does not resolve it out of AF)."""
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    failed = factory.result(session, CheckStatus.FAIL, severity="high")  # 7
    factory.hardening(failed, session, asset, status="success", verification_passed=True)

    score = calc(db, asset)
    # Still fully failing in AF.
    assert float(score.audit_failed_weight) == 7
    assert float(score.audit_risk_score) == 100
    assert score.active_audit_findings_count == 1
    # HF picks up the same finding (fix found) -> HF = 100 * 7/7 = 100.
    assert float(score.hardening_fix_score) == 100
    assert score.hardening_fixes_found_count == 1
    # Verified execute still recorded for display.
    assert score.resolved_by_hardening_count == 1


def test_hf_le_af(db, factory):
    """HF <= AF: only one of two failures has a fix found."""
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    with_fix = factory.result(session, CheckStatus.FAIL, severity="high")   # 7
    factory.result(session, CheckStatus.FAIL, severity="medium")            # 4, no fix
    factory.hardening(with_fix, session, asset, status="success", verification_passed=True)

    score = calc(db, asset)
    # Both fail -> AF numerator 11, denominator 11 -> AF = 100.
    assert float(score.audit_failed_weight) == 11
    assert float(score.audit_risk_score) == 100
    # Only the high finding has a fix -> HF = 100 * 7/11 (stored Numeric(5,2)).
    assert float(score.hardening_fix_score) == round(100.0 * 7 / 11, 2)
    assert float(score.hardening_fix_score) < float(score.audit_risk_score)


def test_no_hardening_data_hf_zero(db, factory, settings):
    asset = factory.asset()
    factory.profile(asset)
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="high")

    score = calc(db, asset)
    assert float(score.hardening_fix_score) == float(settings["no_hardening_data_score"])
    assert score.hardening_fixes_found_count == 0


# ======================================================================
# Full formula — six-factor
# ======================================================================

def test_six_factor_formula(db, factory):
    """AC=100, AR=75, AZ=80, OP=40, AF=100, HF=0
        -> 20 + 15 + 12 + 4 + 25 + 0 = 76  -> High."""
    zone = factory.zone(score=80)                                    # AZ = 80
    asset = factory.asset(risk_level=RiskLevelEnum.HIGH)             # AR = 75
    factory.profile(asset, criticality_level="critical",
                    criticality_score=100, zone=zone)               # AC = 100
    # OP = 40: four critical ports (10 each), factor 1.
    for p in (21, 22, 23, 25):
        factory.port(asset, port=p, severity="critical")
    # AF = 100: a single failing control, all applicable weight fails.
    session = factory.audit_session(asset)
    factory.result(session, CheckStatus.FAIL, severity="critical")  # 10 / 10

    score = calc(db, asset)
    assert float(score.criticality_score) == 100
    assert float(score.asset_risk_score) == 75
    assert float(score.zone_score) == 80
    assert float(score.open_port_score) == 40
    assert float(score.audit_risk_score) == 100
    assert float(score.hardening_fix_score) == 0
    assert float(score.final_risk_score) == 76
    assert score.risk_level == "high"


def test_final_score_is_integer(db, factory):
    asset = factory.asset(risk_level=RiskLevelEnum.MEDIUM)
    factory.profile(asset, criticality_level="high", criticality_score=75)
    score = calc(db, asset)
    assert float(score.final_risk_score) == round(float(score.final_risk_score))


# ======================================================================
# Settings validation
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
        updates={"risk_level_low_threshold": 25},
        background_tasks=BackgroundTasks(),
        current_user=factory.user(),
        db=db,
    )
    assert result["risk_level_low_threshold"] == 25


def _ensure_weight_rows(db):
    set_setting(db, "criticality_weight", 20)
    set_setting(db, "asset_risk_weight", 20)
    set_setting(db, "zone_weight", 15)
    set_setting(db, "open_port_weight", 10)
    set_setting(db, "audit_weight", 25)
    set_setting(db, "hardening_weight", 10)


def test_factor_weights_must_sum_to_100(db, factory):
    from fastapi import BackgroundTasks
    from app.modules.risk.router import update_settings

    _ensure_weight_rows(db)
    with pytest.raises(HTTPException) as exc_info:
        update_settings(
            updates={"hardening_weight": 30},  # sum -> 120
            background_tasks=BackgroundTasks(),
            current_user=factory.user(),
            db=db,
        )
    assert exc_info.value.status_code == 400
    assert "sum to 100" in exc_info.value.detail


def test_criticality_score_setting_editable(db, factory):
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
