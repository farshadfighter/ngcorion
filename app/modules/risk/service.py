"""
Asset Risk Calculation Service

Computes a 0-100 risk score per asset from six weighted factors, following the
NGCorion Risk Score Calculation Specification (risk.pdf):

  RiskScore = (AC*0.20) + (AR*0.20) + (AZ*0.15)
            + (OP*0.10) + (AF*0.25) + (HF*0.10)

  AC  Asset Criticality      asset_risk_profiles          20%
  AR  Asset Risk             asset_inventory.risk_level   20%
  AZ  Asset Zone             risk_zones                   15%
  OP  Open Port Risk         asset_open_ports             10%
  AF  Audit Failure Risk     audit_sessions/audit_results 25%
  HF  Hardening Fix Found    hardening_actions            10%

Every component is normalized to 0-100 before the weights apply; the final
score is rounded to the nearest integer and clamped to 0-100 (PDF sections 9,
11, 12). All tunables (factor weights, severity weights, fallback scores, level
thresholds) come from risk_settings; the hardcoded values below are only the
fallback when a setting row is missing.

Spec model notes (PDF sections 7 & 8):
  - AF is the severity-weighted share of *all* failed applicable controls in
    the latest audit session:
        AF = 100 * (sum of severity weights of FAILED controls)
                 / (sum of severity weights of all applicable controls)
  - HF is the severity-weighted share of failed controls that have a fix
    identified (a hardening_actions row exists for the finding), added as a
    positive risk term:
        HF = 100 * (sum of severity weights of FAILED controls with a fix)
                 / (sum of severity weights of all applicable controls)
    So HF <= AF by construction. Per the PDF, hardening does NOT remove a
    finding from AF; a fixed control only leaves AF once a re-audit flips it
    to PASS. `resolved_by_hardening_count` (a verified successful execute) is
    still computed for display but no longer affects AF or HF.

Schema notes (differ from the raw pseudocode):
  - HardeningAction stores `verification_passed` (Boolean), not a
    verification_status string.
  - AuditResult.status is the CheckStatus enum; NOT_APPLICABLE and ERROR
    results are excluded from the applicable weight.
  - Findings (audit + hardening) and open ports use *different* severity
    scales: severity_*_weight (1/4/7/10) vs port_severity_*_weight (1/3/5/10).
"""

import asyncio
import logging
import re
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.audit import AuditResult, AuditSession, CheckStatus
from app.models.enums import StatusEnum
from app.models.hardening import HardeningAction
from app.models.security_audit_log import log_action
from app.models.user import User
from app.models.risk import (
    AssetOpenPort,
    AssetRiskHistory,
    AssetRiskProfile,
    AssetRiskScore,
    RiskCalculationLog,
    RiskSetting,
    RiskZone,
)

logger = logging.getLogger(__name__)

# Fallbacks used only when the corresponding risk_settings row is missing.
# These mirror the values the Alembic migration seeds; they only take effect on
# a database that predates the risk settings rows.
DEFAULT_SETTINGS = {
    # Factor weights (must sum to 100) — PDF section 2/4:
    #   RiskScore = AC*0.20 + AR*0.20 + AZ*0.15 + OP*0.10 + AF*0.25 + HF*0.10
    "criticality_weight": 20.0,      # AC
    "asset_risk_weight": 20.0,       # AR
    "zone_weight": 15.0,             # AZ
    "open_port_weight": 10.0,        # OP
    "audit_weight": 25.0,            # AF
    "hardening_weight": 10.0,        # HF
    # Finding severity weights (audit failures + hardening fixes found) —
    # PDF sections 7/8: Low 1, Medium 4, High 7, Critical 10.
    "severity_low_weight": 1.0,
    "severity_medium_weight": 4.0,
    "severity_high_weight": 7.0,
    "severity_critical_weight": 10.0,
    # Open-port severity weights (Standard/Low, Medium, High, Critical/Insecure) —
    # PDF section 6: 1, 3, 5, 10.
    "port_severity_low_weight": 1.0,
    "port_severity_medium_weight": 3.0,
    "port_severity_high_weight": 5.0,
    "port_severity_critical_weight": 10.0,
    # Open-port score normalization: OP = min(100, raw * factor).
    # PDF section 6: OP = min(100, Sum(points)) — no extra multiplier, factor = 1.
    "open_port_normalization_factor": 1.0,
    "unknown_zone_score": 50.0,
    "unknown_port_score": 50.0,
    "unknown_audit_score": 50.0,
    "unknown_asset_risk_score": 50.0,
    # HF when the asset has no hardening data at all (spec: 0, not "unknown")
    "no_hardening_data_score": 0.0,
    "include_warning_in_audit_risk": False,
    "criticality_low_score": 25.0,
    "criticality_medium_score": 50.0,
    "criticality_high_score": 75.0,
    "criticality_critical_score": 100.0,
    # asset_inventory.risk_level -> AR score. very_high is a legacy enum
    # member kept mappable; the spec's four levels are low/medium/high/critical.
    "asset_risk_low_score": 25.0,
    "asset_risk_medium_score": 50.0,
    "asset_risk_high_score": 75.0,
    "asset_risk_very_high_score": 90.0,
    "asset_risk_critical_score": 100.0,
    # Inclusive lower bound of each level, evaluated highest to lowest
    # (see _risk_level); a score on a boundary belongs to the higher band:
    #   <20 low | 20-40 medium | 40-60 high | 60-80 very_high | >=80 critical
    "risk_level_low_threshold": 20.0,
    "risk_level_medium_threshold": 40.0,
    "risk_level_high_threshold": 60.0,
    "risk_level_critical_threshold": 80.0,
}


class AssetRiskCalculationService:
    """Calculates and persists per-asset risk scores."""

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    def _load_settings(self, db: Session) -> dict:
        """STEP 1: risk_settings rows parsed by value_type, merged over defaults."""
        settings = dict(DEFAULT_SETTINGS)
        for row in db.query(RiskSetting).all():
            raw = row.setting_value
            try:
                if row.value_type == "bool":
                    value = str(raw).strip().lower() in ("true", "1", "yes")
                elif row.value_type in ("int", "float"):
                    value = float(raw)
                else:
                    value = raw
            except (TypeError, ValueError):
                logger.warning(
                    "Risk setting %s has unparseable value %r; using default",
                    row.setting_key, raw,
                )
                continue
            settings[row.setting_key] = value
        return settings

    def _severity_weight(self, severity, settings: dict, prefix: str = "severity") -> float:
        """Severity -> weight. prefix picks the scale: findings (`severity`,
        1/4/7/10) or open ports (`port_severity`, 1/3/5/10)."""
        key = f"{prefix}_{(severity or 'medium').strip().lower()}_weight"
        if key not in settings:
            # info/unknown severities score as low
            key = (f"{prefix}_low_weight" if severity == "info"
                   else f"{prefix}_medium_weight")
        return float(settings[key])

    def _port_severity_weight(self, severity, settings: dict) -> float:
        return self._severity_weight(severity, settings, prefix="port_severity")

    # ------------------------------------------------------------------
    # Factor scores
    # ------------------------------------------------------------------

    # asset_inventory.confidentiality_level -> criticality level. The asset's
    # confidentiality is set once in Asset List (spec section 3.1), so it is
    # what the risk engine scores unless a risk profile overrides it.
    # ConfidentialityLevelEnum (app/models/enums.py) -> criticality level.
    _CONFIDENTIALITY_TO_CRITICALITY = {
        "public": "low",
        "internal": "medium",
        "confidential": "high",
        "critical": "critical",
        # Imports sometimes carry the criticality words straight through.
        "low": "low",
        "medium": "medium",
        "high": "high",
    }

    def _criticality_level(self, asset: Asset, profile: AssetRiskProfile):
        """Returns (level, from_asset). An explicit profile wins; otherwise the
        asset's own confidentiality is used so the value only has to be set in
        one place."""
        if not profile.criticality_is_default and profile.criticality_level:
            return profile.criticality_level.strip().lower(), False

        raw = getattr(asset, "confidentiality_level", None)
        raw = getattr(raw, "value", raw)
        mapped = self._CONFIDENTIALITY_TO_CRITICALITY.get(
            str(raw or "").strip().lower()
        )
        if mapped:
            return mapped, True

        return (profile.criticality_level or "medium").strip().lower(), False

    def _criticality_score(self, level: str, settings: dict) -> float:
        return float(settings.get(f"criticality_{level}_score",
                                  settings["criticality_medium_score"]))

    def _asset_risk_score(self, asset: Asset, settings: dict):
        """AR: the asset's own risk_level (asset_inventory).

        Returns (level, score, is_unknown); an unset risk_level falls back to
        unknown_asset_risk_score (50 by spec).
        """
        raw = getattr(asset.risk_level, "value", asset.risk_level)
        level = (str(raw).strip().lower() or None) if raw is not None else None
        if not level:
            return None, float(settings["unknown_asset_risk_score"]), True
        return level, float(
            settings.get(f"asset_risk_{level}_score",
                         settings["unknown_asset_risk_score"])
        ), False

    @staticmethod
    def _zone_key(name) -> str:
        """Normalised zone name for matching across the two zone tables.

        The asset form stores a free-text zone name while risk_zones is seeded
        with fixed ones, so "Internet / Public", "internet/public" and
        "Internet-Public" all have to resolve to the same zone.
        """
        return re.sub(r"[^a-z0-9]", "", str(name or "").lower())

    def _zone_score(self, db: Session, asset: Asset, profile: AssetRiskProfile,
                    settings: dict):
        """Returns (zone, zone_score, is_unknown).

        Spec section 3.1 says the zone comes from Asset Management. In practice
        it is picked in the asset form and stored as text on
        asset_inventory.asset_role, so an explicit risk profile wins and the
        asset's own value is the fallback — that way a zone set once in Asset
        List is what the risk engine scores, with no second place to maintain.
        """
        if profile.zone_id is not None:
            zone = db.query(RiskZone).filter(RiskZone.id == profile.zone_id).first()
            if zone is not None:
                return zone, float(zone.score), False

        asset_zone = getattr(asset, "asset_role", None)
        key = self._zone_key(asset_zone)
        if key:
            for zone in db.query(RiskZone).filter(RiskZone.status == "active").all():
                if self._zone_key(zone.name) == key:
                    return zone, float(zone.score), False

        return None, float(settings["unknown_zone_score"]), True

    def _open_port_score(self, db: Session, asset_id: int, settings: dict):
        """Returns (raw_score, score, ports_count, risky_count, is_unknown)."""
        open_ports_count = (
            db.query(func.count(AssetOpenPort.id))
            .filter(AssetOpenPort.asset_id == asset_id,
                    AssetOpenPort.status == "open")
            .scalar()
        ) or 0

        included = (
            db.query(AssetOpenPort)
            .filter(AssetOpenPort.asset_id == asset_id,
                    AssetOpenPort.status == "open",
                    AssetOpenPort.is_included_in_risk.is_(True))
            .all()
        )
        if not included:
            return None, float(settings["unknown_port_score"]), open_ports_count, 0, True

        raw_score = sum(
            self._port_severity_weight(p.severity, settings) for p in included
        )
        factor = float(settings["open_port_normalization_factor"])
        score = min(100.0, raw_score * factor)
        risky_count = sum(
            1 for p in included if (p.severity or "").lower() in ("high", "critical")
        )
        return raw_score, score, open_ports_count, risky_count, False

    def _audit_and_hardening_risk(
        self, db: Session, asset_id: int, settings: dict
    ) -> dict:
        """STEP 7: AF (audit failure risk) and HF (hardening fix found risk).

        Both read the same latest non-running audit session, so they are
        computed in one pass over its results (PDF sections 7 & 8):

            AF_Raw = sum(weight) of ALL failed applicable controls
            AF     = 100 * AF_Raw / MaxPossibleAuditScore
            HF_Raw = sum(weight) of failed controls a fix was *found* for
                     (a hardening_actions row exists for the finding)
            HF     = 100 * HF_Raw / MaxPossibleHardeningScore

        MaxPossibleAuditScore / MaxPossibleHardeningScore are both the
        weighted sum of every applicable control in the session
        (NOT_APPLICABLE/ERROR excluded), so HF <= AF by construction.

        Per the PDF, hardening does not remove a finding from AF: a fixed
        control only leaves AF when a re-audit flips it to PASS. A verified
        successful (non-preview) execute is still counted in
        `resolved_by_hardening` for display, but it affects neither AF nor HF.
        With no hardening rows at all, HF is no_hardening_data_score (0).
        """
        out = {
            "session": None,
            "failed_weight": None,
            "applicable_weight": None,
            "score": float(settings["unknown_audit_score"]),
            "is_unknown": True,
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "resolved_by_hardening": 0,
            "active_findings": 0,
            # HF block
            "hardening_raw": None,
            "hardening_applicable_weight": None,
            "hardening_score": float(settings["no_hardening_data_score"]),
            "hardening_is_unknown": True,
            "fixes_found": 0,
        }

        session = (
            db.query(AuditSession)
            .filter(AuditSession.asset_id == asset_id,
                    AuditSession.status != "running")
            .order_by(AuditSession.started_at.desc())
            .first()
        )
        if session is None:
            return out

        results = (
            db.query(AuditResult)
            .filter(AuditResult.session_id == session.id)
            .all()
        )

        failed_weight = 0.0
        applicable_weight = 0.0
        hardening_weight_found = 0.0
        has_hardening_data = False
        for result in results:
            if result.status in (CheckStatus.NOT_APPLICABLE, CheckStatus.ERROR):
                continue
            weight = self._severity_weight(result.severity, settings)
            applicable_weight += weight

            if result.status != CheckStatus.FAIL:
                continue

            # Every failed applicable control counts toward AF (PDF section 7).
            failed_weight += weight
            out["active_findings"] += 1
            sev = (result.severity or "medium").lower()
            if sev not in out["findings"]:
                sev = "medium"
            out["findings"][sev] += 1

            # One pass over the finding's hardening actions: a fix is "found"
            # when any action row exists (drives HF, PDF section 8); a verified
            # successful non-preview execute is tracked for display only and,
            # per the PDF, does NOT remove the finding from AF or HF.
            actions = (
                db.query(
                    HardeningAction.action_type,
                    HardeningAction.status,
                    HardeningAction.verification_passed,
                )
                .filter(HardeningAction.audit_result_id == result.id)
                .all()
            )
            if actions:
                has_hardening_data = True
                hardening_weight_found += weight
                out["fixes_found"] += 1
            if any(
                action_type != "preview"
                and status == "success"
                and verification_passed is True
                for action_type, status, verification_passed in actions
            ):
                out["resolved_by_hardening"] += 1

        out["session"] = session
        out["failed_weight"] = failed_weight
        out["applicable_weight"] = applicable_weight
        out["is_unknown"] = False

        if applicable_weight == 0:
            logger.warning(
                "Audit session %s for asset %s has no applicable results; "
                "using unknown_audit_score", session.id, asset_id,
            )
            out["score"] = float(settings["unknown_audit_score"])
        else:
            out["score"] = round(100.0 * failed_weight / applicable_weight, 4)

        # HF: only meaningful once the asset has hardening data at all.
        if has_hardening_data and applicable_weight > 0:
            out["hardening_raw"] = hardening_weight_found
            out["hardening_applicable_weight"] = applicable_weight
            out["hardening_score"] = round(
                100.0 * hardening_weight_found / applicable_weight, 4
            )
            out["hardening_is_unknown"] = False
        else:
            out["hardening_raw"] = 0.0 if has_hardening_data else None
            out["hardening_applicable_weight"] = (
                applicable_weight if has_hardening_data else None
            )
            out["hardening_score"] = float(settings["no_hardening_data_score"])
            out["hardening_is_unknown"] = not has_hardening_data
        return out

    def _risk_level(self, score: float, settings: dict) -> str:
        """Spec section 10:
            0 <= s < 20  low | 20 <= s < 40  medium | 40 <= s < 60  high
            60 <= s < 80 very_high | 80 <= s <= 100 critical

        Thresholds are *inclusive* lower bounds: a score sitting exactly on a
        boundary belongs to the higher band, so 20 is medium and 80 is
        critical (spec test 30.7).

        NOTE: this five-level scheme (with very_high, without informational) is
        a direct client requirement and takes precedence over the PDF's
        informational/low/medium/high/critical bands. Do not "restore" the PDF
        wording here without checking with the client first -- the Risk UI's
        level colours, KPI cards and the a4c7e1b90d52 migration all depend on
        very_high existing.
        """
        if score >= float(settings["risk_level_critical_threshold"]):
            return "critical"
        if score >= float(settings["risk_level_high_threshold"]):
            return "very_high"
        if score >= float(settings["risk_level_medium_threshold"]):
            return "high"
        if score >= float(settings["risk_level_low_threshold"]):
            return "medium"
        return "low"

    # ------------------------------------------------------------------
    # Weighted aggregation
    # ------------------------------------------------------------------

    # component key -> the risk_settings weight key that scales it
    _WEIGHT_KEYS = {
        "criticality": "criticality_weight",
        "asset_risk": "asset_risk_weight",
        "zone": "zone_weight",
        "open_port": "open_port_weight",
        "audit": "audit_weight",
        "hardening": "hardening_weight",
    }

    def _final_score(self, components: dict, settings: dict) -> tuple:
        """STEP 8: apply the PDF weights to the six normalized components.

        ``components`` maps each component key in ``_WEIGHT_KEYS`` to its
        already-normalized 0-100 score. Returns ``(final_score, contributions)``
        where contributions maps the same keys to ``score * weight / 100`` and
        ``final_score`` is ``round(sum(contributions))`` clamped to 0-100
        (PDF sections 9, 11, 12 — round the final score to an integer).
        """
        contributions = {
            key: float(components[key]) * float(settings[weight_key]) / 100.0
            for key, weight_key in self._WEIGHT_KEYS.items()
        }
        total = sum(contributions.values())
        final_score = float(min(100.0, max(0.0, round(total))))
        return final_score, contributions

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def calculate(
        self,
        asset_id: int,
        db: Session,
        trigger_type: str,
        trigger_reference_id: int = None,
        triggered_by: int = None,
    ) -> AssetRiskScore:
        """Compute and persist the risk score for one asset.

        Raises ValueError if the asset does not exist; re-raises any
        calculation error after writing a RiskCalculationLog error row.
        """
        started_at = datetime.utcnow()
        input_json = {
            "asset_id": asset_id,
            "trigger_type": trigger_type,
            "trigger_reference_id": trigger_reference_id,
        }
        try:
            settings = self._load_settings(db)

            asset = db.query(Asset).filter(Asset.id == asset_id).first()
            if asset is None:
                raise ValueError("Asset not found")

            incomplete_reasons = []

            # STEP 3: profile (create with defaults when missing)
            profile = (
                db.query(AssetRiskProfile)
                .filter(AssetRiskProfile.asset_id == asset_id)
                .first()
            )
            if profile is None:
                profile = AssetRiskProfile(
                    asset_id=asset_id,
                    criticality_level="medium",
                    criticality_score=50,
                    criticality_is_default=True,
                    zone_is_default=True,
                )
                db.add(profile)
                db.flush()

            # STEP 4: criticality (AC) — from the asset's confidentiality
            # unless the risk profile overrides it.
            criticality_level, criticality_from_asset = self._criticality_level(
                asset, profile
            )
            criticality_score = self._criticality_score(criticality_level, settings)

            # Only genuinely unset criticality is incomplete: a value taken
            # from the asset is a real answer, not a default.
            if profile.criticality_is_default and not criticality_from_asset:
                incomplete_reasons.append("missing_criticality")

            # Keep the profile in step so the detail screen and the score agree.
            if profile.criticality_level != criticality_level:
                profile.criticality_level = criticality_level
            profile.criticality_score = criticality_score

            # STEP 4b: asset's own risk level (AR)
            asset_risk_level, asset_risk_score, asset_risk_unknown = (
                self._asset_risk_score(asset, settings)
            )
            if asset_risk_unknown:
                incomplete_reasons.append("missing_asset_risk")

            # STEP 5: zone
            zone, zone_score, zone_unknown = self._zone_score(
                db, asset, profile, settings
            )
            if zone_unknown:
                incomplete_reasons.append("missing_zone")

            # STEP 6: open ports
            (
                open_port_raw,
                open_port_score,
                open_ports_count,
                risky_ports_count,
                ports_unknown,
            ) = self._open_port_score(db, asset_id, settings)
            if ports_unknown:
                incomplete_reasons.append("missing_port_scan")

            # STEP 7: audit failures (AF) + hardening fixes found (HF)
            audit = self._audit_and_hardening_risk(db, asset_id, settings)
            if audit["is_unknown"]:
                incomplete_reasons.append("missing_audit")

            # STEP 8: weighted final score — PDF sections 2/4/9:
            #   Risk = AC*0.20 + AR*0.20 + AZ*0.15 + OP*0.10 + AF*0.25 + HF*0.10
            criticality_weight = float(settings["criticality_weight"])
            asset_risk_weight = float(settings["asset_risk_weight"])
            zone_weight = float(settings["zone_weight"])
            open_port_weight = float(settings["open_port_weight"])
            audit_weight = float(settings["audit_weight"])
            hardening_weight = float(settings["hardening_weight"])

            final_risk_score, contributions = self._final_score(
                {
                    "criticality": criticality_score,
                    "asset_risk": asset_risk_score,
                    "zone": zone_score,
                    "open_port": open_port_score,
                    "audit": audit["score"],
                    "hardening": audit["hardening_score"],
                },
                settings,
            )
            criticality_contribution = contributions["criticality"]
            asset_risk_contribution = contributions["asset_risk"]
            zone_contribution = contributions["zone"]
            open_port_contribution = contributions["open_port"]
            audit_contribution = contributions["audit"]
            hardening_contribution = contributions["hardening"]

            # STEP 9: level
            risk_level = self._risk_level(final_risk_score, settings)

            incomplete_data = bool(incomplete_reasons)
            calculated_at = datetime.utcnow()
            audit_session = audit["session"]
            audit_id = audit_session.id if audit_session is not None else None

            # STEP 10: upsert score row
            score_row = (
                db.query(AssetRiskScore)
                .filter(AssetRiskScore.asset_id == asset_id)
                .first()
            )
            # Remember the previous level so we can audit-log transitions
            old_risk_level = score_row.risk_level if score_row is not None else None
            if score_row is None:
                score_row = AssetRiskScore(asset_id=asset_id)
                db.add(score_row)

            score_row.criticality_level = profile.criticality_level
            score_row.criticality_score = criticality_score
            score_row.criticality_weight = criticality_weight
            score_row.criticality_contribution = round(criticality_contribution, 2)
            score_row.asset_risk_level = asset_risk_level
            score_row.asset_risk_score = asset_risk_score
            score_row.asset_risk_weight = asset_risk_weight
            score_row.asset_risk_contribution = round(asset_risk_contribution, 2)
            score_row.zone_id = zone.id if zone is not None else None
            score_row.zone_name = zone.name if zone is not None else None
            score_row.zone_score = zone_score
            score_row.zone_weight = zone_weight
            score_row.zone_contribution = round(zone_contribution, 2)
            score_row.open_port_raw_score = open_port_raw
            score_row.open_port_score = open_port_score
            score_row.open_port_weight = open_port_weight
            score_row.open_port_contribution = round(open_port_contribution, 2)
            score_row.audit_failed_weight = audit["failed_weight"]
            score_row.audit_applicable_weight = audit["applicable_weight"]
            score_row.audit_risk_score = audit["score"]
            score_row.audit_weight = audit_weight
            score_row.audit_contribution = round(audit_contribution, 2)
            score_row.hardening_fix_raw_score = audit["hardening_raw"]
            score_row.hardening_applicable_weight = audit["hardening_applicable_weight"]
            score_row.hardening_fix_score = audit["hardening_score"]
            score_row.hardening_weight = hardening_weight
            score_row.hardening_contribution = round(hardening_contribution, 2)
            score_row.hardening_fixes_found_count = audit["fixes_found"]
            score_row.final_risk_score = final_risk_score
            score_row.risk_level = risk_level
            score_row.critical_findings_count = audit["findings"]["critical"]
            score_row.high_findings_count = audit["findings"]["high"]
            score_row.medium_findings_count = audit["findings"]["medium"]
            score_row.low_findings_count = audit["findings"]["low"]
            score_row.open_ports_count = open_ports_count
            score_row.risky_ports_count = risky_ports_count
            score_row.resolved_by_hardening_count = audit["resolved_by_hardening"]
            score_row.active_audit_findings_count = audit["active_findings"]
            score_row.incomplete_data = incomplete_data
            score_row.incomplete_reasons_json = incomplete_reasons
            score_row.audit_id = audit_id
            score_row.calculated_at = calculated_at

            db.add(
                AssetRiskHistory(
                    asset_id=asset_id,
                    risk_score=final_risk_score,
                    risk_level=risk_level,
                    criticality_score=criticality_score,
                    asset_risk_score=asset_risk_score,
                    zone_score=zone_score,
                    open_port_score=open_port_score,
                    audit_risk_score=audit["score"],
                    hardening_fix_score=audit["hardening_score"],
                    criticality_contribution=round(criticality_contribution, 2),
                    asset_risk_contribution=round(asset_risk_contribution, 2),
                    zone_contribution=round(zone_contribution, 2),
                    open_port_contribution=round(open_port_contribution, 2),
                    audit_contribution=round(audit_contribution, 2),
                    hardening_contribution=round(hardening_contribution, 2),
                    audit_id=audit_id,
                    reason=trigger_type,
                    calculated_at=calculated_at,
                )
            )

            output_json = {
                "final_risk_score": final_risk_score,
                "risk_level": risk_level,
                "criticality_score": criticality_score,
                "asset_risk_score": asset_risk_score,
                "zone_score": zone_score,
                "open_port_score": open_port_score,
                "audit_risk_score": audit["score"],
                "hardening_fix_score": audit["hardening_score"],
                "criticality_contribution": round(criticality_contribution, 2),
                "asset_risk_contribution": round(asset_risk_contribution, 2),
                "zone_contribution": round(zone_contribution, 2),
                "open_port_contribution": round(open_port_contribution, 2),
                "audit_contribution": round(audit_contribution, 2),
                "hardening_contribution": round(hardening_contribution, 2),
                "incomplete_data": incomplete_data,
                "incomplete_reasons": incomplete_reasons,
                "audit_session_id": audit_id,
            }
            db.add(
                RiskCalculationLog(
                    asset_id=asset_id,
                    calculation_status="success",
                    input_json=input_json,
                    output_json=output_json,
                    trigger_type=trigger_type,
                    trigger_reference_id=trigger_reference_id,
                    started_at=started_at,
                    finished_at=datetime.utcnow(),
                )
            )
            db.commit()
            db.refresh(score_row)

            # Audit-log a risk-level transition. Wrapped so a logging failure
            # never disrupts an otherwise-successful calculation.
            if old_risk_level != risk_level:
                try:
                    log_username = None
                    if triggered_by is not None:
                        user = (
                            db.query(User)
                            .filter(User.id == triggered_by)
                            .first()
                        )
                        log_username = user.username if user else None
                    log_action(
                        db,
                        user_id=triggered_by,
                        username=log_username,
                        action="risk.level_changed",
                        module="risk",
                        target_id=asset_id,
                        detail=(
                            f"old_value={old_risk_level or 'none'}; "
                            f"new_value={risk_level}; "
                            f"score={final_risk_score}; trigger={trigger_type}"
                        ),
                    )
                except Exception:
                    logger.warning(
                        "Failed to write risk_level_changed log for asset %s",
                        asset_id, exc_info=True,
                    )

            return score_row

        except Exception as exc:
            # STEP 11: roll back the poisoned transaction, then log the failure.
            # First attempt uses the asset FK; if that fails (e.g. the asset
            # doesn't exist), retry with asset_id=None — the real id is
            # preserved in input_json either way.
            db.rollback()
            for log_asset_id in (asset_id, None):
                try:
                    db.add(
                        RiskCalculationLog(
                            asset_id=log_asset_id,
                            calculation_status="error",
                            input_json=input_json,
                            error_message=str(exc)[:2000],
                            trigger_type=trigger_type,
                            trigger_reference_id=trigger_reference_id,
                            started_at=started_at,
                            finished_at=datetime.utcnow(),
                        )
                    )
                    db.commit()
                    break
                except Exception:
                    db.rollback()
            else:
                logger.exception(
                    "Failed to write risk calculation error log for asset %s",
                    asset_id,
                )
            logger.error("Risk calculation failed for asset %s: %s", asset_id, exc)
            raise


risk_calculation_service = AssetRiskCalculationService()


async def recalculate_all(
    db: Session,
    background: bool = True,
    trigger_type: str = "bulk_recalculation",
) -> dict:
    """Recalculate risk for every active asset. One asset failing never stops the loop.

    With background=True, yields to the event loop between assets so long
    runs don't starve other requests.
    """
    asset_ids = [
        row[0]
        for row in db.query(Asset.id)
        .filter(Asset.status == StatusEnum.ACTIVE)
        .order_by(Asset.id)
        .all()
    ]

    succeeded = 0
    failed = 0
    errors = []
    for asset_id in asset_ids:
        try:
            risk_calculation_service.calculate(
                asset_id, db, trigger_type=trigger_type
            )
            succeeded += 1
        except Exception as exc:
            failed += 1
            errors.append({"asset_id": asset_id, "error": str(exc)[:500]})
            logger.warning(
                f"[Risk] bulk recalculation failed for asset {asset_id}: {exc}"
            )
        if background:
            await asyncio.sleep(0)

    summary = {
        "total": len(asset_ids),
        "succeeded": succeeded,
        "failed": failed,
        "errors": errors,
    }
    logger.info(
        "Bulk risk recalculation finished: %d/%d succeeded",
        succeeded, len(asset_ids),
    )
    return summary


def get_risk_summary(db: Session) -> dict:
    """Aggregate stats for the risk dashboard overview."""
    total_scored = db.query(func.count(AssetRiskScore.id)).scalar() or 0
    total_active_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.status == StatusEnum.ACTIVE)
        .scalar()
    ) or 0

    by_level = {
        "informational": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
    }
    for level, count in (
        db.query(AssetRiskScore.risk_level, func.count(AssetRiskScore.id))
        .group_by(AssetRiskScore.risk_level)
        .all()
    ):
        if level in by_level:
            by_level[level] = count

    avg_score = db.query(func.avg(AssetRiskScore.final_risk_score)).scalar()
    max_score = db.query(func.max(AssetRiskScore.final_risk_score)).scalar()
    incomplete_count = (
        db.query(func.count(AssetRiskScore.id))
        .filter(AssetRiskScore.incomplete_data.is_(True))
        .scalar()
    ) or 0
    last_calculated_at = db.query(func.max(AssetRiskScore.calculated_at)).scalar()

    top_risky = (
        db.query(AssetRiskScore, Asset.asset_name)
        .join(Asset, Asset.id == AssetRiskScore.asset_id)
        .order_by(AssetRiskScore.final_risk_score.desc())
        .limit(10)
        .all()
    )

    return {
        "total_active_assets": total_active_assets,
        "total_scored_assets": total_scored,
        "unscored_assets": max(0, total_active_assets - total_scored),
        "by_risk_level": by_level,
        "average_risk_score": round(float(avg_score), 2) if avg_score is not None else None,
        "max_risk_score": float(max_score) if max_score is not None else None,
        "incomplete_data_count": incomplete_count,
        "last_calculated_at": (
            last_calculated_at.isoformat() if last_calculated_at else None
        ),
        "top_risky_assets": [
            {
                "asset_id": score.asset_id,
                "asset_name": name,
                "final_risk_score": float(score.final_risk_score)
                if score.final_risk_score is not None else None,
                "risk_level": score.risk_level,
                "incomplete_data": score.incomplete_data,
                "calculated_at": score.calculated_at.isoformat()
                if score.calculated_at else None,
            }
            for score, name in top_risky
        ],
    }
