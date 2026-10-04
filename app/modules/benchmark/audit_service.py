"""
The audit run of a benchmark module.

Same workflow as the Windows module: resolve the asset, open a session
(running), connect and collect, redact, pick the rules for what was found,
evaluate, store the results, then mark the session completed in one commit.
Software inventory and the risk score are refreshed afterwards and never fail
the audit.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.database import ensure_session_usable
from app.models import Asset, AuditResult, AuditSession
from app.models.audit import CheckStatus

from .connectors import get_connector
from .rules import evaluate, filter_by_profile
from .spec import ModuleSpec

logger = logging.getLogger(__name__)

BATCH_SIZE = 100


def _sanitize_error(exc: Exception) -> str:
    msg = str(exc)
    if any(kw in msg.lower() for kw in ("password", "secret", "token", "login failed")):
        return f"{type(exc).__name__}: Authentication or connection error"
    return f"{type(exc).__name__}: {msg}"[:500]


def _status_for(finding: Dict[str, Any]) -> CheckStatus:
    if finding.get("manual"):
        return CheckStatus.NOT_APPLICABLE
    if finding.get("error"):
        return CheckStatus.ERROR
    return CheckStatus.PASS if finding["compliant"] else CheckStatus.FAIL


class BenchmarkAuditService:
    def __init__(self, spec: ModuleSpec):
        self.spec = spec

    # ── run ────────────────────────────────────────────────────────────────

    def execute(self, db: Session, asset_id: int, user_id: int, credentials: Dict[str, Any],
                profile: str = "FULL", job_name: Optional[str] = None) -> AuditSession:
        spec = self.spec
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        session = AuditSession(
            template_id=None, user_id=user_id, asset_id=asset_id,
            target_ip=asset.ip_address, device_type=spec.device_type,
            job_name=job_name, status="running", started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            software_raw = None
            with get_connector(spec.connector).open(asset.ip_address, credentials) as conn:
                raw_dump = spec.collect(conn)
                if spec.collect_software:
                    try:
                        software_raw = spec.collect_software(conn)
                    except Exception as exc:  # noqa: BLE001 - never fails the audit
                        logger.warning("[%s] software collection failed: %s", spec.key, type(exc).__name__)

            dump = spec.redact(raw_dump)
            rules = filter_by_profile(spec.rules_for(dump), profile)
            if spec.describe:
                try:
                    logger.info("%s audit of asset %s: %s, %d rules", spec.label, asset_id,
                                spec.describe(dump), len(rules))
                except Exception:  # noqa: BLE001
                    pass
            report = evaluate(dump, rules, spec.json_sections)
            summary = report["summary"]

            self._insert_results(db, session.id, report["findings"])

            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = summary["total_rules_scored"]
            session.passed_checks = summary["passed_scored"]
            session.failed_checks = summary["failed_scored"]
            session.error_checks = summary["error_checks"]
            session.compliance_pct = summary["compliance_pct"]
            session.weighted_compliance_pct = summary["weighted_compliance_pct"]
            session.turbo_dump = dump[:100000]
            db.commit()
            db.refresh(session)
            logger.info(
                "%s audit completed for asset %s (%s): %s%% (%s/%s scored, %s not evaluated, %s manual)",
                spec.label, asset_id, asset.ip_address, summary["compliance_pct"],
                summary["passed_scored"], summary["total_rules_scored"],
                summary["error_checks"], summary["manual_checks"])

            if spec.save_software and software_raw is not None:
                spec.save_software(db, asset_id, software_raw, audit_session_id=session.id, user_id=user_id)

            try:
                from app.modules.risk.service import risk_calculation_service
                risk_calculation_service.calculate(asset_id=asset_id, db=db, trigger_type="audit_completed",
                                                   trigger_reference_id=session.id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[Risk] recalculation after %s audit failed for asset %s: %s",
                               spec.label, asset_id, exc)
            return session

        except Exception as exc:
            ensure_session_usable(db)
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)
            session.connection_error = _sanitize_error(exc)
            db.commit()
            db.refresh(session)
            logger.error("%s audit failed for asset %s: %s", spec.label, asset_id, type(exc).__name__)
            raise

    @staticmethod
    def _insert_results(db: Session, session_id: int, findings: List[Dict[str, Any]]) -> None:
        batch = []
        now = datetime.now(timezone.utc)
        for f in findings:
            batch.append(AuditResult(
                session_id=session_id, check_number=f["id"], check_title=f["title"][:500],
                severity=f["severity"], level=f.get("level", "L1"), status=_status_for(f),
                evidence_snippet=f["evidence"], checked_at=now,
            ))
            if len(batch) >= BATCH_SIZE:
                db.bulk_save_objects(batch)
                db.commit()
                batch = []
        if batch:
            db.bulk_save_objects(batch)
            db.commit()

    # ── queries ────────────────────────────────────────────────────────────

    def _query(self, db: Session, owner_id: Optional[int] = None):
        q = db.query(AuditSession).filter(AuditSession.device_type == self.spec.device_type)
        if owner_id is not None:
            q = q.filter(AuditSession.user_id == owner_id)
        return q

    def get_session(self, db: Session, session_id: int) -> Optional[AuditSession]:
        return db.query(AuditSession).filter(AuditSession.id == session_id).first()

    def get_results(self, db: Session, session_id: int) -> List[AuditResult]:
        # Insertion order is the module's rule order (sections ascending).
        return (db.query(AuditResult).filter(AuditResult.session_id == session_id)
                .order_by(AuditResult.id).all())

    def list_sessions(self, db: Session, limit: int, offset: int, owner_id: Optional[int] = None):
        return (self._query(db, owner_id).order_by(AuditSession.started_at.desc())
                .offset(offset).limit(limit).all())

    def count(self, db: Session, owner_id: Optional[int] = None) -> int:
        return self._query(db, owner_id).count()

    def asset_history(self, db: Session, asset_id: int, limit: int, owner_id: Optional[int] = None):
        return (self._query(db, owner_id).filter(AuditSession.asset_id == asset_id)
                .order_by(AuditSession.started_at.desc()).limit(limit).all())

    def summary(self, db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        session = self.get_session(db, session_id)
        if not session:
            return None
        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
        results = self.get_results(db, session_id)
        return {
            "session_id": session.id,
            "job_name": session.job_name,
            "asset_id": session.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "target_ip": session.target_ip,
            "device_type": session.device_type.value,
            "status": session.status,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "duration_seconds": ((session.completed_at - session.started_at).total_seconds()
                                 if session.completed_at and session.started_at else None),
            "compliance": {
                "total_checks": session.total_checks,
                "passed": sum(1 for r in results if r.status == CheckStatus.PASS),
                "failed": sum(1 for r in results if r.status == CheckStatus.FAIL),
                "errors": sum(1 for r in results if r.status == CheckStatus.ERROR),
                "compliance_pct": session.compliance_pct,
                "weighted_compliance_pct": session.weighted_compliance_pct,
            },
            "connection_error": session.connection_error,
        }

    def delete(self, db: Session, session_id: int) -> None:
        session = self.get_session(db, session_id)
        if not session:
            raise ValueError(f"Audit session {session_id} not found")
        db.delete(session)
        db.commit()
