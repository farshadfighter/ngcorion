"""
SQL Server Audit Service Layer

Orchestrates the end-to-end SQL Server CIS audit workflow:
  1. Resolve asset → target IP
  2. Create an AuditSession record (status: running)
  3. Connect to SQL Server, collect audit data via T-SQL queries
  4. Redact sensitive values from the dump
  5. Evaluate CIS rules against the dump
  6. Update session with compliance metrics
  7. Bulk-insert individual AuditResult rows
"""

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import AuditResult, AuditSession, Asset
from app.models.audit import CheckStatus, DeviceType

from .mssql_client import MSSQLClient, redact_sensitive_mssql_data
from .rules import (
    MSSQLCISRule,
    build_mssql_cis_rules_for_distro,
    _detect_distro,
    evaluate_compliance,
    filter_rules_by_profile,
)

logger = logging.getLogger(__name__)


# ============================================================ #
#  Custom exceptions                                            #
# ============================================================ #

class MSSQLAuditError(Exception):
    """Base exception for SQL Server audit errors."""


class MSSQLAuditConnectionError(MSSQLAuditError):
    """SQL Server connection failure."""


class MSSQLAuditValidationError(MSSQLAuditError):
    """Invalid input before connection is attempted."""


# ============================================================ #
#  Service class                                               #
# ============================================================ #

class MSSQLAuditService:
    """Service for executing and managing SQL Server CIS security audits."""

    CACHE_TTL = 3600   # seconds
    BATCH_SIZE = 100
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    # Class-level rule cache
    _rules_cache: Dict[str, List[MSSQLCISRule]] = {}
    _cache_timestamp: Dict[str, float] = {}

    # ---------------------------------------------------------------- #
    #  Internal helpers                                                 #
    # ---------------------------------------------------------------- #

    @staticmethod
    @contextmanager
    def _timed_op(name: str):
        start = time.time()
        logger.info(f"Starting: {name}")
        try:
            yield
        finally:
            logger.info(f"Completed: {name} ({time.time() - start:.2f}s)")

    @staticmethod
    def _get_cached_rules(profile: str, distro: str = "mssql_2022") -> List[MSSQLCISRule]:
        cache_key = f"{distro}_{profile}"
        now = time.time()

        if cache_key in MSSQLAuditService._rules_cache:
            age = now - MSSQLAuditService._cache_timestamp.get(cache_key, 0)
            if age < MSSQLAuditService.CACHE_TTL:
                logger.debug(f"Using cached MSSQL rules for {cache_key} (age {age:.0f}s)")
                return MSSQLAuditService._rules_cache[cache_key]

        logger.info(f"Building SQL Server CIS rules for {distro} profile={profile}")
        all_rules = build_mssql_cis_rules_for_distro(distro)
        filtered = filter_rules_by_profile(all_rules, profile)
        MSSQLAuditService._rules_cache[cache_key] = filtered
        MSSQLAuditService._cache_timestamp[cache_key] = now
        logger.info(f"Cached {len(filtered)} MSSQL rules for {cache_key}")
        return filtered

    @staticmethod
    def _bulk_insert_results(
        db: Session,
        session_id: int,
        findings: List[Dict],
        batch_size: int = None,
    ) -> None:
        batch_size = batch_size or MSSQLAuditService.BATCH_SIZE
        batch = []

        for finding in findings:
            # Manual controls are stored as NOT_APPLICABLE (surfaced as
            # "skipped" by the API); they are never scored as pass/fail.
            if finding.get("manual"):
                status = CheckStatus.NOT_APPLICABLE
            elif finding["compliant"]:
                status = CheckStatus.PASS
            else:
                status = CheckStatus.FAIL
            result = AuditResult(
                session_id=session_id,
                check_number=finding["id"],
                check_title=finding["title"],
                severity=finding["severity"],
                level=finding.get("level", "L1"),
                status=status,
                evidence_snippet=finding["evidence"],
                checked_at=datetime.now(timezone.utc),
            )
            batch.append(result)

            if len(batch) >= batch_size:
                db.bulk_save_objects(batch)
                db.commit()
                batch = []

        if batch:
            db.bulk_save_objects(batch)
            db.commit()

        logger.info(f"Inserted {len(findings)} audit results for session {session_id}")

    @staticmethod
    def _sanitize_error(exc: Exception) -> str:
        msg = str(exc)
        if any(kw in msg.lower() for kw in ("password", "secret", "token", "login failed")):
            return f"{type(exc).__name__}: Authentication or connection error"
        return f"{type(exc).__name__}: {msg}"[:500]

    # ---------------------------------------------------------------- #
    #  Primary audit execution                                          #
    # ---------------------------------------------------------------- #

    @staticmethod
    def execute_mssql_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        mssql_username: str,
        mssql_password: str,
        mssql_port: int = 1433,
        profile: str = "L1",
        job_name: Optional[str] = None,
    ) -> AuditSession:
        """
        Execute a CIS SQL Server compliance audit.

        Args:
            db:               PostgreSQL session (SQLAlchemy)
            asset_id:         Asset record that hosts the SQL Server instance
            user_id:          Authenticated user performing the audit
            mssql_username:   SQL Server login (sa or sysadmin, not stored)
            mssql_password:   SQL Server password (not stored)
            mssql_port:       SQL Server TCP port (default 1433)
            profile:          CIS profile – "L1" or "FULL"
            job_name:         Optional human-readable label for this audit run

        Returns:
            AuditSession with status="completed" and compliance metrics set.

        Raises:
            ValueError:  Asset not found or has no IP address.
            Exception:   Connection / rule evaluation failure.
        """
        # 1. Resolve asset
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(
                f"Asset '{asset.asset_name}' has no IP address configured"
            )
        target_ip = asset.ip_address

        # 2. Create session
        session = AuditSession(
            template_id=None,
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.MSSQL,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. Connect to SQL Server and collect data
            with MSSQLAuditService._timed_op("SQL Server connect & collect audit data"):
                with MSSQLClient(
                    ip=target_ip,
                    username=mssql_username,
                    password=mssql_password,
                    port=mssql_port,
                ) as client:
                    raw_dump = client.collect_audit_data()

            # 4. Redact sensitive values
            clean_dump = redact_sensitive_mssql_data(raw_dump)

            # 5. Resolve the SQL Server version to a distro gate key and load
            #    the matching (2016/2019/2022) rule set.
            distro = _detect_distro(clean_dump)
            logger.info(f"Resolved SQL Server dump to {distro} for asset {asset_id}")
            rules = MSSQLAuditService._get_cached_rules(profile, distro)

            # 6. Evaluate compliance
            with MSSQLAuditService._timed_op(
                f"Evaluate {len(rules)} MSSQL CIS rules"
            ):
                report = evaluate_compliance(clean_dump, rules)

            summary = report["summary"]

            # 7. Persist session metrics
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = summary["total_rules_scored"]
            session.passed_checks = summary["passed_scored"]
            session.failed_checks = summary["failed_scored"]
            session.error_checks = 0
            session.compliance_pct = summary["compliance_pct"]
            session.weighted_compliance_pct = summary["weighted_compliance_pct"]
            session.turbo_dump = clean_dump[:100000]  # Limit size (matches Apache/Linux)
            db.commit()

            # 8. Persist individual check results
            with MSSQLAuditService._timed_op("Bulk insert audit results"):
                MSSQLAuditService._bulk_insert_results(
                    db, session.id, report["findings"]
                )

            db.refresh(session)
            logger.info(
                f"SQL Server audit completed for asset {asset_id} ({target_ip}): "
                f"{summary['compliance_pct']}% compliance"
            )
            return session

        except Exception as exc:
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)
            session.connection_error = MSSQLAuditService._sanitize_error(exc)
            db.commit()
            db.refresh(session)
            logger.error(
                f"SQL Server audit failed for asset {asset_id}: {type(exc).__name__}"
            )
            raise

    # ---------------------------------------------------------------- #
    #  Query helpers                                                    #
    # ---------------------------------------------------------------- #

    @staticmethod
    def get_audit_session(db: Session, session_id: int) -> Optional[AuditSession]:
        return db.query(AuditSession).filter(AuditSession.id == session_id).first()

    @staticmethod
    def get_audit_results(db: Session, session_id: int) -> List[AuditResult]:
        return (
            db.query(AuditResult)
            .filter(AuditResult.session_id == session_id)
            .all()
        )

    @staticmethod
    def get_all_sessions(
        db: Session, limit: int = 50, offset: int = 0
    ) -> List[AuditSession]:
        return (
            db.query(AuditSession)
            .filter(AuditSession.device_type == DeviceType.MSSQL)
            .order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_sessions_count(db: Session) -> int:
        return (
            db.query(AuditSession)
            .filter(AuditSession.device_type == DeviceType.MSSQL)
            .count()
        )

    @staticmethod
    def get_asset_audit_history(
        db: Session, asset_id: int, limit: int = 10
    ) -> List[AuditSession]:
        return (
            db.query(AuditSession)
            .filter(
                AuditSession.asset_id == asset_id,
                AuditSession.device_type == DeviceType.MSSQL,
            )
            .order_by(AuditSession.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_session_summary(
        db: Session, session_id: int
    ) -> Optional[Dict[str, Any]]:
        """Return a JSON-serialisable summary of a single audit session."""
        session = MSSQLAuditService.get_audit_session(db, session_id)
        if not session:
            return None

        asset = (
            db.query(Asset).filter(Asset.id == session.asset_id).first()
            if session.asset_id
            else None
        )
        results = MSSQLAuditService.get_audit_results(db, session_id)

        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        errors = sum(1 for r in results if r.status == CheckStatus.ERROR)

        return {
            "session_id": session.id,
            "job_name": session.job_name,
            "asset_id": session.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "target_ip": session.target_ip,
            "device_type": session.device_type.value,
            "status": session.status,
            "started_at": (
                session.started_at.isoformat() if session.started_at else None
            ),
            "completed_at": (
                session.completed_at.isoformat() if session.completed_at else None
            ),
            "duration_seconds": (
                (session.completed_at - session.started_at).total_seconds()
                if session.completed_at and session.started_at
                else None
            ),
            "compliance": {
                "total_checks": session.total_checks,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "compliance_pct": session.compliance_pct,
                "weighted_compliance_pct": session.weighted_compliance_pct,
            },
            "connection_error": session.connection_error,
        }

    @staticmethod
    def delete_audit_session(db: Session, session_id: int) -> bool:
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Audit session {session_id} not found")
        db.delete(session)
        db.commit()
        return True
