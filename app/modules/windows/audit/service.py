"""
Windows Server Audit Service Layer

Orchestrates the end-to-end Windows Server CIS audit workflow:
  1. Resolve asset → target IP
  2. Create an AuditSession record (status: running)
  3. Connect to Windows Server via WinRM, collect audit data
  4. Redact sensitive values from the dump
  5. Detect OS version and filter rules
  6. Evaluate CIS rules against the dump
  7. Bulk-insert individual AuditResult rows
  8. Update session with compliance metrics (one commit marks it completed)
"""

import logging
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import ensure_session_usable
from app.models import AuditResult, AuditSession, Asset
from app.models.audit import CheckStatus, DeviceType
from app.modules.windows.winrm_endpoint import DEFAULT_WINRM_PORT

from .winrm_client import WindowsWinRMClient, redact_sensitive_windows_data
from .rules import (
    WindowsCISRule,
    build_windows_cis_rules_for_version,
    evaluate_compliance,
    filter_rules_by_profile,
    filter_rules_by_scope,
    is_domain_controller,
    _detect_gate,
    _detect_version,
)

logger = logging.getLogger(__name__)


# ============================================================ #
#  Custom exceptions                                            #
# ============================================================ #

class WindowsAuditError(Exception):
    """Base exception for Windows Server audit errors."""


class WindowsAuditConnectionError(WindowsAuditError):
    """WinRM connection failure."""


class WindowsAuditValidationError(WindowsAuditError):
    """Invalid input before connection is attempted."""


# ============================================================ #
#  Service class                                               #
# ============================================================ #

class WindowsAuditService:
    """Service for executing and managing Windows Server CIS security audits."""

    CACHE_TTL = 3600   # seconds
    BATCH_SIZE = 100
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    # Class-level rule cache
    _rules_cache: Dict[str, List[WindowsCISRule]] = {}
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
    def _get_cached_rules(
        profile: str, gate: str = "win_2025", is_dc: bool = False
    ) -> List[WindowsCISRule]:
        role = "DC" if is_dc else "MS"
        cache_key = f"{gate}_{profile}_{role}"
        now = time.time()

        if cache_key in WindowsAuditService._rules_cache:
            age = now - WindowsAuditService._cache_timestamp.get(cache_key, 0)
            if age < WindowsAuditService.CACHE_TTL:
                logger.debug(f"Using cached Windows rules for {cache_key} (age {age:.0f}s)")
                return WindowsAuditService._rules_cache[cache_key]

        logger.info(f"Building Windows CIS rules for {gate} profile={profile} role={role}")
        rules = build_windows_cis_rules_for_version(gate)
        rules = filter_rules_by_profile(rules, profile)
        rules = filter_rules_by_scope(rules, is_dc)
        WindowsAuditService._rules_cache[cache_key] = rules
        WindowsAuditService._cache_timestamp[cache_key] = now
        logger.info(f"Cached {len(rules)} Windows rules for {cache_key}")
        return rules

    @staticmethod
    def _bulk_insert_results(
        db: Session,
        session_id: int,
        findings: List[Dict],
        batch_size: int = None,
    ) -> None:
        batch_size = batch_size or WindowsAuditService.BATCH_SIZE
        batch = []

        for finding in findings:
            # Manual controls are stored as NOT_APPLICABLE (surfaced as
            # "skipped" by the API); they are never scored as pass/fail.
            # Checks whose data never came back are stored as ERROR — scoring
            # them either way would be a guess.
            if finding.get("manual"):
                status = CheckStatus.NOT_APPLICABLE
            elif finding.get("error"):
                status = CheckStatus.ERROR
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
    def execute_windows_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        windows_username: str,
        windows_password: str,
        winrm_port: int = DEFAULT_WINRM_PORT,
        transport: str = "ntlm",
        profile: str = "L1",
        job_name: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ) -> AuditSession:
        """
        Execute a CIS Windows Server compliance audit.

        Args:
            db:                PostgreSQL session (SQLAlchemy)
            asset_id:          Asset record that hosts the Windows Server
            user_id:           Authenticated user performing the audit
            windows_username:  Windows admin account (domain\\user or local)
            windows_password:  Windows password (not stored)
            winrm_port:        WinRM listener port (default 5985/HTTP; 5986 is HTTPS)
            transport:         WinRM transport: ntlm, kerberos, credssp, basic
            profile:           CIS profile – "L1" or "FULL"
            job_name:          Optional human-readable label for this audit run
            verify_ssl:        Validate the WinRM TLS certificate; None uses
                               settings.WINRM_VERIFY_SSL

        Returns:
            AuditSession with status="completed" and compliance metrics set.
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
        if verify_ssl is None:
            verify_ssl = settings.WINRM_VERIFY_SSL

        # 2. Create session
        session = AuditSession(
            template_id=None,
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.WINDOWS,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. Connect to Windows Server and collect data
            with WindowsAuditService._timed_op("WinRM connect & collect audit data"):
                with WindowsWinRMClient(
                    ip=target_ip,
                    username=windows_username,
                    password=windows_password,
                    port=winrm_port,
                    transport=transport,
                    verify_ssl=verify_ssl,
                ) as client:
                    raw_dump = client.collect_audit_data()

            # 4. Redact sensitive values
            clean_dump = redact_sensitive_windows_data(raw_dump)

            # 5. Resolve the OS build to a version gate key + detect the host
            #    role (member server vs domain controller) and load the matching
            #    rule set.
            gate = _detect_gate(clean_dump)
            is_dc = is_domain_controller(clean_dump)
            logger.info(
                f"Resolved Windows dump to {gate} "
                f"(v{_detect_version(clean_dump)}, {'DC' if is_dc else 'member server'})"
            )
            rules = WindowsAuditService._get_cached_rules(profile, gate, is_dc)

            # 6. Evaluate compliance
            with WindowsAuditService._timed_op(
                f"Evaluate {len(rules)} Windows CIS rules"
            ):
                report = evaluate_compliance(clean_dump, rules)

            summary = report["summary"]

            # 7. Persist individual check results *before* the session is
            #    marked completed: a failure here must not leave a "completed"
            #    session whose counters have no rows behind them.
            with WindowsAuditService._timed_op("Bulk insert audit results"):
                WindowsAuditService._bulk_insert_results(
                    db, session.id, report["findings"]
                )

            # 8. Persist session metrics (the commit that marks it completed)
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = summary["total_rules_scored"]
            session.passed_checks = summary["passed_scored"]
            session.failed_checks = summary["failed_scored"]
            # Checks that could not be evaluated (a section failed to collect).
            session.error_checks = summary["error_checks"]
            session.compliance_pct = summary["compliance_pct"]
            session.weighted_compliance_pct = summary["weighted_compliance_pct"]
            session.turbo_dump = clean_dump[:100000]  # Limit size (matches Apache/Linux)
            db.commit()

            db.refresh(session)
            logger.info(
                f"Windows audit completed for asset {asset_id} ({target_ip}): "
                f"{summary['compliance_pct']}% compliance "
                f"({summary['passed_scored']}/{summary['total_rules_scored']} scored, "
                f"{summary['error_checks']} not evaluated, "
                f"{summary['manual_checks']} manual)"
            )
            if summary["error_checks"]:
                logger.warning(
                    f"Windows audit for asset {asset_id} could not evaluate "
                    f"{summary['error_checks']} checks — some data did not "
                    "collect; compliance is computed over the rest"
                )

            # Risk recalculation trigger
            try:
                from app.modules.risk.service import risk_calculation_service
                if asset_id:
                    risk_calculation_service.calculate(
                        asset_id=asset_id,
                        db=db,
                        trigger_type="audit_completed",
                        trigger_reference_id=session.id,
                    )
            except Exception as e:
                # never block the audit flow
                logger.warning(
                    "[Risk] risk recalculation after Windows audit failed for asset "
                    f"{asset_id}: {e}"
                )

            return session

        except Exception as exc:
            # A DB-layer failure (e.g. an over-long value) leaves the
            # transaction doomed: without this rollback the commit below raises
            # PendingRollbackError, replacing the real error and leaving the
            # session stuck at "running".
            ensure_session_usable(db)
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)
            session.connection_error = WindowsAuditService._sanitize_error(exc)
            db.commit()
            db.refresh(session)
            logger.error(
                f"Windows audit failed for asset {asset_id}: {type(exc).__name__}"
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
        db: Session,
        limit: int = 50,
        offset: int = 0,
        owner_id: Optional[int] = None,
    ) -> List[AuditSession]:
        """``owner_id`` restricts the listing to one user's sessions (None = all,
        for admins). See app.core.dependencies.owner_scope."""
        query = db.query(AuditSession).filter(
            AuditSession.device_type == DeviceType.WINDOWS
        )
        if owner_id is not None:
            query = query.filter(AuditSession.user_id == owner_id)
        return (
            query
            .order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_sessions_count(db: Session, owner_id: Optional[int] = None) -> int:
        query = db.query(AuditSession).filter(
            AuditSession.device_type == DeviceType.WINDOWS
        )
        if owner_id is not None:
            query = query.filter(AuditSession.user_id == owner_id)
        return query.count()

    @staticmethod
    def get_asset_audit_history(
        db: Session,
        asset_id: int,
        limit: int = 10,
        owner_id: Optional[int] = None,
    ) -> List[AuditSession]:
        query = db.query(AuditSession).filter(
            AuditSession.asset_id == asset_id,
            AuditSession.device_type == DeviceType.WINDOWS,
        )
        if owner_id is not None:
            query = query.filter(AuditSession.user_id == owner_id)
        return (
            query
            .order_by(AuditSession.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_session_summary(
        db: Session, session_id: int
    ) -> Optional[Dict[str, Any]]:
        """Return a JSON-serialisable summary of a single audit session."""
        session = WindowsAuditService.get_audit_session(db, session_id)
        if not session:
            return None

        asset = (
            db.query(Asset).filter(Asset.id == session.asset_id).first()
            if session.asset_id
            else None
        )
        results = WindowsAuditService.get_audit_results(db, session_id)

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
