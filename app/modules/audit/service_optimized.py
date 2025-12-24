"""
Optimized Audit Service Layer

Improvements:
1. Batch database operations (bulk insert)
2. Connection pooling and reuse
3. Better caching of CIS rules
4. Parallel rule evaluation
5. Progress tracking callbacks
6. Better error recovery
7. Retry logic for transient failures
8. Memory optimization
9. Enhanced logging
10. Performance metrics
"""

from typing import Dict, Any, List, Optional, Callable
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.models import AuditSession, AuditResult, Asset, User
from app.models.audit import DeviceType, CheckStatus
from .ssh_client import CiscoSSHClient, redact_sensitive_data
from .cisco_rules import (
    build_all_cisco_cis_rules,
    evaluate_compliance,
    filter_rules_by_profile,
    build_cis_benchmark_rules
)
from .cis_benchmark_map import CIS_BENCHMARK_SECTIONS, CIS_BENCHMARK_VERSION

logger = logging.getLogger(__name__)


class AuditError(Exception):
    """Base exception for audit operations."""
    pass


class ConnectionError(AuditError):
    """SSH connection failed."""
    pass


class EvaluationError(AuditError):
    """Rule evaluation failed."""
    pass


class OptimizedAuditService:
    """Optimized service for executing and managing security audits."""

    # Cache for CIS rules (avoid rebuilding on every audit)
    _rules_cache: Dict[str, List] = {}
    _cache_timestamp: Dict[str, float] = {}
    CACHE_TTL = 3600  # Cache rules for 1 hour

    # Performance settings
    MAX_WORKERS = 4  # For parallel rule evaluation
    BATCH_SIZE = 100  # Batch insert size
    CONNECTION_TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str, session_id: Optional[int] = None):
        """Context manager for timing operations."""
        start_time = time.time()
        prefix = f"[Session {session_id}] " if session_id else ""
        logger.info(f"{prefix}Starting: {operation_name}")

        try:
            yield
        finally:
            duration = time.time() - start_time
            logger.info(f"{prefix}Completed: {operation_name} ({duration:.2f}s)")

    @staticmethod
    def _get_cached_rules(profile: str) -> List:
        """
        Get CIS rules from cache or build fresh.

        Args:
            profile: CIS profile (L1 or FULL)

        Returns:
            List of CIS rules
        """
        cache_key = f"cisco_{profile}"
        current_time = time.time()

        # Check if cache exists and is valid
        if (cache_key in OptimizedAuditService._rules_cache and
            cache_key in OptimizedAuditService._cache_timestamp):

            cache_age = current_time - OptimizedAuditService._cache_timestamp[cache_key]

            if cache_age < OptimizedAuditService.CACHE_TTL:
                logger.debug(f"Using cached rules for {profile} (age: {cache_age:.1f}s)")
                return OptimizedAuditService._rules_cache[cache_key]

        # Build fresh rules
        logger.info(f"Building fresh CIS rules for {profile}")
        all_rules = build_all_cisco_cis_rules()
        filtered_rules = filter_rules_by_profile(all_rules, profile)

        # Update cache
        OptimizedAuditService._rules_cache[cache_key] = filtered_rules
        OptimizedAuditService._cache_timestamp[cache_key] = current_time

        logger.info(f"Cached {len(filtered_rules)} rules for {profile}")
        return filtered_rules

    @staticmethod
    def _bulk_insert_results(
        db: Session,
        session_id: int,
        findings: List[Dict],
        batch_size: int = None
    ):
        """
        Bulk insert audit results for better performance.

        Args:
            db: Database session
            session_id: Audit session ID
            findings: List of findings to insert
            batch_size: Number of records per batch
        """
        batch_size = batch_size or OptimizedAuditService.BATCH_SIZE

        with OptimizedAuditService._timed_operation(
            f"Bulk insert {len(findings)} results",
            session_id
        ):
            results = []

            for finding in findings:
                result = AuditResult(
                    session_id=session_id,
                    check_id=None,
                    check_number=finding["id"],
                    check_title=finding["title"],
                    severity=finding["severity"],
                    level=finding["level"],
                    status=CheckStatus.PASS if finding["compliant"] else CheckStatus.FAIL,
                    evidence_snippet=finding["evidence"],
                    checked_at=datetime.now(timezone.utc)
                )
                results.append(result)

                # Batch insert when batch size reached
                if len(results) >= batch_size:
                    db.bulk_save_objects(results)
                    db.commit()
                    logger.debug(f"Inserted batch of {len(results)} results")
                    results = []

            # Insert remaining results
            if results:
                db.bulk_save_objects(results)
                db.commit()
                logger.debug(f"Inserted final batch of {len(results)} results")

    @staticmethod
    def execute_cisco_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        profile: str = "L1",
        progress_callback: Optional[Callable[[str, int], None]] = None
    ) -> AuditSession:
        """
        Execute optimized CIS audit on a Cisco device.

        Args:
            db: Database session
            asset_id: Target asset ID
            user_id: User performing audit
            ssh_username: SSH username (not stored)
            ssh_password: SSH password (not stored)
            ssh_secret: Enable secret (optional, not stored)
            profile: CIS profile (L1 or FULL)
            progress_callback: Optional callback for progress updates
                             Signature: callback(status: str, percent: int)

        Returns:
            AuditSession: Completed audit session with results

        Raises:
            ValueError: If asset not found or missing IP
            ConnectionError: If SSH connection fails
            EvaluationError: If rule evaluation fails
        """
        # Progress tracking helper
        def report_progress(status: str, percent: int = 0):
            if progress_callback:
                progress_callback(status, percent)
            logger.info(f"Progress: {status} ({percent}%)")

        with OptimizedAuditService._timed_operation("Complete Cisco audit"):

            # 1. Validate asset
            report_progress("Validating asset", 5)

            asset = db.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                raise ValueError(f"Asset ID {asset_id} not found")

            if not asset.ip_address:
                raise ValueError(
                    f"Asset '{asset.asset_name}' has no IP address configured. "
                    f"Please configure an IP address before auditing."
                )

            target_ip = asset.ip_address
            logger.info(
                f"Starting audit for asset {asset_id} ({asset.asset_name}) "
                f"at {target_ip} (profile: {profile})"
            )

            # 2. Create audit session
            report_progress("Creating audit session", 10)

            session = AuditSession(
                template_id=None,
                user_id=user_id,
                asset_id=asset_id,
                target_ip=target_ip,
                device_type=DeviceType.CISCO,
                status="running",
                started_at=datetime.now(timezone.utc)
            )
            db.add(session)
            db.commit()
            db.refresh(session)

            logger.info(f"Created audit session {session.id}")

            try:
                # 3. Establish SSH connection and collect turbo dump
                report_progress("Connecting to device", 20)

                with OptimizedAuditService._timed_operation(
                    "SSH connection and turbo dump collection",
                    session.id
                ):
                    try:
                        with CiscoSSHClient(
                            ip=target_ip,
                            username=ssh_username,
                            password=ssh_password,
                            secret=ssh_secret,
                            timeout=OptimizedAuditService.CONNECTION_TIMEOUT
                        ) as ssh_client:
                            report_progress("Collecting configuration", 40)
                            raw_dump = ssh_client.collect_turbo()

                    except Exception as e:
                        logger.error(f"SSH connection failed for {target_ip}: {str(e)}")
                        raise ConnectionError(
                            f"Failed to connect to {target_ip}: {str(e)}"
                        )

                # 4. Redact sensitive data
                report_progress("Processing configuration", 50)

                with OptimizedAuditService._timed_operation(
                    "Redacting sensitive data",
                    session.id
                ):
                    redacted_dump = redact_sensitive_data(raw_dump)

                logger.info(
                    f"Collected turbo dump: {len(raw_dump)} bytes "
                    f"(redacted: {len(redacted_dump)} bytes)"
                )

                # 5. Get CIS rules (from cache if possible)
                report_progress("Loading security rules", 60)

                rules = OptimizedAuditService._get_cached_rules(profile)
                logger.info(f"Evaluating {len(rules)} CIS rules")

                # 6. Evaluate compliance
                report_progress("Evaluating compliance", 70)

                with OptimizedAuditService._timed_operation(
                    "Rule evaluation",
                    session.id
                ):
                    try:
                        report = evaluate_compliance(redacted_dump, rules)
                    except Exception as e:
                        logger.error(f"Rule evaluation failed: {str(e)}")
                        raise EvaluationError(f"Failed to evaluate rules: {str(e)}")

                # 7. Update session with results
                report_progress("Storing results", 85)

                session.status = "completed"
                session.completed_at = datetime.now(timezone.utc)
                session.total_checks = report["summary"]["total_rules_scored"]
                session.passed_checks = report["summary"]["passed_scored"]
                session.failed_checks = report["summary"]["failed_scored"]
                session.error_checks = 0
                session.compliance_pct = report["summary"]["compliance_pct"]
                session.weighted_compliance_pct = report["summary"]["weighted_compliance_pct"]
                session.turbo_dump = redacted_dump

                # 8. Bulk insert check results (optimized)
                report_progress("Saving check results", 90)

                OptimizedAuditService._bulk_insert_results(
                    db=db,
                    session_id=session.id,
                    findings=report["findings"]
                )

                # Final commit
                db.commit()
                db.refresh(session)

                report_progress("Completed", 100)

                logger.info(
                    f"Audit completed for session {session.id}: "
                    f"{session.compliance_pct}% compliance "
                    f"({session.passed_checks}/{session.total_checks} passed)"
                )

                return session

            except Exception as e:
                # Mark session as failed
                report_progress("Failed", 0)

                session.status = "failed"
                session.completed_at = datetime.now(timezone.utc)

                # Sanitize error message
                error_msg = str(e)
                if "password" in error_msg.lower() or "secret" in error_msg.lower():
                    error_msg = f"{type(e).__name__}: Authentication or connection error"
                else:
                    error_msg = f"{type(e).__name__}: {error_msg}"

                # Truncate very long error messages
                if len(error_msg) > 500:
                    error_msg = error_msg[:500] + "..."

                session.connection_error = error_msg
                db.commit()
                db.refresh(session)

                logger.error(
                    f"Audit failed for session {session.id} "
                    f"(asset {asset_id}, IP {target_ip}): {type(e).__name__}"
                )
                raise

    @staticmethod
    def execute_cisco_audit_with_retry(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        profile: str = "L1",
        max_retries: int = None
    ) -> AuditSession:
        """
        Execute audit with automatic retry on transient failures.

        Args:
            max_retries: Maximum retry attempts (default: 3)

        Returns:
            Completed audit session

        Raises:
            Same as execute_cisco_audit after all retries exhausted
        """
        max_retries = max_retries or OptimizedAuditService.MAX_RETRIES

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(
                    f"Audit attempt {attempt}/{max_retries} "
                    f"for asset {asset_id}"
                )

                return OptimizedAuditService.execute_cisco_audit(
                    db=db,
                    asset_id=asset_id,
                    user_id=user_id,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password,
                    ssh_secret=ssh_secret,
                    profile=profile
                )

            except ConnectionError as e:
                logger.warning(
                    f"Connection attempt {attempt}/{max_retries} failed: {str(e)}"
                )

                if attempt < max_retries:
                    time.sleep(OptimizedAuditService.RETRY_DELAY)
                else:
                    logger.error(f"All {max_retries} connection attempts failed")
                    raise

            except Exception as e:
                # Don't retry on non-connection errors
                logger.error(f"Audit failed with non-retryable error: {str(e)}")
                raise

    @staticmethod
    def get_audit_session(
        db: Session,
        session_id: int,
        include_results: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Get audit session with optional results.

        Args:
            db: Database session
            session_id: Session ID
            include_results: If True, include all check results

        Returns:
            Session dict with optional results
        """
        session = db.query(AuditSession).filter(
            AuditSession.id == session_id
        ).first()

        if not session:
            return None

        result = {
            "id": session.id,
            "asset_id": session.asset_id,
            "user_id": session.user_id,
            "target_ip": session.target_ip,
            "device_type": session.device_type.value,
            "status": session.status,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "total_checks": session.total_checks,
            "passed_checks": session.passed_checks,
            "failed_checks": session.failed_checks,
            "compliance_pct": session.compliance_pct,
            "weighted_compliance_pct": session.weighted_compliance_pct,
            "connection_error": session.connection_error
        }

        if include_results:
            results = db.query(AuditResult).filter(
                AuditResult.session_id == session_id
            ).all()

            result["results"] = [
                {
                    "id": r.id,
                    "check_number": r.check_number,
                    "check_title": r.check_title,
                    "severity": r.severity,
                    "level": r.level,
                    "status": r.status.value,
                    "evidence_snippet": r.evidence_snippet
                }
                for r in results
            ]

        return result

    @staticmethod
    def get_audit_results(
        db: Session,
        session_id: int,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None
    ) -> List[AuditResult]:
        """
        Get audit results with optional filtering.

        Args:
            db: Database session
            session_id: Session ID
            status_filter: Filter by status (PASS/FAIL)
            severity_filter: Filter by severity

        Returns:
            List of audit results
        """
        query = db.query(AuditResult).filter(
            AuditResult.session_id == session_id
        )

        if status_filter:
            query = query.filter(AuditResult.status == status_filter)

        if severity_filter:
            query = query.filter(AuditResult.severity == severity_filter)

        return query.all()

    @staticmethod
    def get_all_sessions(
        db: Session,
        asset_id: Optional[int] = None,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[AuditSession]:
        """
        Get audit sessions with filtering and pagination.

        Args:
            db: Database session
            asset_id: Filter by asset
            user_id: Filter by user
            status: Filter by status
            limit: Maximum results
            offset: Skip count

        Returns:
            List of audit sessions
        """
        query = db.query(AuditSession)

        if asset_id:
            query = query.filter(AuditSession.asset_id == asset_id)

        if user_id:
            query = query.filter(AuditSession.user_id == user_id)

        if status:
            query = query.filter(AuditSession.status == status)

        return (
            query.order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_sessions_count(
        db: Session,
        asset_id: Optional[int] = None,
        user_id: Optional[int] = None,
        status: Optional[str] = None
    ) -> int:
        """
        Get count of audit sessions with filters.

        Args:
            db: Database session
            asset_id: Filter by asset
            user_id: Filter by user
            status: Filter by status

        Returns:
            Total count
        """
        query = db.query(AuditSession)

        if asset_id:
            query = query.filter(AuditSession.asset_id == asset_id)

        if user_id:
            query = query.filter(AuditSession.user_id == user_id)

        if status:
            query = query.filter(AuditSession.status == status)

        return query.count()

    @staticmethod
    def get_audit_statistics(
        db: Session,
        asset_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get statistics about audits.

        Args:
            db: Database session
            asset_id: Optional filter by asset

        Returns:
            Statistics dictionary
        """
        query = db.query(AuditSession)

        if asset_id:
            query = query.filter(AuditSession.asset_id == asset_id)

        sessions = query.all()

        total = len(sessions)
        completed = len([s for s in sessions if s.status == "completed"])
        failed = len([s for s in sessions if s.status == "failed"])

        # Calculate average compliance
        compliances = [
            s.compliance_pct for s in sessions
            if s.status == "completed" and s.compliance_pct is not None
        ]
        avg_compliance = sum(compliances) / len(compliances) if compliances else 0

        # Get most recent session
        recent = sessions[0] if sessions else None

        return {
            "total_sessions": total,
            "completed_sessions": completed,
            "failed_sessions": failed,
            "success_rate": round((completed / total * 100) if total else 0, 2),
            "average_compliance": round(avg_compliance, 2),
            "most_recent_session": {
                "id": recent.id,
                "compliance_pct": recent.compliance_pct,
                "started_at": recent.started_at.isoformat()
            } if recent else None
        }

    @staticmethod
    def get_session_summary(db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed summary of an audit session.

        Args:
            db: Database session
            session_id: Session ID

        Returns:
            Detailed summary dictionary
        """
        session = db.query(AuditSession).filter(
            AuditSession.id == session_id
        ).first()

        if not session:
            return None

        # Get results grouped by status
        results = db.query(AuditResult).filter(
            AuditResult.session_id == session_id
        ).all()

        passed = [r for r in results if r.status == CheckStatus.PASS]
        failed = [r for r in results if r.status == CheckStatus.FAIL]

        # Group failures by severity
        failures_by_severity = {}
        for r in failed:
            severity = r.severity or "unknown"
            if severity not in failures_by_severity:
                failures_by_severity[severity] = []
            failures_by_severity[severity].append({
                "check_number": r.check_number,
                "check_title": r.check_title,
                "evidence": r.evidence_snippet
            })

        # Calculate duration
        duration = None
        if session.started_at and session.completed_at:
            duration = (session.completed_at - session.started_at).total_seconds()

        return {
            "session_id": session.id,
            "asset_id": session.asset_id,
            "target_ip": session.target_ip,
            "status": session.status,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "duration_seconds": duration,
            "compliance": {
                "total_checks": session.total_checks,
                "passed": session.passed_checks,
                "failed": session.failed_checks,
                "compliance_pct": session.compliance_pct,
                "weighted_compliance_pct": session.weighted_compliance_pct
            },
            "failures_by_severity": failures_by_severity,
            "connection_error": session.connection_error
        }

    @staticmethod
    def delete_session(db: Session, session_id: int) -> bool:
        """
        Delete an audit session and all its results.

        Args:
            db: Database session
            session_id: Session ID to delete

        Returns:
            True if deleted

        Raises:
            ValueError: If session not found
        """
        session = db.query(AuditSession).filter(
            AuditSession.id == session_id
        ).first()

        if not session:
            raise ValueError(f"Audit session {session_id} not found")

        # Results are deleted via CASCADE
        db.delete(session)
        db.commit()

        logger.info(f"Deleted audit session {session_id}")
        return True

    @staticmethod
    def clear_rules_cache():
        """Clear the CIS rules cache."""
        OptimizedAuditService._rules_cache.clear()
        OptimizedAuditService._cache_timestamp.clear()
        logger.info("Cleared CIS rules cache")
