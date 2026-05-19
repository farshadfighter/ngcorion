"""
Audit Service Layer
"""
from typing import Dict, Any, List, Optional, Callable
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from contextlib import contextmanager
import logging
import time

from app.models import AuditSession, AuditResult, Asset, User
from app.models.audit import DeviceType, CheckStatus
from .ssh_client import CiscoSSHClient, redact_sensitive_data
from .rules import build_all_cisco_cis_rules, evaluate_compliance, filter_rules_by_profile, build_cis_benchmark_rules
from .cis_benchmark_map import CIS_BENCHMARK_SECTIONS, CIS_BENCHMARK_VERSION

logger = logging.getLogger(__name__)


class AuditError(Exception):
    """Base exception for audit errors."""
    pass


class AuditConnectionError(AuditError):
    """Raised when SSH connection fails."""
    pass


class AuditEvaluationError(AuditError):
    """Raised when rule evaluation fails."""
    pass


class AuditValidationError(AuditError):
    """Raised when input validation fails."""
    pass


class AuditService:
    """Service for executing and managing security audits with optimizations."""

    # Configuration constants
    CACHE_TTL = 3600  # 1 hour cache for CIS rules
    BATCH_SIZE = 100  # Bulk insert batch size
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    # Class-level cache for CIS rules
    _rules_cache: Dict[str, List] = {}
    _cache_timestamp: Dict[str, float] = {}

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        """
        Context manager for timing operations.

        Usage:
            with AuditService._timed_operation("Evaluate rules"):
                # operation code

        Logs start and completion with duration.
        """
        start_time = time.time()
        logger.info(f"Starting: {operation_name}")

        try:
            yield
        finally:
            elapsed = time.time() - start_time
            logger.info(f"Completed: {operation_name} ({elapsed:.2f}s)")

    @staticmethod
    def _get_cached_rules(profile: str) -> List:
        """
        Get CIS rules from cache or build fresh.

        Args:
            profile: CIS profile (L1 or FULL)

        Returns:
            List of filtered CIS rules

        Cache is invalidated after CACHE_TTL seconds.
        """
        cache_key = f"cisco_{profile}"
        current_time = time.time()

        # Check if cache exists and is still valid
        if (cache_key in AuditService._rules_cache and
            cache_key in AuditService._cache_timestamp):

            cache_age = current_time - AuditService._cache_timestamp[cache_key]

            if cache_age < AuditService.CACHE_TTL:
                logger.debug(
                    f"Using cached rules for {profile} "
                    f"(age: {cache_age:.1f}s, {len(AuditService._rules_cache[cache_key])} rules)"
                )
                return AuditService._rules_cache[cache_key]
            else:
                logger.debug(f"Cache expired for {profile} (age: {cache_age:.1f}s)")

        # Build fresh rules and cache
        logger.info(f"Building fresh CIS rules for {profile}")
        with AuditService._timed_operation(f"Build CIS rules ({profile})"):
            all_rules = build_all_cisco_cis_rules()
            filtered_rules = filter_rules_by_profile(all_rules, profile)

        AuditService._rules_cache[cache_key] = filtered_rules
        AuditService._cache_timestamp[cache_key] = current_time

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
            findings: List of finding dictionaries
            batch_size: Records per batch (default: BATCH_SIZE)

        Inserts records in batches to reduce database round trips.
        """
        batch_size = batch_size or AuditService.BATCH_SIZE
        results = []

        logger.info(f"Bulk inserting {len(findings)} audit results (batch size: {batch_size})")

        for idx, finding in enumerate(findings, 1):
            result = AuditResult(
                session_id=session_id,
                check_number=finding["check_number"],
                check_title=finding["title"],
                severity=finding["severity"],
                level=finding.get("level", "L1"),
                status=CheckStatus.PASS if finding["passed"] else CheckStatus.FAIL,
                evidence_snippet=finding["evidence"]
            )
            results.append(result)

            # Commit batch
            if len(results) >= batch_size:
                db.bulk_save_objects(results)
                db.commit()
                logger.debug(f"Committed batch: {idx - len(results) + 1} to {idx}")
                results = []

        # Commit final batch
        if results:
            db.bulk_save_objects(results)
            db.commit()
            logger.debug(f"Committed final batch: {len(results)} records")

        logger.info(f"Successfully inserted {len(findings)} audit results")

    @staticmethod
    def execute_cisco_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        profile: str = "L1",
        job_name: Optional[str] = None
    ) -> AuditSession:
        """
        Execute CIS audit on a Cisco device.

        Args:
            db: Database session
            asset_id: Target asset ID
            user_id: User performing audit
            ssh_username: SSH username (not stored)
            ssh_password: SSH password (not stored)
            ssh_secret: Enable secret (optional, not stored)
            profile: CIS profile (L1 or FULL)
            job_name: User-friendly job name

        Returns:
            AuditSession: Completed audit session with results

        Raises:
            ValueError: If asset not found or missing IP
            Exception: If SSH connection or audit fails
        """
        # 1. Fetch asset details
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        target_ip = asset.ip_address

        # 2. Create audit session (status: running)
        session = AuditSession(
            template_id=None,  # Direct CIS scan (not template-based)
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.CISCO,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc)
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. Establish SSH connection and collect turbo dump
            with AuditService._timed_operation("SSH connection and turbo dump"):
                with CiscoSSHClient(
                    ip=target_ip,
                    username=ssh_username,
                    password=ssh_password,
                    secret=ssh_secret
                ) as ssh_client:
                    raw_dump = ssh_client.collect_turbo()

            # 4. Redact sensitive data
            redacted_dump = redact_sensitive_data(raw_dump)

            # 5. Get CIS rules from cache
            rules = AuditService._get_cached_rules(profile)

            # 6. Evaluate compliance
            with AuditService._timed_operation(f"Evaluate {len(rules)} CIS rules"):
                report = evaluate_compliance(redacted_dump, rules)

            # 7. Update session with results
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = report["summary"]["total_rules_scored"]
            session.passed_checks = report["summary"]["passed_scored"]
            session.failed_checks = report["summary"]["failed_scored"]
            session.error_checks = 0
            session.compliance_pct = report["summary"]["compliance_pct"]
            session.weighted_compliance_pct = report["summary"]["weighted_compliance_pct"]
            session.turbo_dump = redacted_dump
            db.commit()

            # 8. Bulk insert check results for better performance
            findings_for_insert = []
            for finding in report["findings"]:
                findings_for_insert.append({
                    "check_number": finding["id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "passed": finding["compliant"],
                    "evidence": finding["evidence"],
                    "remediation": finding.get("remediation")
                })

            with AuditService._timed_operation("Insert audit results"):
                AuditService._bulk_insert_results(db, session.id, findings_for_insert)
            db.refresh(session)

            logger.info(f"Audit completed for asset {asset_id} ({target_ip}): {report['summary']['compliance_pct']}% compliance")
            return session

        except Exception as e:
            # Mark session as failed
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)

            # Sanitize error message to avoid exposing credentials
            error_msg = str(e)
            # Remove any potential credential leaks from error message
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

            logger.error(f"Audit failed for asset {asset_id} ({target_ip}): {type(e).__name__}")
            raise

    @staticmethod
    def get_audit_session(db: Session, session_id: int) -> Optional[AuditSession]:
        """Get audit session by ID."""
        return db.query(AuditSession).filter(AuditSession.id == session_id).first()

    @staticmethod
    def get_audit_results(db: Session, session_id: int) -> List[AuditResult]:
        """Get all results for an audit session."""
        return db.query(AuditResult).filter(AuditResult.session_id == session_id).all()

    @staticmethod
    def get_all_sessions(db: Session, limit: int = 50, offset: int = 0) -> List[AuditSession]:
        """
        Get all audit sessions with pagination.

        Args:
            db: Database session
            limit: Maximum number of sessions to return
            offset: Number of sessions to skip

        Returns:
            List of audit sessions (most recent first)
        """
        return (
            db.query(AuditSession)
            .filter(AuditSession.device_type == DeviceType.CISCO)
            .order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_sessions_count(db: Session) -> int:
        """
        Get total count of audit sessions.

        Args:
            db: Database session

        Returns:
            Total number of audit sessions
        """
        return db.query(AuditSession).filter(AuditSession.device_type == DeviceType.CISCO).count()

    @staticmethod
    def get_asset_audit_history(db: Session, asset_id: int, limit: int = 10) -> List[AuditSession]:
        """
        Get audit history for an asset.

        Args:
            db: Database session
            asset_id: Asset ID
            limit: Maximum number of sessions to return

        Returns:
            List of audit sessions (most recent first)
        """
        return (
            db.query(AuditSession)
            .filter(
                AuditSession.asset_id == asset_id,
                AuditSession.device_type == DeviceType.CISCO
            )
            .order_by(AuditSession.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_session_summary(db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        """
        Get formatted summary of an audit session.

        Returns:
            Dict with session details and compliance summary
        """
        session = AuditService.get_audit_session(db, session_id)
        if not session:
            return None

        # Get asset details
        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None

        # Get result counts by status
        results = db.query(AuditResult).filter(AuditResult.session_id == session_id).all()

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
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
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
                "weighted_compliance_pct": session.weighted_compliance_pct
            },
            "connection_error": session.connection_error
        }

    @staticmethod
    def delete_audit_session(db: Session, session_id: int) -> bool:
        """
        Delete an audit session and all its results.

        Args:
            db: Database session
            session_id: Audit session ID to delete

        Returns:
            bool: True if deleted successfully

        Raises:
            ValueError: If session not found
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Audit session {session_id} not found")

        # Results are deleted automatically via cascade
        db.delete(session)
        db.commit()

        return True

    @staticmethod
    def get_cis_benchmark_table(db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        """
        Get CIS Benchmark table format results.

        Returns results in the official CIS Benchmark table format with
        section numbers (1.1.1, 1.1.2, etc.) and Yes/No checkmarks.

        Args:
            db: Database session
            session_id: Audit session ID

        Returns:
            Dict with:
            - session info
            - benchmark_version
            - sections: list of {section, recommendation, set_correctly}
            - summary with compliance percentage
        """
        session = AuditService.get_audit_session(db, session_id)
        if not session:
            return None

        # Get asset details
        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None

        # Get audit results indexed by check_number
        results = db.query(AuditResult).filter(AuditResult.session_id == session_id).all()
        results_by_id = {r.check_number: r for r in results}

        # Build the CIS Benchmark table
        sections = []
        passed = 0
        failed = 0

        for sec in CIS_BENCHMARK_SECTIONS:
            rule_id = sec["rule_id"]
            section_num = sec["section"]

            # Try both formats: IOS-L1-* (internal) and CIS-* (CIS benchmark)
            # The execute_cis_benchmark_audit uses CIS-* format
            result = results_by_id.get(rule_id)
            if not result:
                # Try CIS section format (e.g., CIS-1.1.1)
                cis_id = f"CIS-{section_num}"
                result = results_by_id.get(cis_id)

            if result:
                set_correctly = result.status == CheckStatus.PASS
                if set_correctly:
                    passed += 1
                else:
                    failed += 1
            else:
                # Rule not found in results - mark as not evaluated
                set_correctly = None

            sections.append({
                "section": section_num,
                "recommendation": sec["recommendation"],
                "set_correctly": set_correctly
            })

        total = passed + failed
        compliance_pct = round(100.0 * passed / total, 2) if total > 0 else 0.0

        return {
            "session_id": session.id,
            "asset_id": session.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "target_ip": session.target_ip,
            "audit_date": session.completed_at.isoformat() if session.completed_at else session.started_at.isoformat() if session.started_at else None,
            "benchmark_version": CIS_BENCHMARK_VERSION,
            "sections": sections,
            "summary": {
                "total_checks": total,
                "passed": passed,
                "failed": failed,
                "compliance_percentage": compliance_pct
            }
        }

    @staticmethod
    def execute_cis_benchmark_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        job_name: Optional[str] = None
    ) -> AuditSession:
        """
        Execute CIS Benchmark audit using official section numbers.

        Similar to execute_cisco_audit but uses CIS Benchmark section IDs
        (1.1.1, 1.1.2, etc.) instead of internal rule IDs.

        Args:
            db: Database session
            asset_id: Target asset ID
            user_id: User performing audit
            ssh_username: SSH username (not stored)
            ssh_password: SSH password (not stored)
            ssh_secret: Enable secret (optional, not stored)

        Returns:
            AuditSession: Completed audit session with results

        Raises:
            ValueError: If asset not found or missing IP
            Exception: If SSH connection or audit fails
        """
        # 1. Fetch asset details
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        target_ip = asset.ip_address

        # 2. Create audit session (status: running)
        session = AuditSession(
            template_id=None,
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.CISCO,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc)
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. Establish SSH connection and collect turbo dump
            with CiscoSSHClient(
                ip=target_ip,
                username=ssh_username,
                password=ssh_password,
                secret=ssh_secret
            ) as ssh_client:
                raw_dump = ssh_client.collect_turbo()

            # 4. Redact sensitive data
            redacted_dump = redact_sensitive_data(raw_dump)

            # 5. Build CIS Benchmark rules (uses CIS- prefixed IDs)
            rules = build_cis_benchmark_rules()

            # 6. Evaluate compliance
            report = evaluate_compliance(redacted_dump, rules)

            # 7. Update session with results
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = report["summary"]["total_rules_scored"]
            session.passed_checks = report["summary"]["passed_scored"]
            session.failed_checks = report["summary"]["failed_scored"]
            session.error_checks = 0
            session.compliance_pct = report["summary"]["compliance_pct"]
            session.weighted_compliance_pct = report["summary"]["weighted_compliance_pct"]
            session.turbo_dump = redacted_dump

            # 8. Store individual check results
            for finding in report["findings"]:
                result = AuditResult(
                    session_id=session.id,
                    check_id=None,
                    check_number=finding["id"],
                    check_title=finding["title"],
                    severity=finding["severity"],
                    level=finding["level"],
                    status=CheckStatus.PASS if finding["compliant"] else CheckStatus.FAIL,
                    evidence_snippet=finding["evidence"],
                    checked_at=datetime.now(timezone.utc)
                )
                db.add(result)

            db.commit()
            db.refresh(session)

            logger.info(f"CIS Benchmark audit completed for asset {asset_id} ({target_ip}): {report['summary']['compliance_pct']}% compliance")
            return session

        except Exception as e:
            # Mark session as failed
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)

            # Sanitize error message to avoid exposing credentials
            error_msg = str(e)
            if "password" in error_msg.lower() or "secret" in error_msg.lower():
                error_msg = f"{type(e).__name__}: Authentication or connection error"
            else:
                error_msg = f"{type(e).__name__}: {error_msg}"

            if len(error_msg) > 500:
                error_msg = error_msg[:500] + "..."

            session.connection_error = error_msg
            db.commit()
            db.refresh(session)

            logger.error(f"CIS Benchmark audit failed for asset {asset_id} ({target_ip}): {type(e).__name__}")
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
        job_name: Optional[str] = None,
        max_retries: int = None
    ) -> AuditSession:
        """
        Execute Cisco audit with automatic retry on transient failures.

        Features:
        - Retries up to max_retries times on connection errors
        - 2-second delay between retries
        - Logs each attempt
        - Only retries on connection errors, not validation errors

        Args:
            max_retries: Maximum retry attempts (default: 3)
            ... (same as execute_cisco_audit)

        Returns:
            AuditSession: Completed audit session

        Raises:
            AuditConnectionError: After all retries exhausted
        """
        max_retries = max_retries or AuditService.MAX_RETRIES

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(
                    f"Audit attempt {attempt}/{max_retries} for asset {asset_id}"
                )

                return AuditService.execute_cisco_audit(
                    db=db,
                    asset_id=asset_id,
                    user_id=user_id,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password,
                    ssh_secret=ssh_secret,
                    profile=profile,
                    job_name=job_name
                )

            except (ConnectionError, TimeoutError, OSError) as e:
                logger.warning(
                    f"Connection attempt {attempt}/{max_retries} failed: {str(e)}"
                )

                if attempt < max_retries:
                    logger.info(f"Retrying in {AuditService.RETRY_DELAY} seconds...")
                    time.sleep(AuditService.RETRY_DELAY)
                else:
                    raise AuditConnectionError(
                        f"Audit failed after {max_retries} connection attempts: {str(e)}"
                    )

            except ValueError as e:
                # Don't retry validation errors
                logger.error(f"Validation error (not retrying): {str(e)}")
                raise AuditValidationError(str(e))

    @staticmethod
    def get_audit_statistics(
        db: Session,
        asset_id: Optional[int] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive statistics about audit sessions.

        Args:
            db: Database session
            asset_id: Optional filter by asset
            user_id: Optional filter by user

        Returns:
            {
                "total_sessions": int,
                "by_status": {"completed": int, "failed": int, "running": int},
                "success_rate": float,
                "average_compliance": float,
                "total_checks_run": int,
                "total_failures": int,
                "most_common_failures": [{"check_number": str, "count": int}, ...],
                "most_recent_session": {...}
            }
        """
        from sqlalchemy import func

        # Query sessions
        query = db.query(AuditSession)
        if asset_id:
            query = query.filter(AuditSession.asset_id == asset_id)
        if user_id:
            query = query.filter(AuditSession.user_id == user_id)

        sessions = query.all()
        total_sessions = len(sessions)

        # Group by status
        by_status = {}
        for session in sessions:
            status = session.status
            by_status[status] = by_status.get(status, 0) + 1

        # Calculate success rate
        completed = by_status.get("completed", 0)
        success_rate = (
            (completed / total_sessions * 100)
            if total_sessions > 0
            else 0.0
        )

        # Calculate average compliance
        compliances = [s.compliance_pct for s in sessions if s.compliance_pct is not None]
        average_compliance = (
            sum(compliances) / len(compliances)
            if compliances
            else 0.0
        )

        # Total checks and failures
        total_checks = sum(s.total_checks or 0 for s in sessions)
        total_failures = sum(s.failed_checks or 0 for s in sessions)

        # Most common failures
        failure_query = db.query(AuditResult).filter(
            AuditResult.status == CheckStatus.FAIL
        )
        if asset_id:
            failure_query = failure_query.join(AuditSession).filter(
                AuditSession.asset_id == asset_id
            )

        failures = failure_query.all()
        failure_counts = {}
        for failure in failures:
            check = failure.check_number
            failure_counts[check] = failure_counts.get(check, 0) + 1

        most_common_failures = [
            {"check_number": check, "count": count}
            for check, count in sorted(
                failure_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        ]

        # Most recent session
        most_recent = (
            query.order_by(AuditSession.started_at.desc()).first()
            if sessions
            else None
        )

        most_recent_data = None
        if most_recent:
            most_recent_data = {
                "id": most_recent.id,
                "status": most_recent.status,
                "compliance_pct": most_recent.compliance_pct,
                "started_at": most_recent.started_at.isoformat() if most_recent.started_at else None
            }

        return {
            "total_sessions": total_sessions,
            "by_status": by_status,
            "success_rate": round(success_rate, 2),
            "average_compliance": round(average_compliance, 2),
            "total_checks_run": total_checks,
            "total_failures": total_failures,
            "most_common_failures": most_common_failures,
            "most_recent_session": most_recent_data
        }
