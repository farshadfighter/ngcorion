"""
Linux Audit Service Layer

Handles CIS benchmark auditing for Linux distributions:
- Ubuntu 22.04 LTS
- Ubuntu 24.04 LTS
- Rocky Linux 8

Follows the same patterns as cisco_service.py for consistency.
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from contextlib import contextmanager
import logging
import time

from app.models import AuditSession, AuditResult, Asset
from app.models.audit import DeviceType, CheckStatus
from app.modules.linux.common.ssh_client import LinuxSSHClient, redact_sensitive_linux_data
from .audit_commands import get_linux_audit_commands
from .rules import (
    build_linux_cis_rules,
    filter_rules_by_profile,
    filter_rules_by_distro,
    evaluate_compliance,
    LinuxCISRule
)

logger = logging.getLogger(__name__)


class LinuxAuditError(Exception):
    """Base exception for Linux audit errors."""
    pass


class LinuxAuditConnectionError(LinuxAuditError):
    """Raised when SSH connection fails."""
    pass


class LinuxAuditEvaluationError(LinuxAuditError):
    """Raised when rule evaluation fails."""
    pass


class LinuxAuditValidationError(LinuxAuditError):
    """Raised when input validation fails."""
    pass


class LinuxAuditService:
    """Service for executing and managing Linux CIS security audits."""

    CACHE_TTL = 3600  # 1 hour cache for CIS rules
    BATCH_SIZE = 100
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    _rules_cache: Dict[str, List[LinuxCISRule]] = {}
    _cache_timestamp: Dict[str, float] = {}

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        """Context manager for timing operations."""
        start_time = time.time()
        logger.info(f"Starting: {operation_name}")
        try:
            yield
        finally:
            elapsed = time.time() - start_time
            logger.info(f"Completed: {operation_name} ({elapsed:.2f}s)")

    @staticmethod
    def _get_cached_rules(profile: str, distro_profile: str) -> List[LinuxCISRule]:
        """
        Get CIS rules from cache or build fresh.

        Args:
            profile: CIS profile (L1 or FULL)
            distro_profile: Distribution profile (ubuntu_22, rocky_8, etc.)

        Returns:
            List of filtered CIS rules
        """
        cache_key = f"linux_{profile}_{distro_profile}"
        current_time = time.time()

        if (cache_key in LinuxAuditService._rules_cache and
            cache_key in LinuxAuditService._cache_timestamp):

            cache_age = current_time - LinuxAuditService._cache_timestamp[cache_key]
            if cache_age < LinuxAuditService.CACHE_TTL:
                logger.debug(f"Using cached rules for {cache_key} (age: {cache_age:.1f}s)")
                return LinuxAuditService._rules_cache[cache_key]

        logger.info(f"Building fresh CIS rules for {cache_key}")
        with LinuxAuditService._timed_operation(f"Build Linux CIS rules ({cache_key})"):
            all_rules = build_linux_cis_rules()
            filtered_rules = filter_rules_by_profile(all_rules, profile)
            filtered_rules = filter_rules_by_distro(filtered_rules, distro_profile)

        LinuxAuditService._rules_cache[cache_key] = filtered_rules
        LinuxAuditService._cache_timestamp[cache_key] = current_time

        logger.info(f"Cached {len(filtered_rules)} rules for {cache_key}")
        return filtered_rules

    @staticmethod
    def _bulk_insert_results(
        db: Session,
        session_id: int,
        findings: List[Dict],
        batch_size: int = None
    ):
        """Bulk insert audit results for performance."""
        batch_size = batch_size or LinuxAuditService.BATCH_SIZE
        results = []

        logger.info(f"Bulk inserting {len(findings)} audit results")

        _STATUS_MAP = {
            "pass": CheckStatus.PASS,
            "fail": CheckStatus.FAIL,
            "error": CheckStatus.ERROR,
        }
        for idx, finding in enumerate(findings, 1):
            status = _STATUS_MAP.get(
                finding.get("status"),
                CheckStatus.PASS if finding["compliant"] else CheckStatus.FAIL,
            )
            result = AuditResult(
                session_id=session_id,
                check_number=finding["id"],
                check_title=finding["title"],
                severity=finding["severity"],
                level=finding.get("level", "L1"),
                status=status,
                evidence_snippet=finding["evidence"]
            )
            results.append(result)

            if len(results) >= batch_size:
                db.bulk_save_objects(results)
                db.commit()
                results = []

        if results:
            db.bulk_save_objects(results)
            db.commit()

        logger.info(f"Successfully inserted {len(findings)} audit results")

    @staticmethod
    def execute_linux_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        sudo_password: Optional[str] = None,
        profile: str = "L1",
        job_name: Optional[str] = None,
        ssh_port: int = 22,
        sub_device_type: Optional[str] = None,
    ) -> AuditSession:
        """
        Execute CIS audit on a Linux server.

        Args:
            db: Database session
            asset_id: Target asset ID
            user_id: User performing audit
            ssh_username: SSH username
            ssh_password: SSH password
            sudo_password: Sudo password (defaults to ssh_password)
            profile: CIS profile (L1 or FULL)

        Returns:
            AuditSession: Completed audit session with results

        Raises:
            ValueError: If asset not found or missing IP
            LinuxAuditConnectionError: If SSH connection fails
            LinuxAuditError: For other failures
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
            device_type=DeviceType.LINUX,
            job_name=job_name,
            sub_device_type=sub_device_type,
            status="running",
            started_at=datetime.now(timezone.utc)
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            # 3. Establish SSH connection
            with LinuxAuditService._timed_operation("SSH connection"):
                ssh_client = LinuxSSHClient(
                    ip=target_ip,
                    username=ssh_username,
                    password=ssh_password,
                    sudo_password=sudo_password,
                    port=ssh_port
                )
                ssh_client.connect()

            try:
                # 4. Detect distribution
                with LinuxAuditService._timed_operation("Distro detection"):
                    distro_info = ssh_client.detect_distro()

                distro_profile = distro_info.get("profile", "linux_generic")
                distro_id = distro_info.get("id", "ubuntu")

                logger.info(f"Detected: {distro_info.get('name')} (profile: {distro_profile})")

                _PROFILE_TO_SUB_DEVICE = {
                    "ubuntu_20": "linux-ubuntu-20",
                    "ubuntu_22": "linux-ubuntu-22",
                    "ubuntu_24": "linux-ubuntu-24",
                    "rhel_8":    "linux-redhat-8",
                    "rhel_9":    "linux-redhat-9",
                    "rhel_10":   "linux-redhat-10",
                    "rocky_8":   "linux-rocky-8",
                    "rocky_9":   "linux-rocky-9",
                    "rocky_10":  "linux-rocky-10",
                }
                detected_sub = _PROFILE_TO_SUB_DEVICE.get(distro_profile)
                if detected_sub:
                    session.sub_device_type = detected_sub
                    db.commit()

                # 5. Get audit commands for this distro
                audit_commands = get_linux_audit_commands(distro_id)

                # 6. Collect audit data
                with LinuxAuditService._timed_operation(f"Collect {len(audit_commands)} commands"):
                    audit_data = ssh_client.collect_audit_data(audit_commands)

            finally:
                ssh_client.disconnect()

            # 7. Redact sensitive data
            redacted_dump = ""
            for key, value in audit_data.items():
                redacted_value = redact_sensitive_linux_data(value)
                redacted_dump += f"## {key}\n{redacted_value}\n\n"

            # 8. Get CIS rules from cache
            rules = LinuxAuditService._get_cached_rules(profile, distro_profile)

            # 9. Evaluate compliance
            with LinuxAuditService._timed_operation(f"Evaluate {len(rules)} CIS rules"):
                report = evaluate_compliance(audit_data, rules, distro_profile)

            # 10. Update session with results
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = report["summary"]["total_rules_scored"]
            session.passed_checks = report["summary"]["passed_scored"]
            session.failed_checks = report["summary"]["failed_scored"]
            session.error_checks = report["summary"].get("error_count", 0)
            session.compliance_pct = report["summary"]["compliance_pct"]
            session.weighted_compliance_pct = report["summary"]["weighted_compliance_pct"]
            session.turbo_dump = redacted_dump[:100000]  # Limit size
            db.commit()

            # 11. Bulk insert check results
            with LinuxAuditService._timed_operation("Insert audit results"):
                LinuxAuditService._bulk_insert_results(db, session.id, report["findings"])

            db.refresh(session)

            logger.info(
                f"Linux audit completed for asset {asset_id} ({target_ip}): "
                f"{report['summary']['compliance_pct']}% compliance"
            )
            return session

        except Exception as e:
            # Mark session as failed
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)

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

            logger.error(f"Linux audit failed for asset {asset_id} ({target_ip}): {type(e).__name__}")
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
    def get_linux_sessions(db: Session, limit: int = 50, offset: int = 0) -> List[AuditSession]:
        """Get all Linux audit sessions with pagination."""
        return (
            db.query(AuditSession)
            .filter(AuditSession.device_type == DeviceType.LINUX)
            .order_by(AuditSession.started_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_linux_sessions_count(db: Session) -> int:
        """Get total count of Linux audit sessions."""
        return db.query(AuditSession).filter(AuditSession.device_type == DeviceType.LINUX).count()

    @staticmethod
    def get_asset_linux_history(db: Session, asset_id: int, limit: int = 10) -> List[AuditSession]:
        """Get Linux audit history for a specific asset."""
        return (
            db.query(AuditSession)
            .filter(
                AuditSession.asset_id == asset_id,
                AuditSession.device_type == DeviceType.LINUX
            )
            .order_by(AuditSession.started_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_session_summary(db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        """Get formatted summary of an audit session."""
        session = LinuxAuditService.get_audit_session(db, session_id)
        if not session:
            return None

        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
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
            "sub_device_type": session.sub_device_type,
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
    def get_failed_checks(db: Session, session_id: int) -> List[Dict[str, Any]]:
        """Get all failed checks for a session."""
        results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL
            )
            .all()
        )

        return [
            {
                "id": r.id,
                "check_number": r.check_number,
                "check_title": r.check_title,
                "severity": r.severity,
                "level": r.level,
                "evidence_snippet": r.evidence_snippet
            }
            for r in results
        ]

    @staticmethod
    def delete_audit_session(db: Session, session_id: int) -> bool:
        """Delete an audit session and all its results."""
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Audit session {session_id} not found")

        db.delete(session)
        db.commit()
        return True

    @staticmethod
    def get_audit_statistics(
        db: Session,
        asset_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get comprehensive statistics about Linux audit sessions."""
        from sqlalchemy import func

        query = db.query(AuditSession).filter(AuditSession.device_type == DeviceType.LINUX)
        if asset_id:
            query = query.filter(AuditSession.asset_id == asset_id)

        sessions = query.all()
        total_sessions = len(sessions)

        by_status = {}
        for session in sessions:
            status = session.status
            by_status[status] = by_status.get(status, 0) + 1

        completed = by_status.get("completed", 0)
        success_rate = (completed / total_sessions * 100) if total_sessions > 0 else 0.0

        compliances = [s.compliance_pct for s in sessions if s.compliance_pct is not None]
        average_compliance = sum(compliances) / len(compliances) if compliances else 0.0

        total_checks = sum(s.total_checks or 0 for s in sessions)
        total_failures = sum(s.failed_checks or 0 for s in sessions)

        most_recent = query.order_by(AuditSession.started_at.desc()).first() if sessions else None
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
            "most_recent_session": most_recent_data
        }
