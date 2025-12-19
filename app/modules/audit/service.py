"""
Audit Service Layer

Orchestrates the complete audit workflow:
1. Fetch asset details
2. Establish SSH connection
3. Collect turbo dump
4. Evaluate CIS rules
5. Store results in database
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging

from app.models import AuditSession, AuditResult, Asset, User
from app.models.audit import DeviceType, CheckStatus
from .ssh_client import CiscoSSHClient, redact_sensitive_data
from .cisco_rules import build_all_cisco_cis_rules, evaluate_compliance, filter_rules_by_profile, build_cis_benchmark_rules
from .cis_benchmark_map import CIS_BENCHMARK_SECTIONS, CIS_BENCHMARK_VERSION

logger = logging.getLogger(__name__)


class AuditService:
    """Service for executing and managing security audits."""

    @staticmethod
    def execute_cisco_audit(
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        profile: str = "L1"
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

            # 5. Build and filter CIS rules
            all_rules = build_all_cisco_cis_rules()
            rules = filter_rules_by_profile(all_rules, profile)

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
                    check_id=None,  # Runtime check (not stored in audit_checks table)
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
        return db.query(AuditSession).count()

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
            .filter(AuditSession.asset_id == asset_id)
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
        ssh_secret: Optional[str] = None
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
