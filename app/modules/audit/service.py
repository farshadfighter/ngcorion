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
from datetime import datetime

from app.models import AuditSession, AuditResult, Asset, User
from app.models.audit import DeviceType, CheckStatus
from .ssh_client import CiscoSSHClient, redact_sensitive_data
from .cisco_rules import build_all_cisco_cis_rules, evaluate_compliance, filter_rules_by_profile


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
            started_at=datetime.utcnow()
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
            session.completed_at = datetime.utcnow()
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
                    checked_at=datetime.utcnow()
                )
                db.add(result)

            db.commit()
            db.refresh(session)

            return session

        except Exception as e:
            # Mark session as failed
            session.status = "failed"
            session.completed_at = datetime.utcnow()
            session.connection_error = f"{type(e).__name__}: {str(e)}"
            db.commit()
            db.refresh(session)

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
