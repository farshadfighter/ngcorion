"""
Apache Hardening Service Layer

Provides high-level hardening operations for Apache HTTP Server:
- Get session parameters
- Preview auto-hardening
- Execute automatic hardening with CIS defaults
- Execute batch hardening with user parameters
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging

from app.models import AuditSession, AuditResult, Asset
from app.models.audit import DeviceType, CheckStatus
from .parameter_metadata import (
    aggregate_apache_parameters_for_checks,
    categorize_apache_checks_by_fixability,
    get_apache_auto_fix_preview,
    get_apache_check_defaults,
    is_apache_check_auto_fixable,
    APACHE_CHECK_PARAMETER_MAP,
    get_all_supported_checks
)
from .command_templates import get_apache_hardening_template
from .ssh_executor import ApacheHardeningBatchExecutor

logger = logging.getLogger(__name__)


def _recompute_session_stats(db: Session, session_id: int) -> None:
    """
    Refresh AuditSession pass/fail counters and compliance_pct after hardening
    flips AuditResult rows to PASS, so the sessions list stays consistent.
    """
    session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
    if not session:
        return
    results = db.query(AuditResult).filter(AuditResult.session_id == session_id).all()
    # INFO-level rows are unscored (matches evaluate_compliance's counters).
    scored_rows = [r for r in results if (r.level or "L1") != "INFO"]
    passed = sum(1 for r in scored_rows if r.status == CheckStatus.PASS)
    failed = sum(1 for r in scored_rows if r.status == CheckStatus.FAIL)
    errors = sum(1 for r in scored_rows if r.status == CheckStatus.ERROR)
    session.passed_checks = passed
    session.failed_checks = failed
    session.error_checks = errors
    scored = passed + failed
    if scored > 0:
        session.compliance_pct = round(100.0 * passed / scored, 2)


class ApacheHardeningService:
    """Service for Apache CIS hardening operations."""

    @staticmethod
    def get_session_parameters(
        db: Session,
        session_id: int
    ) -> Dict[str, Any]:
        """
        Get aggregated parameters needed to fix all failed checks in a session.

        Args:
            db: Database session
            session_id: Audit session ID

        Returns:
            Dict with:
            - parameters: Aggregated parameter metadata
            - categorized_checks: Checks grouped by fixability
            - failed_checks: List of failed check details
        """
        # Verify session exists and is Apache
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.device_type != DeviceType.APACHE:
            raise ValueError(f"Session {session_id} is not an Apache audit")

        # Get failed checks
        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL
            )
            .all()
        )

        failed_check_ids = [r.check_number for r in failed_results]

        # Categorize checks
        categorized = categorize_apache_checks_by_fixability(failed_check_ids)

        # Aggregate parameters for checks that need them
        needs_params_ids = categorized["needs_params"]
        parameters = aggregate_apache_parameters_for_checks(needs_params_ids)

        # Build detailed failed checks list
        failed_checks = []
        for r in failed_results:
            template = get_apache_hardening_template(r.check_number)
            failed_checks.append({
                "check_number": r.check_number,
                "check_title": r.check_title,
                "severity": r.severity,
                "level": r.level,
                "has_template": template is not None,
                "auto_fixable": is_apache_check_auto_fixable(r.check_number),
                "template_description": template.description if template else None
            })

        return {
            "session_id": session_id,
            "total_failed": len(failed_check_ids),
            "parameters": parameters,
            "categorized_checks": categorized,
            "failed_checks": failed_checks
        }

    @staticmethod
    def get_auto_harden_preview(
        db: Session,
        session_id: int
    ) -> Dict[str, Any]:
        """
        Get preview of what will be applied in automatic hardening mode.

        Args:
            db: Database session
            session_id: Audit session ID

        Returns:
            Dict with preview of auto-fixable checks and their defaults
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL
            )
            .all()
        )

        failed_check_ids = [r.check_number for r in failed_results]

        # Get preview
        preview = get_apache_auto_fix_preview(failed_check_ids)

        # Categorize
        categorized = categorize_apache_checks_by_fixability(failed_check_ids)

        # Add check titles to preview
        check_titles = {r.check_number: r.check_title for r in failed_results}
        for item in preview:
            item["check_title"] = check_titles.get(item["check_number"], "Unknown")
            template = get_apache_hardening_template(item["check_number"])
            item["description"] = template.description if template else None

        return {
            "session_id": session_id,
            "total_failed": len(failed_check_ids),
            "auto_fixable_count": len(categorized["auto_fixable"]),
            "needs_params_count": len(categorized["needs_params"]),
            "not_supported_count": len(categorized["not_supported"]),
            "preview": preview,
            "skipped": {
                "needs_params": categorized["needs_params"],
                "not_supported": categorized["not_supported"]
            }
        }

    @staticmethod
    def auto_harden_with_defaults(
        db: Session,
        session_id: int,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22,
        sudo_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute automatic hardening using CIS default values only.

        Only fixes checks that don't require user input.

        Args:
            db: Database session
            session_id: Audit session ID
            asset_id: Target asset ID
            ssh_username: SSH username
            ssh_password: SSH password
            sudo_password: Sudo password

        Returns:
            Execution summary with results
        """
        # Verify session and asset
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address")

        # Get failed checks
        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL
            )
            .all()
        )

        failed_check_ids = [r.check_number for r in failed_results]

        logger.info(f"Auto-hardening {len(failed_check_ids)} failed Apache checks on {asset.ip_address}")

        # Execute hardening
        executor = ApacheHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password,
            port=ssh_port,
        )

        result = executor.execute_auto_harden(failed_check_ids)

        for check_result in result.get("results", []):
            if check_result.get("success"):
                audit_row = (
                    db.query(AuditResult)
                    .filter(
                        AuditResult.session_id == session_id,
                        AuditResult.check_number == check_result.get("check_id"),
                    )
                    .first()
                )
                if audit_row:
                    audit_row.status = CheckStatus.PASS
                    audit_row.evidence_snippet = check_result.get("verification_result") or ""
        _recompute_session_stats(db, session_id)
        db.commit()

        result["session_id"] = session_id
        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Apache auto-hardening completed: {result['successful']}/{result['auto_fixable']} successful"
        )

        return result

    @staticmethod
    def batch_execute_selected(
        db: Session,
        session_id: int,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22,
        sudo_password: Optional[str] = None,
        checks: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            db: Database session
            session_id: Audit session ID
            asset_id: Target asset ID
            ssh_username: SSH username
            ssh_password: SSH password
            sudo_password: Sudo password
            checks: List of dicts with check_id and parameters

        Returns:
            Execution summary with results
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address")

        logger.info(f"Batch hardening {len(checks)} Apache checks on {asset.ip_address}")

        executor = ApacheHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password,
            port=ssh_port,
        )

        result = executor.execute_selected(checks or [])

        for check_result in result.get("results", []):
            if check_result.get("success"):
                audit_row = (
                    db.query(AuditResult)
                    .filter(
                        AuditResult.session_id == session_id,
                        AuditResult.check_number == check_result.get("check_id"),
                    )
                    .first()
                )
                if audit_row:
                    audit_row.status = CheckStatus.PASS
                    audit_row.evidence_snippet = check_result.get("verification_result") or ""
        _recompute_session_stats(db, session_id)
        db.commit()

        result["session_id"] = session_id
        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Apache batch hardening completed: {result['successful']}/{result['total']} successful"
        )

        return result

    @staticmethod
    def execute_single_fix(
        db: Session,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        check_id: str,
        parameters: Dict[str, str] = None,
        ssh_port: int = 22,
        sudo_password: Optional[str] = None,
        session_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute hardening for a single check.

        Args:
            db: Database session
            asset_id: Target asset ID
            ssh_username: SSH username
            ssh_password: SSH password
            sudo_password: Sudo password
            check_id: CIS check ID
            parameters: Parameter values

        Returns:
            Execution result
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address")

        logger.info(f"Executing single Apache fix {check_id} on {asset.ip_address}")

        executor = ApacheHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password,
            port=ssh_port,
        )

        result = executor.execute_single(check_id, parameters)

        if result.get("success") and session_id is not None:
            audit_row = (
                db.query(AuditResult)
                .filter(
                    AuditResult.session_id == session_id,
                    AuditResult.check_number == check_id,
                )
                .first()
            )
            if audit_row:
                audit_row.status = CheckStatus.PASS
                audit_row.evidence_snippet = result.get("verification_result") or ""
                _recompute_session_stats(db, session_id)
                db.commit()

        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        return result

    @staticmethod
    def get_supported_checks() -> Dict[str, Any]:
        """
        Get list of all checks that have hardening support.

        Returns:
            Dict with supported checks and their metadata
        """
        supported = get_all_supported_checks()

        checks_info = []
        for check_id in sorted(supported):
            template = get_apache_hardening_template(check_id)
            auto_fixable = is_apache_check_auto_fixable(check_id)
            defaults = get_apache_check_defaults(check_id)

            checks_info.append({
                "check_id": check_id,
                "description": template.description if template else None,
                "auto_fixable": auto_fixable,
                "requires_service_restart": template.requires_service_restart if template else False,
                "default_parameters": defaults
            })

        return {
            "total_supported": len(supported),
            "checks": checks_info
        }
