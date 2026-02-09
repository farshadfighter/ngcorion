"""
Linux Hardening Service Layer

Provides high-level hardening operations for Linux servers:
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
from .linux_parameter_metadata import (
    aggregate_linux_parameters_for_checks,
    categorize_linux_checks_by_fixability,
    get_linux_auto_fix_preview,
    get_linux_check_defaults,
    is_linux_check_auto_fixable,
    LINUX_CHECK_PARAMETER_MAP
)
from .linux_command_templates import get_linux_hardening_template, get_all_supported_checks
from .linux_ssh_executor import LinuxHardeningBatchExecutor

logger = logging.getLogger(__name__)


class LinuxHardeningService:
    """Service for Linux CIS hardening operations."""

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
        # Verify session exists and is Linux
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.device_type != DeviceType.LINUX:
            raise ValueError(f"Session {session_id} is not a Linux audit")

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
        categorized = categorize_linux_checks_by_fixability(failed_check_ids)

        # Aggregate parameters for checks that need them
        needs_params_ids = categorized["needs_params"]
        parameters = aggregate_linux_parameters_for_checks(needs_params_ids)

        # Build detailed failed checks list
        failed_checks = []
        for r in failed_results:
            template = get_linux_hardening_template(r.check_number)
            failed_checks.append({
                "check_number": r.check_number,
                "check_title": r.check_title,
                "severity": r.severity,
                "level": r.level,
                "has_template": template is not None,
                "auto_fixable": is_linux_check_auto_fixable(r.check_number),
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
        preview = get_linux_auto_fix_preview(failed_check_ids)

        # Categorize
        categorized = categorize_linux_checks_by_fixability(failed_check_ids)

        # Add check titles to preview
        check_titles = {r.check_number: r.check_title for r in failed_results}
        for item in preview:
            item["check_title"] = check_titles.get(item["check_number"], "Unknown")
            template = get_linux_hardening_template(item["check_number"])
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

        logger.info(f"Auto-hardening {len(failed_check_ids)} failed checks on {asset.ip_address}")

        # Execute hardening
        executor = LinuxHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password
        )

        result = executor.execute_auto_harden(failed_check_ids)

        # Add metadata
        result["session_id"] = session_id
        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Auto-hardening completed: {result['successful']}/{result['auto_fixable']} successful"
        )

        return result

    @staticmethod
    def batch_execute_selected(
        db: Session,
        session_id: int,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        sudo_password: Optional[str],
        checks: List[Dict[str, Any]]
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

        logger.info(f"Batch hardening {len(checks)} checks on {asset.ip_address}")

        executor = LinuxHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password
        )

        result = executor.execute_selected(checks)

        result["session_id"] = session_id
        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"Batch hardening completed: {result['successful']}/{result['total']} successful"
        )

        return result

    @staticmethod
    def execute_single_fix(
        db: Session,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        sudo_password: Optional[str],
        check_id: str,
        parameters: Dict[str, str] = None
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

        logger.info(f"Executing single fix {check_id} on {asset.ip_address}")

        executor = LinuxHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password
        )

        result = executor.execute_single(check_id, parameters)

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
            template = get_linux_hardening_template(check_id)
            auto_fixable = is_linux_check_auto_fixable(check_id)
            defaults = get_linux_check_defaults(check_id)

            checks_info.append({
                "check_id": check_id,
                "description": template.description if template else None,
                "auto_fixable": auto_fixable,
                "requires_reboot": template.requires_reboot if template else False,
                "requires_service_restart": template.requires_service_restart if template else None,
                "default_parameters": defaults
            })

        return {
            "total_supported": len(supported),
            "checks": checks_info
        }
