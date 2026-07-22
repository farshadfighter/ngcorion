"""
Windows Server Hardening Service Layer

High-level hardening operations for Windows Server instances:
- Get session parameters (aggregated UI metadata for failed checks)
- Preview auto-hardening (what will run with defaults)
- Execute automatic hardening with CIS default values
- Execute batch hardening with user-supplied parameters
- Execute single-check hardening
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import Asset, AuditResult, AuditSession
from app.models.audit import CheckStatus, DeviceType

from .command_templates import get_all_supported_checks, get_windows_hardening_template
from .parameter_metadata import (
    WINDOWS_CHECK_PARAMETER_MAP,
    aggregate_windows_parameters_for_checks,
    categorize_windows_checks_by_fixability,
    get_windows_auto_fix_preview,
    get_windows_check_defaults,
    is_windows_check_auto_fixable,
)
from .winrm_executor import WindowsHardeningBatchExecutor

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


class WindowsHardeningService:
    """Service for Windows Server CIS hardening operations."""

    # ---------------------------------------------------------------- #
    #  Read-only / preview methods                                      #
    # ---------------------------------------------------------------- #

    @staticmethod
    def get_session_parameters(
        db: Session,
        session_id: int,
    ) -> Dict[str, Any]:
        """
        Return aggregated parameter metadata needed to fix all failed checks.
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.device_type != DeviceType.WINDOWS:
            raise ValueError(f"Session {session_id} is not a Windows audit session")

        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL,
            )
            .all()
        )

        failed_check_ids = [r.check_number for r in failed_results]
        categorized = categorize_windows_checks_by_fixability(failed_check_ids)
        parameters = aggregate_windows_parameters_for_checks(categorized["needs_params"])

        failed_checks = []
        for r in failed_results:
            template = get_windows_hardening_template(r.check_number)
            failed_checks.append({
                # check_number is the key the shared HardenAll UI reads
                # (matches the Linux/Apache payload); check_id kept for
                # backwards compatibility.
                "check_number": r.check_number,
                "check_id": r.check_number,
                "check_title": r.check_title,
                "severity": r.severity,
                "level": r.level,
                "has_template": template is not None,
                "auto_fixable": is_windows_check_auto_fixable(r.check_number),
                "manual_only": template.manual_only if template else True,
                "requires_restart": template.requires_restart if template else False,
                "template_description": template.description if template else None,
            })

        return {
            "session_id": session_id,
            "total_failed": len(failed_check_ids),
            "parameters": parameters,
            "categorized_checks": categorized,
            "failed_checks": failed_checks,
        }

    @staticmethod
    def get_auto_harden_preview(
        db: Session,
        session_id: int,
    ) -> Dict[str, Any]:
        """
        Return a preview of what automatic hardening will apply.
        No changes are made to the target server.
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL,
            )
            .all()
        )

        failed_check_ids = [r.check_number for r in failed_results]
        categorized = categorize_windows_checks_by_fixability(failed_check_ids)
        preview = get_windows_auto_fix_preview(failed_check_ids)

        check_titles = {r.check_number: r.check_title for r in failed_results}
        for item in preview:
            item["check_title"] = check_titles.get(item["check_id"], "Unknown")
            template = get_windows_hardening_template(item["check_id"])
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
                "not_supported": categorized["not_supported"],
            },
        }

    # ---------------------------------------------------------------- #
    #  Execution methods                                                #
    # ---------------------------------------------------------------- #

    @staticmethod
    def auto_harden_with_defaults(
        db: Session,
        session_id: int,
        asset_id: int,
        windows_username: str,
        windows_password: str,
        winrm_port: int = 5986,
        transport: str = "ntlm",
    ) -> Dict[str, Any]:
        """
        Execute automatic hardening using CIS default values only.
        Skips checks that require custom parameters.
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")
        if session.device_type != DeviceType.WINDOWS:
            raise ValueError(f"Session {session_id} is not a Windows audit session")

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL,
            )
            .all()
        )
        failed_check_ids = [r.check_number for r in failed_results]

        logger.info(
            f"Auto-hardening {len(failed_check_ids)} failed Windows checks on "
            f"{asset.ip_address}:{winrm_port}"
        )

        executor = WindowsHardeningBatchExecutor(
            ip=asset.ip_address,
            username=windows_username,
            password=windows_password,
            port=winrm_port,
            transport=transport,
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
            f"Windows auto-hardening completed: "
            f"{result['successful']}/{result['auto_fixable']} successful"
        )
        return result

    @staticmethod
    def batch_execute_selected(
        db: Session,
        session_id: int,
        asset_id: int,
        windows_username: str,
        windows_password: str,
        checks: List[Dict[str, Any]],
        winrm_port: int = 5986,
        transport: str = "ntlm",
        create_backup: bool = False,
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute hardening for selected checks with user-provided parameters.

        ``create_backup`` snapshots the security/audit policy first and records
        it on the Backups page.
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        logger.info(
            f"Batch Windows hardening: {len(checks)} checks on "
            f"{asset.ip_address}:{winrm_port}"
        )

        executor = WindowsHardeningBatchExecutor(
            ip=asset.ip_address,
            username=windows_username,
            password=windows_password,
            port=winrm_port,
            transport=transport,
        )

        result = executor.execute_selected(checks, create_backup=create_backup)

        if create_backup:
            backup_content = result.pop("backup_content", None)
            backup_error = result.pop("backup_error", None)
            if backup_content:
                from app.modules.shared.hardening_backup import save_device_backup
                save_device_backup(
                    db,
                    backup=backup_content,
                    device_ip=asset.ip_address,
                    device_type="windows",
                    user_id=user_id,
                    asset_id=asset_id,
                )
                result["backup_created"] = True
            else:
                result["backup_created"] = False
                result["backup_error"] = backup_error or "No backup content captured"

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
            f"Windows batch hardening completed: "
            f"{result['successful']}/{result['total']} successful"
        )
        return result

    @staticmethod
    def execute_single_fix(
        db: Session,
        asset_id: int,
        windows_username: str,
        windows_password: str,
        check_id: str,
        parameters: Dict[str, str] = None,
        winrm_port: int = 5986,
        transport: str = "ntlm",
        session_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute hardening for a single check with given parameters."""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        logger.info(f"Single Windows fix: {check_id} on {asset.ip_address}:{winrm_port}")

        executor = WindowsHardeningBatchExecutor(
            ip=asset.ip_address,
            username=windows_username,
            password=windows_password,
            port=winrm_port,
            transport=transport,
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
        """Return metadata for all checks that have hardening templates."""
        supported = get_all_supported_checks()

        checks_info = []
        for check_id in sorted(supported):
            template = get_windows_hardening_template(check_id)
            auto_fixable = is_windows_check_auto_fixable(check_id)
            defaults = get_windows_check_defaults(check_id)

            checks_info.append({
                "check_id": check_id,
                "description": template.description if template else None,
                "auto_fixable": auto_fixable,
                "manual_only": template.manual_only if template else True,
                "requires_restart": template.requires_restart if template else False,
                "default_parameters": defaults,
            })

        return {
            "total_supported": len(supported),
            "checks": checks_info,
        }
