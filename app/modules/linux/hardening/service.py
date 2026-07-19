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
from .parameter_metadata import (
    aggregate_linux_parameters_for_checks,
    categorize_linux_checks_by_fixability,
    get_linux_auto_fix_preview,
    get_linux_check_defaults,
    is_linux_check_auto_fixable,
    LINUX_CHECK_PARAMETER_MAP
)
from .command_templates import (
    get_linux_hardening_template,
    get_linux_hardening_template_for_distro,
    get_linux_template_commands_for_distro,
    get_linux_verify_commands_for_distro,
    get_all_supported_checks,
)
from .ssh_executor import LinuxHardeningBatchExecutor

logger = logging.getLogger(__name__)


# Maps the distro variant the audit stored on the session (sub_device_type) back
# to the distro_id the hardening templates expect. Used to skip the redundant
# `detect_distro()` SSH round-trip on a single fix: the audit already detected
# the distro, so re-running `cat /etc/os-release` on a fresh connection just adds
# latency. An unknown/None value falls back to live auto-detection (unchanged
# behavior), so this is safe for older sessions that never recorded a variant.
_SUB_DEVICE_TO_DISTRO_ID = {
    "linux-ubuntu-20": "ubuntu",
    "linux-ubuntu-22": "ubuntu",
    "linux-ubuntu-24": "ubuntu",
    "linux-redhat-8":  "rhel",
    "linux-redhat-9":  "rhel",
    "linux-redhat-10": "rhel",
    "linux-rocky-8":   "rocky",
    "linux-rocky-9":   "rocky",
    "linux-rocky-10":  "rocky",
}


def _distro_id_from_sub_device(sub_device_type: Optional[str]) -> Optional[str]:
    """Resolve an audit sub_device_type (e.g. 'linux-ubuntu-22') to a hardening
    distro_id (e.g. 'ubuntu'). Returns None when unknown so callers auto-detect."""
    if not sub_device_type:
        return None
    return _SUB_DEVICE_TO_DISTRO_ID.get(sub_device_type)


def _merge_check_parameters(check_id: str, parameters: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Template defaults under caller values; empty strings don't override."""
    merged = dict(get_linux_check_defaults(check_id))
    for k, v in (parameters or {}).items():
        if v is not None and str(v).strip() != "":
            merged[k] = v
    return merged


def _dry_run_check_result(check_id: str, distro_id: str, parameters: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """
    Build the dry-run entry for one check: the exact distro-aware commands that
    WOULD be executed (parameters substituted), without touching the host.
    """
    template = get_linux_hardening_template_for_distro(check_id, distro_id)
    if not template:
        return {
            "check_id": check_id,
            "check_title": None,
            "dry_run": True,
            "success": False,
            "commands": [],
            "verify_commands": [],
            "error_message": f"No hardening template found for {check_id}",
        }
    params = _merge_check_parameters(check_id, parameters)
    return {
        "check_id": check_id,
        "check_title": template.description,
        "dry_run": True,
        "success": True,
        "commands": get_linux_template_commands_for_distro(check_id, distro_id, params),
        "verify_commands": get_linux_verify_commands_for_distro(check_id, distro_id, params),
        "requires_reboot": template.requires_reboot,
        "requires_service_restart": template.requires_service_restart,
        "parameters_used": params,
        "error_message": None,
    }


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
        sudo_password: Optional[str] = None,
        ssh_port: int = 22,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute automatic hardening using CIS default values only.

        Only fixes checks that don't require user input.
        With dry_run=True, no SSH connection is made and no DB rows change:
        the response lists the commands that WOULD run for each check.

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

        if dry_run:
            distro_id = _distro_id_from_sub_device(session.sub_device_type) or "ubuntu"
            auto_fixable = [cid for cid in failed_check_ids if is_linux_check_auto_fixable(cid)]
            skipped = [cid for cid in failed_check_ids if cid not in auto_fixable]
            results = [_dry_run_check_result(cid, distro_id, None) for cid in auto_fixable]
            return {
                "dry_run": True,
                "total_requested": len(failed_check_ids),
                "auto_fixable": len(auto_fixable),
                "skipped": skipped,
                "successful": 0,
                "failed": 0,
                "distro_id": distro_id,
                "results": results,
                "session_id": session_id,
                "asset_id": asset_id,
                "target_ip": asset.ip_address,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }

        logger.info(f"Auto-hardening {len(failed_check_ids)} failed checks on {asset.ip_address}")

        # Execute hardening
        executor = LinuxHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password,
            port=ssh_port
        )

        result = executor.execute_auto_harden(failed_check_ids)

        # Update AuditResult.status for every check that passed verification
        for check_result in result.get("results", []):
            if check_result.get("success"):
                audit_row = (
                    db.query(AuditResult)
                    .filter(
                        AuditResult.session_id == session_id,
                        AuditResult.check_number == check_result.get("check_id")
                    )
                    .first()
                )
                if audit_row:
                    audit_row.status = CheckStatus.PASS
                    audit_row.evidence_snippet = check_result.get("verification_result") or ""
        _recompute_session_stats(db, session_id)
        db.commit()

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
        checks: List[Dict[str, Any]],
        ssh_port: int = 22,
        dry_run: bool = False
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

        if dry_run:
            session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
            distro_id = (
                _distro_id_from_sub_device(session.sub_device_type) if session else None
            ) or "ubuntu"
            results = [
                _dry_run_check_result(c.get("check_id"), distro_id, c.get("parameters"))
                for c in checks
            ]
            return {
                "dry_run": True,
                "total": len(checks),
                "successful": 0,
                "failed": 0,
                "distro_id": distro_id,
                "results": results,
                "session_id": session_id,
                "asset_id": asset_id,
                "target_ip": asset.ip_address,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }

        logger.info(f"Batch hardening {len(checks)} checks on {asset.ip_address}")

        executor = LinuxHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password,
            port=ssh_port
        )

        result = executor.execute_selected(checks)

        # Update AuditResult.status for every check that passed verification
        for check_result in result.get("results", []):
            if check_result.get("success"):
                audit_row = (
                    db.query(AuditResult)
                    .filter(
                        AuditResult.session_id == session_id,
                        AuditResult.check_number == check_result.get("check_id")
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
        parameters: Dict[str, str] = None,
        ssh_port: int = 22,
        session_id: Optional[int] = None,
        sub_device_type: Optional[str] = None,
        dry_run: bool = False
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
            session_id: Audit session ID (used to update status and to recover the
                already-detected distro when sub_device_type isn't supplied)
            sub_device_type: Distro variant from the audit (e.g. 'linux-ubuntu-22');
                lets us skip the live distro-detection round-trip on connect

        Returns:
            Execution result
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address")

        # Reuse the distro the audit already detected so the executor can skip the
        # extra `cat /etc/os-release` round-trip. Prefer the caller's hint, then the
        # session's stored variant; fall back to live auto-detection when neither
        # resolves (keeps behavior identical for older/unknown sessions).
        distro_id = _distro_id_from_sub_device(sub_device_type)
        if distro_id is None and session_id is not None:
            session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
            if session is not None:
                distro_id = _distro_id_from_sub_device(session.sub_device_type)

        if dry_run:
            result = _dry_run_check_result(check_id, distro_id or "ubuntu", parameters)
            result["asset_id"] = asset_id
            result["target_ip"] = asset.ip_address
            result["distro_id"] = distro_id or "ubuntu"
            result["executed_at"] = datetime.now(timezone.utc).isoformat()
            return result

        logger.info(
            f"Executing single fix {check_id} on {asset.ip_address} "
            f"(distro: {distro_id or 'auto-detect'})"
        )

        executor = LinuxHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            sudo_password=sudo_password,
            port=ssh_port,
            distro_id=distro_id
        )

        result = executor.execute_single(check_id, parameters)

        # Update AuditResult.status if the fix passed and we know the session
        if result.get("success") and session_id is not None:
            audit_row = (
                db.query(AuditResult)
                .filter(
                    AuditResult.session_id == session_id,
                    AuditResult.check_number == check_id
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
