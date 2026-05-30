"""
MongoDB Hardening Service Layer

Provides high-level hardening operations for MongoDB servers:
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

from .command_templates import get_all_supported_checks, get_mongodb_hardening_template
from .parameter_metadata import (
    MONGODB_CHECK_PARAMETER_MAP,
    aggregate_mongodb_parameters_for_checks,
    categorize_mongodb_checks_by_fixability,
    get_mongodb_auto_fix_preview,
    get_mongodb_check_defaults,
    is_mongodb_check_auto_fixable,
)
from .ssh_executor import MongoDBHardeningBatchExecutor

logger = logging.getLogger(__name__)


class MongoDBHardeningService:
    """Service for MongoDB CIS hardening operations."""

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

        Args:
            db:         Database session
            session_id: Audit session ID

        Returns:
            {
                "session_id": ...,
                "total_failed": ...,
                "parameters": {param_name: {metadata + checks}},
                "categorized_checks": {auto_fixable, needs_params, not_supported},
                "failed_checks": [{check_id, title, severity, auto_fixable, ...}]
            }
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

        if session.device_type != DeviceType.MONGODB:
            raise ValueError(f"Session {session_id} is not a MongoDB audit session")

        failed_results = (
            db.query(AuditResult)
            .filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL,
            )
            .all()
        )

        failed_check_ids = [r.check_number for r in failed_results]
        categorized = categorize_mongodb_checks_by_fixability(failed_check_ids)
        parameters = aggregate_mongodb_parameters_for_checks(categorized["needs_params"])

        failed_checks = []
        for r in failed_results:
            template = get_mongodb_hardening_template(r.check_number)
            failed_checks.append({
                "check_id": r.check_number,
                "check_title": r.check_title,
                "severity": r.severity,
                "level": r.level,
                "has_template": template is not None,
                "auto_fixable": is_mongodb_check_auto_fixable(r.check_number),
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

        Shows which failed checks are auto-fixable and their default values.
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
        categorized = categorize_mongodb_checks_by_fixability(failed_check_ids)
        preview = get_mongodb_auto_fix_preview(failed_check_ids)

        check_titles = {r.check_number: r.check_title for r in failed_results}
        for item in preview:
            item["check_title"] = check_titles.get(item["check_id"], "Unknown")
            template = get_mongodb_hardening_template(item["check_id"])
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
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22,
    ) -> Dict[str, Any]:
        """
        Execute automatic hardening using CIS default values only.

        Skips checks that require custom parameters (e.g. TLS cert paths).

        Returns:
            Execution summary with per-check results.
        """
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")

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
            f"Auto-hardening {len(failed_check_ids)} failed MongoDB checks on {asset.ip_address}"
        )

        executor = MongoDBHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            ssh_port=ssh_port,
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
        db.commit()

        result["session_id"] = session_id
        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"MongoDB auto-hardening completed: "
            f"{result['successful']}/{result['auto_fixable']} successful"
        )
        return result

    @staticmethod
    def batch_execute_selected(
        db: Session,
        session_id: int,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        checks: List[Dict[str, Any]],
        ssh_port: int = 22,
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        Args:
            checks: List of {"check_id": str, "parameters": {name: value}} dicts
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        logger.info(
            f"Batch MongoDB hardening: {len(checks)} checks on {asset.ip_address}"
        )

        executor = MongoDBHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            ssh_port=ssh_port,
        )

        result = executor.execute_selected(checks)

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
        db.commit()

        result["session_id"] = session_id
        result["asset_id"] = asset_id
        result["target_ip"] = asset.ip_address
        result["executed_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"MongoDB batch hardening completed: "
            f"{result['successful']}/{result['total']} successful"
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
        session_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute hardening for a single check with given parameters."""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        logger.info(f"Single MongoDB fix: {check_id} on {asset.ip_address}")

        executor = MongoDBHardeningBatchExecutor(
            ip=asset.ip_address,
            username=ssh_username,
            password=ssh_password,
            ssh_port=ssh_port,
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
            template = get_mongodb_hardening_template(check_id)
            auto_fixable = is_mongodb_check_auto_fixable(check_id)
            defaults = get_mongodb_check_defaults(check_id)

            checks_info.append({
                "check_id": check_id,
                "description": template.description if template else None,
                "auto_fixable": auto_fixable,
                "requires_service_restart": template.requires_service_restart if template else False,
                "default_parameters": defaults,
            })

        return {
            "total_supported": len(supported),
            "checks": checks_info,
        }
