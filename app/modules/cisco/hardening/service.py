"""
Hardening Service Layer

Orchestrates the complete hardening workflow:
1. Preview - Parse remediation and generate commands
2. Execute - Apply fixes via SSH and verify results
3. History - Track all hardening attempts
"""

from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from contextlib import contextmanager
import json
import logging
import time

from app.models import (
    AuditResult,
    AuditSession,
    Asset,
    User,
    HardeningAction
)
from app.models.audit import CheckStatus
from app.modules.cisco.audit.rules import build_all_cisco_cis_rules, CISRule
from .command_parser import RemediationParser, apply_defaults
from .ssh_executor import CiscoHardeningExecutor, redact_secrets_in_output

logger = logging.getLogger(__name__)


class HardeningError(Exception):
    """Base exception for hardening operations."""
    pass


class CheckAlreadyPassingError(HardeningError):
    """Raised when trying to fix a check that already passes."""
    pass


class MissingParametersError(HardeningError):
    """Raised when required parameters are not provided."""
    pass


class HardeningExecutionError(HardeningError):
    """Raised when command execution fails."""
    pass


class HardeningVerificationError(HardeningError):
    """Raised when verification fails."""
    pass


class HardeningService:
    """Service for automated device hardening with optimizations."""

    # Configuration constants
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds
    BATCH_SIZE = 10

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        """
        Context manager for timing operations.

        Usage:
            with HardeningService._timed_operation("Fix device"):
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
    def preview_hardening(
        db: Session,
        audit_result_id: int,
        user_id: int,
        parameters: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Preview hardening commands for a failed check.

        Steps:
        1. Fetch audit result and verify it's FAIL status
        2. Block if already passing
        3. Get CIS rule by check_number
        4. Parse remediation into commands
        5. Extract required parameters
        6. Create preview record in hardening_actions
        7. Return preview response

        Args:
            db: Database session
            audit_result_id: ID of failed audit result to fix
            user_id: User performing the preview
            parameters: Optional parameters for command generation

        Returns:
            Dict with preview details:
            - action_id: int
            - check_number: str
            - check_title: str
            - commands: List[str]
            - requires_config_mode: bool
            - required_parameters: List[str]
            - optional_parameters: List[str]
            - warnings: List[str]

        Raises:
            CheckAlreadyPassingError: If check is already passing
            ValueError: If audit result not found or invalid
        """
        # 1. Fetch and validate audit result
        result = db.query(AuditResult).filter(AuditResult.id == audit_result_id).first()
        if not result:
            raise ValueError(f"Audit result {audit_result_id} not found")

        # 2. Block if check is passing
        if result.status == CheckStatus.PASS:
            raise CheckAlreadyPassingError(
                f"Check {result.check_number} is already passing. No fix needed."
            )

        # 3. Block if check is INFO level (informational only)
        if result.level == "INFO":
            raise ValueError("INFO level checks cannot be auto-fixed")

        # 4. Get the audit session and asset
        session = db.query(AuditSession).filter(
            AuditSession.id == result.session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session not found for result {audit_result_id}")

        asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
        if not asset:
            raise ValueError(f"Asset not found for audit session {session.id}")

        # 5. Get CIS rule by check_number
        rule = HardeningService._get_rule_by_check_number(result.check_number)

        # 6. Parse remediation into commands
        parsed = RemediationParser.parse_remediation(
            remediation=rule.remediation,
            check_number=result.check_number
        )

        # 7. Apply any user-provided parameters (for preview)
        if parameters:
            params_with_defaults = apply_defaults(parameters, parsed.defaults)
        else:
            params_with_defaults = parsed.defaults.copy()

        # 8. Try to substitute parameters to validate
        try:
            test_commands = RemediationParser.substitute_parameters(
                parsed.commands,
                params_with_defaults
            )
        except ValueError:
            # Missing required parameters - that's fine for preview
            test_commands = parsed.commands  # Show placeholders

        # 9. Create preview record in database
        action = HardeningAction(
            audit_result_id=audit_result_id,
            user_id=user_id,
            asset_id=asset.id,
            audit_session_id=session.id,
            check_number=result.check_number,
            check_title=result.check_title,
            action_type="preview",
            status="pending",
            commands_json=json.dumps(parsed.commands),
            requires_config_mode=parsed.requires_config_mode,
            credentials_provided=False
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        logger.info(f"Created preview action {action.id} for check {result.check_number}")

        # 10. Return preview response
        return {
            "action_id": action.id,
            "check_number": result.check_number,
            "check_title": result.check_title,
            "commands": test_commands,  # Commands with parameters substituted if provided
            "requires_config_mode": parsed.requires_config_mode,
            "required_parameters": parsed.required_parameters,
            "optional_parameters": parsed.optional_parameters,
            "warnings": parsed.warnings
        }

    @staticmethod
    def execute_hardening(
        db: Session,
        action_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str],
        parameters: Dict[str, str],
        skip_backup: bool = False,
        ssh_port: int = 22
    ) -> Dict[str, Any]:
        """
        Execute hardening commands on device.

        Steps:
        1. Fetch action record and validate
        2. Establish SSH connection
        3. Backup running config
        4. Substitute parameters in commands
        5. Execute commands via SSH
        6. Save config (write memory)
        7. Verify fix by re-running check
        8. Update action record with results
        9. Return execution response

        Args:
            db: Database session
            action_id: ID of preview action
            user_id: User executing the fix
            ssh_username: Fresh SSH username
            ssh_password: Fresh SSH password
            ssh_secret: Enable secret
            parameters: Parameter values for command substitution
            skip_backup: Skip config backup (NOT RECOMMENDED)

        Returns:
            Dict with execution results:
            - action_id: int
            - status: str ("success" or "failed")
            - verification_passed: bool
            - verification_evidence: str
            - backup_created: bool
            - commands_executed: List[str]
            - error_message: Optional[str]

        Raises:
            ValueError: If action not found or invalid
            MissingParametersError: If required parameters missing
        """
        # 1. Fetch and validate action
        action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first()
        if not action:
            raise ValueError(f"Hardening action {action_id} not found")

        if action.status != "pending":
            raise ValueError(
                f"Action {action_id} has status '{action.status}'. "
                "Only pending actions can be executed."
            )

        # 2. Get related records
        audit_result = db.query(AuditResult).filter(
            AuditResult.id == action.audit_result_id
        ).first()
        if not audit_result:
            raise ValueError(f"Audit result {action.audit_result_id} not found")

        # Re-check if still failing
        if audit_result.status == CheckStatus.PASS:
            action.status = "blocked"
            action.error_message = "Check is now passing (fixed elsewhere)"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise CheckAlreadyPassingError("Check is already passing")

        asset = db.query(Asset).filter(Asset.id == action.asset_id).first()
        if not asset:
            raise ValueError(f"Asset {action.asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        # 3. Get commands — use the live template when available so stale
        #    commands_json (from an old preview) never reaches the device.
        from .command_templates import has_template, get_template
        if has_template(action.check_number):
            template = get_template(action.check_number)
            commands = template["commands"]
            template_defaults = template.get("defaults", {})
        else:
            commands = json.loads(action.commands_json)
            template_defaults = {}

        # 4. Apply defaults and substitute parameters
        params_with_defaults = apply_defaults(parameters, template_defaults)

        try:
            final_commands = RemediationParser.substitute_parameters(
                commands,
                params_with_defaults
            )
        except ValueError as e:
            raise MissingParametersError(str(e))

        # 5. Update action to executing status
        action.action_type = "execute"
        action.status = "executing"
        action.executed_at = datetime.now(timezone.utc)
        action.credentials_provided = True
        db.commit()

        try:
            # 6. Execute via SSH
            with CiscoHardeningExecutor(
                ip=asset.ip_address,
                username=ssh_username,
                password=ssh_password,
                secret=ssh_secret,
                port=ssh_port
            ) as executor:
                # Test connectivity
                executor.test_connectivity()

                # Backup config
                backup = None
                if not skip_backup:
                    backup = executor.backup_config()
                    action.backup_config = backup
                    db.commit()
                    try:
                        from app.models.backup import DeviceBackup
                        db.add(DeviceBackup(
                            asset_id=asset.id,
                            asset_name=asset.asset_name,
                            device_ip=asset.ip_address,
                            device_type="cisco",
                            config_content=backup,
                            source="hardening",
                            hardening_action_id=action.id,
                            created_by=user_id,
                        ))
                        db.commit()
                    except Exception as _be:
                        logger.warning(f"Failed to save DeviceBackup row: {_be}")

                # Execute commands
                exec_result = executor.execute_commands(
                    final_commands,
                    requires_config_mode=action.requires_config_mode
                )

                if not exec_result["success"]:
                    # Execution failed
                    action.status = "failed"
                    action.error_message = "; ".join(exec_result["errors"])
                    action.output = redact_secrets_in_output(exec_result["output"])
                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                    logger.error(f"Hardening execution failed for action {action_id}: {action.error_message}")

                    return {
                        "action_id": action.id,
                        "status": "failed",
                        "verification_passed": False,
                        "verification_evidence": "",
                        "backup_created": backup is not None,
                        "commands_executed": final_commands,
                        "error_message": action.error_message
                    }

                # Save config
                save_output = executor.save_config()

                # Store output
                full_output = exec_result["output"] + "\n\n" + save_output
                action.output = redact_secrets_in_output(full_output)

                # 7. Verify the fix
                rule = HardeningService._get_rule_by_check_number(action.check_number)
                passed, evidence = executor.verify_check(rule)

                action.verification_passed = passed
                action.verification_evidence = evidence

                # 8. Update final status
                if passed:
                    action.status = "success"
                    audit_result = db.query(AuditResult).filter(
                        AuditResult.id == action.audit_result_id
                    ).first()
                    if audit_result:
                        audit_result.status = CheckStatus.PASS
                        audit_result.evidence_snippet = evidence
                    logger.info(f"Hardening action {action_id} completed successfully and verified")
                else:
                    action.status = "failed"
                    action.error_message = "Verification failed: check still not passing after fix"
                    logger.warning(f"Hardening action {action_id} completed but verification failed")

                action.completed_at = datetime.now(timezone.utc)
                db.commit()

                # 9. Return response
                return {
                    "action_id": action.id,
                    "status": action.status,
                    "verification_passed": passed,
                    "verification_evidence": evidence,
                    "backup_created": backup is not None,
                    "commands_executed": final_commands,
                    "error_message": action.error_message
                }

        except Exception as e:
            # Execution exception
            action.status = "failed"
            action.error_message = f"{type(e).__name__}: {str(e)}"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()

            logger.error(f"Hardening execution exception for action {action_id}: {str(e)}")
            raise

    @staticmethod
    def get_action_history(
        db: Session,
        asset_id: Optional[int] = None,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[HardeningAction]:
        """
        Get filtered hardening action history.

        Args:
            db: Database session
            asset_id: Filter by asset ID
            user_id: Filter by user ID
            status: Filter by status
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of HardeningAction records
        """
        query = db.query(HardeningAction)

        if asset_id:
            query = query.filter(HardeningAction.asset_id == asset_id)

        if user_id:
            query = query.filter(HardeningAction.user_id == user_id)

        if status:
            query = query.filter(HardeningAction.status == status)

        return (
            query.order_by(HardeningAction.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_action_by_id(db: Session, action_id: int) -> Optional[HardeningAction]:
        """Get hardening action by ID."""
        return db.query(HardeningAction).filter(HardeningAction.id == action_id).first()

    @staticmethod
    def delete_action(db: Session, action_id: int) -> bool:
        """
        Delete a hardening action record.

        Args:
            db: Database session
            action_id: Action ID to delete

        Returns:
            True if deleted

        Raises:
            ValueError: If action not found
        """
        action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first()
        if not action:
            raise ValueError(f"Hardening action {action_id} not found")

        db.delete(action)
        db.commit()

        logger.info(f"Deleted hardening action {action_id}")
        return True

    @staticmethod
    def _get_rule_by_check_number(check_number: str) -> CISRule:
        """
        Get CIS rule by check number. Accepts both CIS-X.X.X and IOS-L1-XXX formats.

        Args:
            check_number: Check number (e.g., "CIS-1.1.2" or "IOS-L1-001")

        Returns:
            CISRule object

        Raises:
            ValueError: If rule not found
        """
        from app.modules.cisco.audit.rules import build_cis_benchmark_rules
        for rule in build_cis_benchmark_rules():
            if rule.id == check_number:
                return rule
        for rule in build_all_cisco_cis_rules():
            if rule.id == check_number:
                return rule
        raise ValueError(f"CIS rule {check_number} not found")

    # ==================== AUTO-HARDENING METHODS ====================

    @staticmethod
    def _is_check_fixable(
        check_number: str,
        provided_params: Optional[Dict[str, str]] = None
    ) -> tuple[bool, List[str]]:
        """
        Determine if a check can be auto-fixed.

        Args:
            check_number: CIS check number
            provided_params: Parameters user provided upfront

        Returns:
            (is_fixable: bool, missing_params: List[str])

        Logic:
            - If no template exists: NOT fixable
            - If template has no required params: fixable
            - If all required params provided: fixable
            - Otherwise: NOT fixable
        """
        from .command_templates import has_template, get_template

        if not has_template(check_number):
            return False, ["NO_TEMPLATE"]

        template = get_template(check_number)
        required = template.get("required_params", [])

        if not required:
            return True, []

        if provided_params:
            missing = [p for p in required if p not in provided_params]
            return len(missing) == 0, missing

        return False, required

    @staticmethod
    def _categorize_failures(
        failures: List[AuditResult],
        provided_params: Optional[Dict[str, str]] = None
    ) -> Dict[str, List[Dict]]:
        """
        Categorize failures into fixable and unfixable.

        Returns:
            {
                "fixable": [{"id": ..., "check_number": ..., ...}],
                "unfixable": [{"id": ..., "check_number": ..., "missing_params": [...]}]
            }
        """
        fixable = []
        unfixable = []

        for result in failures:
            is_fixable, missing_params = HardeningService._is_check_fixable(
                result.check_number,
                provided_params
            )

            result_dict = {
                "result_id": result.id,
                "check_number": result.check_number,
                "check_title": result.check_title,
                "severity": result.severity
            }

            if is_fixable:
                fixable.append(result_dict)
            else:
                result_dict["missing_params"] = missing_params
                unfixable.append(result_dict)

        return {"fixable": fixable, "unfixable": unfixable}

    @staticmethod
    def auto_audit_device(
        db: Session,
        user_id: int,
        ip_address: str,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        profile: str = "L1",
        asset_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Perform audit on device without requiring pre-existing asset.

        Steps:
        1. Create temporary asset if needed OR use provided asset_id
        2. Run CIS audit (reuse audit service logic)
        3. Store audit session + results in DB
        4. Return summary with fixable failures

        Args:
            ip_address: Device IP (required)
            ssh_username/password/secret: Fresh credentials
            profile: CIS profile (L1 or FULL)
            asset_id: Optional link to existing asset

        Returns:
            {
                "audit_session_id": int,
                "device_ip": str,
                "total_checks": int,
                "passed": int,
                "failed": int,
                "compliance_pct": float,
                "fixable_failures": List[Dict],  # Checks we can auto-fix
                "unfixable_failures": List[Dict]  # Need parameters
            }
        """
        from app.modules.cisco.audit.service import AuditService
        from app.models.audit import DeviceType

        logger.info(f"Starting auto-audit for device {ip_address}")

        # If no asset_id provided, create a temporary asset
        temp_asset_created = False
        if asset_id is None:
            logger.info(f"Creating temporary asset for {ip_address}")
            temp_asset = Asset(
                asset_name=f"Auto-Audit-{ip_address}",
                hostname=f"auto-{ip_address}",
                ip_address=ip_address,
                asset_type_id=1,  # Assuming type 1 exists (network device)
                status="active"
            )
            db.add(temp_asset)
            db.commit()
            db.refresh(temp_asset)
            asset_id = temp_asset.id
            temp_asset_created = True
            logger.info(f"Created temporary asset ID {asset_id}")

        # Execute audit using existing audit service
        session = AuditService.execute_cisco_audit(
            db=db,
            asset_id=asset_id,
            user_id=user_id,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_secret=ssh_secret,
            profile=profile
        )

        session_id = session.id

        # Get the audit session
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Audit session {session_id} not found after audit")

        # Get all failed results
        failed_results = db.query(AuditResult).filter(
            AuditResult.session_id == session_id,
            AuditResult.status == CheckStatus.FAIL
        ).all()

        # Categorize failures into fixable and unfixable
        categorized = HardeningService._categorize_failures(failed_results, None)

        logger.info(
            f"Auto-audit complete for {ip_address}: "
            f"{len(categorized['fixable'])} fixable, "
            f"{len(categorized['unfixable'])} unfixable"
        )

        return {
            "audit_session_id": session_id,
            "device_ip": ip_address,
            "total_checks": session.total_checks,
            "passed": session.passed_checks,
            "failed": session.failed_checks,
            "compliance_pct": session.compliance_pct,
            "fixable_failures": categorized["fixable"],
            "unfixable_failures": categorized["unfixable"]
        }

    @staticmethod
    def auto_fix_all_failures(
        db: Session,
        audit_session_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        parameters: Optional[Dict[str, str]] = None,
        skip_backup: bool = False,
        ssh_port: int = 22
    ) -> Dict[str, Any]:
        """
        Automatically fix all failures from an audit session.

        Steps:
        1. Get all failed results from audit session
        2. For each failure:
           a. Check if we have a template
           b. Check if parameters are needed
           c. If fixable: apply fix
           d. If needs params: skip or use provided params
        3. Re-audit fixed checks to verify
        4. Return summary

        Args:
            db: Database session
            audit_session_id: Audit session to fix
            user_id: User performing fixes
            ssh_username/password/secret: Fresh SSH credentials
            parameters: Optional parameters for checks that need them
            skip_backup: Skip config backup (NOT RECOMMENDED)

        Returns:
            {
                "audit_session_id": int,
                "total_failures": int,
                "fixed_count": int,
                "skipped_count": int,
                "failed_count": int,
                "actions": List[int],  # HardeningAction IDs
                "final_compliance_pct": float
            }
        """
        logger.info(f"Starting auto-fix for audit session {audit_session_id}")

        # Get audit session
        session = db.query(AuditSession).filter(
            AuditSession.id == audit_session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session {audit_session_id} not found")

        # Get device IP
        device_ip = session.target_ip
        if not device_ip:
            raise ValueError(f"Audit session {audit_session_id} has no target IP")

        # Get all failed results
        failed_results = db.query(AuditResult).filter(
            AuditResult.session_id == audit_session_id,
            AuditResult.status == CheckStatus.FAIL
        ).all()

        total_failures = len(failed_results)
        logger.info(f"Found {total_failures} failed checks to fix")

        # Categorize into fixable and unfixable
        categorized = HardeningService._categorize_failures(failed_results, parameters)
        fixable = categorized["fixable"]
        unfixable = categorized["unfixable"]

        fixed_count = 0
        failed_count = 0
        action_ids = []

        # Connect to device once for all fixes
        with CiscoHardeningExecutor(
            ip=device_ip,
            username=ssh_username,
            password=ssh_password,
            secret=ssh_secret,
            port=ssh_port
        ) as executor:
            # Test connectivity
            executor.test_connectivity()

            # Backup config once before all fixes
            backup = None
            if not skip_backup:
                logger.info(f"Creating backup for {device_ip}")
                backup = executor.backup_config()
                try:
                    from app.models.backup import DeviceBackup
                    _asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
                    db.add(DeviceBackup(
                        asset_id=session.asset_id,
                        asset_name=_asset.asset_name if _asset else None,
                        device_ip=device_ip,
                        device_type="cisco",
                        config_content=backup,
                        source="hardening",
                        hardening_action_id=None,
                        created_by=user_id,
                    ))
                    db.commit()
                except Exception as _be:
                    logger.warning(f"Failed to save DeviceBackup row: {_be}")

            # Process each fixable check
            for fix_item in fixable:
                result_id = fix_item["result_id"]
                check_number = fix_item["check_number"]

                try:
                    logger.info(f"Fixing check {check_number} (result {result_id})")

                    # Get the audit result
                    audit_result = db.query(AuditResult).filter(
                        AuditResult.id == result_id
                    ).first()

                    # Get CIS rule
                    rule = HardeningService._get_rule_by_check_number(check_number)

                    # Parse remediation
                    parsed = RemediationParser.parse_remediation(
                        remediation=rule.remediation,
                        check_number=check_number
                    )

                    # Apply parameters
                    params_with_defaults = apply_defaults(parameters or {}, parsed.defaults)
                    final_commands = RemediationParser.substitute_parameters(
                        parsed.commands,
                        params_with_defaults
                    )

                    # Create hardening action record
                    action = HardeningAction(
                        audit_result_id=result_id,
                        user_id=user_id,
                        asset_id=session.asset_id,  # May be None
                        audit_session_id=audit_session_id,
                        check_number=check_number,
                        check_title=audit_result.check_title,
                        action_type="execute",
                        status="executing",
                        commands_json=json.dumps(final_commands),
                        requires_config_mode=parsed.requires_config_mode,
                        credentials_provided=True,
                        backup_config=backup if not skip_backup else None,
                        executed_at=datetime.now(timezone.utc)
                    )
                    db.add(action)
                    db.commit()
                    db.refresh(action)

                    action_ids.append(action.id)

                    # Execute commands
                    exec_result = executor.execute_commands(
                        final_commands,
                        requires_config_mode=parsed.requires_config_mode
                    )

                    if not exec_result["success"]:
                        action.status = "failed"
                        action.error_message = "; ".join(exec_result["errors"])
                        action.output = redact_secrets_in_output(exec_result["output"])
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        failed_count += 1
                        logger.warning(f"Fix failed for {check_number}: {action.error_message}")
                        continue

                    # Store output
                    action.output = redact_secrets_in_output(exec_result["output"])

                    # Verify fix
                    passed, evidence = executor.verify_check(rule)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        audit_result.status = CheckStatus.PASS
                        audit_result.evidence_snippet = evidence
                        fixed_count += 1
                        logger.info(f"Successfully fixed {check_number}")
                    else:
                        action.status = "failed"
                        action.error_message = "Verification failed: check still failing after fix"
                        failed_count += 1
                        logger.warning(f"Fix applied but verification failed for {check_number}")

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except Exception as e:
                    logger.error(f"Exception fixing {check_number}: {str(e)}")
                    failed_count += 1
                    # Action may or may not exist - update if it does
                    if 'action' in locals():
                        action.status = "failed"
                        action.error_message = f"{type(e).__name__}: {str(e)}"
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()

            # Save config once after all fixes
            if fixed_count > 0:
                logger.info(f"Saving configuration for {device_ip}")
                executor.save_config()

        # Calculate final compliance
        session_updated = db.query(AuditSession).filter(
            AuditSession.id == audit_session_id
        ).first()

        logger.info(
            f"Auto-fix complete: {fixed_count} fixed, "
            f"{failed_count} failed, {len(unfixable)} skipped"
        )

        return {
            "audit_session_id": audit_session_id,
            "total_failures": total_failures,
            "fixed_count": fixed_count,
            "skipped_count": len(unfixable),
            "failed_count": failed_count,
            "actions": action_ids,
            "final_compliance_pct": session_updated.compliance_pct if session_updated else None
        }

    @staticmethod
    def execute_hardening_with_retry(
        db: Session,
        action_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str],
        parameters: Dict[str, str],
        skip_backup: bool = False,
        max_retries: int = None,
        ssh_port: int = 22
    ) -> Dict[str, Any]:
        """
        Execute hardening with automatic retry on transient failures.

        Features:
        - Automatic retry up to max_retries attempts
        - 2-second delay between retries
        - Logs each attempt
        - Only retries on transient failures

        Args:
            max_retries: Maximum retry attempts (default: 3)
            ... (same as execute_hardening)

        Returns:
            Same as execute_hardening()

        Raises:
            HardeningExecutionError: After all retries exhausted
        """
        max_retries = max_retries or HardeningService.MAX_RETRIES

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(
                    f"Hardening execution attempt {attempt}/{max_retries} "
                    f"for action {action_id}"
                )

                return HardeningService.execute_hardening(
                    db=db,
                    action_id=action_id,
                    user_id=user_id,
                    ssh_username=ssh_username,
                    ssh_password=ssh_password,
                    ssh_secret=ssh_secret,
                    parameters=parameters,
                    skip_backup=skip_backup,
                    ssh_port=ssh_port
                )

            except Exception as e:
                error_msg = str(e)
                logger.warning(
                    f"Attempt {attempt}/{max_retries} failed for action {action_id}: "
                    f"{error_msg}"
                )

                if attempt < max_retries:
                    logger.info(f"Retrying in {HardeningService.RETRY_DELAY} seconds...")
                    time.sleep(HardeningService.RETRY_DELAY)
                else:
                    raise HardeningExecutionError(
                        f"Hardening failed after {max_retries} attempts: {error_msg}"
                    )

    @staticmethod
    def get_action_statistics(
        db: Session,
        asset_id: Optional[int] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive statistics about hardening actions.

        Args:
            db: Database session
            asset_id: Optional filter by asset
            user_id: Optional filter by user

        Returns:
            {
                "total_actions": int,
                "by_status": {"success": int, "failed": int, "pending": int},
                "by_type": {"execute": int, "preview": int},
                "total_executions": int,
                "successful_executions": int,
                "success_rate": float,
                "most_common_checks": [{"check_number": str, "count": int}, ...]
            }
        """
        from sqlalchemy import func

        query = db.query(HardeningAction)

        if asset_id:
            query = query.filter(HardeningAction.asset_id == asset_id)
        if user_id:
            query = query.filter(HardeningAction.user_id == user_id)

        all_actions = query.all()
        total_actions = len(all_actions)

        # Group by status
        by_status = {}
        for action in all_actions:
            status = action.status
            by_status[status] = by_status.get(status, 0) + 1

        # Group by type
        by_type = {}
        for action in all_actions:
            action_type = action.action_type
            by_type[action_type] = by_type.get(action_type, 0) + 1

        # Calculate success rate for executions
        executions = [a for a in all_actions if a.action_type == "execute"]
        total_executions = len(executions)
        successful_executions = len([a for a in executions if a.status == "success"])
        success_rate = (
            (successful_executions / total_executions * 100)
            if total_executions > 0
            else 0.0
        )

        # Most common checks
        check_counts = {}
        for action in all_actions:
            check = action.check_number
            check_counts[check] = check_counts.get(check, 0) + 1

        most_common_checks = [
            {"check_number": check, "count": count}
            for check, count in sorted(
                check_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        ]

        return {
            "total_actions": total_actions,
            "by_status": by_status,
            "by_type": by_type,
            "total_executions": total_executions,
            "successful_executions": successful_executions,
            "success_rate": round(success_rate, 2),
            "most_common_checks": most_common_checks
        }

    # ==================== THREE-MODE HARDENING METHODS ====================

    @staticmethod
    def get_session_parameters(
        db: Session,
        audit_session_id: int,
        check_ids: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Get aggregated parameters for hardening an audit session.

        This endpoint supports the "Fix All" mode by collecting all required
        parameters across selected failed checks.

        Args:
            db: Database session
            audit_session_id: Audit session to analyze
            check_ids: Optional list of specific check result IDs to include
                      (if None, includes all failed checks)

        Returns:
            {
                "session_id": 123,
                "total_failed": 8,
                "selected_count": 5,
                "fixable_count": 4,
                "unfixable_count": 1,
                "required_parameters": {...},
                "auto_fixable_checks": [...],
                "needs_params_checks": [...]
            }
        """
        from .parameter_metadata import (
            aggregate_parameters_for_checks,
            categorize_checks_by_fixability,
            check_has_required_params
        )
        from .command_templates import has_template

        # Validate session exists
        session = db.query(AuditSession).filter(
            AuditSession.id == audit_session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session {audit_session_id} not found")

        # Get failed results
        query = db.query(AuditResult).filter(
            AuditResult.session_id == audit_session_id,
            AuditResult.status == CheckStatus.FAIL
        )

        # Filter by specific check IDs if provided
        if check_ids:
            query = query.filter(AuditResult.id.in_(check_ids))

        failed_results = query.all()

        if not failed_results:
            return {
                "session_id": audit_session_id,
                "total_failed": 0,
                "selected_count": 0,
                "fixable_count": 0,
                "unfixable_count": 0,
                "required_parameters": {},
                "auto_fixable_checks": [],
                "needs_params_checks": []
            }

        # Extract check numbers
        check_numbers = [r.check_number for r in failed_results]

        # Filter to only checks with templates
        templated_checks = [cn for cn in check_numbers if has_template(cn)]
        no_template_checks = [cn for cn in check_numbers if not has_template(cn)]

        # Categorize checks
        categorized = categorize_checks_by_fixability(templated_checks)

        # Aggregate parameters for all templated checks
        aggregated_params = aggregate_parameters_for_checks(templated_checks)

        # Build result ID map for frontend
        check_result_map = {r.check_number: r.id for r in failed_results}

        return {
            "session_id": audit_session_id,
            "total_failed": len(check_numbers),
            "selected_count": len(check_numbers) if not check_ids else len(check_ids),
            "fixable_count": len(templated_checks),
            "unfixable_count": len(no_template_checks),
            "required_parameters": aggregated_params,
            "auto_fixable_checks": [
                {
                    "check_number": cn,
                    "result_id": check_result_map.get(cn)
                }
                for cn in categorized["auto_fixable"]
            ],
            "needs_params_checks": [
                {
                    "check_number": cn,
                    "result_id": check_result_map.get(cn)
                }
                for cn in categorized["needs_params"]
            ],
            "no_template_checks": [
                {
                    "check_number": cn,
                    "result_id": check_result_map.get(cn),
                    "reason": "No remediation template available"
                }
                for cn in no_template_checks
            ]
        }

    @staticmethod
    def get_auto_harden_preview(
        db: Session,
        audit_session_id: int
    ) -> Dict[str, Any]:
        """
        Get preview of automatic hardening with CIS defaults.

        Shows what will be applied and what will be skipped before user confirms.

        Args:
            db: Database session
            audit_session_id: Audit session to preview

        Returns:
            {
                "auto_fixable_count": 5,
                "skipped_count": 3,
                "checks_with_defaults": [
                    {
                        "check_number": "IOS-L1-002",
                        "check_title": "Set exec timeout",
                        "result_id": 123,
                        "defaults": {"TIMEOUT_MIN": "5", "TIMEOUT_SEC": "0"}
                    },
                    ...
                ],
                "skipped_checks": [
                    {
                        "check_number": "IOS-L1-001",
                        "check_title": "Use enable secret",
                        "result_id": 124,
                        "reason": "Requires STRONG_SECRET parameter"
                    },
                    ...
                ]
            }
        """
        from .parameter_metadata import (
            is_check_auto_fixable,
            get_check_defaults,
            get_required_parameters_for_check
        )
        from .command_templates import has_template

        # Validate session exists
        session = db.query(AuditSession).filter(
            AuditSession.id == audit_session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session {audit_session_id} not found")

        # Get failed results
        failed_results = db.query(AuditResult).filter(
            AuditResult.session_id == audit_session_id,
            AuditResult.status == CheckStatus.FAIL
        ).all()

        checks_with_defaults = []
        skipped_checks = []

        for result in failed_results:
            check_number = result.check_number

            # Skip checks without templates
            if not has_template(check_number):
                skipped_checks.append({
                    "check_number": check_number,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "reason": "No remediation template available"
                })
                continue

            # Check if auto-fixable
            if is_check_auto_fixable(check_number):
                defaults = get_check_defaults(check_number)
                checks_with_defaults.append({
                    "check_number": check_number,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "defaults": defaults
                })
            else:
                # Get required parameters for explanation
                required_params = get_required_parameters_for_check(check_number)
                param_names = [p.name for p in required_params]
                skipped_checks.append({
                    "check_number": check_number,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "reason": f"Requires {', '.join(param_names)} parameter(s)"
                })

        return {
            "session_id": audit_session_id,
            "auto_fixable_count": len(checks_with_defaults),
            "skipped_count": len(skipped_checks),
            "checks_with_defaults": checks_with_defaults,
            "skipped_checks": skipped_checks
        }

    @staticmethod
    def auto_harden_with_defaults(
        db: Session,
        audit_session_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        skip_backup: bool = False,
        ssh_port: int = 22
    ) -> Dict[str, Any]:
        """
        Automatically harden device using only CIS default values.

        This differs from auto_fix_all_failures by:
        - ONLY applying checks where all parameters have defaults
        - NOT accepting user-provided parameters
        - Skipping ALL checks that require user input

        Args:
            db: Database session
            audit_session_id: Audit session to fix
            user_id: User performing the hardening
            ssh_username/password/secret: SSH credentials
            skip_backup: Skip config backup (NOT RECOMMENDED)

        Returns:
            {
                "audit_session_id": int,
                "fixed_count": int,
                "skipped_count": int,
                "failed_count": int,
                "actions": List[int],
                "fixed_checks": List[Dict],
                "skipped_checks": List[Dict]
            }
        """
        from .command_templates import has_template, get_template

        logger.info(f"Starting auto-harden with defaults for session {audit_session_id}")

        # Get session
        session = db.query(AuditSession).filter(
            AuditSession.id == audit_session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session {audit_session_id} not found")

        device_ip = session.target_ip
        if not device_ip:
            raise ValueError(f"Audit session {audit_session_id} has no target IP")

        # Get failed results
        failed_results = db.query(AuditResult).filter(
            AuditResult.session_id == audit_session_id,
            AuditResult.status == CheckStatus.FAIL
        ).all()

        # Separate auto-fixable from skipped
        auto_fixable = []
        skipped = []

        for result in failed_results:
            check_number = result.check_number

            # Fixability is decided from the command template (which is CIS-aware via
            # CIS_SECTION_TO_IOS), not from parameter_metadata. A template's
            # `required_params` lists exactly the placeholders that have no default and
            # therefore need user input — so a check is auto-fixable-with-defaults only
            # when that list is empty. This keeps the decision consistent with what
            # substitution actually does below (no "Missing required parameters" surprises).
            if not has_template(check_number):
                skipped.append({
                    "check_number": check_number,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "reason": "No template"
                })
                continue

            if get_template(check_number).get("required_params"):
                skipped.append({
                    "check_number": check_number,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "reason": "Requires user input"
                })
                continue

            auto_fixable.append(result)

        if not auto_fixable:
            logger.info("No auto-fixable checks found")
            return {
                "audit_session_id": audit_session_id,
                "fixed_count": 0,
                "skipped_count": len(skipped),
                "failed_count": 0,
                "actions": [],
                "fixed_checks": [],
                "skipped_checks": skipped
            }

        fixed_count = 0
        failed_count = 0
        action_ids = []
        fixed_checks = []

        # Connect to device
        with CiscoHardeningExecutor(
            ip=device_ip,
            username=ssh_username,
            password=ssh_password,
            secret=ssh_secret,
            port=ssh_port
        ) as executor:
            executor.test_connectivity()

            # Backup once
            backup = None
            if not skip_backup:
                logger.info(f"Creating backup for {device_ip}")
                backup = executor.backup_config()
                try:
                    from app.models.backup import DeviceBackup
                    _asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
                    db.add(DeviceBackup(
                        asset_id=session.asset_id,
                        asset_name=_asset.asset_name if _asset else None,
                        device_ip=device_ip,
                        device_type="cisco",
                        config_content=backup,
                        source="hardening",
                        hardening_action_id=None,
                        created_by=user_id,
                    ))
                    db.commit()
                except Exception as _be:
                    logger.warning(f"Failed to save DeviceBackup row: {_be}")

            # Process each auto-fixable check
            for result in auto_fixable:
                check_number = result.check_number

                try:
                    logger.info(f"Auto-fixing {check_number}")

                    # Get rule and parse
                    rule = HardeningService._get_rule_by_check_number(check_number)
                    parsed = RemediationParser.parse_remediation(
                        remediation=rule.remediation,
                        check_number=check_number
                    )

                    # Substitute using the template's own (contextually-correct) defaults.
                    # Because the categorization above only admits checks with no
                    # required_params, every remaining placeholder is covered here.
                    defaults = parsed.defaults
                    final_commands = RemediationParser.substitute_parameters(
                        parsed.commands,
                        apply_defaults({}, defaults)
                    )

                    # Create action record
                    action = HardeningAction(
                        audit_result_id=result.id,
                        user_id=user_id,
                        asset_id=session.asset_id,
                        audit_session_id=audit_session_id,
                        check_number=check_number,
                        check_title=result.check_title,
                        action_type="execute",
                        status="executing",
                        commands_json=json.dumps(final_commands),
                        requires_config_mode=parsed.requires_config_mode,
                        credentials_provided=True,
                        backup_config=backup if not skip_backup else None,
                        executed_at=datetime.now(timezone.utc)
                    )
                    db.add(action)
                    db.commit()
                    db.refresh(action)
                    action_ids.append(action.id)

                    # Execute commands
                    exec_result = executor.execute_commands(
                        final_commands,
                        requires_config_mode=parsed.requires_config_mode
                    )

                    if not exec_result["success"]:
                        action.status = "failed"
                        action.error_message = "; ".join(exec_result["errors"])
                        action.output = redact_secrets_in_output(exec_result["output"])
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        failed_count += 1
                        continue

                    # Store output
                    action.output = redact_secrets_in_output(exec_result["output"])

                    # Verify
                    passed, evidence = executor.verify_check(rule)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        fixed_count += 1
                        fixed_checks.append({
                            "check_number": check_number,
                            "check_title": result.check_title,
                            "action_id": action.id,
                            "defaults_applied": defaults
                        })
                        logger.info(f"Successfully auto-fixed {check_number}")
                    else:
                        action.status = "failed"
                        action.error_message = "Verification failed after fix"
                        failed_count += 1

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except ValueError as e:
                    # A template whose commands still contain unsubstituted placeholders
                    # despite empty required_params is a template-authoring bug, not a
                    # device failure. Skip it (so it can't spam errors or be miscounted as
                    # a failed remediation) and surface it for follow-up.
                    logger.warning(f"Skipping {check_number}: unresolved template parameters: {e}")
                    skipped.append({
                        "check_number": check_number,
                        "check_title": result.check_title,
                        "result_id": result.id,
                        "reason": "Requires user input"
                    })

                except Exception as e:
                    logger.error(f"Error auto-fixing {check_number}: {str(e)}")
                    failed_count += 1

            # Save config once after all fixes
            if fixed_count > 0:
                logger.info(f"Saving configuration for {device_ip}")
                executor.save_config()

        logger.info(
            f"Auto-harden complete: {fixed_count} fixed, "
            f"{failed_count} failed, {len(skipped)} skipped"
        )

        return {
            "audit_session_id": audit_session_id,
            "fixed_count": fixed_count,
            "skipped_count": len(skipped),
            "failed_count": failed_count,
            "actions": action_ids,
            "fixed_checks": fixed_checks,
            "skipped_checks": skipped
        }

    @staticmethod
    def batch_execute_selected(
        db: Session,
        audit_session_id: int,
        user_id: int,
        check_ids: List[int],
        parameters: Dict[str, str],
        ssh_username: str,
        ssh_password: str,
        ssh_secret: Optional[str] = None,
        skip_backup: bool = False,
        ssh_port: int = 22
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected checks with user-provided parameters.

        This is the "Fix All" mode where users select specific checks and
        provide all required parameters.

        Args:
            db: Database session
            audit_session_id: Audit session ID
            user_id: User performing hardening
            check_ids: List of AuditResult IDs to fix
            parameters: User-provided parameters for all checks
            ssh_username/password/secret: SSH credentials
            skip_backup: Skip config backup

        Returns:
            {
                "audit_session_id": int,
                "total_selected": int,
                "fixed_count": int,
                "failed_count": int,
                "skipped_count": int,
                "actions": List[int],
                "results": List[Dict]
            }
        """
        from .parameter_metadata import get_check_defaults
        from .command_templates import has_template

        logger.info(f"Starting batch execute for {len(check_ids)} selected checks")

        # Get session
        session = db.query(AuditSession).filter(
            AuditSession.id == audit_session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session {audit_session_id} not found")

        device_ip = session.target_ip
        if not device_ip:
            raise ValueError(f"Audit session {audit_session_id} has no target IP")

        # Get selected results
        results = db.query(AuditResult).filter(
            AuditResult.id.in_(check_ids),
            AuditResult.session_id == audit_session_id
        ).all()

        if not results:
            raise ValueError("No valid checks selected")

        fixed_count = 0
        failed_count = 0
        skipped_count = 0
        action_ids = []
        execution_results = []

        with CiscoHardeningExecutor(
            ip=device_ip,
            username=ssh_username,
            password=ssh_password,
            secret=ssh_secret,
            port=ssh_port
        ) as executor:
            executor.test_connectivity()

            # Backup once
            backup = None
            if not skip_backup:
                logger.info(f"Creating backup for {device_ip}")
                backup = executor.backup_config()
                try:
                    from app.models.backup import DeviceBackup
                    _asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
                    db.add(DeviceBackup(
                        asset_id=session.asset_id,
                        asset_name=_asset.asset_name if _asset else None,
                        device_ip=device_ip,
                        device_type="cisco",
                        config_content=backup,
                        source="hardening",
                        hardening_action_id=None,
                        created_by=user_id,
                    ))
                    db.commit()
                except Exception as _be:
                    logger.warning(f"Failed to save DeviceBackup row: {_be}")

            for result in results:
                check_number = result.check_number

                # Skip if no template
                if not has_template(check_number):
                    skipped_count += 1
                    execution_results.append({
                        "check_number": check_number,
                        "check_title": result.check_title,
                        "status": "skipped",
                        "reason": "No template available"
                    })
                    continue

                # Skip if already passing
                if result.status == CheckStatus.PASS:
                    skipped_count += 1
                    execution_results.append({
                        "check_number": check_number,
                        "check_title": result.check_title,
                        "status": "skipped",
                        "reason": "Already passing"
                    })
                    continue

                try:
                    logger.info(f"Fixing {check_number}")

                    # Get rule and parse
                    rule = HardeningService._get_rule_by_check_number(check_number)
                    parsed = RemediationParser.parse_remediation(
                        remediation=rule.remediation,
                        check_number=check_number
                    )

                    # Merge user parameters with defaults
                    defaults = get_check_defaults(check_number)
                    merged_params = apply_defaults(parameters, defaults)

                    # Substitute parameters
                    try:
                        final_commands = RemediationParser.substitute_parameters(
                            parsed.commands,
                            merged_params
                        )
                    except ValueError as e:
                        skipped_count += 1
                        execution_results.append({
                            "check_number": check_number,
                            "check_title": result.check_title,
                            "status": "skipped",
                            "reason": f"Missing parameters: {str(e)}"
                        })
                        continue

                    # Create action record
                    action = HardeningAction(
                        audit_result_id=result.id,
                        user_id=user_id,
                        asset_id=session.asset_id,
                        audit_session_id=audit_session_id,
                        check_number=check_number,
                        check_title=result.check_title,
                        action_type="execute",
                        status="executing",
                        commands_json=json.dumps(final_commands),
                        requires_config_mode=parsed.requires_config_mode,
                        credentials_provided=True,
                        backup_config=backup if not skip_backup else None,
                        executed_at=datetime.now(timezone.utc)
                    )
                    db.add(action)
                    db.commit()
                    db.refresh(action)
                    action_ids.append(action.id)

                    # Execute
                    exec_result = executor.execute_commands(
                        final_commands,
                        requires_config_mode=parsed.requires_config_mode
                    )

                    if not exec_result["success"]:
                        action.status = "failed"
                        action.error_message = "; ".join(exec_result["errors"])
                        action.output = redact_secrets_in_output(exec_result["output"])
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        failed_count += 1
                        execution_results.append({
                            "check_number": check_number,
                            "check_title": result.check_title,
                            "status": "failed",
                            "action_id": action.id,
                            "error": action.error_message
                        })
                        continue

                    action.output = redact_secrets_in_output(exec_result["output"])

                    # Verify
                    passed, evidence = executor.verify_check(rule)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        fixed_count += 1
                        execution_results.append({
                            "check_number": check_number,
                            "check_title": result.check_title,
                            "status": "success",
                            "action_id": action.id,
                            "verification_passed": True
                        })
                    else:
                        action.status = "failed"
                        action.error_message = "Verification failed"
                        failed_count += 1
                        execution_results.append({
                            "check_number": check_number,
                            "check_title": result.check_title,
                            "status": "failed",
                            "action_id": action.id,
                            "verification_passed": False
                        })

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except Exception as e:
                    logger.error(f"Error fixing {check_number}: {str(e)}")
                    failed_count += 1
                    execution_results.append({
                        "check_number": check_number,
                        "check_title": result.check_title,
                        "status": "failed",
                        "error": str(e)
                    })

            # Save config after all fixes
            if fixed_count > 0:
                executor.save_config()

        logger.info(
            f"Batch execute complete: {fixed_count} fixed, "
            f"{failed_count} failed, {skipped_count} skipped"
        )

        return {
            "audit_session_id": audit_session_id,
            "total_selected": len(check_ids),
            "fixed_count": fixed_count,
            "failed_count": failed_count,
            "skipped_count": skipped_count,
            "actions": action_ids,
            "results": execution_results
        }
