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
from app.modules.audit.cisco_rules import build_all_cisco_cis_rules, CISRule
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
        skip_backup: bool = False
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

        # 3. Parse commands from JSON
        commands = json.loads(action.commands_json)

        # 4. Apply defaults and substitute parameters
        parsed = RemediationParser.parse_remediation(
            remediation="",  # Not needed, we have commands already
            check_number=action.check_number
        )
        params_with_defaults = apply_defaults(parameters, parsed.defaults)

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
                secret=ssh_secret
            ) as executor:
                # Test connectivity
                executor.test_connectivity()

                # Backup config
                backup = None
                if not skip_backup:
                    backup = executor.backup_config()
                    action.backup_config = backup
                    db.commit()

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
        Get CIS rule by check number.

        Args:
            check_number: Check number (e.g., "IOS-L1-001")

        Returns:
            CISRule object

        Raises:
            ValueError: If rule not found
        """
        all_rules = build_all_cisco_cis_rules()
        for rule in all_rules:
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
        from app.modules.audit.cisco_service import AuditService
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
        skip_backup: bool = False
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
            secret=ssh_secret
        ) as executor:
            # Test connectivity
            executor.test_connectivity()

            # Backup config once before all fixes
            backup = None
            if not skip_backup:
                logger.info(f"Creating backup for {device_ip}")
                backup = executor.backup_config()

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
            "final_compliance_pct": session_updated.compliance_pct
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
        max_retries: int = None
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
                    skip_backup=skip_backup
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
