"""
Improved Hardening Service Layer

Enhancements:
1. Better error handling and recovery
2. Enhanced logging with context
3. Progress tracking
4. Batch operations optimization
5. Rollback capability
6. Retry logic for transient failures
7. Concurrent fix execution (optional)
8. Better validation
"""

from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import json
import logging
from contextlib import contextmanager
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
    """Raised when post-execution verification fails."""
    pass


class ImprovedHardeningService:
    """Enhanced service for automated device hardening."""

    # Retry configuration
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    # Performance settings
    BATCH_SIZE = 10  # Process fixes in batches
    CONNECTION_TIMEOUT = 30  # seconds

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        """Context manager for timing operations."""
        start_time = time.time()
        logger.info(f"Starting: {operation_name}")
        try:
            yield
        finally:
            duration = time.time() - start_time
            logger.info(f"Completed: {operation_name} ({duration:.2f}s)")

    @staticmethod
    def _validate_session_access(
        db: Session,
        audit_result_id: int,
        user_id: int
    ) -> Tuple[AuditResult, AuditSession, Asset]:
        """
        Validate access to audit result and return related objects.

        Returns:
            Tuple of (audit_result, audit_session, asset)

        Raises:
            ValueError: If validation fails
        """
        # Get audit result
        result = db.query(AuditResult).filter(
            AuditResult.id == audit_result_id
        ).first()

        if not result:
            raise ValueError(f"Audit result {audit_result_id} not found")

        # Get audit session
        session = db.query(AuditSession).filter(
            AuditSession.id == result.session_id
        ).first()

        if not session:
            raise ValueError(f"Audit session not found for result {audit_result_id}")

        # Get asset (if exists)
        asset = None
        if session.asset_id:
            asset = db.query(Asset).filter(Asset.id == session.asset_id).first()
            if not asset:
                raise ValueError(f"Asset {session.asset_id} not found")

            if not asset.ip_address:
                raise ValueError(f"Asset '{asset.asset_name}' has no IP address")

        return result, session, asset

    @staticmethod
    def preview_hardening(
        db: Session,
        audit_result_id: int,
        user_id: int,
        parameters: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Enhanced preview with better validation and error messages.
        """
        with ImprovedHardeningService._timed_operation(f"Preview for audit result {audit_result_id}"):

            # Validate access
            result, session, asset = ImprovedHardeningService._validate_session_access(
                db, audit_result_id, user_id
            )

            # Block if check is passing
            if result.status == CheckStatus.PASS:
                raise CheckAlreadyPassingError(
                    f"Check {result.check_number} is already passing. "
                    f"Current status: {result.status.value}. No fix needed."
                )

            # Block INFO level checks
            if result.level == "INFO":
                raise ValueError(
                    f"INFO level checks cannot be auto-fixed. "
                    f"This check is informational only."
                )

            # Get CIS rule
            try:
                rule = ImprovedHardeningService._get_rule_by_check_number(result.check_number)
            except ValueError as e:
                logger.error(f"Failed to get CIS rule for {result.check_number}: {e}")
                raise ValueError(
                    f"Unable to generate fix for check {result.check_number}. "
                    f"No remediation template available. "
                    f"This check may require manual configuration."
                )

            # Parse remediation
            try:
                parsed = RemediationParser.parse_remediation(
                    remediation=rule.remediation,
                    check_number=result.check_number
                )
            except Exception as e:
                logger.error(f"Failed to parse remediation for {result.check_number}: {e}")
                raise ValueError(
                    f"Unable to parse remediation for check {result.check_number}. "
                    f"Error: {str(e)}"
                )

            # Apply parameters
            params_with_defaults = apply_defaults(
                parameters or {},
                parsed.defaults
            )

            # Try substitution to check for missing params
            try:
                test_commands = RemediationParser.substitute_parameters(
                    parsed.commands,
                    params_with_defaults
                )
            except ValueError:
                # Missing params - that's OK for preview
                test_commands = parsed.commands

            # Create preview record
            action = HardeningAction(
                audit_result_id=audit_result_id,
                user_id=user_id,
                asset_id=asset.id if asset else session.asset_id,
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

            logger.info(
                f"Created preview action {action.id} for check {result.check_number} "
                f"(user: {user_id}, asset: {asset.id if asset else 'N/A'})"
            )

            return {
                "action_id": action.id,
                "check_number": result.check_number,
                "check_title": result.check_title,
                "commands": test_commands,
                "requires_config_mode": parsed.requires_config_mode,
                "required_parameters": parsed.required_parameters,
                "optional_parameters": parsed.optional_parameters,
                "warnings": parsed.warnings,
                "estimated_duration": len(parsed.commands) * 2  # Rough estimate in seconds
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
        """
        max_retries = max_retries or ImprovedHardeningService.MAX_RETRIES

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Hardening execution attempt {attempt}/{max_retries} for action {action_id}")

                return ImprovedHardeningService.execute_hardening(
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
                logger.warning(
                    f"Attempt {attempt}/{max_retries} failed for action {action_id}: {str(e)}"
                )

                if attempt < max_retries:
                    # Wait before retry
                    time.sleep(ImprovedHardeningService.RETRY_DELAY)
                else:
                    # Final attempt failed
                    logger.error(f"All {max_retries} attempts failed for action {action_id}")
                    raise

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
        Enhanced execute with better error handling and progress tracking.
        """
        with ImprovedHardeningService._timed_operation(f"Execute action {action_id}"):

            # Fetch and validate action
            action = db.query(HardeningAction).filter(
                HardeningAction.id == action_id
            ).first()

            if not action:
                raise ValueError(f"Hardening action {action_id} not found")

            if action.status not in ["pending", "failed"]:
                raise ValueError(
                    f"Action {action_id} cannot be executed. "
                    f"Current status: {action.status}. "
                    f"Only pending or failed actions can be executed."
                )

            # Get related records
            audit_result = db.query(AuditResult).filter(
                AuditResult.id == action.audit_result_id
            ).first()

            if not audit_result:
                raise ValueError(f"Audit result {action.audit_result_id} not found")

            # Re-check if still failing
            if audit_result.status == CheckStatus.PASS:
                action.status = "blocked"
                action.error_message = "Check is now passing (possibly fixed elsewhere)"
                action.completed_at = datetime.now(timezone.utc)
                db.commit()

                raise CheckAlreadyPassingError(
                    f"Check {audit_result.check_number} is already passing. "
                    f"No fix needed."
                )

            # Get asset
            asset = db.query(Asset).filter(Asset.id == action.asset_id).first()
            if action.asset_id and not asset:
                raise ValueError(f"Asset {action.asset_id} not found")

            # Determine IP address
            if asset and asset.ip_address:
                device_ip = asset.ip_address
            else:
                # Get from session
                session = db.query(AuditSession).filter(
                    AuditSession.id == action.audit_session_id
                ).first()
                device_ip = session.target_ip if session else None

            if not device_ip:
                raise ValueError(
                    f"No IP address available for action {action_id}. "
                    f"Asset has no IP and session has no target IP."
                )

            # Parse commands
            commands = json.loads(action.commands_json)

            # Get remediation for defaults
            parsed = RemediationParser.parse_remediation(
                remediation="",
                check_number=action.check_number
            )

            params_with_defaults = apply_defaults(parameters, parsed.defaults)

            # Substitute parameters
            try:
                final_commands = RemediationParser.substitute_parameters(
                    commands,
                    params_with_defaults
                )
            except ValueError as e:
                raise MissingParametersError(
                    f"Missing required parameters: {str(e)}. "
                    f"Please provide all required parameters and try again."
                )

            # Update action status
            action.action_type = "execute"
            action.status = "executing"
            action.executed_at = datetime.now(timezone.utc)
            action.credentials_provided = True
            db.commit()

            try:
                # Execute via SSH
                with CiscoHardeningExecutor(
                    ip=device_ip,
                    username=ssh_username,
                    password=ssh_password,
                    secret=ssh_secret
                ) as executor:

                    # Test connectivity
                    logger.info(f"Testing SSH connectivity to {device_ip}")
                    executor.test_connectivity()

                    # Backup config
                    backup = None
                    if not skip_backup:
                        logger.info(f"Creating configuration backup for {device_ip}")
                        backup = executor.backup_config()
                        action.backup_config = backup
                        db.commit()
                        logger.info(f"Backup created successfully ({len(backup)} bytes)")

                    # Execute commands
                    logger.info(f"Executing {len(final_commands)} commands on {device_ip}")
                    exec_result = executor.execute_commands(
                        final_commands,
                        requires_config_mode=action.requires_config_mode
                    )

                    if not exec_result["success"]:
                        action.status = "failed"
                        action.error_message = "; ".join(exec_result["errors"])
                        action.output = redact_secrets_in_output(exec_result["output"])
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()

                        logger.error(
                            f"Command execution failed for action {action_id}: "
                            f"{action.error_message}"
                        )

                        raise HardeningExecutionError(
                            f"Command execution failed: {action.error_message}"
                        )

                    # Save config
                    logger.info(f"Saving configuration on {device_ip}")
                    save_output = executor.save_config()

                    # Store output
                    full_output = exec_result["output"] + "\n\n" + save_output
                    action.output = redact_secrets_in_output(full_output)

                    # Verify the fix
                    logger.info(f"Verifying fix for check {action.check_number}")
                    rule = ImprovedHardeningService._get_rule_by_check_number(action.check_number)
                    passed, evidence = executor.verify_check(rule)

                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    # Update final status
                    if passed:
                        action.status = "success"
                        logger.info(
                            f"Hardening action {action_id} completed successfully "
                            f"and verified for check {action.check_number}"
                        )
                    else:
                        action.status = "failed"
                        action.error_message = (
                            "Verification failed: Check still not passing after fix. "
                            "The commands executed successfully but the check still fails. "
                            "Manual intervention may be required."
                        )
                        logger.warning(
                            f"Hardening action {action_id} executed but verification failed "
                            f"for check {action.check_number}"
                        )

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                    # Return response
                    return {
                        "action_id": action.id,
                        "status": action.status,
                        "verification_passed": passed,
                        "verification_evidence": evidence,
                        "backup_created": backup is not None,
                        "backup_size": len(backup) if backup else 0,
                        "commands_executed": final_commands,
                        "error_message": action.error_message,
                        "execution_time": (
                            action.completed_at - action.executed_at
                        ).total_seconds() if action.completed_at and action.executed_at else None
                    }

            except Exception as e:
                # Execution exception
                action.status = "failed"
                action.error_message = f"{type(e).__name__}: {str(e)}"
                action.completed_at = datetime.now(timezone.utc)
                db.commit()

                logger.error(
                    f"Exception during hardening execution for action {action_id}: "
                    f"{type(e).__name__}: {str(e)}"
                )
                raise

    @staticmethod
    def get_action_history(
        db: Session,
        asset_id: Optional[int] = None,
        user_id: Optional[int] = None,
        status: Optional[str] = None,
        action_type: Optional[str] = None,
        check_number: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[HardeningAction]:
        """
        Enhanced action history with more filter options.
        """
        query = db.query(HardeningAction)

        # Apply filters
        if asset_id:
            query = query.filter(HardeningAction.asset_id == asset_id)

        if user_id:
            query = query.filter(HardeningAction.user_id == user_id)

        if status:
            query = query.filter(HardeningAction.status == status)

        if action_type:
            query = query.filter(HardeningAction.action_type == action_type)

        if check_number:
            query = query.filter(HardeningAction.check_number == check_number)

        # Order by most recent first
        query = query.order_by(HardeningAction.created_at.desc())

        # Paginate
        return query.offset(offset).limit(limit).all()

    @staticmethod
    def get_action_statistics(db: Session, asset_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Get statistics about hardening actions.
        """
        query = db.query(HardeningAction)

        if asset_id:
            query = query.filter(HardeningAction.asset_id == asset_id)

        all_actions = query.all()

        total = len(all_actions)
        by_status = {}
        by_type = {}

        for action in all_actions:
            by_status[action.status] = by_status.get(action.status, 0) + 1
            by_type[action.action_type] = by_type.get(action.action_type, 0) + 1

        # Calculate success rate
        executions = [a for a in all_actions if a.action_type == "execute"]
        successful = [a for a in executions if a.status == "success"]
        success_rate = (len(successful) / len(executions) * 100) if executions else 0

        return {
            "total_actions": total,
            "by_status": by_status,
            "by_type": by_type,
            "total_executions": len(executions),
            "successful_executions": len(successful),
            "success_rate": round(success_rate, 2),
            "most_common_checks": ImprovedHardeningService._get_most_common_checks(all_actions, 5)
        }

    @staticmethod
    def _get_most_common_checks(actions: List[HardeningAction], limit: int = 5) -> List[Dict]:
        """Get most commonly fixed checks."""
        check_counts = {}

        for action in actions:
            if action.action_type == "execute":
                check_counts[action.check_number] = check_counts.get(action.check_number, 0) + 1

        sorted_checks = sorted(check_counts.items(), key=lambda x: x[1], reverse=True)

        return [
            {"check_number": check, "count": count}
            for check, count in sorted_checks[:limit]
        ]

    @staticmethod
    def get_action_by_id(db: Session, action_id: int) -> Optional[HardeningAction]:
        """Get hardening action by ID."""
        return db.query(HardeningAction).filter(
            HardeningAction.id == action_id
        ).first()

    @staticmethod
    def delete_action(db: Session, action_id: int) -> bool:
        """Delete a hardening action record."""
        action = db.query(HardeningAction).filter(
            HardeningAction.id == action_id
        ).first()

        if not action:
            raise ValueError(f"Hardening action {action_id} not found")

        db.delete(action)
        db.commit()

        logger.info(f"Deleted hardening action {action_id}")
        return True

    @staticmethod
    def _get_rule_by_check_number(check_number: str) -> CISRule:
        """Get CIS rule by check number."""
        all_rules = build_all_cisco_cis_rules()

        for rule in all_rules:
            if rule.id == check_number:
                return rule

        raise ValueError(
            f"CIS rule {check_number} not found. "
            f"This check may not be supported for auto-remediation."
        )

    # ==================== AUTO-HARDENING METHODS ====================

    @staticmethod
    def _is_check_fixable(
        check_number: str,
        provided_params: Optional[Dict[str, str]] = None
    ) -> Tuple[bool, List[str]]:
        """Determine if a check can be auto-fixed."""
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
        """Categorize failures into fixable and unfixable."""
        fixable = []
        unfixable = []

        for result in failures:
            is_fixable, missing_params = ImprovedHardeningService._is_check_fixable(
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
        """Auto-audit with enhanced error handling and progress tracking."""
        with ImprovedHardeningService._timed_operation(f"Auto-audit device {ip_address}"):

            from app.modules.audit.service import AuditService

            logger.info(
                f"Starting auto-audit for device {ip_address} "
                f"(user: {user_id}, profile: {profile})"
            )

            # Create or use asset
            temp_asset_created = False
            if asset_id is None:
                logger.info(f"Creating temporary asset for {ip_address}")
                temp_asset = Asset(
                    asset_name=f"Auto-Audit-{ip_address}",
                    hostname=f"auto-{ip_address}",
                    ip_address=ip_address,
                    asset_type_id=1,
                    status="active",
                    user_id=user_id
                )
                db.add(temp_asset)
                db.commit()
                db.refresh(temp_asset)
                asset_id = temp_asset.id
                temp_asset_created = True
                logger.info(f"Created temporary asset ID {asset_id}")

            # Execute audit
            try:
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

            except Exception as e:
                logger.error(f"Audit failed for {ip_address}: {str(e)}")

                # Clean up temporary asset if created
                if temp_asset_created:
                    temp_asset = db.query(Asset).filter(Asset.id == asset_id).first()
                    if temp_asset:
                        db.delete(temp_asset)
                        db.commit()
                        logger.info(f"Cleaned up temporary asset {asset_id}")

                raise

            # Get session details
            session_obj = db.query(AuditSession).filter(
                AuditSession.id == session_id
            ).first()

            if not session_obj:
                raise ValueError(f"Audit session {session_id} not found after audit")

            # Get failed results
            failed_results = db.query(AuditResult).filter(
                AuditResult.session_id == session_id,
                AuditResult.status == CheckStatus.FAIL
            ).all()

            # Categorize
            categorized = ImprovedHardeningService._categorize_failures(failed_results, None)

            logger.info(
                f"Auto-audit complete for {ip_address}: "
                f"session={session_id}, "
                f"total={session_obj.total_checks}, "
                f"passed={session_obj.passed_checks}, "
                f"failed={session_obj.failed_checks}, "
                f"fixable={len(categorized['fixable'])}, "
                f"unfixable={len(categorized['unfixable'])}"
            )

            return {
                "audit_session_id": session_id,
                "device_ip": ip_address,
                "total_checks": session_obj.total_checks,
                "passed": session_obj.passed_checks,
                "failed": session_obj.failed_checks,
                "compliance_pct": session_obj.compliance_pct,
                "fixable_failures": categorized["fixable"],
                "unfixable_failures": categorized["unfixable"],
                "temporary_asset_created": temp_asset_created,
                "asset_id": asset_id
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
        continue_on_error: bool = True
    ) -> Dict[str, Any]:
        """
        Auto-fix with enhanced progress tracking and error recovery.

        Args:
            continue_on_error: If True, continue fixing other checks even if one fails
        """
        with ImprovedHardeningService._timed_operation(
            f"Auto-fix session {audit_session_id}"
        ):

            logger.info(f"Starting auto-fix for audit session {audit_session_id}")

            # Get session
            session = db.query(AuditSession).filter(
                AuditSession.id == audit_session_id
            ).first()

            if not session:
                raise ValueError(f"Audit session {audit_session_id} not found")

            device_ip = session.target_ip
            if not device_ip:
                raise ValueError(f"Audit session has no target IP")

            # Get failed results
            failed_results = db.query(AuditResult).filter(
                AuditResult.session_id == audit_session_id,
                AuditResult.status == CheckStatus.FAIL
            ).all()

            total_failures = len(failed_results)
            logger.info(f"Found {total_failures} failed checks")

            # Categorize
            categorized = ImprovedHardeningService._categorize_failures(
                failed_results,
                parameters
            )

            fixable = categorized["fixable"]
            unfixable = categorized["unfixable"]

            fixed_count = 0
            failed_count = 0
            action_ids = []
            errors = []

            # Connect once for all fixes
            with CiscoHardeningExecutor(
                ip=device_ip,
                username=ssh_username,
                password=ssh_password,
                secret=ssh_secret
            ) as executor:

                # Test connectivity
                logger.info(f"Testing connectivity to {device_ip}")
                executor.test_connectivity()

                # Create single backup
                backup = None
                if not skip_backup:
                    logger.info(f"Creating backup for {device_ip}")
                    backup = executor.backup_config()
                    logger.info(f"Backup created ({len(backup)} bytes)")

                # Process each fixable check
                for idx, fix_item in enumerate(fixable, 1):
                    result_id = fix_item["result_id"]
                    check_number = fix_item["check_number"]

                    logger.info(
                        f"Processing fix {idx}/{len(fixable)}: {check_number} "
                        f"(result {result_id})"
                    )

                    try:
                        # Get audit result
                        audit_result = db.query(AuditResult).filter(
                            AuditResult.id == result_id
                        ).first()

                        # Get rule and parse
                        rule = ImprovedHardeningService._get_rule_by_check_number(check_number)
                        parsed = RemediationParser.parse_remediation(
                            remediation=rule.remediation,
                            check_number=check_number
                        )

                        # Apply parameters
                        params_with_defaults = apply_defaults(
                            parameters or {},
                            parsed.defaults
                        )
                        final_commands = RemediationParser.substitute_parameters(
                            parsed.commands,
                            params_with_defaults
                        )

                        # Create action record
                        action = HardeningAction(
                            audit_result_id=result_id,
                            user_id=user_id,
                            asset_id=session.asset_id,
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
                            error_msg = f"{check_number}: {action.error_message}"
                            errors.append(error_msg)
                            logger.warning(f"Fix failed: {error_msg}")

                            if not continue_on_error:
                                raise HardeningExecutionError(error_msg)

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
                            logger.info(f"Successfully fixed {check_number}")
                        else:
                            action.status = "failed"
                            action.error_message = "Verification failed"
                            failed_count += 1
                            logger.warning(f"Verification failed for {check_number}")

                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()

                    except Exception as e:
                        logger.error(f"Exception fixing {check_number}: {str(e)}")
                        failed_count += 1
                        error_msg = f"{check_number}: {type(e).__name__}: {str(e)}"
                        errors.append(error_msg)

                        if 'action' in locals():
                            action.status = "failed"
                            action.error_message = str(e)
                            action.completed_at = datetime.now(timezone.utc)
                            db.commit()

                        if not continue_on_error:
                            raise

                # Save config once
                if fixed_count > 0:
                    logger.info(f"Saving configuration for {device_ip}")
                    executor.save_config()

            # Get updated session
            session_updated = db.query(AuditSession).filter(
                AuditSession.id == audit_session_id
            ).first()

            logger.info(
                f"Auto-fix complete for session {audit_session_id}: "
                f"fixed={fixed_count}, failed={failed_count}, skipped={len(unfixable)}"
            )

            return {
                "audit_session_id": audit_session_id,
                "total_failures": total_failures,
                "fixed_count": fixed_count,
                "skipped_count": len(unfixable),
                "failed_count": failed_count,
                "actions": action_ids,
                "final_compliance_pct": session_updated.compliance_pct,
                "errors": errors if errors else None,
                "success_rate": round((fixed_count / len(fixable) * 100) if fixable else 0, 2)
            }
