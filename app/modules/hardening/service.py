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
import json
import logging

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


class HardeningService:
    """Service for automated device hardening."""

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
