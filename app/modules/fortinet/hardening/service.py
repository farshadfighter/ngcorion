"""
FortiGate Hardening Service Layer

Orchestrates the complete FortiGate hardening workflow:
1. Preview - Parse remediation and generate commands
2. Execute - Apply fixes via SSH and verify results
3. History - Track all hardening attempts

Supports three hardening modes:
- Fix Single: Fix one check at a time
- Fix All: Fix selected checks with user parameters
- Automatic Hardening: Apply all auto-fixable checks with defaults
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
from app.modules.fortinet.audit.rules import get_fortinet_controls, FortiGateControl
from .command_parser import FortiGateRemediationParser, apply_fortigate_defaults
from .ssh_executor import (
    FortiGateHardeningExecutor,
    redact_fortigate_secrets,
    FortiGateHardeningExecutionError
)
from .command_templates import has_fortigate_template

logger = logging.getLogger(__name__)


class FortiGateHardeningError(Exception):
    """Base exception for FortiGate hardening operations."""
    pass


class FortiGateCheckAlreadyPassingError(FortiGateHardeningError):
    """Raised when trying to fix a check that already passes."""
    pass


class FortiGateMissingParametersError(FortiGateHardeningError):
    """Raised when required parameters are not provided."""
    pass


class FortiGateHardeningService:
    """Service for automated FortiGate device hardening."""

    # Configuration constants
    MAX_RETRIES = 3
    RETRY_DELAY = 2  # seconds

    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        """Context manager for timing operations."""
        start_time = time.time()
        logger.info(f"Starting: {operation_name}")

        try:
            yield
        finally:
            elapsed = time.time() - start_time
            logger.info(f"Completed: {operation_name} ({elapsed:.2f}s)")

    @staticmethod
    def _get_control_by_id(check_id: str) -> FortiGateControl:
        """
        Get FortiGate control by check ID.

        Args:
            check_id: Check ID (e.g., "FG-BL-001")

        Returns:
            FortiGateControl object

        Raises:
            ValueError: If control not found
        """
        all_controls = get_fortinet_controls()
        for control in all_controls:
            if control.id == check_id:
                return control

        raise ValueError(f"FortiGate control {check_id} not found")

    @staticmethod
    def preview_hardening(
        db: Session,
        audit_result_id: int,
        user_id: int,
        parameters: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Preview hardening commands for a failed FortiGate check.

        Args:
            db: Database session
            audit_result_id: ID of failed audit result to fix
            user_id: User performing the preview
            parameters: Optional parameters for command generation

        Returns:
            Dict with preview details

        Raises:
            FortiGateCheckAlreadyPassingError: If check is already passing
            ValueError: If audit result not found or invalid
        """
        # Fetch and validate audit result
        result = db.query(AuditResult).filter(AuditResult.id == audit_result_id).first()
        if not result:
            raise ValueError(f"Audit result {audit_result_id} not found")

        # Block if check is passing
        if result.status == CheckStatus.PASS:
            raise FortiGateCheckAlreadyPassingError(
                f"Check {result.check_number} is already passing. No fix needed."
            )

        # Get audit session and asset
        session = db.query(AuditSession).filter(
            AuditSession.id == result.session_id
        ).first()
        if not session:
            raise ValueError(f"Audit session not found for result {audit_result_id}")

        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None

        # Get FortiGate control
        control = FortiGateHardeningService._get_control_by_id(result.check_number)

        # Parse remediation into commands
        parsed = FortiGateRemediationParser.parse_remediation(
            remediation=control.remediation,
            check_id=result.check_number
        )

        # Apply any user-provided parameters (for preview)
        if parameters:
            params_with_defaults = apply_fortigate_defaults(parameters, parsed.defaults)
        else:
            params_with_defaults = parsed.defaults.copy()

        # Try to substitute parameters to validate
        try:
            test_commands = FortiGateRemediationParser.substitute_parameters(
                parsed.commands,
                params_with_defaults
            )
        except ValueError:
            # Missing required parameters - that's fine for preview
            test_commands = parsed.commands  # Show placeholders

        # Create preview record in database
        action = HardeningAction(
            audit_result_id=audit_result_id,
            user_id=user_id,
            asset_id=asset.id if asset else None,
            audit_session_id=session.id,
            check_number=result.check_number,
            check_title=result.check_title,
            action_type="preview",
            status="pending",
            commands_json=json.dumps(parsed.commands),
            requires_config_mode=True,  # FortiGate always uses config mode
            credentials_provided=False
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        logger.info(f"Created FortiGate preview action {action.id} for check {result.check_number}")

        return {
            "action_id": action.id,
            "check_number": result.check_number,
            "check_title": result.check_title,
            "commands": test_commands,
            "vdom_context": parsed.vdom_context,
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
        parameters: Dict[str, str],
        vdom: Optional[str] = None,
        skip_backup: bool = False
    ) -> Dict[str, Any]:
        """
        Execute hardening commands on FortiGate device.

        Args:
            db: Database session
            action_id: ID of preview action
            user_id: User executing the fix
            ssh_username: SSH username
            ssh_password: SSH password
            parameters: Parameter values for command substitution
            vdom: Optional VDOM context
            skip_backup: Skip config backup (NOT RECOMMENDED)

        Returns:
            Dict with execution results

        Raises:
            ValueError: If action not found or invalid
            FortiGateMissingParametersError: If required parameters missing
        """
        # Fetch and validate action
        action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first()
        if not action:
            raise ValueError(f"Hardening action {action_id} not found")

        if action.status != "pending":
            raise ValueError(
                f"Action {action_id} has status '{action.status}'. "
                "Only pending actions can be executed."
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
            action.error_message = "Check is now passing (fixed elsewhere)"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise FortiGateCheckAlreadyPassingError("Check is already passing")

        # Get device IP
        session = db.query(AuditSession).filter(
            AuditSession.id == action.audit_session_id
        ).first()
        if not session or not session.target_ip:
            raise ValueError(f"No device IP found for action {action_id}")

        device_ip = session.target_ip

        # Parse commands from JSON
        commands = json.loads(action.commands_json)

        # Apply defaults and substitute parameters
        parsed = FortiGateRemediationParser.parse_remediation(
            remediation="",
            check_id=action.check_number
        )
        params_with_defaults = apply_fortigate_defaults(parameters, parsed.defaults)

        try:
            final_commands = FortiGateRemediationParser.substitute_parameters(
                commands,
                params_with_defaults
            )
        except ValueError as e:
            raise FortiGateMissingParametersError(str(e))

        # Update action to executing status
        action.action_type = "execute"
        action.status = "executing"
        action.executed_at = datetime.now(timezone.utc)
        action.credentials_provided = True
        db.commit()

        try:
            # Execute via SSH
            with FortiGateHardeningExecutor(
                ip=device_ip,
                username=ssh_username,
                password=ssh_password,
                vdom=vdom
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
                    vdom=vdom
                )

                if not exec_result["success"]:
                    action.status = "failed"
                    action.error_message = "; ".join(exec_result["errors"])
                    action.output = redact_fortigate_secrets(exec_result["output"])
                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                    logger.error(f"FortiGate hardening failed for action {action_id}: {action.error_message}")

                    return {
                        "action_id": action.id,
                        "status": "failed",
                        "verification_passed": False,
                        "verification_evidence": "",
                        "backup_created": backup is not None,
                        "commands_executed": final_commands,
                        "error_message": action.error_message
                    }

                # Store output
                action.output = redact_fortigate_secrets(exec_result["output"])

                # Verify the fix
                control = FortiGateHardeningService._get_control_by_id(action.check_number)
                passed, evidence = executor.verify_check(control, vdom=vdom)

                action.verification_passed = passed
                action.verification_evidence = evidence

                # Update final status
                if passed:
                    action.status = "success"
                    logger.info(f"FortiGate hardening action {action_id} completed successfully")
                else:
                    action.status = "failed"
                    action.error_message = "Verification failed: check still not passing after fix"
                    logger.warning(f"FortiGate hardening action {action_id} completed but verification failed")

                action.completed_at = datetime.now(timezone.utc)
                db.commit()

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
            action.status = "failed"
            action.error_message = f"{type(e).__name__}: {str(e)}"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()

            logger.error(f"FortiGate hardening exception for action {action_id}: {str(e)}")
            raise

    @staticmethod
    def get_session_parameters(
        db: Session,
        audit_session_id: int,
        check_ids: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Get aggregated parameters for hardening a FortiGate audit session.

        Supports "Fix All" mode by collecting all required parameters
        across selected failed checks.

        Args:
            db: Database session
            audit_session_id: Audit session to analyze
            check_ids: Optional list of specific check result IDs

        Returns:
            Dict with session parameters and check categorization
        """
        from .fortinet_parameter_metadata import (
            aggregate_fortigate_parameters_for_checks,
            categorize_fortigate_checks_by_fixability
        )

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
        templated_checks = [cn for cn in check_numbers if has_fortigate_template(cn)]
        no_template_checks = [cn for cn in check_numbers if not has_fortigate_template(cn)]

        # Categorize checks
        categorized = categorize_fortigate_checks_by_fixability(templated_checks)

        # Aggregate parameters
        aggregated_params = aggregate_fortigate_parameters_for_checks(templated_checks)

        # Build result ID map
        check_result_map = {r.check_number: r.id for r in failed_results}

        return {
            "session_id": audit_session_id,
            "total_failed": len(check_numbers),
            "selected_count": len(check_numbers) if not check_ids else len(check_ids),
            "fixable_count": len(templated_checks),
            "unfixable_count": len(no_template_checks),
            "required_parameters": aggregated_params,
            "auto_fixable_checks": [
                {"check_number": cn, "result_id": check_result_map.get(cn)}
                for cn in categorized["auto_fixable"]
            ],
            "needs_params_checks": [
                {"check_number": cn, "result_id": check_result_map.get(cn)}
                for cn in categorized["needs_params"]
            ],
            "no_template_checks": [
                {"check_number": cn, "result_id": check_result_map.get(cn), "reason": "No remediation template"}
                for cn in no_template_checks
            ]
        }

    @staticmethod
    def get_auto_harden_preview(
        db: Session,
        audit_session_id: int
    ) -> Dict[str, Any]:
        """
        Get preview of automatic hardening with defaults.

        Shows what will be applied and what will be skipped.

        Args:
            db: Database session
            audit_session_id: Audit session to preview

        Returns:
            Dict with checks_with_defaults and skipped_checks
        """
        from .fortinet_parameter_metadata import (
            is_fortigate_check_auto_fixable,
            get_fortigate_check_defaults,
            get_fortigate_required_parameters_for_check
        )

        # Validate session
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
            check_id = result.check_number

            # Skip checks without templates
            if not has_fortigate_template(check_id):
                skipped_checks.append({
                    "check_number": check_id,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "reason": "No remediation template available"
                })
                continue

            # Check if auto-fixable
            if is_fortigate_check_auto_fixable(check_id):
                defaults = get_fortigate_check_defaults(check_id)
                checks_with_defaults.append({
                    "check_number": check_id,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "defaults": defaults
                })
            else:
                required_params = get_fortigate_required_parameters_for_check(check_id)
                param_names = [p.name for p in required_params]
                skipped_checks.append({
                    "check_number": check_id,
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
        vdom: Optional[str] = None,
        skip_backup: bool = False
    ) -> Dict[str, Any]:
        """
        Automatically harden FortiGate using only default values.

        Only applies checks where all parameters have defaults.
        Skips checks requiring user input.

        Args:
            db: Database session
            audit_session_id: Audit session to fix
            user_id: User performing the hardening
            ssh_username/password: SSH credentials
            vdom: Optional VDOM context
            skip_backup: Skip config backup

        Returns:
            Dict with execution summary
        """
        from .fortinet_parameter_metadata import (
            is_fortigate_check_auto_fixable,
            get_fortigate_check_defaults
        )

        logger.info(f"Starting FortiGate auto-harden with defaults for session {audit_session_id}")

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
            check_id = result.check_number
            if has_fortigate_template(check_id) and is_fortigate_check_auto_fixable(check_id):
                auto_fixable.append(result)
            else:
                reason = "No template" if not has_fortigate_template(check_id) else "Requires user input"
                skipped.append({
                    "check_number": check_id,
                    "check_title": result.check_title,
                    "result_id": result.id,
                    "reason": reason
                })

        if not auto_fixable:
            logger.info("No auto-fixable FortiGate checks found")
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
        with FortiGateHardeningExecutor(
            ip=device_ip,
            username=ssh_username,
            password=ssh_password,
            vdom=vdom
        ) as executor:
            executor.test_connectivity()

            # Backup once
            backup = None
            if not skip_backup:
                logger.info(f"Creating backup for FortiGate {device_ip}")
                backup = executor.backup_config()

            # Process each auto-fixable check
            for result in auto_fixable:
                check_id = result.check_number

                try:
                    logger.info(f"Auto-fixing FortiGate check {check_id}")

                    # Get control and parse
                    control = FortiGateHardeningService._get_control_by_id(check_id)
                    parsed = FortiGateRemediationParser.parse_remediation(
                        remediation=control.remediation,
                        check_id=check_id
                    )

                    # Get defaults and substitute
                    defaults = get_fortigate_check_defaults(check_id)
                    final_commands = FortiGateRemediationParser.substitute_parameters(
                        parsed.commands,
                        apply_fortigate_defaults({}, defaults)
                    )

                    # Create action record
                    action = HardeningAction(
                        audit_result_id=result.id,
                        user_id=user_id,
                        asset_id=session.asset_id,
                        audit_session_id=audit_session_id,
                        check_number=check_id,
                        check_title=result.check_title,
                        action_type="execute",
                        status="executing",
                        commands_json=json.dumps(final_commands),
                        requires_config_mode=True,
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
                        vdom=vdom
                    )

                    if not exec_result["success"]:
                        action.status = "failed"
                        action.error_message = "; ".join(exec_result["errors"])
                        action.output = redact_fortigate_secrets(exec_result["output"])
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        failed_count += 1
                        continue

                    # Store output
                    action.output = redact_fortigate_secrets(exec_result["output"])

                    # Verify
                    passed, evidence = executor.verify_check(control, vdom=vdom)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        fixed_count += 1
                        fixed_checks.append({
                            "check_number": check_id,
                            "check_title": result.check_title,
                            "action_id": action.id,
                            "defaults_applied": defaults
                        })
                        logger.info(f"Successfully auto-fixed FortiGate check {check_id}")
                    else:
                        action.status = "failed"
                        action.error_message = "Verification failed after fix"
                        failed_count += 1

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except Exception as e:
                    logger.error(f"Error auto-fixing FortiGate check {check_id}: {str(e)}")
                    failed_count += 1

        logger.info(
            f"FortiGate auto-harden complete: {fixed_count} fixed, "
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
        vdom: Optional[str] = None,
        skip_backup: bool = False
    ) -> Dict[str, Any]:
        """
        Execute hardening for selected FortiGate checks with user parameters.

        "Fix All" mode where users select specific checks and provide all required parameters.

        Args:
            db: Database session
            audit_session_id: Audit session ID
            user_id: User performing hardening
            check_ids: List of AuditResult IDs to fix
            parameters: User-provided parameters
            ssh_username/password: SSH credentials
            vdom: Optional VDOM context
            skip_backup: Skip config backup

        Returns:
            Dict with execution results
        """
        from .fortinet_parameter_metadata import get_fortigate_check_defaults

        logger.info(f"Starting FortiGate batch execute for {len(check_ids)} selected checks")

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

        with FortiGateHardeningExecutor(
            ip=device_ip,
            username=ssh_username,
            password=ssh_password,
            vdom=vdom
        ) as executor:
            executor.test_connectivity()

            # Backup once
            backup = None
            if not skip_backup:
                logger.info(f"Creating backup for FortiGate {device_ip}")
                backup = executor.backup_config()

            for result in results:
                check_id = result.check_number

                # Skip if no template
                if not has_fortigate_template(check_id):
                    skipped_count += 1
                    execution_results.append({
                        "check_number": check_id,
                        "check_title": result.check_title,
                        "status": "skipped",
                        "reason": "No template available"
                    })
                    continue

                # Skip if already passing
                if result.status == CheckStatus.PASS:
                    skipped_count += 1
                    execution_results.append({
                        "check_number": check_id,
                        "check_title": result.check_title,
                        "status": "skipped",
                        "reason": "Already passing"
                    })
                    continue

                try:
                    logger.info(f"Fixing FortiGate check {check_id}")

                    # Get control and parse
                    control = FortiGateHardeningService._get_control_by_id(check_id)
                    parsed = FortiGateRemediationParser.parse_remediation(
                        remediation=control.remediation,
                        check_id=check_id
                    )

                    # Merge user parameters with defaults
                    defaults = get_fortigate_check_defaults(check_id)
                    merged_params = apply_fortigate_defaults(parameters, defaults)

                    # Substitute parameters
                    try:
                        final_commands = FortiGateRemediationParser.substitute_parameters(
                            parsed.commands,
                            merged_params
                        )
                    except ValueError as e:
                        skipped_count += 1
                        execution_results.append({
                            "check_number": check_id,
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
                        check_number=check_id,
                        check_title=result.check_title,
                        action_type="execute",
                        status="executing",
                        commands_json=json.dumps(final_commands),
                        requires_config_mode=True,
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
                        vdom=vdom
                    )

                    if not exec_result["success"]:
                        action.status = "failed"
                        action.error_message = "; ".join(exec_result["errors"])
                        action.output = redact_fortigate_secrets(exec_result["output"])
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()
                        failed_count += 1
                        execution_results.append({
                            "check_number": check_id,
                            "check_title": result.check_title,
                            "status": "failed",
                            "action_id": action.id,
                            "error": action.error_message
                        })
                        continue

                    action.output = redact_fortigate_secrets(exec_result["output"])

                    # Verify
                    passed, evidence = executor.verify_check(control, vdom=vdom)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        fixed_count += 1
                        execution_results.append({
                            "check_number": check_id,
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
                            "check_number": check_id,
                            "check_title": result.check_title,
                            "status": "failed",
                            "action_id": action.id,
                            "verification_passed": False
                        })

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except Exception as e:
                    logger.error(f"Error fixing FortiGate check {check_id}: {str(e)}")
                    failed_count += 1
                    execution_results.append({
                        "check_number": check_id,
                        "check_title": result.check_title,
                        "status": "failed",
                        "error": str(e)
                    })

        logger.info(
            f"FortiGate batch execute complete: {fixed_count} fixed, "
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

    @staticmethod
    def get_action_history(
        db: Session,
        asset_id: Optional[int] = None,
        audit_session_id: Optional[int] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[HardeningAction]:
        """
        Get filtered FortiGate hardening action history.

        Args:
            db: Database session
            asset_id: Filter by asset ID
            audit_session_id: Filter by audit session ID
            status: Filter by status
            limit: Maximum results
            offset: Results to skip

        Returns:
            List of HardeningAction records
        """
        query = db.query(HardeningAction)

        # Filter to FortiGate checks (FG-* prefix)
        query = query.filter(HardeningAction.check_number.like("FG-%"))

        if asset_id:
            query = query.filter(HardeningAction.asset_id == asset_id)

        if audit_session_id:
            query = query.filter(HardeningAction.audit_session_id == audit_session_id)

        if status:
            query = query.filter(HardeningAction.status == status)

        return (
            query.order_by(HardeningAction.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
