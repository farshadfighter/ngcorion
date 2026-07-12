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
from app.modules.fortinet.audit.service import _parse_table_entries
from app.modules.fortinet.audit.ssh_client import (
    SCOPE_GLOBAL,
    SCOPE_VDOM,
    SCOPE_VDOM_ROOT,
    ROOT_VDOM,
)
from .command_parser import FortiGateRemediationParser, apply_fortigate_defaults
from .ssh_executor import (
    FortiGateHardeningExecutor,
    redact_fortigate_secrets,
    FortiGateHardeningExecutionError
)
from .command_templates import has_fortigate_template, IFACE_ALLOWACCESS_FORBIDDEN
from .manual_remediation import (
    DEVICE_OPTION_TYPES,
    device_option_types_for_check,
    get_manual_remediation,
    has_manual_remediation,
    render_manual_command_blocks,
    redact_manual_secret_values,
    ManualParameterError,
)

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


class FortiGateNotAutoFixableError(FortiGateHardeningError):
    """Raised when a check has no automated remediation template (manual/review only)."""
    pass


class FortiGateManualNotExecutableError(FortiGateHardeningError):
    """Raised when a manual check has no executable remediation template (guidance only)."""
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
    def _display_target_vdom(scope: str, result_vdom: Optional[str]) -> Optional[str]:
        """
        The VDOM context a fix for this control lands in, for display/records:
        "global" for global-scope controls, "root" for vdom_root, the finding's
        own VDOM for per-VDOM controls. ``None`` when the audit recorded no VDOM
        (flat device — there is only one context, so no VDOM is shown).
        """
        if not result_vdom:
            return None
        if scope == SCOPE_GLOBAL:
            return "global"
        if scope == SCOPE_VDOM_ROOT:
            return ROOT_VDOM
        return result_vdom

    @staticmethod
    def discover_vdoms(
        db: Session,
        asset_id: int,
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22
    ) -> List[str]:
        """
        Discover VDOMs on a FortiGate device for the hardening flow.

        Connects over SSH and runs `show vdom` (and fallbacks) so the UI can
        present the available virtual domains once the user enables VDOM mode.

        Args:
            db: Database session
            asset_id: Target asset ID
            ssh_username: SSH username (not stored)
            ssh_password: SSH password (not stored)
            ssh_port: SSH port (default 22)

        Returns:
            List of VDOM names (empty if VDOMs are disabled on the device)

        Raises:
            ValueError: If asset not found or missing IP
            Exception: If SSH connection fails
        """
        # Imported here to avoid a circular import at module load time.
        from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")

        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")

        target_ip = asset.ip_address

        try:
            with FortiGateSSHClient(
                host=target_ip,
                username=ssh_username,
                password=ssh_password,
                port=ssh_port
            ) as ssh_client:
                vdoms = ssh_client.discover_vdoms()

            logger.info(f"Discovered {len(vdoms)} VDOMs on {target_ip}: {vdoms}")
            return vdoms

        except Exception as e:
            logger.error(f"VDOM discovery failed for {target_ip}: {type(e).__name__}")
            raise

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

        # Block manual/review-only checks: without a remediation template,
        # parse_remediation falls back to treating the prose remediation as CLI,
        # which the device rejects (e.g. "Unknown action 0"). These must be applied
        # manually — consistent with the batch/auto-harden flows that skip them.
        if not has_fortigate_template(result.check_number):
            raise FortiGateNotAutoFixableError(
                f"Check {result.check_number} ('{control.title}') has no automated "
                f"remediation and must be applied manually. Guidance: {control.remediation}"
            )

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

        # The VDOM context the fix will land in (shown in the UI and recorded).
        target_vdom = FortiGateHardeningService._display_target_vdom(
            control.scope, result.vdom
        )

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
            credentials_provided=False,
            target_vdom=target_vdom
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
            "vdom_context": control.scope,
            "scope": control.scope,
            "target_vdom": target_vdom,
            "required_parameters": parsed.required_parameters,
            "optional_parameters": parsed.optional_parameters,
            "parameter_defaults": parsed.defaults,
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
        skip_backup: bool = False,
        ssh_port: int = 22
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

        # Defense in depth: never push a non-templated (manual/prose) remediation to
        # the device. preview_hardening now blocks creating such actions, but guard
        # legacy or directly-created actions too, since their commands_json would hold
        # prose that the device rejects with "Unknown action ...".
        if not has_fortigate_template(action.check_number):
            action.status = "blocked"
            action.error_message = "No automated remediation template; manual remediation required"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()
            raise FortiGateNotAutoFixableError(
                f"Check {action.check_number} has no automated remediation and "
                "must be applied manually."
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

        # Resolve the control and the VDOM this fix must target. Per-VDOM controls
        # are applied in the VDOM the finding came from (audit_result.vdom);
        # global/root controls ignore the VDOM (the SSH engine routes by scope).
        control = FortiGateHardeningService._get_control_by_id(action.check_number)
        target_vdom = audit_result.vdom if control.scope == SCOPE_VDOM else None
        display_vdom = FortiGateHardeningService._display_target_vdom(
            control.scope, audit_result.vdom
        )

        # Update action to executing status
        action.action_type = "execute"
        action.status = "executing"
        action.executed_at = datetime.now(timezone.utc)
        action.credentials_provided = True
        action.target_vdom = display_vdom
        db.commit()

        try:
            # Per-phase wall-time profile for this action (logged as a single
            # summary line below — the go-to signal for "why was this slow?").
            timings: Dict[str, float] = {}
            t_start = time.perf_counter()

            # Execute via SSH
            with FortiGateHardeningExecutor(
                ip=device_ip,
                username=ssh_username,
                password=ssh_password,
                vdom=vdom,
                port=ssh_port
            ) as executor:
                timings["connect"] = time.perf_counter() - t_start

                # Test connectivity
                t0 = time.perf_counter()
                executor.test_connectivity()
                timings["connectivity"] = time.perf_counter() - t0

                # Backup config
                backup = None
                if not skip_backup:
                    t0 = time.perf_counter()
                    backup = executor.backup_config()
                    timings["backup"] = time.perf_counter() - t0
                    action.backup_config = backup
                    db.commit()

                # Dynamic (device-state-aware) remediation: controls like FG-BL-002
                # can't use a static template — the correct fix depends on each
                # interface's current allowaccess. Now that we're connected, read the
                # live config and strip only the forbidden cleartext services,
                # preserving the rest. Empty result = already compliant (no-op).
                if action.check_number in IFACE_ALLOWACCESS_FORBIDDEN:
                    final_commands = executor.build_iface_allowaccess_fix(
                        scope=control.scope,
                        vdom=target_vdom,
                        forbidden=IFACE_ALLOWACCESS_FORBIDDEN[action.check_number],
                    )

                # Execute commands
                t0 = time.perf_counter()
                exec_result = executor.execute_commands(
                    final_commands,
                    scope=control.scope,
                    vdom=target_vdom,
                )
                timings["execute"] = time.perf_counter() - t0

                # Store output regardless of execution errors
                action.output = redact_fortigate_secrets(exec_result["output"])

                if not exec_result["success"]:
                    logger.warning(
                        f"FortiGate execution had errors for action {action_id}: "
                        f"{exec_result['errors']} — still running verification"
                    )

                # Always verify: FortiGate sometimes returns "Command fail. Return code -7"
                # when a setting is already at the requested value (idempotent no-op).
                # Verification is the authoritative check of whether the fix succeeded.
                t0 = time.perf_counter()
                passed, evidence = executor.verify_check(control, vdom=target_vdom)
                timings["verify"] = time.perf_counter() - t0

                action.verification_passed = passed
                action.verification_evidence = evidence

                if passed:
                    action.status = "success"
                    audit_result.status = CheckStatus.PASS
                    audit_result.evidence_snippet = evidence
                    logger.info(f"FortiGate hardening action {action_id} completed successfully")
                else:
                    action.status = "failed"
                    if not exec_result["success"]:
                        action.error_message = "; ".join(exec_result["errors"])
                    else:
                        action.error_message = "Verification failed: check still not passing after fix"
                    logger.warning(f"FortiGate hardening action {action_id} completed but verification failed")

                action.completed_at = datetime.now(timezone.utc)
                db.commit()

                timings["total"] = time.perf_counter() - t_start
                logger.info(
                    "FG timing: action %s (%s) %s",
                    action_id, action.check_number,
                    " ".join(f"{k}={v:.2f}s" for k, v in timings.items()),
                )

                return {
                    "action_id": action.id,
                    "status": action.status,
                    "verification_passed": passed,
                    "verification_evidence": evidence,
                    "backup_created": backup is not None,
                    "commands_executed": final_commands,
                    "error_message": action.error_message,
                    "check_number": action.check_number,
                    "scope": control.scope,
                    "target_vdom": display_vdom
                }

        except Exception as e:
            action.status = "failed"
            action.error_message = f"{type(e).__name__}: {str(e)}"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()

            logger.error(
                "FortiGate hardening exception for action %s: %s",
                action_id, e, exc_info=True,
            )
            raise

    @staticmethod
    def execute_manual_remediation(
        db: Session,
        audit_result_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        parameters: Optional[Dict[str, str]] = None,
        vdom: Optional[str] = None,
        skip_backup: bool = True,
        ssh_port: int = 22,
    ) -> Dict[str, Any]:
        """
        Execute a MANUAL check's remediation on the device.

        Unlike :meth:`execute_hardening` (auto-fix templates), this path:
          * renders a parameterised block from the manual-remediation catalog,
          * pushes it in the control's scope/VDOM via the same SSH engine,
          * performs **NO verification** and never flips the audit result to PASS
            (a Manual control can't be proven from config alone),
          * records the attempt as a ``manual-execute`` HardeningAction.

        Returns ``{success, output, errors, commands_executed, check_number,
        check_title}``.
        """
        parameters = parameters or {}

        # Resolve the failed result -> session/asset/control.
        result = db.query(AuditResult).filter(AuditResult.id == audit_result_id).first()
        if not result:
            raise ValueError(f"Audit result {audit_result_id} not found")

        control = FortiGateHardeningService._get_control_by_id(result.check_number)

        if not has_manual_remediation(result.check_number):
            raise FortiGateManualNotExecutableError(
                f"Check {result.check_number} ('{control.title}') has no executable "
                "remediation and can only be applied by hand."
            )

        session = db.query(AuditSession).filter(
            AuditSession.id == result.session_id
        ).first()
        if not session or not session.target_ip:
            raise ValueError(f"No device IP found for audit result {audit_result_id}")

        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
        device_ip = session.target_ip

        # Render the command block(s) (raises FortiGateMissingParametersError on
        # gaps). Multi-target checks (e.g. several failing policy IDs) render one
        # block per target; single-target checks render one (None, commands) block.
        try:
            blocks = render_manual_command_blocks(result.check_number, parameters)
        except ManualParameterError as e:
            raise FortiGateMissingParametersError(str(e))
        commands = [cmd for _target, cmds in blocks for cmd in cmds]

        # Per-VDOM controls target the VDOM the finding came from; global controls
        # ignore it (the SSH engine routes by scope).
        target_vdom = result.vdom if control.scope == SCOPE_VDOM else None
        display_vdom = FortiGateHardeningService._display_target_vdom(
            control.scope, result.vdom
        )

        redacted_cmds = redact_manual_secret_values(
            "\n".join(commands), result.check_number, parameters
        ).split("\n")

        action = HardeningAction(
            audit_result_id=audit_result_id,
            user_id=user_id,
            asset_id=asset.id if asset else None,
            audit_session_id=session.id,
            check_number=result.check_number,
            check_title=result.check_title,
            action_type="manual-execute",
            status="executing",
            commands_json=json.dumps(redacted_cmds),
            requires_config_mode=True,
            credentials_provided=True,
            executed_at=datetime.now(timezone.utc),
            target_vdom=display_vdom,
        )
        db.add(action)
        db.commit()
        db.refresh(action)

        try:
            with FortiGateHardeningExecutor(
                ip=device_ip,
                username=ssh_username,
                password=ssh_password,
                vdom=vdom,
                port=ssh_port,
            ) as executor:
                executor.test_connectivity()

                backup = None
                if not skip_backup:
                    backup = executor.backup_config()
                    action.backup_config = backup
                    db.commit()

                # Run every block in this one SSH session, tracking per-target
                # success/failure (multi-policy selections keep going after one
                # policy errors, so the report shows exactly which ones failed).
                def _clean(text: str) -> str:
                    return redact_manual_secret_values(
                        redact_fortigate_secrets(text), result.check_number, parameters,
                    )

                per_target: List[Dict[str, Any]] = []
                output_parts: List[str] = []
                all_errors: List[str] = []
                overall_success = True

                # Dynamic manual checks (FG-NET-002): the catalog block is empty
                # on purpose — the per-interface commands are computed NOW from
                # the live config (same mechanism as FG-BL-002's auto-fix), only
                # for the selected interfaces. Targets with nothing to push
                # (already compliant / unknown interface / lockout guard) go
                # straight to the per-target report without touching the device.
                if get_manual_remediation(result.check_number).dynamic == "wan_iface_allowaccess":
                    built = executor.build_wan_iface_allowaccess_blocks(
                        selections=[t for t, _cmds in blocks],
                        scope=control.scope,
                        vdom=target_vdom,
                    )
                    blocks = [(b["target"], b["commands"]) for b in built if b["commands"]]
                    for b in built:
                        if b["commands"]:
                            continue
                        per_target.append({"target": b["target"], "success": b["success"],
                                           "errors": [] if b["success"] else [b["skip_reason"]],
                                           "note": b["skip_reason"]})
                        output_parts.append(f"### Target {b['target']}\n[skipped] {b['skip_reason']}")
                        if not b["success"]:
                            all_errors.append(f"[{b['target']}] {b['skip_reason']}")
                            overall_success = False
                    # Record the real commands now that they are known (the
                    # pre-connection render had none for a dynamic check).
                    commands = [c for _t, cmds in blocks for c in cmds]
                    redacted_cmds = list(commands)
                    action.commands_json = json.dumps(redacted_cmds)
                    db.commit()

                for target, block in blocks:
                    exec_result = executor.execute_commands(
                        block, scope=control.scope, vdom=target_vdom,
                    )
                    block_output = _clean(exec_result["output"])
                    block_errors = [_clean(e) for e in exec_result["errors"]]
                    overall_success = overall_success and exec_result["success"]
                    if target is not None:
                        output_parts.append(f"### Target {target}\n{block_output}")
                        all_errors.extend(f"[{target}] {e}" for e in block_errors)
                        per_target.append({
                            "target": target,
                            "success": exec_result["success"],
                            "errors": block_errors,
                        })
                    else:
                        output_parts.append(block_output)
                        all_errors.extend(block_errors)

                clean_output = "\n\n".join(output_parts)

                action.output = clean_output
                # No verification is performed for manual checks; leave
                # verification_passed NULL so nothing is reported as verified.
                action.status = "success" if overall_success else "failed"
                if not overall_success:
                    action.error_message = "; ".join(all_errors)
                action.completed_at = datetime.now(timezone.utc)
                db.commit()

                return {
                    "success": overall_success,
                    "output": clean_output,
                    "errors": all_errors,
                    "commands_executed": redacted_cmds,
                    "backup_created": backup is not None,
                    "check_number": result.check_number,
                    "check_title": result.check_title,
                    "per_target": per_target,
                    "scope": control.scope,
                    "target_vdom": display_vdom,
                }

        except Exception as e:
            action.status = "failed"
            action.error_message = f"{type(e).__name__}: {str(e)}"
            action.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error(
                "FortiGate manual remediation exception for result %s (check %s): %s",
                audit_result_id, result.check_number, e, exc_info=True,
            )
            raise

    @staticmethod
    def get_device_options(
        db: Session,
        audit_result_id: int,
        option_type: str,
        ssh_username: str,
        ssh_password: str,
        ssh_port: int = 22,
    ) -> List[str]:
        """
        Fetch the existing device objects behind one smart-dropdown parameter
        (e.g. antivirus profile names for FG-UTM-002's AV_PROFILE).

        Read-only: runs the option type's ``show`` command over SSH in the
        control's scope (or global, for global-only objects) and returns the
        entry names. Only option types actually declared by the failing check's
        parameters are allowed.
        """
        result = db.query(AuditResult).filter(AuditResult.id == audit_result_id).first()
        if not result:
            raise ValueError(f"Audit result {audit_result_id} not found")

        control = FortiGateHardeningService._get_control_by_id(result.check_number)

        allowed = device_option_types_for_check(result.check_number)
        if option_type not in allowed:
            raise ValueError(
                f"Option type '{option_type}' is not used by check {result.check_number}"
            )
        spec = DEVICE_OPTION_TYPES[option_type]

        session = db.query(AuditSession).filter(
            AuditSession.id == result.session_id
        ).first()
        if not session or not session.target_ip:
            raise ValueError(f"No device IP found for audit result {audit_result_id}")

        scope = SCOPE_GLOBAL if spec.scope_override == "global" else control.scope
        vdom = result.vdom if scope == SCOPE_VDOM else None

        with FortiGateHardeningExecutor(
            ip=session.target_ip,
            username=ssh_username,
            password=ssh_password,
            port=ssh_port,
        ) as executor:
            raw = executor.ssh_client.collect(
                [spec.command], scope=scope, vdom=vdom, use_cache=False,
            )[spec.command]

        names = [e["name"].strip().strip('"') for e in _parse_table_entries(raw)]
        return list(dict.fromkeys(n for n in names if n))

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
        from .parameter_metadata import (
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
        from .parameter_metadata import (
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
        skip_backup: bool = False,
        ssh_port: int = 22
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
        from .parameter_metadata import (
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
            vdom=vdom,
            port=ssh_port
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
                    target_vdom = result.vdom if control.scope == SCOPE_VDOM else None
                    display_vdom = FortiGateHardeningService._display_target_vdom(
                        control.scope, result.vdom
                    )
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
                        executed_at=datetime.now(timezone.utc),
                        target_vdom=display_vdom
                    )
                    db.add(action)
                    db.commit()
                    db.refresh(action)
                    action_ids.append(action.id)

                    # Execute commands
                    exec_result = executor.execute_commands(
                        final_commands,
                        scope=control.scope,
                        vdom=target_vdom,
                    )

                    # Store output regardless of execution errors
                    action.output = redact_fortigate_secrets(exec_result["output"])

                    if not exec_result["success"]:
                        logger.warning(
                            f"FortiGate execution had errors for {check_id}: "
                            f"{exec_result['errors']} — still running verification"
                        )

                    # Always verify — FortiGate may return non-fatal errors (e.g.
                    # "Command fail. Return code -7") when a value is already set.
                    passed, evidence = executor.verify_check(control, vdom=target_vdom)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        result.status = CheckStatus.PASS
                        result.evidence_snippet = evidence
                        fixed_count += 1
                        fixed_checks.append({
                            "check_number": check_id,
                            "check_title": result.check_title,
                            "action_id": action.id,
                            "defaults_applied": defaults,
                            "vdom": display_vdom
                        })
                        logger.info(f"Successfully auto-fixed FortiGate check {check_id}")
                    else:
                        action.status = "failed"
                        if not exec_result["success"]:
                            action.error_message = "; ".join(exec_result["errors"])
                        else:
                            action.error_message = "Verification failed after fix"
                        failed_count += 1

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except Exception as e:
                    logger.error(
                        "Error auto-fixing FortiGate check %s: %s",
                        check_id, e, exc_info=True,
                    )
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
        skip_backup: bool = False,
        ssh_port: int = 22
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
        from .parameter_metadata import get_fortigate_check_defaults

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
            vdom=vdom,
            port=ssh_port
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
                    target_vdom = result.vdom if control.scope == SCOPE_VDOM else None
                    display_vdom = FortiGateHardeningService._display_target_vdom(
                        control.scope, result.vdom
                    )
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
                        executed_at=datetime.now(timezone.utc),
                        target_vdom=display_vdom
                    )
                    db.add(action)
                    db.commit()
                    db.refresh(action)
                    action_ids.append(action.id)

                    # Execute
                    exec_result = executor.execute_commands(
                        final_commands,
                        scope=control.scope,
                        vdom=target_vdom,
                    )

                    # Store output regardless of execution errors
                    action.output = redact_fortigate_secrets(exec_result["output"])

                    if not exec_result["success"]:
                        logger.warning(
                            f"FortiGate execution had errors for {check_id}: "
                            f"{exec_result['errors']} — still running verification"
                        )

                    # Always verify — FortiGate may return non-fatal errors (e.g.
                    # "Command fail. Return code -7") when a value is already set.
                    passed, evidence = executor.verify_check(control, vdom=target_vdom)
                    action.verification_passed = passed
                    action.verification_evidence = evidence

                    if passed:
                        action.status = "success"
                        result.status = CheckStatus.PASS
                        result.evidence_snippet = evidence
                        fixed_count += 1
                        execution_results.append({
                            "check_number": check_id,
                            "check_title": result.check_title,
                            "status": "success",
                            "action_id": action.id,
                            "verification_passed": True,
                            "vdom": display_vdom
                        })
                    else:
                        action.status = "failed"
                        if not exec_result["success"]:
                            action.error_message = "; ".join(exec_result["errors"])
                        else:
                            action.error_message = "Verification failed"
                        failed_count += 1
                        execution_results.append({
                            "check_number": check_id,
                            "check_title": result.check_title,
                            "status": "failed",
                            "action_id": action.id,
                            "verification_passed": False,
                            "vdom": display_vdom
                        })

                    action.completed_at = datetime.now(timezone.utc)
                    db.commit()

                except Exception as e:
                    logger.error(
                        "Error fixing FortiGate check %s: %s",
                        check_id, e, exc_info=True,
                    )
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
