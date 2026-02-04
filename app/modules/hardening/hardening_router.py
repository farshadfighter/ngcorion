"""
Unified Hardening Router

New schema-driven API endpoints for hardening operations.
Supports both post-audit mode (fix failed checks) and full hardening mode (all controls).
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import json
import logging

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import AuditSession, AuditResult, Asset, HardeningAction
from app.models.audit import CheckStatus

from .schemas import SchemaLoader, SchemaValidator, ControlDefinition, InputDefinition
from .cisco_service import HardeningService
from .cisco_command_parser import RemediationParser, apply_defaults
from .cisco_ssh_executor import CiscoHardeningExecutor, redact_secrets_in_output

logger = logging.getLogger(__name__)


# ============================================
# Pydantic Request/Response Models
# ============================================

class HardeningFormRequest(BaseModel):
    """Request to get the hardening form schema."""
    device_type: str = Field(..., description="Device type: cisco, fortinet, linux, windows, apache")
    mode: str = Field(..., description="Mode: 'post_audit' or 'full'")
    session_id: Optional[int] = Field(None, description="Audit session ID (required for post_audit mode)")
    check_numbers: Optional[List[str]] = Field(None, description="Specific check numbers to include")


class SharedFieldValue(BaseModel):
    """Value for a shared field."""
    name: str
    value: Any


class ControlStateInput(BaseModel):
    """State and inputs for a single control."""
    control_id: str
    state: str = Field(..., description="SKIP, AUDIT, or APPLY")
    inputs: Dict[str, Any] = Field(default_factory=dict)


class ValidateRequest(BaseModel):
    """Request to validate control inputs."""
    device_type: str
    control_states: List[ControlStateInput]
    shared_fields: Dict[str, Any] = Field(default_factory=dict)


class ValidationErrorResponse(BaseModel):
    """Single validation error."""
    field: str
    message: str
    control_id: Optional[str] = None


class ValidateResponse(BaseModel):
    """Response from validation."""
    valid: bool
    errors: Dict[str, List[ValidationErrorResponse]] = Field(default_factory=dict)


class SSHCredentials(BaseModel):
    """SSH credentials for execution."""
    username: str
    password: str
    secret: Optional[str] = None


class ExecuteControlsRequest(BaseModel):
    """Request to execute hardening controls."""
    device_type: str
    device_ip: Optional[str] = Field(None, description="Device IP (required for full mode)")
    session_id: Optional[int] = Field(None, description="Session ID (for post-audit mode)")
    control_states: List[ControlStateInput]
    shared_fields: Dict[str, Any] = Field(default_factory=dict)
    ssh_credentials: SSHCredentials
    skip_backup: bool = False


class InputDefinitionResponse(BaseModel):
    """Input definition for frontend."""
    name: str
    type: str
    required: bool
    label: Optional[str] = None
    hint: Optional[str] = None
    default: Optional[Any] = None
    options: Optional[List[str]] = None
    min: Optional[int] = None
    max: Optional[int] = None
    ref: Optional[str] = None
    item_validation: Optional[Dict[str, Any]] = None
    item_schema: Optional[Dict[str, Any]] = None
    depends_on: Optional[Dict[str, Any]] = None


class ControlDefinitionResponse(BaseModel):
    """Control definition for frontend."""
    control_id: str
    title: str
    state_options: List[str]
    inputs: List[InputDefinitionResponse]
    risk_level: Optional[str] = None
    check_number: Optional[str] = None


class SharedFieldDefinitionResponse(BaseModel):
    """Shared field definition for frontend."""
    name: str
    type: str
    label: str
    required: bool
    hint: Optional[str] = None
    default: Optional[Any] = None
    options: Optional[List[str]] = None


class HardeningFormResponse(BaseModel):
    """Response with form schema."""
    device_type: str
    mode: str
    controls: List[ControlDefinitionResponse]
    shared_fields: List[SharedFieldDefinitionResponse]
    defaults: Dict[str, Any]


class ControlExecutionResult(BaseModel):
    """Result of executing a single control."""
    control_id: str
    status: str  # "success", "failed", "skipped"
    message: Optional[str] = None
    commands_executed: Optional[List[str]] = None
    verification_passed: Optional[bool] = None
    error: Optional[str] = None


class ExecuteControlsResponse(BaseModel):
    """Response from control execution."""
    total_controls: int
    applied_count: int
    skipped_count: int
    audited_count: int
    failed_count: int
    results: List[ControlExecutionResult]


# ============================================
# Router
# ============================================

router = APIRouter(prefix="/api/hardening/schema", tags=["Hardening Schema"])


def _input_to_response(input_def: InputDefinition) -> InputDefinitionResponse:
    """Convert InputDefinition to response model."""
    item_schema_dict = None
    if input_def.item_schema:
        item_schema_dict = {
            "type": input_def.item_schema.type,
            "fields": [
                {
                    "name": f.name,
                    "type": f.type.value if hasattr(f.type, 'value') else f.type,
                    "required": f.required,
                    "label": f.label,
                    "hint": f.hint,
                    "default": f.default,
                    "options": f.options,
                    "min": f.min,
                    "max": f.max,
                    "depends_on": f.depends_on.model_dump() if f.depends_on else None,
                }
                for f in input_def.item_schema.fields
            ]
        }

    depends_on_dict = None
    if input_def.depends_on:
        depends_on_dict = input_def.depends_on.model_dump(exclude_none=True)

    item_validation_dict = None
    if input_def.item_validation:
        item_validation_dict = input_def.item_validation.model_dump(exclude_none=True)

    return InputDefinitionResponse(
        name=input_def.name,
        type=input_def.type.value if hasattr(input_def.type, 'value') else input_def.type,
        required=input_def.required,
        label=input_def.label,
        hint=input_def.hint,
        default=input_def.default,
        options=input_def.options,
        min=input_def.min,
        max=input_def.max,
        ref=input_def.ref,
        item_validation=item_validation_dict,
        item_schema=item_schema_dict,
        depends_on=depends_on_dict,
    )


def _control_to_response(control: ControlDefinition) -> ControlDefinitionResponse:
    """Convert ControlDefinition to response model."""
    return ControlDefinitionResponse(
        control_id=control.control_id,
        title=control.title,
        state_options=control.state_options,
        inputs=[_input_to_response(inp) for inp in control.inputs],
        risk_level=control.risk_level,
        check_number=control.check_number,
    )


@router.post("/form", response_model=HardeningFormResponse)
async def get_hardening_form(
    request: HardeningFormRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("HARDENING", "read"))
):
    """
    Get the hardening form schema for a device type.

    Modes:
    - post_audit: Returns controls only for failed checks from an audit session
    - full: Returns all controls for the device type

    Response includes:
    - Control definitions with inputs
    - Shared field definitions
    - Default values and states
    """
    device_type = request.device_type.lower()

    # Load schema
    schema = SchemaLoader.get_schema(device_type)
    if not schema:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown device type: {device_type}. Supported: cisco, fortinet, linux, windows, apache"
        )

    # Get controls based on mode
    if request.mode == "post_audit":
        if request.check_numbers:
            # Use provided check numbers
            controls = SchemaLoader.get_controls_for_checks(device_type, request.check_numbers)
        elif request.session_id:
            # Query audit results for failed checks from the session
            session = db.query(AuditSession).filter(
                AuditSession.id == request.session_id
            ).first()
            if not session:
                raise HTTPException(
                    status_code=404,
                    detail=f"Audit session {request.session_id} not found"
                )

            # Get all failed results from the session
            failed_results = db.query(AuditResult).filter(
                AuditResult.session_id == request.session_id,
                AuditResult.status == CheckStatus.FAIL
            ).all()

            if not failed_results:
                raise HTTPException(
                    status_code=400,
                    detail="No failed checks found in the audit session"
                )

            # Extract check numbers and get corresponding controls
            check_numbers = [r.check_number for r in failed_results]
            controls = SchemaLoader.get_controls_for_checks(device_type, check_numbers)

            logger.info(f"Post-audit mode: Found {len(failed_results)} failed checks, mapped to {len(controls)} controls")
        else:
            raise HTTPException(
                status_code=400,
                detail="post_audit mode requires either session_id or check_numbers"
            )
    elif request.mode == "full":
        controls = SchemaLoader.get_all_controls(device_type)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown mode: {request.mode}. Supported: post_audit, full"
        )

    # Convert controls to response format
    control_responses = [_control_to_response(c) for c in controls]

    # Get shared fields
    shared_fields = schema.shared_fields
    shared_field_responses = [
        SharedFieldDefinitionResponse(
            name=name,
            type=sf.type.value if hasattr(sf.type, 'value') else sf.type,
            label=sf.label,
            required=sf.required,
            hint=sf.hint,
            default=sf.default,
            options=sf.options,
        )
        for name, sf in shared_fields.items()
    ]

    return HardeningFormResponse(
        device_type=device_type,
        mode=request.mode,
        controls=control_responses,
        shared_fields=shared_field_responses,
        defaults={
            "state": schema.defaults.state,
            "show_preview_config": schema.defaults.show_preview_config,
            "auto_fill_from_previous_inputs": schema.defaults.auto_fill_from_previous_inputs,
        }
    )


@router.post("/validate", response_model=ValidateResponse)
async def validate_hardening_inputs(
    request: ValidateRequest,
    current_user = Depends(require_permission("HARDENING", "read"))
):
    """
    Validate control inputs before execution.

    Validates:
    - Required fields for APPLY controls
    - Type-specific validation (int ranges, enum values, etc.)
    - Dependency conditions
    - List item validation (IP, CIDR, etc.)
    - Nested repeater fields
    """
    device_type = request.device_type.lower()

    # Build control states dict
    control_states = {
        cs.control_id: {"state": cs.state, "inputs": cs.inputs}
        for cs in request.control_states
    }

    # Validate all controls
    is_valid, errors = SchemaValidator.validate_all_controls(
        device_type,
        control_states,
        request.shared_fields
    )

    # Convert errors to response format
    error_responses = {}
    for control_id, control_errors in errors.items():
        error_responses[control_id] = [
            ValidationErrorResponse(
                field=e.field,
                message=e.message,
                control_id=e.control_id
            )
            for e in control_errors
        ]

    return ValidateResponse(
        valid=is_valid,
        errors=error_responses
    )


@router.post("/execute", response_model=ExecuteControlsResponse)
async def execute_hardening_controls(
    request: ExecuteControlsRequest,
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("HARDENING", "write"))
):
    """
    Execute hardening controls on a device.

    Process:
    1. Validate all inputs
    2. Generate commands for each APPLY control
    3. Connect to device via SSH
    4. Execute commands with backup
    5. Verify changes
    6. Return results per control
    """
    device_type = request.device_type.lower()

    # Build control states dict for validation
    control_states = {
        cs.control_id: {"state": cs.state, "inputs": cs.inputs}
        for cs in request.control_states
    }

    # Validate first
    is_valid, errors = SchemaValidator.validate_all_controls(
        device_type,
        control_states,
        request.shared_fields
    )

    if not is_valid:
        # Return validation errors
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Validation failed",
                "errors": {
                    control_id: [e.to_dict() for e in err_list]
                    for control_id, err_list in errors.items()
                }
            }
        )

    # Get device IP and session info
    device_ip = request.device_ip
    audit_session = None
    asset = None

    if request.session_id:
        # Post-audit mode: get IP from session
        audit_session = db.query(AuditSession).filter(
            AuditSession.id == request.session_id
        ).first()
        if audit_session:
            device_ip = audit_session.target_ip
            if audit_session.asset_id:
                asset = db.query(Asset).filter(Asset.id == audit_session.asset_id).first()

    if not device_ip:
        raise HTTPException(
            status_code=400,
            detail="Device IP is required (provide device_ip or session_id)"
        )

    # Count by state
    applied_count = 0
    skipped_count = 0
    audited_count = 0
    failed_count = 0
    results: List[ControlExecutionResult] = []

    # Separate controls by state
    apply_controls = [cs for cs in request.control_states if cs.state == "APPLY"]

    # Process SKIP and AUDIT first (no device connection needed)
    for cs in request.control_states:
        if cs.state == "SKIP":
            skipped_count += 1
            results.append(ControlExecutionResult(
                control_id=cs.control_id,
                status="skipped",
                message="Control skipped by user"
            ))
        elif cs.state == "AUDIT":
            audited_count += 1
            results.append(ControlExecutionResult(
                control_id=cs.control_id,
                status="audited",
                message="Control marked for audit only"
            ))

    # If no controls to apply, return early
    if not apply_controls:
        return ExecuteControlsResponse(
            total_controls=len(request.control_states),
            applied_count=applied_count,
            skipped_count=skipped_count,
            audited_count=audited_count,
            failed_count=failed_count,
            results=results
        )

    # Connect to device and execute APPLY controls
    try:
        with CiscoHardeningExecutor(
            ip=device_ip,
            username=request.ssh_credentials.username,
            password=request.ssh_credentials.password,
            secret=request.ssh_credentials.secret
        ) as executor:
            # Test connectivity
            executor.test_connectivity()

            # Backup config once before all changes
            backup = None
            if not request.skip_backup:
                logger.info(f"Creating backup for {device_ip}")
                backup = executor.backup_config()

            # Process each APPLY control
            for cs in apply_controls:
                control = SchemaLoader.get_control(device_type, cs.control_id)
                if not control:
                    failed_count += 1
                    results.append(ControlExecutionResult(
                        control_id=cs.control_id,
                        status="failed",
                        error=f"Control {cs.control_id} not found in schema"
                    ))
                    continue

                check_number = control.check_number

                # Get audit result if available (for creating HardeningAction)
                audit_result = None
                if audit_session and check_number:
                    audit_result = db.query(AuditResult).filter(
                        AuditResult.session_id == audit_session.id,
                        AuditResult.check_number == check_number
                    ).first()

                try:
                    # Get CIS rule and generate commands
                    rule = HardeningService._get_rule_by_check_number(check_number)
                    parsed = RemediationParser.parse_remediation(
                        remediation=rule.remediation,
                        check_number=check_number
                    )

                    # Merge control inputs with shared fields
                    all_params = {**request.shared_fields, **cs.inputs}
                    params_with_defaults = apply_defaults(all_params, parsed.defaults)

                    # Substitute parameters
                    final_commands = RemediationParser.substitute_parameters(
                        parsed.commands,
                        params_with_defaults
                    )

                    # Create HardeningAction record if we have audit context
                    action = None
                    if audit_result:
                        action = HardeningAction(
                            audit_result_id=audit_result.id,
                            user_id=current_user.id,
                            asset_id=asset.id if asset else audit_session.asset_id,
                            audit_session_id=audit_session.id,
                            check_number=check_number,
                            check_title=control.title,
                            action_type="execute",
                            status="executing",
                            commands_json=json.dumps(final_commands),
                            requires_config_mode=parsed.requires_config_mode,
                            credentials_provided=True,
                            backup_config=backup if not request.skip_backup else None,
                            executed_at=datetime.now(timezone.utc)
                        )
                        db.add(action)
                        db.commit()
                        db.refresh(action)

                    # Execute commands
                    exec_result = executor.execute_commands(
                        final_commands,
                        requires_config_mode=parsed.requires_config_mode
                    )

                    if not exec_result["success"]:
                        failed_count += 1
                        error_msg = "; ".join(exec_result["errors"])
                        if action:
                            action.status = "failed"
                            action.error_message = error_msg
                            action.output = redact_secrets_in_output(exec_result["output"])
                            action.completed_at = datetime.now(timezone.utc)
                            db.commit()

                        results.append(ControlExecutionResult(
                            control_id=cs.control_id,
                            status="failed",
                            commands_executed=final_commands,
                            error=error_msg
                        ))
                        continue

                    # Store output
                    if action:
                        action.output = redact_secrets_in_output(exec_result["output"])

                    # Verify the fix
                    passed, evidence = executor.verify_check(rule)

                    if action:
                        action.verification_passed = passed
                        action.verification_evidence = evidence

                    if passed:
                        applied_count += 1
                        if action:
                            action.status = "success"
                        results.append(ControlExecutionResult(
                            control_id=cs.control_id,
                            status="success",
                            message="Control applied and verified",
                            commands_executed=final_commands,
                            verification_passed=True
                        ))
                    else:
                        failed_count += 1
                        if action:
                            action.status = "failed"
                            action.error_message = "Verification failed: check still not passing"
                        results.append(ControlExecutionResult(
                            control_id=cs.control_id,
                            status="failed",
                            commands_executed=final_commands,
                            verification_passed=False,
                            error="Verification failed: check still not passing after fix"
                        ))

                    if action:
                        action.completed_at = datetime.now(timezone.utc)
                        db.commit()

                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error executing control {cs.control_id}: {str(e)}")
                    results.append(ControlExecutionResult(
                        control_id=cs.control_id,
                        status="failed",
                        error=f"{type(e).__name__}: {str(e)}"
                    ))

            # Save config once after all fixes
            if applied_count > 0:
                logger.info(f"Saving configuration for {device_ip}")
                executor.save_config()

    except Exception as e:
        logger.error(f"Connection error to {device_ip}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to connect to device: {str(e)}"
        )

    return ExecuteControlsResponse(
        total_controls=len(request.control_states),
        applied_count=applied_count,
        skipped_count=skipped_count,
        audited_count=audited_count,
        failed_count=failed_count,
        results=results
    )


@router.get("/devices")
async def get_supported_devices(
    current_user = Depends(require_permission("HARDENING", "read"))
):
    """
    Get list of supported device types.
    """
    return {
        "devices": [
            {"type": "cisco", "name": "Cisco IOS/IOS-XE", "status": "available"},
            {"type": "fortinet", "name": "FortiGate", "status": "coming_soon"},
            {"type": "linux", "name": "Linux", "status": "coming_soon"},
            {"type": "windows", "name": "Windows Server", "status": "coming_soon"},
            {"type": "apache", "name": "Apache HTTP Server", "status": "coming_soon"},
        ]
    }


@router.get("/control/{device_type}/{control_id}")
async def get_control_details(
    device_type: str,
    control_id: str,
    current_user = Depends(require_permission("HARDENING", "read"))
):
    """
    Get details for a specific control.
    """
    control = SchemaLoader.get_control(device_type.lower(), control_id)
    if not control:
        raise HTTPException(
            status_code=404,
            detail=f"Control {control_id} not found for device type {device_type}"
        )

    return _control_to_response(control)
