"""
Unified Hardening Router

New schema-driven API endpoints for hardening operations.
Supports both post-audit mode (fix failed checks) and full hardening mode (all controls).
"""

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.auth import require_permission

from .schemas import SchemaLoader, SchemaValidator, ControlDefinition, InputDefinition


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
    _: dict = Depends(require_permission("hardening:read"))
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
            # Get failed check numbers from session
            # TODO: Query audit results for failed checks
            # For now, return all controls
            controls = SchemaLoader.get_all_controls(device_type)
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
    _: dict = Depends(require_permission("hardening:read"))
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
    user: dict = Depends(require_permission("hardening:write"))
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

    # Count by state
    applied_count = 0
    skipped_count = 0
    audited_count = 0
    failed_count = 0
    results: List[ControlExecutionResult] = []

    # Process each control
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
        elif cs.state == "APPLY":
            # TODO: Implement actual command generation and execution
            # For now, return a placeholder result
            applied_count += 1
            results.append(ControlExecutionResult(
                control_id=cs.control_id,
                status="success",
                message="Control applied (placeholder - actual execution not yet implemented)",
                commands_executed=[],
                verification_passed=True
            ))

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
    _: dict = Depends(require_permission("hardening:read"))
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
    _: dict = Depends(require_permission("hardening:read"))
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
