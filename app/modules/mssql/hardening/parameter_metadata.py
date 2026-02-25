"""
SQL Server Hardening Parameter Metadata

UI metadata for each hardening parameter used in MSSQL command templates.
Drives dynamic form generation in the frontend.

IMPORTANT: Every check in MSSQL_CHECK_PARAMETER_MAP must be present or
it will be classified as "not_supported" by the categorize function.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_mssql_hardening_template,
    get_mssql_template_statements,
    get_mssql_verify_statements,
)


@dataclass
class ParameterMetadata:
    """Metadata for a single hardening parameter."""
    name: str
    input_type: str       # text, number, ip, select, textarea
    label: str
    description: str
    required: bool = True
    default: Optional[str] = None
    placeholder: Optional[str] = None
    validation: Optional[str] = None
    options: Optional[List[str]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None


# ===================================================================
# Parameter registry
# ===================================================================

MSSQL_PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {

    "DB_NAME": ParameterMetadata(
        name="DB_NAME",
        input_type="text",
        label="Database Name",
        description="Name of the user database to apply the setting to",
        required=True,
        placeholder="MyDatabase",
    ),

    "NEW_SA_NAME": ParameterMetadata(
        name="NEW_SA_NAME",
        input_type="text",
        label="New SA Login Name",
        description="New name to assign to the 'sa' login account",
        required=True,
        placeholder="sqladmin",
    ),

    "SYSADMIN_LOGIN": ParameterMetadata(
        name="SYSADMIN_LOGIN",
        input_type="text",
        label="Sysadmin Login to Remove",
        description="SQL Server login to be removed from the sysadmin fixed server role",
        required=True,
        placeholder="domain\\user",
    ),

    "CONTROL_LOGIN": ParameterMetadata(
        name="CONTROL_LOGIN",
        input_type="text",
        label="Login to Revoke CONTROL SERVER From",
        description="SQL Server login from which CONTROL SERVER permission will be revoked",
        required=True,
        placeholder="domain\\user",
    ),

    "LOGIN_NAME": ParameterMetadata(
        name="LOGIN_NAME",
        input_type="text",
        label="SQL Login Name",
        description="SQL Server login on which to enforce the password policy setting",
        required=True,
        placeholder="appuser",
    ),

    "NUM_ERROR_LOGS": ParameterMetadata(
        name="NUM_ERROR_LOGS",
        input_type="number",
        label="Number of Error Log Files",
        description="How many SQL Server error log files to retain (CIS recommends ≥ 12)",
        required=False,
        default="12",
        placeholder="12",
        min_value=6,
        max_value=99,
    ),

    "AUDIT_NAME": ParameterMetadata(
        name="AUDIT_NAME",
        input_type="text",
        label="SQL Server Audit Name",
        description="Name of the SQL Server Audit object",
        required=True,
        placeholder="SecurityAudit",
    ),

    "AUDIT_FILE_PATH": ParameterMetadata(
        name="AUDIT_FILE_PATH",
        input_type="text",
        label="Audit File Path",
        description=(
            "Directory path on the SQL Server host where audit files will be written "
            "(e.g. C:\\SQLAudit\\)"
        ),
        required=True,
        placeholder="C:\\SQLAudit\\",
    ),

    "SPEC_NAME": ParameterMetadata(
        name="SPEC_NAME",
        input_type="text",
        label="Audit Specification Name",
        description="Name for the Server Audit Specification capturing login events",
        required=True,
        placeholder="LoginAuditSpec",
    ),
}


# ===================================================================
# Check → parameter mapping
# ===================================================================
# Every check that has (or could have) a hardening template must appear here.
# Checks with [] are auto-fixable with no user input.
# Checks with parameter names require at least one value before execution.

MSSQL_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {

    # Auto-fixable — no required parameters
    "MSSQL-L1-002": [],   # Ad Hoc Distributed Queries = 0
    "MSSQL-L1-003": [],   # CLR enabled = 0
    "MSSQL-L1-004": [],   # Cross DB ownership chaining = 0
    "MSSQL-L1-005": [],   # Database Mail XPs = 0
    "MSSQL-L1-006": [],   # Ole Automation Procedures = 0
    "MSSQL-L1-007": [],   # Remote access = 0
    "MSSQL-L2-008": [],   # Remote admin connections = 0
    "MSSQL-L1-009": [],   # Scan for startup procs = 0
    "MSSQL-L1-010": [],   # xp_cmdshell = 0
    "MSSQL-L2-012": [],   # SQL Mail XPs = 0
    "MSSQL-L1-014": [],   # SA login disabled

    # Auto-fixable — all parameters have defaults
    "MSSQL-L1-019": ["NUM_ERROR_LOGS"],  # Error log count (default=12)

    # Parameterized — require user-supplied values
    "MSSQL-L1-011": ["DB_NAME"],
    "MSSQL-L2-015": ["NEW_SA_NAME"],
    "MSSQL-L1-016": ["SYSADMIN_LOGIN"],
    "MSSQL-L1-017": ["CONTROL_LOGIN"],
    "MSSQL-L1-020": ["AUDIT_NAME", "AUDIT_FILE_PATH"],
    "MSSQL-L1-021": ["AUDIT_NAME"],
    "MSSQL-L2-022": ["AUDIT_NAME", "SPEC_NAME"],
    "MSSQL-L1-023": ["LOGIN_NAME"],
    "MSSQL-L1-024": ["LOGIN_NAME"],

    # Manual only — no automated remediation
    # MSSQL-L1-001: patch level (Windows Update / manual)
    # MSSQL-L1-013: auth mode (requires SSMS + restart)
    # MSSQL-L2-018: public role permissions (manual review)
    # MSSQL-L2-025: TDE (multi-step, multi-DB)
    # MSSQL-L1-026: port change (Configuration Manager + restart)
}


# ===================================================================
# Helper functions
# ===================================================================

def get_mssql_parameter_metadata(param_name: str) -> Optional[ParameterMetadata]:
    """Return metadata for a parameter by name."""
    return MSSQL_PARAMETER_REGISTRY.get(param_name)


def get_mssql_parameters_for_check(check_id: str) -> List[ParameterMetadata]:
    """Return all ParameterMetadata objects for the given check."""
    param_names = MSSQL_CHECK_PARAMETER_MAP.get(check_id, [])
    return [
        MSSQL_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in MSSQL_PARAMETER_REGISTRY
    ]


def is_mssql_check_auto_fixable(check_id: str) -> bool:
    """
    Return True if the check can be fixed without any required user input.

    A check is auto-fixable when:
    - It exists in MSSQL_CHECK_PARAMETER_MAP, AND
    - It has no parameters, OR all its parameters have default values, AND
    - Its template is not manual_only.
    """
    if check_id not in MSSQL_CHECK_PARAMETER_MAP:
        return False
    template = get_mssql_hardening_template(check_id)
    if template and template.manual_only:
        return False
    params = get_mssql_parameters_for_check(check_id)
    if not params:
        return True
    return all(p.default is not None for p in params)


def get_mssql_check_defaults(check_id: str) -> Dict[str, str]:
    """Return a dict of {param_name: default_value} for all params with defaults."""
    params = get_mssql_parameters_for_check(check_id)
    return {p.name: p.default for p in params if p.default is not None}


def aggregate_mssql_parameters_for_checks(check_ids: List[str]) -> Dict[str, Any]:
    """
    Aggregate unique parameters needed across multiple checks.

    Returns a dict keyed by parameter name with metadata and which checks use it.
    """
    aggregated: Dict[str, Any] = {}

    for check_id in check_ids:
        for param in get_mssql_parameters_for_check(check_id):
            if param.name not in aggregated:
                aggregated[param.name] = {
                    "type": param.input_type,
                    "label": param.label,
                    "description": param.description,
                    "required": param.required and param.default is None,
                    "default": param.default,
                    "placeholder": param.placeholder,
                    "validation": param.validation,
                    "options": param.options,
                    "min_value": param.min_value,
                    "max_value": param.max_value,
                    "checks": [check_id],
                }
            else:
                if check_id not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_id)

    return aggregated


def categorize_mssql_checks_by_fixability(check_ids: List[str]) -> Dict[str, List[str]]:
    """
    Split a list of check IDs into auto_fixable, needs_params, and not_supported.
    """
    auto_fixable: List[str] = []
    needs_params: List[str] = []
    not_supported: List[str] = []

    for check_id in check_ids:
        if check_id not in MSSQL_CHECK_PARAMETER_MAP:
            not_supported.append(check_id)
        elif is_mssql_check_auto_fixable(check_id):
            auto_fixable.append(check_id)
        else:
            needs_params.append(check_id)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params,
        "not_supported": not_supported,
    }


def get_mssql_auto_fix_preview(check_ids: List[str]) -> List[Dict[str, Any]]:
    """Return preview items for auto-fixable checks with their default parameter values."""
    preview = []
    for check_id in check_ids:
        if is_mssql_check_auto_fixable(check_id):
            defaults = get_mssql_check_defaults(check_id)
            preview.append({
                "check_id": check_id,
                "defaults": defaults,
            })
    return preview
