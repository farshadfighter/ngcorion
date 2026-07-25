"""
Windows Server Hardening Parameter Metadata

UI metadata for each hardening parameter used in Windows command templates.
Drives dynamic form generation in the frontend.

The check → parameter map is *derived* from the hardening templates
(``get_all_supported_checks``) so every check that has a template is represented
here: parameterised checks pull their parameter list from ``_PARAM_OVERRIDES``;
every other supported check is auto-fixable with no required input.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_all_supported_checks,
    get_windows_hardening_template,
    get_windows_template_statements,   # re-exported for callers
    get_windows_verify_statements,     # re-exported for callers
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

WINDOWS_PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {

    "NEW_ADMIN_NAME": ParameterMetadata(
        name="NEW_ADMIN_NAME", input_type="text",
        label="New Administrator Account Name",
        description="New name for the built-in Administrator account",
        required=True, placeholder="WinAdmin",
    ),

    "NEW_GUEST_NAME": ParameterMetadata(
        name="NEW_GUEST_NAME", input_type="text",
        label="New Guest Account Name",
        description="New name for the built-in Guest account",
        required=True, placeholder="WinGuest",
    ),

    "MAX_PASSWORD_AGE": ParameterMetadata(
        name="MAX_PASSWORD_AGE", input_type="number",
        label="Maximum Password Age (days)",
        description="Maximum days before a password must change (CIS: <= 365, not 0)",
        required=False, default="365", placeholder="365",
        min_value=1, max_value=365,
    ),

    "LOCKOUT_DURATION": ParameterMetadata(
        name="LOCKOUT_DURATION", input_type="number",
        label="Account Lockout Duration (minutes)",
        description="How long an account stays locked (CIS: >= 15 minutes)",
        required=False, default="15", placeholder="15",
        min_value=15, max_value=99999,
    ),

    "LOCKOUT_THRESHOLD": ParameterMetadata(
        name="LOCKOUT_THRESHOLD", input_type="number",
        label="Account Lockout Threshold (attempts)",
        description="Failed logons before lockout (CIS: 1-5)",
        required=False, default="5", placeholder="5",
        min_value=1, max_value=5,
    ),

    "LOCKOUT_WINDOW": ParameterMetadata(
        name="LOCKOUT_WINDOW", input_type="number",
        label="Reset Lockout Counter After (minutes)",
        description="Time before the lockout counter resets (CIS: >= 15 minutes)",
        required=False, default="15", placeholder="15",
        min_value=15, max_value=99999,
    ),
}


# ===================================================================
# Check → parameter mapping (derived from templates)
# ===================================================================

# Only the checks that take user input need an override; everything else that
# has a template is auto-fixable with no parameters.
_PARAM_OVERRIDES: Dict[str, List[str]] = {
    "WIN-2025-1.1.2": ["MAX_PASSWORD_AGE"],
    "WIN-2025-1.2.1": ["LOCKOUT_DURATION"],
    "WIN-2025-1.2.2": ["LOCKOUT_THRESHOLD"],
    "WIN-2025-1.2.4": ["LOCKOUT_WINDOW"],
    "WIN-2025-2.3.1.3": ["NEW_ADMIN_NAME"],
    "WIN-2025-2.3.1.4": ["NEW_GUEST_NAME"],
}


def _build_check_parameter_map() -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for check_id in get_all_supported_checks():
        template = get_windows_hardening_template(check_id)
        if template and template.manual_only:
            # Manual-only checks are intentionally excluded from the map so
            # categorize() classifies them as not auto-fixable.
            continue
        mapping[check_id] = _PARAM_OVERRIDES.get(check_id, [])
    return mapping


WINDOWS_CHECK_PARAMETER_MAP: Dict[str, List[str]] = _build_check_parameter_map()


# ===================================================================
# Helper functions
# ===================================================================

def get_windows_parameter_metadata(param_name: str) -> Optional[ParameterMetadata]:
    """Return metadata for a parameter by name."""
    return WINDOWS_PARAMETER_REGISTRY.get(param_name)


def get_windows_parameters_for_check(check_id: str) -> List[ParameterMetadata]:
    """Return all ParameterMetadata objects for the given check."""
    param_names = WINDOWS_CHECK_PARAMETER_MAP.get(check_id, [])
    return [
        WINDOWS_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in WINDOWS_PARAMETER_REGISTRY
    ]


def is_windows_check_auto_fixable(check_id: str) -> bool:
    """
    True if the check can be fixed without any required user input.

    Auto-fixable when it is in WINDOWS_CHECK_PARAMETER_MAP, its template is not
    manual_only, and it has no parameters (or all have defaults).
    """
    if check_id not in WINDOWS_CHECK_PARAMETER_MAP:
        return False
    template = get_windows_hardening_template(check_id)
    if template and template.manual_only:
        return False
    params = get_windows_parameters_for_check(check_id)
    if not params:
        return True
    return all(p.default is not None for p in params)


def get_windows_check_defaults(check_id: str) -> Dict[str, str]:
    """Return {param_name: default_value} for all params that have defaults."""
    params = get_windows_parameters_for_check(check_id)
    return {p.name: p.default for p in params if p.default is not None}


def aggregate_windows_parameters_for_checks(check_ids: List[str]) -> Dict[str, Any]:
    """Aggregate unique parameters needed across multiple checks."""
    aggregated: Dict[str, Any] = {}
    for check_id in check_ids:
        for param in get_windows_parameters_for_check(check_id):
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
            elif check_id not in aggregated[param.name]["checks"]:
                aggregated[param.name]["checks"].append(check_id)
    return aggregated


def categorize_windows_checks_by_fixability(check_ids: List[str]) -> Dict[str, List[str]]:
    """Split check IDs into auto_fixable, needs_params, and not_supported."""
    auto_fixable: List[str] = []
    needs_params: List[str] = []
    not_supported: List[str] = []
    for check_id in check_ids:
        if check_id not in WINDOWS_CHECK_PARAMETER_MAP:
            not_supported.append(check_id)
        elif is_windows_check_auto_fixable(check_id):
            auto_fixable.append(check_id)
        else:
            needs_params.append(check_id)
    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params,
        "not_supported": not_supported,
    }


def get_windows_auto_fix_preview(check_ids: List[str]) -> List[Dict[str, Any]]:
    """Return preview items for auto-fixable checks with their default values."""
    preview = []
    for check_id in check_ids:
        if is_windows_check_auto_fixable(check_id):
            defaults = get_windows_check_defaults(check_id)
            preview.append({
                "check_id": check_id,
                "check_number": check_id,
                "defaults": defaults,
                "has_defaults": bool(defaults),
            })
    return preview
