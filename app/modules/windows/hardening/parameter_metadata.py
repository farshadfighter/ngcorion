"""
Windows Server Hardening Parameter Metadata

UI metadata for each hardening parameter used in Windows command templates.
Drives dynamic form generation in the frontend.

IMPORTANT: Every check in WINDOWS_CHECK_PARAMETER_MAP must be present or
it will be classified as "not_supported" by the categorize function.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .command_templates import (
    get_windows_hardening_template,
    get_windows_template_statements,
    get_windows_verify_statements,
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
        name="NEW_ADMIN_NAME",
        input_type="text",
        label="New Administrator Account Name",
        description="New name to assign to the built-in Administrator account",
        required=True,
        placeholder="WinAdmin",
    ),

    "NEW_GUEST_NAME": ParameterMetadata(
        name="NEW_GUEST_NAME",
        input_type="text",
        label="New Guest Account Name",
        description="New name to assign to the built-in Guest account",
        required=True,
        placeholder="WinGuest",
    ),

    "MAX_PASSWORD_AGE": ParameterMetadata(
        name="MAX_PASSWORD_AGE",
        input_type="number",
        label="Maximum Password Age (days)",
        description="Maximum number of days before a password must be changed (CIS: ≤ 365, not 0)",
        required=False,
        default="365",
        placeholder="365",
        min_value=1,
        max_value=365,
    ),

    "LOCKOUT_DURATION": ParameterMetadata(
        name="LOCKOUT_DURATION",
        input_type="number",
        label="Account Lockout Duration (minutes)",
        description="How long an account stays locked (CIS: ≥ 15 minutes)",
        required=False,
        default="15",
        placeholder="15",
        min_value=15,
        max_value=99999,
    ),

    "LOCKOUT_THRESHOLD": ParameterMetadata(
        name="LOCKOUT_THRESHOLD",
        input_type="number",
        label="Account Lockout Threshold (attempts)",
        description="Number of failed logons before lockout (CIS: 1-5)",
        required=False,
        default="5",
        placeholder="5",
        min_value=1,
        max_value=10,
    ),

    "LOCKOUT_WINDOW": ParameterMetadata(
        name="LOCKOUT_WINDOW",
        input_type="number",
        label="Reset Lockout Counter After (minutes)",
        description="Time before the lockout counter resets (CIS: ≥ 15 minutes)",
        required=False,
        default="15",
        placeholder="15",
        min_value=15,
        max_value=99999,
    ),

    "INACTIVITY_TIMEOUT": ParameterMetadata(
        name="INACTIVITY_TIMEOUT",
        input_type="number",
        label="Machine Inactivity Limit (seconds)",
        description="Screen lock timeout in seconds (CIS: ≤ 900, not 0)",
        required=False,
        default="900",
        placeholder="900",
        min_value=1,
        max_value=900,
    ),

    "SERVICE_NAME": ParameterMetadata(
        name="SERVICE_NAME",
        input_type="text",
        label="Windows Service Name",
        description="The short name of the Windows service to disable",
        required=True,
        placeholder="Spooler",
    ),
}


# ===================================================================
# Check → parameter mapping
# ===================================================================

WINDOWS_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {

    # Auto-fixable — no required parameters
    "WIN-L1-001": [],              # Password history = 24
    "WIN-L1-003": [],              # Min password age = 1
    "WIN-L1-004": [],              # Min password length = 14
    "WIN-L1-026": [],              # Disable Guest account
    "WIN-L1-029": [],              # Force audit subcategory
    "WIN-L1-030": [],              # Don't display last user name
    "WIN-L1-034": [],              # RestrictAnonymousSAM
    "WIN-L1-035": [],              # RestrictAnonymous
    "WIN-L1-036": [],              # EveryoneIncludesAnonymous = 0
    "WIN-L1-038": [],              # LmCompatibilityLevel = 5
    "WIN-L1-039": [],              # NoLMHash = 1
    "WIN-L1-040": [],              # FilterAdministratorToken = 1
    "WIN-L1-045": [],              # EnableLUA = 1
    "WIN-L1-046": [],              # PromptOnSecureDesktop = 1
    "WIN-L1-048": [],              # Disable Print Spooler
    "WIN-L1-051": [],              # Disable SSDP Discovery
    "WIN-L1-052": [],              # Disable UPnP Device Host
    "WIN-L1-095": [],              # Disable SMBv1
    "WIN-L1-098": [],              # Disable WDigest
    "WIN-L1-101": [],              # Enable NLA for RDP
    "WIN-L1-103": [],              # Disable PowerShell v2

    # Firewall auto-fixable
    "WIN-L1-058": [],              # Domain firewall on
    "WIN-L1-059": [],              # Domain inbound block
    "WIN-L1-060": [],              # Domain log dropped
    "WIN-L1-061": [],              # Private firewall on
    "WIN-L1-062": [],              # Private inbound block
    "WIN-L1-063": [],              # Private log dropped
    "WIN-L1-064": [],              # Public firewall on
    "WIN-L1-065": [],              # Public inbound block
    "WIN-L1-066": [],              # Public log dropped

    # Audit policy auto-fixable
    "WIN-L1-067": [],              # Credential Validation
    "WIN-L1-068": [],              # Application Group Management
    "WIN-L1-069": [],              # Computer Account Management
    "WIN-L1-071": [],              # Security Group Management
    "WIN-L1-072": [],              # User Account Management
    "WIN-L1-075": [],              # Account Lockout
    "WIN-L1-078": [],              # Logon
    "WIN-L1-085": [],              # Audit Policy Change
    "WIN-L1-089": [],              # Sensitive Privilege Use
    "WIN-L1-092": [],              # Security State Change
    "WIN-L1-093": [],              # Security System Extension
    "WIN-L1-094": [],              # System Integrity

    # Auto-fixable with defaults
    "WIN-L1-002": ["MAX_PASSWORD_AGE"],      # Max password age (default=365)
    "WIN-L1-008": ["LOCKOUT_DURATION"],      # Lockout duration (default=15)
    "WIN-L1-009": ["LOCKOUT_THRESHOLD"],     # Lockout threshold (default=5)
    "WIN-L1-011": ["LOCKOUT_WINDOW"],        # Reset lockout counter (default=15)
    "WIN-L1-031": ["INACTIVITY_TIMEOUT"],    # Inactivity timeout (default=900)
    "WIN-L1-097": [],              # LSA Protection (auto, requires restart)

    # Parameterized — require user input
    "WIN-L1-027": ["NEW_ADMIN_NAME"],
    "WIN-L1-028": ["NEW_GUEST_NAME"],
    "WIN-L1-048-CUSTOM": ["SERVICE_NAME"],

    # Manual only — comments for reference
    # WIN-L1-005: Password complexity (GPO)
    # WIN-L1-007: Reversible encryption (GPO)
    # WIN-L1-025: Block Microsoft accounts (GPO)
    # WIN-L1-107: Patch level (WSUS / manual)
    # WIN-L2-108: Credential Guard (UEFI/Hyper-V)
}


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
    Return True if the check can be fixed without any required user input.

    A check is auto-fixable when:
    - It exists in WINDOWS_CHECK_PARAMETER_MAP, AND
    - It has no parameters, OR all its parameters have default values, AND
    - Its template is not manual_only.
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
    """Return a dict of {param_name: default_value} for all params with defaults."""
    params = get_windows_parameters_for_check(check_id)
    return {p.name: p.default for p in params if p.default is not None}


def aggregate_windows_parameters_for_checks(check_ids: List[str]) -> Dict[str, Any]:
    """
    Aggregate unique parameters needed across multiple checks.

    Returns a dict keyed by parameter name with metadata and which checks use it.
    """
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
            else:
                if check_id not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_id)

    return aggregated


def categorize_windows_checks_by_fixability(check_ids: List[str]) -> Dict[str, List[str]]:
    """
    Split a list of check IDs into auto_fixable, needs_params, and not_supported.
    """
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
    """Return preview items for auto-fixable checks with their default parameter values."""
    preview = []
    for check_id in check_ids:
        if is_windows_check_auto_fixable(check_id):
            defaults = get_windows_check_defaults(check_id)
            preview.append({
                "check_id": check_id,
                # Same value under the key the Apache/Linux previews use, so
                # the shared UI can read either shape.
                "check_number": check_id,
                "defaults": defaults,
                "has_defaults": bool(defaults),
            })
    return preview
