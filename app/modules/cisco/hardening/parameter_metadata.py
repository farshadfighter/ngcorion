"""
Cisco Hardening Parameter Metadata

Defines UI metadata for each hardening parameter used in command templates.
This metadata is used to generate dynamic forms in the frontend.

Each parameter includes:
- type: Input type (password, text, textarea, number, ip, select)
- label: Display name for the form field
- description: Help text/tooltip
- placeholder: Example value
- validation: Validation rules (optional)
- default: Default value (optional)
- options: Choices for select type (optional)
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ParameterMetadata:
    """Metadata for a single hardening parameter."""
    name: str
    input_type: str  # password, text, textarea, number, ip, select
    label: str
    description: str
    required: bool = True
    default: Optional[str] = None
    placeholder: Optional[str] = None
    validation: Optional[str] = None
    options: Optional[List[str]] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None


# Parameter registry - all known parameters and their UI metadata
PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {
    # ==================== SECRETS/PASSWORDS ====================
    "STRONG_SECRET": ParameterMetadata(
        name="STRONG_SECRET",
        input_type="password",
        label="Enable Secret",
        description="New enable secret password (will be hashed with Type 5)",
        required=True,
        placeholder="MySecureSecret123!",
        validation="min_length:8"
    ),

    # ==================== BANNER TEXT ====================
    "BANNER_TEXT": ParameterMetadata(
        name="BANNER_TEXT",
        input_type="textarea",
        label="Banner Message",
        description="Warning/legal banner text displayed to users",
        required=True,
        placeholder="Authorized users only. All activity is monitored and logged.",
        validation="min_length:10"
    ),

    # ==================== NETWORK CONFIGURATION ====================
    "ACL_NAME": ParameterMetadata(
        name="ACL_NAME",
        input_type="text",
        label="VTY Access List Name",
        description="Name of existing ACL to apply to VTY lines for SSH access control",
        required=True,
        placeholder="VTY_ACCESS",
        validation="acl_name"
    ),

    "SYSLOG_SERVER": ParameterMetadata(
        name="SYSLOG_SERVER",
        input_type="ip",
        label="Syslog Server IP",
        description="IP address of central syslog server for log forwarding",
        required=True,
        placeholder="192.168.1.100"
    ),

    "NTP_SERVER": ParameterMetadata(
        name="NTP_SERVER",
        input_type="ip",
        label="NTP Server IP",
        description="IP address of NTP time server for clock synchronization",
        required=True,
        placeholder="192.168.1.10"
    ),

    # ==================== AAA CONFIGURATION ====================
    "METHOD_NAME": ParameterMetadata(
        name="METHOD_NAME",
        input_type="text",
        label="AAA Method List Name",
        description="Name for AAA authentication method list",
        required=True,
        default="default",
        placeholder="default"
    ),

    "METHOD_TYPE": ParameterMetadata(
        name="METHOD_TYPE",
        input_type="select",
        label="AAA Method Type",
        description="Authentication method type for AAA",
        required=True,
        options=["local", "group tacacs+", "group radius", "enable"],
        default="local"
    ),

    # ==================== DEVICE IDENTITY ====================
    "HOSTNAME": ParameterMetadata(
        name="HOSTNAME",
        input_type="text",
        label="Device Hostname",
        description="Hostname for the device (affects prompt and identification)",
        required=True,
        placeholder="ROUTER-01",
        validation="hostname"
    ),

    "DOMAIN_NAME": ParameterMetadata(
        name="DOMAIN_NAME",
        input_type="text",
        label="Domain Name",
        description="Domain name for FQDN and SSH key generation",
        required=True,
        placeholder="example.com",
        validation="domain"
    ),

    # ==================== TIMEOUTS (have defaults) ====================
    "TIMEOUT_MIN": ParameterMetadata(
        name="TIMEOUT_MIN",
        input_type="number",
        label="Exec Timeout (minutes)",
        description="Idle timeout in minutes before session disconnection",
        required=False,
        default="5",
        min_value=1,
        max_value=60
    ),

    "TIMEOUT_SEC": ParameterMetadata(
        name="TIMEOUT_SEC",
        input_type="number",
        label="Exec Timeout (seconds)",
        description="Additional seconds for exec timeout",
        required=False,
        default="0",
        min_value=0,
        max_value=59
    ),

    # ==================== SSH CONFIGURATION ====================
    "RETRIES": ParameterMetadata(
        name="RETRIES",
        input_type="number",
        label="SSH Auth Retries",
        description="Maximum SSH authentication retry attempts",
        required=False,
        default="3",
        min_value=1,
        max_value=5
    ),

    # ==================== CRYPTO ====================
    "MODULUS": ParameterMetadata(
        name="MODULUS",
        input_type="select",
        label="RSA Key Modulus (bits)",
        description=(
            "Size of the RSA host key generated for SSH. CIS requires at least "
            "2048 bits; smaller keys (the IOS default is 512, and legacy devices "
            "commonly carry 1024) do not satisfy this control."
        ),
        required=False,
        default="2048",
        options=["2048", "4096"],
        min_value=2048,
        max_value=4096
    ),

    # ==================== LOGGING ====================
    "SIZE": ParameterMetadata(
        name="SIZE",
        input_type="number",
        label="Logging Buffer Size",
        description="Size of logging buffer in bytes",
        required=False,
        default="16384",
        min_value=4096,
        max_value=2147483647
    ),
}


# Mapping of check numbers to their required parameters
CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    "IOS-L1-001": ["STRONG_SECRET"],
    "IOS-L1-002": ["TIMEOUT_MIN", "TIMEOUT_SEC"],
    "IOS-L1-003": ["ACL_NAME"],
    "IOS-L1-004": [],  # No parameters
    "IOS-L1-005": ["BANNER_TEXT"],
    "IOS-L1-006": ["BANNER_TEXT"],
    "IOS-L1-007": [],  # No parameters
    "IOS-L1-008": ["TIMEOUT_SEC"],
    "IOS-L1-009": ["RETRIES"],
    "IOS-L1-010": [],  # No parameters
    "IOS-L1-011": [],  # No parameters
    "IOS-L1-012": [],  # No parameters
    "IOS-L1-013": ["METHOD_NAME", "METHOD_TYPE"],
    "IOS-L1-014": ["SYSLOG_SERVER"],
    "IOS-L1-015": ["SIZE"],
    "IOS-L1-016": [],  # No parameters
    "IOS-L1-017": ["NTP_SERVER"],
    "IOS-L1-018": [],  # No parameters
    "IOS-L1-019": [],  # No parameters
    "IOS-L1-0010": ["HOSTNAME"],
    "IOS-L1-0011": ["DOMAIN_NAME"],
    "IOS-L1-0012": [],  # No parameters
    "IOS-L1-020": [],  # No parameters
    "IOS-L1-021": [],  # No parameters
    "IOS-L1-022": [],  # No parameters
    "IOS-L1-023": [],  # No parameters
}


def get_parameter_metadata(param_name: str) -> Optional[ParameterMetadata]:
    """
    Get metadata for a parameter by name.

    Args:
        param_name: Parameter name (e.g., "STRONG_SECRET")

    Returns:
        ParameterMetadata object or None if not found
    """
    return PARAMETER_REGISTRY.get(param_name)


def get_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """
    Get all parameter metadata for a specific check.

    Driven by the command template, which is the single source of truth for what
    placeholders a check's remediation actually needs. The template is CIS-aware
    (it resolves CIS-X.X.X ids via CIS_SECTION_TO_IOS), unlike the legacy
    CHECK_PARAMETER_MAP, which is keyed only by IOS-L1-XXX ids and is incomplete.

    For each placeholder, UI metadata (label/type/description/…) comes from
    PARAMETER_REGISTRY (keyed by parameter name), while `default` and `required`
    come from the template: a parameter is required iff the template lists it in
    `required_params` and provides no default for it.

    Args:
        check_number: CIS check number (e.g., "CIS-1.1.2") or IOS id ("IOS-L1-001")

    Returns:
        List of ParameterMetadata objects for the check's parameters
    """
    import dataclasses
    from .command_templates import has_template, get_template
    from .command_parser import RemediationParser

    if not has_template(check_number):
        return []

    template = get_template(check_number)
    required_params = template.get("required_params", [])
    optional_params = template.get("optional_params", [])
    template_defaults = template.get("defaults", {})

    # Placeholder names, order-preserving and de-duplicated. Fall back to the
    # placeholders actually present in the commands if the template doesn't
    # enumerate them explicitly.
    param_names = list(dict.fromkeys(list(required_params) + list(optional_params)))
    if not param_names:
        seen = set()
        for cmd in template.get("commands", []):
            for name in RemediationParser.extract_parameters(cmd):
                if name not in seen:
                    seen.add(name)
                    param_names.append(name)

    params: List[ParameterMetadata] = []
    for name in param_names:
        base = PARAMETER_REGISTRY.get(name)
        # Default comes from the template only (contextually correct). The registry
        # is used purely for UI metadata — its name-keyed defaults are not always
        # valid in every command context, so they must not drive fixability.
        default = template_defaults.get(name)
        required = name in required_params and name not in template_defaults
        if base is not None:
            params.append(dataclasses.replace(base, default=default, required=required))
        else:
            # No UI metadata registered for this placeholder — synthesize a
            # generic text field so the form can still collect it.
            params.append(ParameterMetadata(
                name=name,
                input_type="text",
                label=name.replace("_", " ").title(),
                description=f"Value for {name}",
                required=required,
                default=default,
            ))
    return params


def get_required_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """
    Get only required parameters (no defaults) for a specific check.

    Args:
        check_number: CIS check number

    Returns:
        List of required ParameterMetadata objects
    """
    params = get_parameters_for_check(check_number)
    return [p for p in params if p.required and p.default is None]


def check_has_required_params(check_number: str) -> bool:
    """
    Check if a check has any required parameters without defaults.

    Args:
        check_number: CIS check number

    Returns:
        True if check requires user input, False if auto-fixable
    """
    return len(get_required_parameters_for_check(check_number)) > 0


def get_check_defaults(check_number: str) -> Dict[str, str]:
    """
    Get default values for a check's parameters.

    Args:
        check_number: CIS check number

    Returns:
        Dict of parameter names to default values
    """
    params = get_parameters_for_check(check_number)
    return {
        p.name: p.default
        for p in params
        if p.default is not None
    }


def is_check_auto_fixable(check_number: str) -> bool:
    """
    Determine if a check can be auto-fixed with defaults only.

    A check is auto-fixable if:
    - It has no parameters, OR
    - All its parameters have default values

    Args:
        check_number: CIS check number

    Returns:
        True if can be fixed without user input
    """
    params = get_parameters_for_check(check_number)
    if not params:
        return True
    return all(p.default is not None for p in params)


def aggregate_parameters_for_checks(check_numbers: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate all unique parameters needed for a set of checks.

    Args:
        check_numbers: List of CIS check numbers

    Returns:
        Dict of parameter names to their metadata and which checks use them:
        {
            "STRONG_SECRET": {
                "type": "password",
                "label": "Enable Secret",
                "description": "...",
                "required": True,
                "default": None,
                "checks": ["IOS-L1-001"]
            },
            ...
        }
    """
    aggregated: Dict[str, Dict[str, Any]] = {}

    for check_number in check_numbers:
        params = get_parameters_for_check(check_number)
        for param in params:
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
                    "checks": [check_number]
                }
            else:
                # Parameter already exists, just add the check reference
                if check_number not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_number)

    return aggregated


def categorize_checks_by_fixability(check_numbers: List[str]) -> Dict[str, List[str]]:
    """
    Categorize checks into auto-fixable and needs-params.

    Args:
        check_numbers: List of CIS check numbers

    Returns:
        {
            "auto_fixable": ["IOS-L1-002", "IOS-L1-004", ...],
            "needs_params": ["IOS-L1-001", "IOS-L1-005", ...]
        }
    """
    auto_fixable = []
    needs_params = []

    for check_number in check_numbers:
        if is_check_auto_fixable(check_number):
            auto_fixable.append(check_number)
        else:
            needs_params.append(check_number)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params
    }


def get_auto_fix_preview(check_numbers: List[str]) -> List[Dict[str, Any]]:
    """
    Get preview of what will be applied in automatic mode.

    Args:
        check_numbers: List of failed check numbers

    Returns:
        List of checks with their default values:
        [
            {
                "check_number": "IOS-L1-002",
                "defaults": {"TIMEOUT_MIN": "5", "TIMEOUT_SEC": "0"}
            },
            ...
        ]
    """
    preview = []

    for check_number in check_numbers:
        if is_check_auto_fixable(check_number):
            defaults = get_check_defaults(check_number)
            preview.append({
                "check_number": check_number,
                "defaults": defaults
            })

    return preview
