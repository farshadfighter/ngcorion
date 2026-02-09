"""
Linux Hardening Parameter Metadata

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
from dataclasses import dataclass


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
LINUX_PARAMETER_REGISTRY: Dict[str, ParameterMetadata] = {
    # ==================== NETWORK CONFIGURATION ====================
    "SYSLOG_SERVER": ParameterMetadata(
        name="SYSLOG_SERVER",
        input_type="ip",
        label="Syslog Server IP",
        description="IP address of central syslog server for remote logging",
        required=True,
        placeholder="192.168.1.100"
    ),

    "NTP_SERVER": ParameterMetadata(
        name="NTP_SERVER",
        input_type="ip",
        label="NTP Server IP",
        description="IP address of NTP time server",
        required=True,
        placeholder="pool.ntp.org"
    ),

    "ALLOWED_SSH_USERS": ParameterMetadata(
        name="ALLOWED_SSH_USERS",
        input_type="text",
        label="Allowed SSH Users",
        description="Space-separated list of users allowed to SSH (AllowUsers)",
        required=False,
        placeholder="admin deploy operator",
        default=""
    ),

    "ALLOWED_SSH_GROUPS": ParameterMetadata(
        name="ALLOWED_SSH_GROUPS",
        input_type="text",
        label="Allowed SSH Groups",
        description="Space-separated list of groups allowed to SSH (AllowGroups)",
        required=False,
        placeholder="sshusers wheel",
        default=""
    ),

    # ==================== BANNER TEXT ====================
    "BANNER_TEXT": ParameterMetadata(
        name="BANNER_TEXT",
        input_type="textarea",
        label="Warning Banner",
        description="Warning/legal banner text displayed to users",
        required=True,
        placeholder="Authorized users only. All activity is monitored and logged.",
        validation="min_length:10"
    ),

    "MOTD_TEXT": ParameterMetadata(
        name="MOTD_TEXT",
        input_type="textarea",
        label="MOTD Message",
        description="Message of the day displayed after login",
        required=False,
        placeholder="Welcome to this system. Unauthorized access is prohibited.",
        default="Authorized access only. All activity is monitored and logged."
    ),

    # ==================== PASSWORD POLICY ====================
    "PASS_MAX_DAYS": ParameterMetadata(
        name="PASS_MAX_DAYS",
        input_type="number",
        label="Password Max Age (days)",
        description="Maximum days before password must be changed",
        required=False,
        default="365",
        min_value=1,
        max_value=365
    ),

    "PASS_MIN_DAYS": ParameterMetadata(
        name="PASS_MIN_DAYS",
        input_type="number",
        label="Password Min Age (days)",
        description="Minimum days before password can be changed",
        required=False,
        default="1",
        min_value=0,
        max_value=7
    ),

    "PASS_WARN_AGE": ParameterMetadata(
        name="PASS_WARN_AGE",
        input_type="number",
        label="Password Warning Age (days)",
        description="Days before expiry to warn user",
        required=False,
        default="7",
        min_value=1,
        max_value=30
    ),

    "PASS_MIN_LEN": ParameterMetadata(
        name="PASS_MIN_LEN",
        input_type="number",
        label="Minimum Password Length",
        description="Minimum password length requirement",
        required=False,
        default="14",
        min_value=8,
        max_value=128
    ),

    # ==================== SSH CONFIGURATION ====================
    "SSH_MAX_AUTH_TRIES": ParameterMetadata(
        name="SSH_MAX_AUTH_TRIES",
        input_type="number",
        label="SSH Max Auth Tries",
        description="Maximum SSH authentication attempts",
        required=False,
        default="4",
        min_value=1,
        max_value=10
    ),

    "SSH_CLIENT_ALIVE_INTERVAL": ParameterMetadata(
        name="SSH_CLIENT_ALIVE_INTERVAL",
        input_type="number",
        label="SSH Client Alive Interval (seconds)",
        description="Interval for SSH keepalive checks",
        required=False,
        default="300",
        min_value=60,
        max_value=900
    ),

    "SSH_CLIENT_ALIVE_COUNT_MAX": ParameterMetadata(
        name="SSH_CLIENT_ALIVE_COUNT_MAX",
        input_type="number",
        label="SSH Client Alive Count Max",
        description="Maximum missed keepalive responses before disconnect",
        required=False,
        default="3",
        min_value=0,
        max_value=10
    ),

    "SSH_LOG_LEVEL": ParameterMetadata(
        name="SSH_LOG_LEVEL",
        input_type="select",
        label="SSH Log Level",
        description="SSH daemon logging verbosity",
        required=False,
        options=["INFO", "VERBOSE"],
        default="INFO"
    ),

    # ==================== AUDIT CONFIGURATION ====================
    "AUDIT_MAX_LOG_FILE": ParameterMetadata(
        name="AUDIT_MAX_LOG_FILE",
        input_type="number",
        label="Audit Max Log File Size (MB)",
        description="Maximum size of audit log files before rotation",
        required=False,
        default="8",
        min_value=1,
        max_value=100
    ),

    "AUDIT_SPACE_LEFT_ACTION": ParameterMetadata(
        name="AUDIT_SPACE_LEFT_ACTION",
        input_type="select",
        label="Audit Space Left Action",
        description="Action when audit disk space is low",
        required=False,
        options=["email", "syslog", "exec", "suspend", "single", "halt"],
        default="email"
    ),

    # ==================== FIREWALL CONFIGURATION ====================
    "FIREWALL_DEFAULT_POLICY": ParameterMetadata(
        name="FIREWALL_DEFAULT_POLICY",
        input_type="select",
        label="Firewall Default Policy",
        description="Default policy for incoming connections",
        required=False,
        options=["deny", "reject"],
        default="deny"
    ),

    # ==================== SYSCTL SETTINGS (have CIS defaults) ====================
    "SYSCTL_KERNEL_RANDOMIZE_VA_SPACE": ParameterMetadata(
        name="SYSCTL_KERNEL_RANDOMIZE_VA_SPACE",
        input_type="select",
        label="ASLR Level",
        description="Address Space Layout Randomization setting",
        required=False,
        options=["0", "1", "2"],
        default="2"
    ),

    "SYSCTL_FS_SUID_DUMPABLE": ParameterMetadata(
        name="SYSCTL_FS_SUID_DUMPABLE",
        input_type="select",
        label="Core Dump Setting",
        description="Allow core dumps for SUID programs",
        required=False,
        options=["0", "1", "2"],
        default="0"
    ),
}


# Mapping of Linux check numbers to their required parameters
LINUX_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # Section 1 - Initial Setup
    "LNX-L1-1.5.1": [],  # ASLR - no params, uses default
    "LNX-L1-1.5.4": [],  # Core dumps - no params
    "LNX-L1-1.6.1": ["MOTD_TEXT"],
    "LNX-L1-1.6.2": ["BANNER_TEXT"],

    # Section 2 - Services
    "LNX-L1-2.4.1": ["NTP_SERVER"],

    # Section 3 - Network
    "LNX-L1-3.1.1": [],  # IP forwarding - no params
    "LNX-L1-3.1.2": [],  # Packet redirects - no params
    "LNX-L1-3.2.1": [],  # Source routing - no params
    "LNX-L1-3.2.2": [],  # ICMP redirects - no params
    "LNX-L1-3.2.4": [],  # Log martians - no params
    "LNX-L1-3.2.5": [],  # Broadcast ICMP - no params
    "LNX-L1-3.2.7": [],  # RP filter - no params
    "LNX-L1-3.2.8": [],  # TCP SYN cookies - no params
    "LNX-L1-3.4.1": ["FIREWALL_DEFAULT_POLICY"],

    # Section 4 - Logging
    "LNX-L1-4.1.1": [],  # rsyslog enabled - no params
    "LNX-L1-4.2.1": [],  # auditd enabled - no params
    "LNX-L1-4.2.2": ["AUDIT_MAX_LOG_FILE", "AUDIT_SPACE_LEFT_ACTION"],

    # Section 5 - Access Control
    "LNX-L1-5.2.1": [],  # sshd_config permissions - no params
    "LNX-L1-5.2.6": [],  # X11 forwarding - no params
    "LNX-L1-5.2.7": ["SSH_MAX_AUTH_TRIES"],
    "LNX-L1-5.2.10": [],  # PermitRootLogin - no params
    "LNX-L1-5.2.11": [],  # PermitEmptyPasswords - no params
    "LNX-L1-5.2.12": [],  # PermitUserEnvironment - no params
    "LNX-L1-5.2.13": ["SSH_CLIENT_ALIVE_INTERVAL", "SSH_CLIENT_ALIVE_COUNT_MAX"],
    "LNX-L1-5.2.15": ["ALLOWED_SSH_USERS", "ALLOWED_SSH_GROUPS"],
    "LNX-L1-5.3.1": ["PASS_MIN_LEN"],
    "LNX-L1-5.4.1.1": ["PASS_MAX_DAYS"],
    "LNX-L1-5.4.1.2": ["PASS_MIN_DAYS"],

    # Section 6 - System Maintenance
    "LNX-L1-6.1.1": [],  # passwd permissions - no params
    "LNX-L1-6.2.1": [],  # UID 0 check - manual review
}


def get_linux_parameter_metadata(param_name: str) -> Optional[ParameterMetadata]:
    """Get metadata for a parameter by name."""
    return LINUX_PARAMETER_REGISTRY.get(param_name)


def get_linux_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """Get all parameter metadata for a specific check."""
    param_names = LINUX_CHECK_PARAMETER_MAP.get(check_number, [])
    return [
        LINUX_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in LINUX_PARAMETER_REGISTRY
    ]


def get_linux_required_parameters_for_check(check_number: str) -> List[ParameterMetadata]:
    """Get only required parameters (no defaults) for a specific check."""
    params = get_linux_parameters_for_check(check_number)
    return [p for p in params if p.required and p.default is None]


def linux_check_has_required_params(check_number: str) -> bool:
    """Check if a check has any required parameters without defaults."""
    return len(get_linux_required_parameters_for_check(check_number)) > 0


def get_linux_check_defaults(check_number: str) -> Dict[str, str]:
    """Get default values for a check's parameters."""
    params = get_linux_parameters_for_check(check_number)
    return {
        p.name: p.default
        for p in params
        if p.default is not None
    }


def is_linux_check_auto_fixable(check_number: str) -> bool:
    """
    Determine if a check can be auto-fixed with defaults only.

    A check is auto-fixable if:
    - It has no parameters, OR
    - All its parameters have default values
    """
    # Check if it's in our map
    if check_number not in LINUX_CHECK_PARAMETER_MAP:
        return False

    params = get_linux_parameters_for_check(check_number)
    if not params:
        return True
    return all(p.default is not None for p in params)


def aggregate_linux_parameters_for_checks(check_numbers: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate all unique parameters needed for a set of checks.

    Returns dict of parameter names to their metadata and which checks use them.
    """
    aggregated: Dict[str, Dict[str, Any]] = {}

    for check_number in check_numbers:
        params = get_linux_parameters_for_check(check_number)
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
                if check_number not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_number)

    return aggregated


def categorize_linux_checks_by_fixability(check_numbers: List[str]) -> Dict[str, List[str]]:
    """
    Categorize checks into auto-fixable and needs-params.
    """
    auto_fixable = []
    needs_params = []
    not_supported = []

    for check_number in check_numbers:
        if check_number not in LINUX_CHECK_PARAMETER_MAP:
            not_supported.append(check_number)
        elif is_linux_check_auto_fixable(check_number):
            auto_fixable.append(check_number)
        else:
            needs_params.append(check_number)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params,
        "not_supported": not_supported
    }


def get_linux_auto_fix_preview(check_numbers: List[str]) -> List[Dict[str, Any]]:
    """
    Get preview of what will be applied in automatic mode.
    """
    preview = []

    for check_number in check_numbers:
        if is_linux_check_auto_fixable(check_number):
            defaults = get_linux_check_defaults(check_number)
            preview.append({
                "check_number": check_number,
                "defaults": defaults
            })

    return preview
