"""
FortiGate hardening parameter metadata.

UI metadata for the parameters used by the auto-remediation templates
(:mod:`command_templates`). Only the parameters those templates actually
reference are defined here; the frontend renders a dynamic form from this.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class FortiGateParameterMetadata:
    """Metadata for a single FortiGate hardening parameter."""
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


# Only the parameters referenced by the 22 auto-remediation templates.
FORTIGATE_PARAMETER_REGISTRY: Dict[str, FortiGateParameterMetadata] = {
    "DNS_PRIMARY": FortiGateParameterMetadata(
        name="DNS_PRIMARY", input_type="ip", label="Primary DNS Server",
        description="IP address of the primary DNS server", required=True, placeholder="8.8.8.8"),
    "HOSTNAME": FortiGateParameterMetadata(
        name="HOSTNAME", input_type="text", label="Hostname",
        description="Device hostname for identification in logs and management",
        required=True, placeholder="fgt-hq-01"),
    "ADMIN_TIMEOUT": FortiGateParameterMetadata(
        name="ADMIN_TIMEOUT", input_type="number", label="Admin Idle Timeout (minutes)",
        description="Idle minutes before an admin session disconnects",
        required=False, default="10", min_value=1, max_value=480),
    "ADMIN_LOCKOUT_THRESHOLD": FortiGateParameterMetadata(
        name="ADMIN_LOCKOUT_THRESHOLD", input_type="number", label="Admin Lockout Threshold",
        description="Failed admin login attempts before lockout",
        required=False, default="3", min_value=1, max_value=10),
    "ADMIN_LOCKOUT_DURATION": FortiGateParameterMetadata(
        name="ADMIN_LOCKOUT_DURATION", input_type="number", label="Admin Lockout Duration (seconds)",
        description="Lockout period after exceeding the admin login retry threshold",
        required=False, default="60", min_value=1, max_value=86400),
    "HA_MONITOR_INTERFACE": FortiGateParameterMetadata(
        name="HA_MONITOR_INTERFACE", input_type="text", label="HA Monitored Interface(s)",
        description="Interface(s) to monitor for HA failover (space-separated)",
        required=True, placeholder="port1 port2"),
    "DNSFILTER_PROFILE": FortiGateParameterMetadata(
        name="DNSFILTER_PROFILE", input_type="text", label="DNS Filter Profile",
        description="Name of the DNS filter profile to update",
        required=False, default="default", placeholder="default"),
    "APP_LIST": FortiGateParameterMetadata(
        name="APP_LIST", input_type="text", label="Application Control List",
        description="Name of the application control sensor/list to update",
        required=False, default="default", placeholder="default"),
    "AUTH_LOCKOUT_THRESHOLD": FortiGateParameterMetadata(
        name="AUTH_LOCKOUT_THRESHOLD", input_type="number", label="User Auth Lockout Threshold",
        description="Failed user login attempts before lockout",
        required=False, default="3", min_value=1, max_value=10),
    "AUTH_LOCKOUT_DURATION": FortiGateParameterMetadata(
        name="AUTH_LOCKOUT_DURATION", input_type="number", label="User Auth Lockout Duration (seconds)",
        description="Lockout period after exceeding the user login retry threshold",
        required=False, default="60", min_value=1, max_value=86400),
    "FAZ_SERVER": FortiGateParameterMetadata(
        name="FAZ_SERVER", input_type="ip", label="FortiAnalyzer Server IP",
        description="IP address of FortiAnalyzer for centralized logging",
        required=True, placeholder="192.168.1.200"),
}


# Check ID -> required/optional parameter names. Only the templated (auto-fixable)
# checks need entries; everything else is gated out by ``has_fortigate_template``.
FORTIGATE_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    "FG-BL-043": ["DNS_PRIMARY"],
    "FG-BL-092": [],
    "FG-SYS-001": [],
    "FG-BL-040": [],
    "FG-SYS-003": ["HOSTNAME"],
    "FG-SYS-005": [],
    "FG-SYS-006": [],
    "FG-BL-090": [],
    "FG-BL-030": [],
    "FG-PW-001": ["ADMIN_LOCKOUT_THRESHOLD", "ADMIN_LOCKOUT_DURATION"],
    "FG-BL-004": ["ADMIN_TIMEOUT"],
    "FG-BL-002": [],
    "FG-HA-005": ["HA_MONITOR_INTERFACE"],
    "FG-AV-001": [],
    "FG-AV-003": [],
    "FG-AV-004": [],
    "FG-DNS-001": ["DNSFILTER_PROFILE"],
    "FG-APP-002": ["APP_LIST"],
    "FG-USER-001": ["AUTH_LOCKOUT_THRESHOLD", "AUTH_LOCKOUT_DURATION"],
    "FG-LOG-001": [],
    "FG-LOG-002": [],
    "FG-FAZ-001": ["FAZ_SERVER"],
}


def get_fortigate_parameter_metadata(param_name: str) -> Optional[FortiGateParameterMetadata]:
    return FORTIGATE_PARAMETER_REGISTRY.get(param_name)


def get_fortigate_parameters_for_check(check_id: str) -> List[FortiGateParameterMetadata]:
    return [FORTIGATE_PARAMETER_REGISTRY[name]
            for name in FORTIGATE_CHECK_PARAMETER_MAP.get(check_id, [])
            if name in FORTIGATE_PARAMETER_REGISTRY]


def get_fortigate_required_parameters_for_check(check_id: str) -> List[FortiGateParameterMetadata]:
    return [p for p in get_fortigate_parameters_for_check(check_id) if p.required and p.default is None]


def fortigate_check_has_required_params(check_id: str) -> bool:
    return len(get_fortigate_required_parameters_for_check(check_id)) > 0


def get_fortigate_check_defaults(check_id: str) -> Dict[str, str]:
    return {p.name: p.default for p in get_fortigate_parameters_for_check(check_id) if p.default is not None}


def is_fortigate_check_auto_fixable(check_id: str) -> bool:
    """A check is auto-fixable if every parameter it needs has a default."""
    params = get_fortigate_parameters_for_check(check_id)
    return all(p.default is not None for p in params) if params else True


def aggregate_fortigate_parameters_for_checks(check_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    aggregated: Dict[str, Dict[str, Any]] = {}
    for check_id in check_ids:
        for param in get_fortigate_parameters_for_check(check_id):
            if param.name not in aggregated:
                aggregated[param.name] = {
                    "type": param.input_type, "label": param.label, "description": param.description,
                    "required": param.required and param.default is None, "default": param.default,
                    "placeholder": param.placeholder, "validation": param.validation,
                    "options": param.options, "min_value": param.min_value, "max_value": param.max_value,
                    "checks": [check_id],
                }
            elif check_id not in aggregated[param.name]["checks"]:
                aggregated[param.name]["checks"].append(check_id)
    return aggregated


def categorize_fortigate_checks_by_fixability(check_ids: List[str]) -> Dict[str, List[str]]:
    auto_fixable, needs_params = [], []
    for check_id in check_ids:
        (auto_fixable if is_fortigate_check_auto_fixable(check_id) else needs_params).append(check_id)
    return {"auto_fixable": auto_fixable, "needs_params": needs_params}


def get_fortigate_auto_fix_preview(check_ids: List[str]) -> List[Dict[str, Any]]:
    return [{"check_id": cid, "defaults": get_fortigate_check_defaults(cid)}
            for cid in check_ids if is_fortigate_check_auto_fixable(cid)]
