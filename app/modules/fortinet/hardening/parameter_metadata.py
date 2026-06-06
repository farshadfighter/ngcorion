"""
FortiGate Hardening Parameter Metadata

Defines UI metadata for each hardening parameter used in FortiGate command templates.
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


# Parameter registry - all known FortiGate parameters and their UI metadata
FORTIGATE_PARAMETER_REGISTRY: Dict[str, FortiGateParameterMetadata] = {
    # ==================== TIMEOUTS ====================
    "ADMIN_TIMEOUT": FortiGateParameterMetadata(
        name="ADMIN_TIMEOUT",
        input_type="number",
        label="Admin Idle Timeout (minutes)",
        description="Idle timeout in minutes before admin session disconnection",
        required=False,
        default="10",
        min_value=1,
        max_value=480
    ),

    # ==================== NTP CONFIGURATION ====================
    "NTP_SERVER": FortiGateParameterMetadata(
        name="NTP_SERVER",
        input_type="ip",
        label="NTP Server IP",
        description="IP address of NTP time server for clock synchronization",
        required=True,
        placeholder="192.168.1.10"
    ),

    "NTP_INTERFACE": FortiGateParameterMetadata(
        name="NTP_INTERFACE",
        input_type="text",
        label="NTP Source Interface",
        description="Interface to use for NTP communication",
        required=False,
        default="port1",
        placeholder="port1"
    ),

    # ==================== DNS CONFIGURATION ====================
    "DNS_PRIMARY": FortiGateParameterMetadata(
        name="DNS_PRIMARY",
        input_type="ip",
        label="Primary DNS Server",
        description="IP address of primary DNS server",
        required=True,
        placeholder="8.8.8.8"
    ),

    "DNS_SECONDARY": FortiGateParameterMetadata(
        name="DNS_SECONDARY",
        input_type="ip",
        label="Secondary DNS Server",
        description="IP address of secondary DNS server",
        required=False,
        placeholder="8.8.4.4"
    ),

    # ==================== LOGGING ====================
    "SYSLOG_SERVER": FortiGateParameterMetadata(
        name="SYSLOG_SERVER",
        input_type="ip",
        label="Syslog Server IP",
        description="IP address of central syslog server for log forwarding",
        required=True,
        placeholder="192.168.1.100"
    ),

    "SYSLOG_FACILITY": FortiGateParameterMetadata(
        name="SYSLOG_FACILITY",
        input_type="select",
        label="Syslog Facility",
        description="Syslog facility for log messages",
        required=False,
        default="local7",
        options=["kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
                 "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
                 "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
    ),

    # ==================== FORTIANALYZER ====================
    "FAZ_SERVER": FortiGateParameterMetadata(
        name="FAZ_SERVER",
        input_type="ip",
        label="FortiAnalyzer Server IP",
        description="IP address of FortiAnalyzer for centralized logging",
        required=True,
        placeholder="192.168.1.200"
    ),

    # ==================== SNMP CONFIGURATION ====================
    "SNMP_CONTACT": FortiGateParameterMetadata(
        name="SNMP_CONTACT",
        input_type="text",
        label="SNMP Contact",
        description="Contact information for SNMP sysinfo",
        required=False,
        placeholder="admin@example.com"
    ),

    "SNMP_LOCATION": FortiGateParameterMetadata(
        name="SNMP_LOCATION",
        input_type="text",
        label="SNMP Location",
        description="Physical location for SNMP sysinfo",
        required=False,
        placeholder="Data Center Rack A1"
    ),

    # ==================== PASSWORD POLICY ====================
    "PASSWORD_MIN_LENGTH": FortiGateParameterMetadata(
        name="PASSWORD_MIN_LENGTH",
        input_type="number",
        label="Minimum Password Length",
        description="Minimum length for admin passwords",
        required=False,
        default="12",
        min_value=8,
        max_value=128
    ),

    "PASSWORD_MIN_CHANGED_CHARS": FortiGateParameterMetadata(
        name="PASSWORD_MIN_CHANGED_CHARS",
        input_type="number",
        label="Minimum Changed Characters",
        description="Minimum number of characters that must change when updating password",
        required=False,
        default="4",
        min_value=0,
        max_value=128
    ),

    # ==================== ADMIN TRUSTHOST ====================
    "ADMIN_TRUSTHOST": FortiGateParameterMetadata(
        name="ADMIN_TRUSTHOST",
        input_type="text",
        label="Admin Trusthost",
        description="Management subnet allowed for admin access (CIDR format)",
        required=True,
        placeholder="192.168.1.0/24"
    ),

    # ==================== MANAGEMENT PORT ====================
    "ADMIN_HTTPS_PORT": FortiGateParameterMetadata(
        name="ADMIN_HTTPS_PORT",
        input_type="number",
        label="HTTPS Admin Port",
        description="Custom HTTPS port for admin access (default 443)",
        required=False,
        default="10443",
        min_value=1,
        max_value=65535
    ),

    # ==================== HA CONFIGURATION ====================
    "HA_PASSWORD": FortiGateParameterMetadata(
        name="HA_PASSWORD",
        input_type="password",
        label="HA Heartbeat Password",
        description="Password for HA heartbeat encryption",
        required=True,
        placeholder="StrongHAPassword123!"
    ),

    # ==================== BANNER ====================
    "BANNER_TEXT": FortiGateParameterMetadata(
        name="BANNER_TEXT",
        input_type="textarea",
        label="Pre-Login Banner",
        description="Warning banner displayed before login",
        required=True,
        placeholder="Authorized access only. All activity is monitored.",
        validation="min_length:10"
    ),

    # ==================== CIS BENCHMARK COVERAGE ====================
    "HOSTNAME": FortiGateParameterMetadata(
        name="HOSTNAME",
        input_type="text",
        label="Hostname",
        description="Device hostname for identification in logs and management",
        required=True,
        placeholder="fgt-hq-01"
    ),
    "ADMIN_LOCKOUT_THRESHOLD": FortiGateParameterMetadata(
        name="ADMIN_LOCKOUT_THRESHOLD",
        input_type="number",
        label="Admin Lockout Threshold",
        description="Failed admin login attempts before lockout",
        required=False,
        default="3",
        min_value=1,
        max_value=10
    ),
    "ADMIN_LOCKOUT_DURATION": FortiGateParameterMetadata(
        name="ADMIN_LOCKOUT_DURATION",
        input_type="number",
        label="Admin Lockout Duration (seconds)",
        description="Lockout period after exceeding the admin login retry threshold",
        required=False,
        default="60",
        min_value=1,
        max_value=86400
    ),
    "AUTH_LOCKOUT_THRESHOLD": FortiGateParameterMetadata(
        name="AUTH_LOCKOUT_THRESHOLD",
        input_type="number",
        label="User Auth Lockout Threshold",
        description="Failed user login attempts before lockout",
        required=False,
        default="3",
        min_value=1,
        max_value=10
    ),
    "AUTH_LOCKOUT_DURATION": FortiGateParameterMetadata(
        name="AUTH_LOCKOUT_DURATION",
        input_type="number",
        label="User Auth Lockout Duration (seconds)",
        description="Lockout period after exceeding the user login retry threshold",
        required=False,
        default="60",
        min_value=1,
        max_value=86400
    ),
    "HA_MONITOR_INTERFACE": FortiGateParameterMetadata(
        name="HA_MONITOR_INTERFACE",
        input_type="text",
        label="HA Monitored Interface(s)",
        description="Interface(s) to monitor for HA failover (space-separated)",
        required=True,
        placeholder="port1 port2"
    ),
    "DNSFILTER_PROFILE": FortiGateParameterMetadata(
        name="DNSFILTER_PROFILE",
        input_type="text",
        label="DNS Filter Profile",
        description="Name of the DNS filter profile to update",
        required=False,
        default="default",
        placeholder="default"
    ),
    "APP_LIST": FortiGateParameterMetadata(
        name="APP_LIST",
        input_type="text",
        label="Application Control List",
        description="Name of the application control sensor/list to update",
        required=False,
        default="default",
        placeholder="default"
    ),
}


# Mapping of FortiGate check IDs to their required parameters
# Checks with empty list [] are auto-fixable (no user input needed)
FORTIGATE_CHECK_PARAMETER_MAP: Dict[str, List[str]] = {
    # ==================== BASELINE PACK ====================
    # Management Plane Security
    "FG-BL-001": [],  # Admin HTTPS enabled - no params
    "FG-BL-002": [],  # Admin HTTP disabled - no params
    "FG-BL-003": [],  # Admin Telnet disabled - no params
    "FG-BL-004": ["ADMIN_TIMEOUT"],  # Admin idle timeout
    "FG-BL-005": [],  # Admin GUI TLS 1.0/1.1 disabled - no params
    "FG-BL-006": [],  # Weak SSH ciphers disabled - no params
    "FG-BL-007": ["ADMIN_HTTPS_PORT"],  # Admin sport restricted
    "FG-BL-008": [],  # Admin SSH enabled - no params

    # Identity & Access Management
    "FG-BL-020": ["ADMIN_TRUSTHOST"],  # Admin trusthost configured
    "FG-BL-021": [],  # Default admin account (informational)
    "FG-BL-022": [],  # MFA (informational - needs FortiToken setup)

    # Password Policy
    "FG-BL-030": [],  # Password policy enabled - no params
    "FG-BL-031": ["PASSWORD_MIN_LENGTH"],  # Password min length
    "FG-BL-032": [],  # Password must contain uppercase - no params
    "FG-BL-033": [],  # Password must contain lowercase - no params
    "FG-BL-034": [],  # Password must contain numbers - no params
    "FG-BL-035": [],  # Password must contain special chars - no params
    "FG-BL-036": ["PASSWORD_MIN_CHANGED_CHARS"],  # Password min changed chars

    # Time & Sync
    "FG-BL-040": [],  # NTP enabled - no params
    "FG-BL-041": ["NTP_SERVER"],  # NTP server configured
    "FG-BL-042": ["NTP_INTERFACE"],  # NTP sync interface

    # DNS
    "FG-BL-043": ["DNS_PRIMARY"],  # DNS primary configured
    "FG-BL-044": ["DNS_SECONDARY"],  # DNS secondary configured

    # SNMP Security
    "FG-BL-050": [],  # SNMPv2 community disabled - no params (just remove)
    "FG-BL-051": [],  # SNMPv3 user exists (informational)
    "FG-BL-052": ["SNMP_CONTACT", "SNMP_LOCATION"],  # SNMP contact/location

    # Logging & Monitoring
    "FG-BL-060": ["SYSLOG_SERVER"],  # Remote syslog enabled
    "FG-BL-061": ["SYSLOG_SERVER"],  # Remote syslog server set
    "FG-BL-062": ["SYSLOG_FACILITY"],  # Syslog facility
    "FG-BL-063": [],  # Local disk logging enabled - no params
    "FG-BL-064": [],  # Log invalid traffic enabled - no params
    "FG-BL-065": [],  # User event logging enabled - no params

    # Automation & Management
    "FG-BL-070": [],  # Auto-script disabled - no params
    "FG-BL-071": [],  # Central management (informational)

    # Firewall Policy
    "FG-BL-080": [],  # No Any/Any/ALL ACCEPT (informational)
    "FG-BL-081": [],  # Explicit deny rule (informational)
    "FG-BL-082": [],  # Policy logging (informational)

    # Global Settings
    "FG-BL-090": [],  # Strong encryption required - no params
    "FG-BL-091": [],  # FGFM auto-update disabled - no params
    "FG-BL-092": ["BANNER_TEXT"],  # Pre-login banner configured
    "FG-BL-093": [],  # GUI display hostname enabled - no params

    # WAN Interface Exposure
    "FG-BL-WAN-HTTP": [],
    "FG-BL-WAN-HTTPS": [],
    "FG-BL-WAN-SSH": [],
    "FG-BL-WAN-TELNET": [],
    "FG-BL-WAN-SNMP": [],
    "FG-BL-WAN-FGFM": [],
    "FG-BL-WAN-PING": [],
    "FG-BL-WAN-FABRIC": [],

    # ==================== HA PACK ====================
    "FG-HA-001": [],  # HA status readable (informational)
    "FG-HA-002": [],  # HA override disabled - no params
    "FG-HA-003": ["HA_PASSWORD"],  # HA heartbeat encryption
    "FG-HA-004": [],  # HA mode configured - no params

    # ==================== SD-WAN PACK ====================
    "FG-SDW-001": [],  # SD-WAN configuration (informational)
    "FG-SDW-002": [],  # SD-WAN health-check (informational)

    # ==================== VPN PACKS ====================
    "FG-VPN-SSL-001": [],  # SSL-VPN TLS 1.0/1.1 disabled - no params
    "FG-VPN-SSL-002": [],  # SSL-VPN weak ciphers disabled - no params
    "FG-VPN-IPSEC-001": [],  # IPsec Phase1 weak proposals disabled (informational)
    "FG-VPN-IPSEC-002": [],  # IPsec DPD enabled (informational)

    # ==================== NAT & EXPOSURE ====================
    "FG-CNAT-001": [],  # Central SNAT map (informational)
    "FG-LIP-001": [],  # Local-in-policy (informational)
    "FG-EXP-001": [],  # VIP objects (informational)
    "FG-EXP-002": [],  # VIP extintf (informational)

    # ==================== UTM PACK ====================
    "FG-UTM-001": [],  # WAN inbound UTM (informational)
    "FG-UTM-002": [],  # Antivirus profile (informational)
    "FG-UTM-003": [],  # IPS sensor (informational)
    "FG-UTM-004": [],  # Web filter profile (informational)

    # ==================== FAZ PACK ====================
    "FG-FAZ-001": ["FAZ_SERVER"],  # FortiAnalyzer logging enabled
    "FG-FAZ-002": ["FAZ_SERVER"],  # FortiAnalyzer server configured

    # ==================== CIS BENCHMARK COVERAGE ====================
    # 1 Network Settings
    "FG-NET-001": [],   # intra-zone traffic (Manual - no auto-fix)
    # 2.1 General Settings
    "FG-SYS-001": [],                 # post-login banner enable
    "FG-SYS-002": [],                 # timezone (Manual)
    "FG-SYS-003": ["HOSTNAME"],       # hostname
    "FG-SYS-004": [],                 # firmware (Manual)
    "FG-SYS-005": [],                 # USB auto-install disable
    "FG-SYS-006": [],                 # static TLS keys disable
    # 2.2 Password Policy
    "FG-PW-001": ["ADMIN_LOCKOUT_THRESHOLD", "ADMIN_LOCKOUT_DURATION"],  # retries/lockout
    # 2.3 SNMP
    "FG-SNMP-001": [],                # SNMPv3 trusted hosts (Manual)
    # 2.4 Administrators
    "FG-ADM-001": [],                 # admin profiles (Manual)
    # 2.5 High Availability
    "FG-HA-005": ["HA_MONITOR_INTERFACE"],  # HA monitor interfaces
    "FG-HA-006": [],                  # HA reserved mgmt (Manual)
    # 3 Policy and Objects
    "FG-POL-001": [],                 # unused policies (Manual)
    "FG-POL-002": [],                 # ISDB deny (Manual)
    # 4.1 IPS
    "FG-IPS-001": [],                 # botnet connections (Manual)
    # 4.2 Antivirus
    "FG-AV-001": [],                  # push updates
    "FG-AV-002": [],                  # outbreak prevention (manual remediation)
    "FG-AV-003": [],                  # AI/heuristic detection
    "FG-AV-004": [],                  # grayware detection
    # 4.3 DNS Filter
    "FG-DNS-001": ["DNSFILTER_PROFILE"],  # botnet C&C blocking
    "FG-DNS-002": [],                 # DNS logs (Manual)
    "FG-DNS-003": [],                 # apply DNS filter (Manual)
    # 4.4 Application Control
    "FG-APP-001": [],                 # high risk categories (Manual)
    "FG-APP-002": ["APP_LIST"],       # non-default ports
    "FG-APP-003": [],                 # app log (Manual)
    "FG-APP-004": [],                 # apply app control (Manual)
    # 5 Security Fabric
    "FG-FAB-001": [],                 # quarantine automation (manual remediation)
    "FG-FAB-002": [],                 # security fabric (manual remediation - risky)
    # 6 VPN
    "FG-VPN-SSL-003": [],             # VPN portal cert (Manual)
    # 7 Users and Authentication
    "FG-USER-001": ["AUTH_LOCKOUT_THRESHOLD", "AUTH_LOCKOUT_DURATION"],  # login attempts
    # 8 Logs and Reports
    "FG-LOG-001": [],                 # event logging enable
    "FG-LOG-002": [],                 # encrypt log transmission
}


def get_fortigate_parameter_metadata(param_name: str) -> Optional[FortiGateParameterMetadata]:
    """
    Get metadata for a FortiGate parameter by name.

    Args:
        param_name: Parameter name (e.g., "ADMIN_TIMEOUT")

    Returns:
        FortiGateParameterMetadata object or None if not found
    """
    return FORTIGATE_PARAMETER_REGISTRY.get(param_name)


def get_fortigate_parameters_for_check(check_id: str) -> List[FortiGateParameterMetadata]:
    """
    Get all parameter metadata for a specific FortiGate check.

    Args:
        check_id: FortiGate check ID (e.g., "FG-BL-001")

    Returns:
        List of FortiGateParameterMetadata objects for the check's parameters
    """
    param_names = FORTIGATE_CHECK_PARAMETER_MAP.get(check_id, [])
    return [
        FORTIGATE_PARAMETER_REGISTRY[name]
        for name in param_names
        if name in FORTIGATE_PARAMETER_REGISTRY
    ]


def get_fortigate_required_parameters_for_check(check_id: str) -> List[FortiGateParameterMetadata]:
    """
    Get only required parameters (no defaults) for a specific FortiGate check.

    Args:
        check_id: FortiGate check ID

    Returns:
        List of required FortiGateParameterMetadata objects
    """
    params = get_fortigate_parameters_for_check(check_id)
    return [p for p in params if p.required and p.default is None]


def fortigate_check_has_required_params(check_id: str) -> bool:
    """
    Check if a FortiGate check has any required parameters without defaults.

    Args:
        check_id: FortiGate check ID

    Returns:
        True if check requires user input, False if auto-fixable
    """
    return len(get_fortigate_required_parameters_for_check(check_id)) > 0


def get_fortigate_check_defaults(check_id: str) -> Dict[str, str]:
    """
    Get default values for a FortiGate check's parameters.

    Args:
        check_id: FortiGate check ID

    Returns:
        Dict of parameter names to default values
    """
    params = get_fortigate_parameters_for_check(check_id)
    return {
        p.name: p.default
        for p in params
        if p.default is not None
    }


def is_fortigate_check_auto_fixable(check_id: str) -> bool:
    """
    Determine if a FortiGate check can be auto-fixed with defaults only.

    A check is auto-fixable if:
    - It has no parameters, OR
    - All its parameters have default values

    Args:
        check_id: FortiGate check ID

    Returns:
        True if can be fixed without user input
    """
    params = get_fortigate_parameters_for_check(check_id)
    if not params:
        return True
    return all(p.default is not None for p in params)


def aggregate_fortigate_parameters_for_checks(check_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate all unique parameters needed for a set of FortiGate checks.

    Args:
        check_ids: List of FortiGate check IDs

    Returns:
        Dict of parameter names to their metadata and which checks use them:
        {
            "ADMIN_TIMEOUT": {
                "type": "number",
                "label": "Admin Idle Timeout",
                "description": "...",
                "required": False,
                "default": "10",
                "checks": ["FG-BL-004"]
            },
            ...
        }
    """
    aggregated: Dict[str, Dict[str, Any]] = {}

    for check_id in check_ids:
        params = get_fortigate_parameters_for_check(check_id)
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
                    "checks": [check_id]
                }
            else:
                # Parameter already exists, just add the check reference
                if check_id not in aggregated[param.name]["checks"]:
                    aggregated[param.name]["checks"].append(check_id)

    return aggregated


def categorize_fortigate_checks_by_fixability(check_ids: List[str]) -> Dict[str, List[str]]:
    """
    Categorize FortiGate checks into auto-fixable and needs-params.

    Args:
        check_ids: List of FortiGate check IDs

    Returns:
        {
            "auto_fixable": ["FG-BL-001", "FG-BL-002", ...],
            "needs_params": ["FG-BL-004", "FG-BL-041", ...]
        }
    """
    auto_fixable = []
    needs_params = []

    for check_id in check_ids:
        if is_fortigate_check_auto_fixable(check_id):
            auto_fixable.append(check_id)
        else:
            needs_params.append(check_id)

    return {
        "auto_fixable": auto_fixable,
        "needs_params": needs_params
    }


def get_fortigate_auto_fix_preview(check_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Get preview of what will be applied in automatic mode for FortiGate.

    Args:
        check_ids: List of failed FortiGate check IDs

    Returns:
        List of checks with their default values:
        [
            {
                "check_id": "FG-BL-004",
                "defaults": {"ADMIN_TIMEOUT": "10"}
            },
            ...
        ]
    """
    preview = []

    for check_id in check_ids:
        if is_fortigate_check_auto_fixable(check_id):
            defaults = get_fortigate_check_defaults(check_id)
            preview.append({
                "check_id": check_id,
                "defaults": defaults
            })

    return preview
