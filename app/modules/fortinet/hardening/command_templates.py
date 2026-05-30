"""
FortiGate Hardening Command Templates

Static command templates for FortiGate CIS checks that can be auto-remediated.

Each template includes:
- commands: List of CLI commands to execute (config/set/end pattern)
- required_params: Parameters that must be provided by user
- optional_params: Parameters with defaults
- defaults: Default values for optional parameters
- warnings: Safety warnings to display to user
- vdom_context: Whether this is global or per-VDOM ("global" or "vdom")

FortiGate uses hierarchical config blocks:
- config <section>
- set <key> <value>
- end

When VDOMs are enabled, global-context templates are wrapped in "config global" / "end"
so they execute in the correct context. Per-VDOM templates are executed inside the
target VDOM (entered by the executor via "config vdom" / "edit <vdom>").
"""

from typing import Dict, List, Any


# Command templates mapped by FortiGate check ID (FG-XX-XXX)
FORTIGATE_COMMAND_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ==================== MANAGEMENT PLANE SECURITY ====================
    "FG-BL-001": {
        "commands": [
            "config global",
            "config system global",
            "set admin-https enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables HTTPS access to FortiGate management interface"
        ],
        "vdom_context": "global"
    },

    "FG-BL-002": {
        "commands": [
            "config global",
            "config system global",
            "set admin-http disable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables unencrypted HTTP management access",
            "Ensure HTTPS is working before applying"
        ],
        "vdom_context": "global"
    },

    "FG-BL-003": {
        "commands": [
            "config global",
            "config system global",
            "set admin-telnet disable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables Telnet management access",
            "Ensure SSH is working before applying"
        ],
        "vdom_context": "global"
    },

    "FG-BL-004": {
        "commands": [
            "config global",
            "config system global",
            "set admintimeout {ADMIN_TIMEOUT}",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": ["ADMIN_TIMEOUT"],
        "defaults": {
            "ADMIN_TIMEOUT": "10"
        },
        "warnings": [
            "Sets idle timeout for admin sessions",
            "Default is 10 minutes"
        ],
        "vdom_context": "global"
    },

    "FG-BL-005": {
        "commands": [
            "config global",
            "config system global",
            "set admin-https-ssl-versions tlsv1-2 tlsv1-3",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables TLS 1.0 and 1.1 for admin HTTPS",
            "Only TLS 1.2 and 1.3 will be allowed"
        ],
        "vdom_context": "global"
    },

    "FG-BL-006": {
        "commands": [
            "config global",
            "config system global",
            "set ssh-enc-algo aes256-ctr aes192-ctr aes128-ctr aes256-gcm@openssh.com aes128-gcm@openssh.com",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Removes weak SSH ciphers (DES, 3DES, RC4)",
            "Only strong ciphers will be allowed"
        ],
        "vdom_context": "global"
    },

    "FG-BL-007": {
        "commands": [
            "config global",
            "config system global",
            "set admin-sport {ADMIN_HTTPS_PORT}",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": ["ADMIN_HTTPS_PORT"],
        "defaults": {
            "ADMIN_HTTPS_PORT": "10443"
        },
        "warnings": [
            "Changes HTTPS admin port from default 443",
            "Update bookmarks/scripts after applying"
        ],
        "vdom_context": "global"
    },

    "FG-BL-008": {
        "commands": [
            "config global",
            "config system global",
            "set admin-ssh enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables SSH CLI access"
        ],
        "vdom_context": "global"
    },

    # ==================== PASSWORD POLICY ====================
    # NOTE: config system password-policy is configured at the root CLI level
    # on both VDOM-enabled and non-VDOM devices. "config global" is NOT used
    # here because on many FortiOS versions the password-policy block does not
    # accept set commands when entered inside a config-global context.
    "FG-BL-030": {
        "commands": [
            "config system password-policy",
            "set status enable",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables password policy enforcement"
        ],
        "vdom_context": "global"
    },

    "FG-BL-031": {
        "commands": [
            "config system password-policy",
            "set minimum-length {PASSWORD_MIN_LENGTH}",
            "end"
        ],
        "required_params": [],
        "optional_params": ["PASSWORD_MIN_LENGTH"],
        "defaults": {
            "PASSWORD_MIN_LENGTH": "12"
        },
        "warnings": [
            "Sets minimum password length",
            "Existing passwords not affected until changed"
        ],
        "vdom_context": "global"
    },

    "FG-BL-032": {
        "commands": [
            "config system password-policy",
            "set must-contain uppercase-letter enable",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Requires uppercase letter in passwords"
        ],
        "vdom_context": "global"
    },

    "FG-BL-033": {
        "commands": [
            "config system password-policy",
            "set must-contain lowercase-letter enable",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Requires lowercase letter in passwords"
        ],
        "vdom_context": "global"
    },

    "FG-BL-034": {
        "commands": [
            "config system password-policy",
            "set must-contain number enable",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Requires number in passwords"
        ],
        "vdom_context": "global"
    },

    "FG-BL-035": {
        "commands": [
            "config system password-policy",
            "set must-contain non-alphanumeric enable",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Requires special character in passwords"
        ],
        "vdom_context": "global"
    },

    "FG-BL-036": {
        "commands": [
            "config system password-policy",
            "set min-changed-characters {PASSWORD_MIN_CHANGED_CHARS}",
            "end"
        ],
        "required_params": [],
        "optional_params": ["PASSWORD_MIN_CHANGED_CHARS"],
        "defaults": {
            "PASSWORD_MIN_CHANGED_CHARS": "4"
        },
        "warnings": [
            "Sets minimum characters that must change on password update"
        ],
        "vdom_context": "global"
    },

    # ==================== TIME & SYNC ====================
    "FG-BL-040": {
        "commands": [
            "config global",
            "config system ntp",
            "set status enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables NTP time synchronization"
        ],
        "vdom_context": "global"
    },

    "FG-BL-041": {
        "commands": [
            "config global",
            "config system ntp",
            "config ntpserver",
            "edit 1",
            "set server {NTP_SERVER}",
            "end",
            "end",
            "end"
        ],
        "required_params": ["NTP_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Configures NTP server",
            "Ensure NTP server is reachable"
        ],
        "vdom_context": "global"
    },

    "FG-BL-042": {
        "commands": [
            "config global",
            "config system ntp",
            "set interface {NTP_INTERFACE}",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": ["NTP_INTERFACE"],
        "defaults": {
            "NTP_INTERFACE": "port1"
        },
        "warnings": [
            "Sets source interface for NTP traffic"
        ],
        "vdom_context": "global"
    },

    # ==================== DNS ====================
    "FG-BL-043": {
        "commands": [
            "config global",
            "config system dns",
            "set primary {DNS_PRIMARY}",
            "end",
            "end"
        ],
        "required_params": ["DNS_PRIMARY"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Configures primary DNS server"
        ],
        "vdom_context": "global"
    },

    "FG-BL-044": {
        "commands": [
            "config global",
            "config system dns",
            "set secondary {DNS_SECONDARY}",
            "end",
            "end"
        ],
        "required_params": ["DNS_SECONDARY"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Configures secondary DNS server"
        ],
        "vdom_context": "global"
    },

    # ==================== SNMP ====================
    "FG-BL-052": {
        "commands": [
            "config global",
            "config system snmp sysinfo",
            "set contact-info {SNMP_CONTACT}",
            "set location {SNMP_LOCATION}",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": ["SNMP_CONTACT", "SNMP_LOCATION"],
        "defaults": {
            "SNMP_CONTACT": "admin@company.com",
            "SNMP_LOCATION": "Data Center"
        },
        "warnings": [
            "Sets SNMP contact and location information"
        ],
        "vdom_context": "global"
    },

    # ==================== LOGGING ====================
    "FG-BL-060": {
        "commands": [
            "config global",
            "config log syslogd setting",
            "set status enable",
            "set server {SYSLOG_SERVER}",
            "end",
            "end"
        ],
        "required_params": ["SYSLOG_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables syslog logging",
            "Ensure syslog server is reachable"
        ],
        "vdom_context": "global"
    },

    "FG-BL-061": {
        "commands": [
            "config global",
            "config log syslogd setting",
            "set server {SYSLOG_SERVER}",
            "end",
            "end"
        ],
        "required_params": ["SYSLOG_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Sets syslog server IP address"
        ],
        "vdom_context": "global"
    },

    "FG-BL-062": {
        "commands": [
            "config global",
            "config log syslogd setting",
            "set facility {SYSLOG_FACILITY}",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": ["SYSLOG_FACILITY"],
        "defaults": {
            "SYSLOG_FACILITY": "local7"
        },
        "warnings": [
            "Sets syslog facility"
        ],
        "vdom_context": "global"
    },

    "FG-BL-063": {
        "commands": [
            "config global",
            "config log setting",
            "set local-disk enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables local disk logging"
        ],
        "vdom_context": "global"
    },

    "FG-BL-064": {
        "commands": [
            "config global",
            "config log setting",
            "set log-invalid-packet enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables logging of invalid packets"
        ],
        "vdom_context": "global"
    },

    "FG-BL-065": {
        "commands": [
            "config global",
            "config log setting",
            "set log-user-in-upper enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables user event logging"
        ],
        "vdom_context": "global"
    },

    # ==================== GLOBAL SETTINGS ====================
    "FG-BL-090": {
        "commands": [
            "config global",
            "config system global",
            "set strong-crypto enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables strong cryptography globally",
            "Weak ciphers will be disabled"
        ],
        "vdom_context": "global"
    },

    "FG-BL-091": {
        "commands": [
            "config global",
            "config system global",
            "set fgfm-auto-update disable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables automatic FGFM updates",
            "Manual updates recommended for production"
        ],
        "vdom_context": "global"
    },

    "FG-BL-092": {
        "commands": [
            "config global",
            "config system global",
            "set pre-login-banner enable",
            "set pre-login-banner-message \"{BANNER_TEXT}\"",
            "end",
            "end"
        ],
        "required_params": ["BANNER_TEXT"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Sets pre-login warning banner"
        ],
        "vdom_context": "global"
    },

    "FG-BL-093": {
        "commands": [
            "config global",
            "config system settings",
            "set gui-display-hostname enable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Displays hostname in GUI"
        ],
        "vdom_context": "global"
    },

    # ==================== HA PACK ====================
    "FG-HA-002": {
        "commands": [
            "config global",
            "config system ha",
            "set override disable",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables HA override for stable failover"
        ],
        "vdom_context": "global"
    },

    "FG-HA-003": {
        "commands": [
            "config global",
            "config system ha",
            "set password {HA_PASSWORD}",
            "end",
            "end"
        ],
        "required_params": ["HA_PASSWORD"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Sets HA heartbeat password",
            "Must match on all HA members"
        ],
        "vdom_context": "global"
    },

    "FG-HA-004": {
        "commands": [
            "config global",
            "config system ha",
            "set mode a-p",
            "end",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Configures HA in active-passive mode"
        ],
        "vdom_context": "global"
    },

    # ==================== VPN SSL ====================
    "FG-VPN-SSL-001": {
        "commands": [
            "config vpn ssl settings",
            "set ssl-min-proto-version tlsv1-2",
            "end"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables TLS 1.0/1.1 for SSL-VPN",
            "Older clients may not be able to connect"
        ],
        "vdom_context": "vdom"
    },

    # ==================== FAZ ====================
    "FG-FAZ-001": {
        "commands": [
            "config global",
            "config log fortianalyzer setting",
            "set status enable",
            "set server {FAZ_SERVER}",
            "end",
            "end"
        ],
        "required_params": ["FAZ_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables FortiAnalyzer logging",
            "Ensure FortiAnalyzer is configured to accept this device"
        ],
        "vdom_context": "global"
    },

    "FG-FAZ-002": {
        "commands": [
            "config global",
            "config log fortianalyzer setting",
            "set server {FAZ_SERVER}",
            "end",
            "end"
        ],
        "required_params": ["FAZ_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Sets FortiAnalyzer server IP"
        ],
        "vdom_context": "global"
    },
}


def get_fortigate_template(check_id: str) -> Dict[str, Any]:
    """
    Get command template for a FortiGate check ID.

    Args:
        check_id: FortiGate check ID (e.g., "FG-BL-001")

    Returns:
        Command template dict

    Raises:
        KeyError: If check_id not found in templates
    """
    if check_id not in FORTIGATE_COMMAND_TEMPLATES:
        raise KeyError(f"No command template found for {check_id}")

    return FORTIGATE_COMMAND_TEMPLATES[check_id]


def has_fortigate_template(check_id: str) -> bool:
    """Check if a template exists for the given FortiGate check ID."""
    return check_id in FORTIGATE_COMMAND_TEMPLATES


def get_all_fortigate_templated_checks() -> List[str]:
    """Get list of all FortiGate check IDs that have templates."""
    return list(FORTIGATE_COMMAND_TEMPLATES.keys())


def get_fortigate_template_vdom_context(check_id: str) -> str:
    """
    Get the VDOM context for a check template.

    Args:
        check_id: FortiGate check ID

    Returns:
        "global" or "vdom"
    """
    template = FORTIGATE_COMMAND_TEMPLATES.get(check_id, {})
    return template.get("vdom_context", "global")
