"""
Cisco Hardening Command Templates

Static command templates for common CIS checks that can be auto-remediated.

Each template includes:
- commands: List of CLI commands to execute
- required_params: Parameters that must be provided by user
- optional_params: Parameters with defaults
- defaults: Default values for optional parameters
- warnings: Safety warnings to display to user
- config_mode: Whether commands need configuration mode
"""

from typing import Dict, List, Any


# Command templates mapped by check number (IOS-L1-XXX)
COMMAND_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ==================== ENABLE SECRET ====================
    "IOS-L1-001": {
        "commands": [
            "configure terminal",
            "no enable password",
            "enable secret {STRONG_SECRET}",
            "end",
            "write memory"
        ],
        "required_params": ["STRONG_SECRET"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will remove the existing enable password",
            "Ensure you have documented the new enable secret"
        ],
        "config_mode": True
    },

    # ==================== EXEC TIMEOUT ====================
    "IOS-L1-002": {
        "commands": [
            "configure terminal",
            "line console 0",
            "exec-timeout {TIMEOUT_MIN} {TIMEOUT_SEC}",
            "exit",
            "line vty 0 15",
            "exec-timeout {TIMEOUT_MIN} {TIMEOUT_SEC}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["TIMEOUT_MIN", "TIMEOUT_SEC"],
        "defaults": {
            "TIMEOUT_MIN": "5",
            "TIMEOUT_SEC": "0"
        },
        "warnings": [
            "This will apply exec-timeout to console and VTY lines 0-15",
            "Default timeout is 5 minutes"
        ],
        "config_mode": True
    },

    # ==================== VTY ACCESS-CLASS ====================
    "IOS-L1-003": {
        "commands": [
            "configure terminal",
            "line vty 0 15",
            "access-class {ACL_NAME} in",
            "end",
            "write memory"
        ],
        "required_params": ["ACL_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure ACL {ACL_NAME} exists before applying",
            "Applying ACL may block your current session if not configured correctly"
        ],
        "config_mode": True
    },

    # ==================== VTY TRANSPORT SSH ONLY ====================
    "IOS-L1-004": {
        "commands": [
            "configure terminal",
            "line vty 0 15",
            "transport input ssh",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will disable Telnet access on VTY lines",
            "Ensure SSH is configured before applying"
        ],
        "config_mode": True
    },

    # ==================== BANNERS ====================
    "IOS-L1-005": {
        "commands": [
            "configure terminal",
            "banner motd ^{BANNER_TEXT}^",
            "end",
            "write memory"
        ],
        "required_params": ["BANNER_TEXT"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Banner will be displayed before login"
        ],
        "config_mode": True
    },

    "IOS-L1-006": {
        "commands": [
            "configure terminal",
            "banner login ^{BANNER_TEXT}^",
            "end",
            "write memory"
        ],
        "required_params": ["BANNER_TEXT"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Login banner will be displayed at login prompt"
        ],
        "config_mode": True
    },

    # ==================== SSH VERSION 2 ====================
    "IOS-L1-007": {
        "commands": [
            "configure terminal",
            "ip ssh version 2",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will force SSH version 2 only (disables SSH v1)"
        ],
        "config_mode": True
    },

    # ==================== SSH TIMEOUT ====================
    "IOS-L1-008": {
        "commands": [
            "configure terminal",
            "ip ssh timeout {TIMEOUT_SEC}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["TIMEOUT_SEC"],
        "defaults": {
            "TIMEOUT_SEC": "60"
        },
        "warnings": [
            "Default SSH timeout is 60 seconds"
        ],
        "config_mode": True
    },

    # ==================== SSH AUTHENTICATION RETRIES ====================
    "IOS-L1-009": {
        "commands": [
            "configure terminal",
            "ip ssh authentication-retries {RETRIES}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["RETRIES"],
        "defaults": {
            "RETRIES": "3"
        },
        "warnings": [
            "Default retry count is 3 attempts"
        ],
        "config_mode": True
    },

    # ==================== SERVICE PASSWORD-ENCRYPTION ====================
    "IOS-L1-010": {
        "commands": [
            "configure terminal",
            "service password-encryption",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will encrypt all plaintext passwords in the configuration"
        ],
        "config_mode": True
    },

    # ==================== DISABLE HTTP SERVER ====================
    "IOS-L1-011": {
        "commands": [
            "configure terminal",
            "no ip http server",
            "no ip http secure-server",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will disable both HTTP and HTTPS servers",
            "Web-based management will not be available"
        ],
        "config_mode": True
    },

    # ==================== AAA NEW-MODEL ====================
    "IOS-L1-012": {
        "commands": [
            "configure terminal",
            "aaa new-model",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enabling AAA may affect authentication if not properly configured",
            "Ensure you have console access before applying"
        ],
        "config_mode": True
    },

    # ==================== AAA AUTHENTICATION LOGIN ====================
    "IOS-L1-013": {
        "commands": [
            "configure terminal",
            "aaa authentication login {METHOD_NAME} {METHOD_TYPE}",
            "line vty 0 15",
            "login authentication {METHOD_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["METHOD_NAME", "METHOD_TYPE"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Common METHOD_TYPE values: local, group tacacs+, group radius",
            "Ensure method is properly configured before applying"
        ],
        "config_mode": True
    },

    # ==================== LOGGING ====================
    "IOS-L1-014": {
        "commands": [
            "configure terminal",
            "logging host {SYSLOG_SERVER}",
            "end",
            "write memory"
        ],
        "required_params": ["SYSLOG_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure syslog server is reachable"
        ],
        "config_mode": True
    },

    "IOS-L1-015": {
        "commands": [
            "configure terminal",
            "logging buffered {SIZE}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["SIZE"],
        "defaults": {
            "SIZE": "16384"
        },
        "warnings": [
            "Default buffer size is 16384 bytes"
        ],
        "config_mode": True
    },

    # ==================== SERVICE TIMESTAMPS ====================
    "IOS-L1-016": {
        "commands": [
            "configure terminal",
            "service timestamps log datetime localtime show-timezone",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will add timestamps to all log messages"
        ],
        "config_mode": True
    },

    # ==================== NTP ====================
    "IOS-L1-017": {
        "commands": [
            "configure terminal",
            "ntp server {NTP_SERVER}",
            "end",
            "write memory"
        ],
        "required_params": ["NTP_SERVER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure NTP server is reachable"
        ],
        "config_mode": True
    },

    # ==================== DISABLE CDP ====================
    "IOS-L1-018": {
        "commands": [
            "configure terminal",
            "no cdp run",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will disable CDP globally",
            "CDP is useful for network discovery but poses security risks"
        ],
        "config_mode": True
    },

    # ==================== DISABLE IP SOURCE-ROUTE ====================
    "IOS-L1-019": {
        "commands": [
            "configure terminal",
            "no ip source-route",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== HOSTNAME ====================
    "IOS-L1-0010": {
        "commands": [
            "configure terminal",
            "hostname {HOSTNAME}",
            "end",
            "write memory"
        ],
        "required_params": ["HOSTNAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Changing hostname will affect device identification"
        ],
        "config_mode": True
    },

    # ==================== IP DOMAIN-NAME ====================
    "IOS-L1-0011": {
        "commands": [
            "configure terminal",
            "ip domain-name {DOMAIN_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["DOMAIN_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Domain name is required for SSH key generation"
        ],
        "config_mode": True
    },

    # ==================== NO IP DOMAIN-LOOKUP ====================
    "IOS-L1-0012": {
        "commands": [
            "configure terminal",
            "no ip domain-lookup",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== DISABLE BOOTP ====================
    "IOS-L1-020": {
        "commands": [
            "configure terminal",
            "no ip bootp server",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== TCP KEEPALIVES-IN ====================
    "IOS-L1-021": {
        "commands": [
            "configure terminal",
            "service tcp-keepalives-in",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This will enable TCP keepalives for incoming connections"
        ],
        "config_mode": True
    },

    # ==================== NO SERVICE PAD ====================
    "IOS-L1-022": {
        "commands": [
            "configure terminal",
            "no service pad",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== DISABLE IDENTD ====================
    "IOS-L1-023": {
        "commands": [
            "configure terminal",
            "no ip identd",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },
}


def get_template(check_number: str) -> Dict[str, Any]:
    """
    Get command template for a check number.

    Args:
        check_number: CIS check number (e.g., "IOS-L1-001")

    Returns:
        Command template dict or None if not found

    Raises:
        KeyError: If check_number not found in templates
    """
    if check_number not in COMMAND_TEMPLATES:
        raise KeyError(f"No command template found for {check_number}")

    return COMMAND_TEMPLATES[check_number]


def has_template(check_number: str) -> bool:
    """Check if a template exists for the given check number."""
    return check_number in COMMAND_TEMPLATES


def get_all_templated_checks() -> List[str]:
    """Get list of all check numbers that have templates."""
    return list(COMMAND_TEMPLATES.keys())
