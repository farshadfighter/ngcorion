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

    "IOS-L1-0051": {
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
            "ip ssh time-out {TIMEOUT_SEC}",
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

    # ==================== SSH TIMEOUT ====================
    "IOS-L1-0112": {
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
            "Default SSH timeout is 60 seconds (valid range: 5-120)"
        ],
        "config_mode": True
    },

    # ==================== RSA KEY GENERATION ====================
    "IOS-L1-0120": {
        "commands": [
            "configure terminal",
            "crypto key generate rsa modulus {MODULUS}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["MODULUS"],
        "defaults": {
            "MODULUS": "2048"
        },
        "warnings": [
            "This will generate or replace the existing RSA key pair",
            "Key generation may take a moment to complete"
        ],
        "config_mode": True
    },

    # ==================== LOGIN FAILURE/SUCCESS LOGGING ====================
    "IOS-L1-0131": {
        "commands": [
            "configure terminal",
            "login on-failure log",
            "login on-success log",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== ARCHIVE CONFIG LOGGING ====================
    "IOS-L1-0244": {
        "commands": [
            "configure terminal",
            "archive",
            "log config",
            "logging enable",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This enables configuration change logging via the archive subsystem"
        ],
        "config_mode": True
    },

    # ==================== CONFIG-REGISTER ====================
    "IOS-L1-090": {
        "commands": [
            "configure terminal",
            "config-register 0x2102",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Config-register change takes effect on the next reload"
        ],
        "config_mode": True
    },

    # ==================== SECURE BOOT ====================
    "IOS-L2-091": {
        "commands": [
            "configure terminal",
            "secure boot-image",
            "secure boot-config",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Secure boot requires IOS Resilience feature support",
            "Verify platform supports 'secure boot-image' before applying"
        ],
        "config_mode": True
    },

    # ==================== CONTROL-PLANE POLICING ====================
    "IOS-L2-110": {
        "commands": [
            "configure terminal",
            "ip access-list extended ACL-COPP-MGMT",
            "permit tcp any any eq 22",
            "permit tcp any any eq 443",
            "exit",
            "class-map match-any COPP-MGMT",
            "match access-group name ACL-COPP-MGMT",
            "exit",
            "policy-map type control-plane COPP-POLICY",
            "class COPP-MGMT",
            "police rate 1000 pps",
            "exit",
            "exit",
            "control-plane",
            "service-policy input COPP-POLICY",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This applies a basic CoPP policy — review and adjust rate limits before applying",
            "Test in a lab environment before applying to production devices"
        ],
        "config_mode": True
    },

    # ==================== NTP AUTHENTICATION ====================
    "IOS-L1-080": {
        "commands": [
            "configure terminal",
            "ntp authenticate",
            "ntp authentication-key {NTP_KEY_ID} md5 {NTP_KEY}",
            "ntp trusted-key {NTP_KEY_ID}",
            "end",
            "write memory"
        ],
        "required_params": ["NTP_KEY_ID", "NTP_KEY"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "NTP_KEY_ID must match the key ID configured on your NTP server",
            "Associate the key with your NTP server: ntp server <IP> key <ID>"
        ],
        "config_mode": True
    },

    # ==================== SNMP COMMUNITY WITH ACL ====================
    "IOS-L1-030B": {
        "commands": [
            "configure terminal",
            "snmp-server community {COMMUNITY_STRING} RO {ACL_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["COMMUNITY_STRING", "ACL_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure ACL {ACL_NAME} exists and permits only trusted management hosts",
            "Repeat for each bare community string found in the config"
        ],
        "config_mode": True
    },

    # ==================== REPLACE WEAK USERNAME PASSWORD ====================
    "IOS-L1-071": {
        "commands": [
            "configure terminal",
            "no username {OLD_USERNAME}",
            "username {OLD_USERNAME} privilege 15 secret {NEW_SECRET}",
            "end",
            "write memory"
        ],
        "required_params": ["OLD_USERNAME", "NEW_SECRET"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Run once per user that has a plaintext 'password' entry",
            "Verify the new secret works before closing your current session"
        ],
        "config_mode": True
    },

    # ==================== INTERFACE INGRESS ACL ====================
    "IOS-L1-061": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip access-group {ACL_NAME} in",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME", "ACL_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure ACL {ACL_NAME} is defined before applying",
            "Verify the ACL does not block your management access"
        ],
        "config_mode": True
    },

    # ==================== AAA AUTHENTICATION ENABLE DEFAULT ====================
    "IOS-L1-0211": {
        "commands": [
            "configure terminal",
            "aaa authentication enable default enable",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This enables AAA authentication for privileged EXEC mode",
            "Ensure AAA is configured before applying"
        ],
        "config_mode": True
    },

    # ==================== LOGIN AUTHENTICATION LINE CON 0 ====================
    "IOS-L1-0212": {
        "commands": [
            "configure terminal",
            "line console 0",
            "login authentication {AAA_LIST}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["AAA_LIST"],
        "defaults": {"AAA_LIST": "default"},
        "warnings": [
            "Ensure AAA authentication list {AAA_LIST} exists before applying",
            "Misconfiguration can lock you out of console access"
        ],
        "config_mode": True
    },

    # ==================== LOGIN AUTHENTICATION LINE TTY ====================
    "IOS-L1-0213": {
        "commands": [
            "configure terminal",
            "line tty 0 4",
            "login authentication {AAA_LIST}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["AAA_LIST"],
        "defaults": {"AAA_LIST": "default"},
        "warnings": [
            "Ensure AAA authentication list {AAA_LIST} exists",
            "Adjust TTY line range if your device uses different numbers"
        ],
        "config_mode": True
    },

    # ==================== AAA ACCOUNTING CONNECTION ====================
    "IOS-L1-0221": {
        "commands": [
            "configure terminal",
            "aaa accounting connection default start-stop group {ACCT_GROUP}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["ACCT_GROUP"],
        "defaults": {"ACCT_GROUP": "tacacs+"},
        "warnings": [
            "Ensure TACACS+/RADIUS server is reachable before enabling accounting"
        ],
        "config_mode": True
    },

    # ==================== AAA ACCOUNTING EXEC ====================
    "IOS-L1-0222": {
        "commands": [
            "configure terminal",
            "aaa accounting exec default start-stop group {ACCT_GROUP}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["ACCT_GROUP"],
        "defaults": {"ACCT_GROUP": "tacacs+"},
        "warnings": [
            "Ensure TACACS+/RADIUS server is reachable before enabling accounting"
        ],
        "config_mode": True
    },

    # ==================== AAA ACCOUNTING NETWORK ====================
    "IOS-L1-0223": {
        "commands": [
            "configure terminal",
            "aaa accounting network default start-stop group {ACCT_GROUP}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["ACCT_GROUP"],
        "defaults": {"ACCT_GROUP": "tacacs+"},
        "warnings": [
            "Ensure TACACS+/RADIUS server is reachable before enabling accounting"
        ],
        "config_mode": True
    },

    # ==================== AAA ACCOUNTING SYSTEM ====================
    "IOS-L1-0224": {
        "commands": [
            "configure terminal",
            "aaa accounting system default start-stop group {ACCT_GROUP}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["ACCT_GROUP"],
        "defaults": {"ACCT_GROUP": "tacacs+"},
        "warnings": [
            "Ensure TACACS+/RADIUS server is reachable before enabling accounting",
            "If server is unreachable at startup, device may be inaccessible for ~2 minutes"
        ],
        "config_mode": True
    },

    # ==================== PRIVILEGE 1 FOR LOCAL USERS ====================
    "IOS-L1-0061": {
        "commands": [
            "configure terminal",
            "username {USERNAME} privilege 1 secret {USER_SECRET}",
            "end",
            "write memory"
        ],
        "required_params": ["USERNAME", "USER_SECRET"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This sets privilege level 1 (restricted) for the specified user",
            "Do NOT set privilege 15 for regular users"
        ],
        "config_mode": True
    },

    # ==================== VTY ACCESS-LIST CREATION ====================
    "IOS-L1-0031": {
        "commands": [
            "configure terminal",
            "ip access-list standard {VTY_ACL_NAME}",
            "permit {MGMT_HOST_OR_NET}",
            "deny any log",
            "end",
            "write memory"
        ],
        "required_params": ["VTY_ACL_NAME", "MGMT_HOST_OR_NET"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Replace {MGMT_HOST_OR_NET} with your management station IP or subnet",
            "Apply this ACL to VTY lines using access-class {VTY_ACL_NAME} in"
        ],
        "config_mode": True
    },

    # ==================== BANNER EXEC ====================
    "IOS-L1-0052": {
        "commands": [
            "configure terminal",
            "banner exec ^{BANNER_TEXT}^",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["BANNER_TEXT"],
        "defaults": {
            "BANNER_TEXT": "AUTHORIZED ACCESS ONLY. All activity may be monitored and reported."
        },
        "warnings": [
            "Banner text must not contain the delimiter character (^)"
        ],
        "config_mode": True
    },

    # ==================== SERVICE PASSWORD-ENCRYPTION ====================
    "IOS-L1-070": {
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
            "This uses Cisco type 7 encryption which is weak — use 'secret' for stronger protection",
            "Encrypts all plaintext passwords in the configuration"
        ],
        "config_mode": True
    },

    # ==================== SNMP: DISABLE SNMP WHEN UNUSED ====================
    "IOS-L1-0301": {
        "commands": [
            "configure terminal",
            "no snmp-server",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This completely disables SNMP — do not apply if SNMP is required for monitoring"
        ],
        "config_mode": True
    },

    # ==================== SNMP: REMOVE 'private' COMMUNITY ====================
    "IOS-L1-0302": {
        "commands": [
            "configure terminal",
            "no snmp-server community private",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Removes the default 'private' SNMP community string"
        ],
        "config_mode": True
    },

    # ==================== SNMP: REMOVE 'public' COMMUNITY ====================
    "IOS-L1-0303": {
        "commands": [
            "configure terminal",
            "no snmp-server community public",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Removes the default 'public' SNMP community string"
        ],
        "config_mode": True
    },

    # ==================== SNMP: REMOVE RW COMMUNITY ====================
    "IOS-L1-0304": {
        "commands": [
            "configure terminal",
            "no snmp-server community {RW_COMMUNITY} RW",
            "end",
            "write memory"
        ],
        "required_params": ["RW_COMMUNITY"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Removes the specified SNMP read-write community string"
        ],
        "config_mode": True
    },

    # ==================== SNMP: CREATE ACL FOR SNMP ====================
    "IOS-L1-0305": {
        "commands": [
            "configure terminal",
            "ip access-list standard {SNMP_ACL_NAME}",
            "permit {NMS_HOST_OR_NET}",
            "deny any log",
            "end",
            "write memory"
        ],
        "required_params": ["SNMP_ACL_NAME", "NMS_HOST_OR_NET"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Replace {NMS_HOST_OR_NET} with your NMS IP address or management subnet"
        ],
        "config_mode": True
    },

    # ==================== SNMP: SET snmp-server host ====================
    "IOS-L1-0306": {
        "commands": [
            "configure terminal",
            "snmp-server host {NMS_IP} {SNMP_COMMUNITY}",
            "end",
            "write memory"
        ],
        "required_params": ["NMS_IP", "SNMP_COMMUNITY"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure {NMS_IP} is your authorized SNMP trap receiver"
        ],
        "config_mode": True
    },

    # ==================== SNMP: ENABLE TRAPS ====================
    "IOS-L1-0307": {
        "commands": [
            "configure terminal",
            "snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure snmp-server host is configured to receive traps"
        ],
        "config_mode": True
    },

    # ==================== SNMP: SNMPv3 GROUP WITH PRIV ====================
    "IOS-L1-030A": {
        "commands": [
            "configure terminal",
            "snmp-server group {SNMP_GROUP} v3 priv",
            "end",
            "write memory"
        ],
        "required_params": ["SNMP_GROUP"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "SNMPv3 priv provides both authentication and encryption"
        ],
        "config_mode": True
    },

    # ==================== SNMP: SNMPv3 USER WITH AES128 ====================
    "IOS-L1-0308": {
        "commands": [
            "configure terminal",
            "snmp-server user {SNMP_USER} {SNMP_GROUP} v3 auth sha {AUTH_PASSWORD} priv aes 128 {PRIV_PASSWORD}",
            "end",
            "write memory"
        ],
        "required_params": ["SNMP_USER", "SNMP_GROUP", "AUTH_PASSWORD", "PRIV_PASSWORD"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Authentication password and privacy password must be at least 8 characters",
            "AES 128 is the minimum required encryption level"
        ],
        "config_mode": True
    },

    # ==================== SSH AUTH RETRIES ====================
    "IOS-L1-0113": {
        "commands": [
            "configure terminal",
            "ip ssh authentication-retries {SSH_RETRIES}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["SSH_RETRIES"],
        "defaults": {"SSH_RETRIES": "3"},
        "warnings": [
            "CIS recommends a maximum of 3 authentication retries"
        ],
        "config_mode": True
    },

    # ==================== NO IP BOOTP SERVER ====================
    "IOS-L1-081": {
        "commands": [
            "configure terminal",
            "no ip bootp server",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables the BOOTP service — no impact unless device is used as BOOTP server"
        ],
        "config_mode": True
    },

    # ==================== NO SERVICE DHCP ====================
    "IOS-L1-082": {
        "commands": [
            "configure terminal",
            "no service dhcp",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables DHCP server/relay — do not apply if device provides DHCP services"
        ],
        "config_mode": True
    },

    # ==================== NO IP IDENTD ====================
    "IOS-L1-083": {
        "commands": [
            "configure terminal",
            "no ip identd",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables the identd service on TCP port 113"
        ],
        "config_mode": True
    },

    # ==================== SERVICE TCP-KEEPALIVES-IN ====================
    "IOS-L1-084": {
        "commands": [
            "configure terminal",
            "service tcp-keepalives-in",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== NO SERVICE PAD ====================
    "IOS-L1-085": {
        "commands": [
            "configure terminal",
            "no service pad",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Disables PAD (Packet Assembler/Disassembler) — not needed on modern networks"
        ],
        "config_mode": True
    },

    # ==================== LOGGING ON ====================
    "IOS-L1-0240": {
        "commands": [
            "configure terminal",
            "logging on",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== LOGGING BUFFERED ====================
    "IOS-L1-0242": {
        "commands": [
            "configure terminal",
            "logging buffered {BUFFER_SIZE}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["BUFFER_SIZE"],
        "defaults": {"BUFFER_SIZE": "16384"},
        "warnings": [
            "Larger buffer uses more memory — CIS recommends at least 16384 bytes"
        ],
        "config_mode": True
    },

    # ==================== LOGGING CONSOLE CRITICAL ====================
    "IOS-L1-0245": {
        "commands": [
            "configure terminal",
            "logging console critical",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Sets console logging to critical severity level only to reduce console flood"
        ],
        "config_mode": True
    },

    # ==================== LOGGING HOST ====================
    "IOS-L1-024": {
        "commands": [
            "configure terminal",
            "logging host {SYSLOG_IP}",
            "end",
            "write memory"
        ],
        "required_params": ["SYSLOG_IP"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure {SYSLOG_IP} is your authorized syslog server"
        ],
        "config_mode": True
    },

    # ==================== LOGGING TRAP INFORMATIONAL ====================
    "IOS-L1-0243": {
        "commands": [
            "configure terminal",
            "logging trap informational",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== SERVICE TIMESTAMPS DEBUG DATETIME ====================
    "IOS-L1-0241": {
        "commands": [
            "configure terminal",
            "service timestamps debug datetime msec show-timezone",
            "service timestamps log datetime msec show-timezone",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== LOGGING SOURCE INTERFACE ====================
    "IOS-L1-0246": {
        "commands": [
            "configure terminal",
            "logging source-interface {SOURCE_INTERFACE}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["SOURCE_INTERFACE"],
        "defaults": {"SOURCE_INTERFACE": "Loopback0"},
        "warnings": [
            "Ensure {SOURCE_INTERFACE} exists and has an IP address configured"
        ],
        "config_mode": True
    },

    # ==================== NTP AUTHENTICATION KEY ====================
    "IOS-L1-0611": {
        "commands": [
            "configure terminal",
            "ntp authentication-key {NTP_KEY_ID} md5 {NTP_KEY_STRING}",
            "end",
            "write memory"
        ],
        "required_params": ["NTP_KEY_ID", "NTP_KEY_STRING"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Key ID must match the key ID configured on the NTP server"
        ],
        "config_mode": True
    },

    # ==================== NTP TRUSTED KEY ====================
    "IOS-L1-0612": {
        "commands": [
            "configure terminal",
            "ntp trusted-key {NTP_KEY_ID}",
            "end",
            "write memory"
        ],
        "required_params": ["NTP_KEY_ID"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Must match the key ID in ntp authentication-key"
        ],
        "config_mode": True
    },

    # ==================== NTP SERVER WITH KEY ====================
    "IOS-L1-0613": {
        "commands": [
            "configure terminal",
            "ntp server {NTP_SERVER_IP} key {NTP_KEY_ID}",
            "end",
            "write memory"
        ],
        "required_params": ["NTP_SERVER_IP", "NTP_KEY_ID"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure ntp authenticate and ntp trusted-key are configured first"
        ],
        "config_mode": True
    },

    # ==================== AAA SOURCE INTERFACE ====================
    "IOS-L2-1101": {
        "commands": [
            "configure terminal",
            "ip radius source-interface {LOOPBACK_INTERFACE}",
            "ip tacacs source-interface {LOOPBACK_INTERFACE}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["LOOPBACK_INTERFACE"],
        "defaults": {"LOOPBACK_INTERFACE": "Loopback0"},
        "warnings": [
            "Ensure {LOOPBACK_INTERFACE} exists and has an IP address"
        ],
        "config_mode": True
    },

    # ==================== NTP SOURCE LOOPBACK ====================
    "IOS-L2-1102": {
        "commands": [
            "configure terminal",
            "ntp source {LOOPBACK_INTERFACE}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["LOOPBACK_INTERFACE"],
        "defaults": {"LOOPBACK_INTERFACE": "Loopback0"},
        "warnings": [
            "Ensure {LOOPBACK_INTERFACE} exists and has an IP address"
        ],
        "config_mode": True
    },

    # ==================== IP TFTP SOURCE INTERFACE ====================
    "IOS-L2-1103": {
        "commands": [
            "configure terminal",
            "ip tftp source-interface {LOOPBACK_INTERFACE}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["LOOPBACK_INTERFACE"],
        "defaults": {"LOOPBACK_INTERFACE": "Loopback0"},
        "warnings": [
            "Ensure {LOOPBACK_INTERFACE} exists and has an IP address"
        ],
        "config_mode": True
    },

    # ==================== NO IP PROXY-ARP ====================
    "IOS-L1-091": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "no ip proxy-arp",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Apply to each interface individually",
            "Must be applied to all routed interfaces"
        ],
        "config_mode": True
    },

    # ==================== NO INTERFACE TUNNEL ====================
    "IOS-L1-092": {
        "commands": [
            "configure terminal",
            "no interface Tunnel{TUNNEL_NUMBER}",
            "end",
            "write memory"
        ],
        "required_params": ["TUNNEL_NUMBER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "WARNING: This permanently removes the tunnel interface",
            "Verify the tunnel is not used for any active traffic before removing"
        ],
        "config_mode": True
    },

    # ==================== IP VERIFY UNICAST SOURCE ====================
    "IOS-L1-093": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip verify unicast source reachable-via rx",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Enables uRPF — verify CEF is enabled on this interface",
            "Apply to external-facing interfaces only"
        ],
        "config_mode": True
    },

    # ==================== IP ACCESS-LIST EXTENDED - BLOCK PRIVATE ====================
    "IOS-L1-094": {
        "commands": [
            "configure terminal",
            "ip access-list extended {ACL_NAME}",
            "deny ip 10.0.0.0 0.255.255.255 any log",
            "deny ip 172.16.0.0 0.15.255.255 any log",
            "deny ip 192.168.0.0 0.0.255.255 any log",
            "deny ip 127.0.0.0 0.255.255.255 any log",
            "permit ip any any",
            "end",
            "write memory"
        ],
        "required_params": ["ACL_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Apply this ACL inbound on external interfaces using ip access-group",
            "Verify legitimate traffic is not blocked before applying"
        ],
        "config_mode": True
    },

    # ==================== IP ACCESS-GROUP INBOUND ON EXTERNAL ====================
    "IOS-L1-095": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip access-group {ACL_NAME} in",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME", "ACL_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure ACL {ACL_NAME} is defined before applying",
            "Verify the ACL allows your management traffic to avoid lockout"
        ],
        "config_mode": True
    },

    # ==================== EIGRP: KEY CHAIN ====================
    "IOS-L2-100": {
        "commands": [
            "configure terminal",
            "key chain {KEY_CHAIN_NAME}",
            "key {KEY_ID}",
            "key-string {KEY_STRING}",
            "end",
            "write memory"
        ],
        "required_params": ["KEY_CHAIN_NAME", "KEY_ID", "KEY_STRING"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Key chain is required for EIGRP/RIP authentication"
        ],
        "config_mode": True
    },

    # ==================== EIGRP: KEY ====================
    "IOS-L2-1001": {
        "commands": [
            "configure terminal",
            "key chain {KEY_CHAIN_NAME}",
            "key {KEY_ID}",
            "end",
            "write memory"
        ],
        "required_params": ["KEY_CHAIN_NAME", "KEY_ID"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== EIGRP: KEY-STRING ====================
    "IOS-L2-1002": {
        "commands": [
            "configure terminal",
            "key chain {KEY_CHAIN_NAME}",
            "key {KEY_ID}",
            "key-string {KEY_STRING}",
            "end",
            "write memory"
        ],
        "required_params": ["KEY_CHAIN_NAME", "KEY_ID", "KEY_STRING"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== EIGRP: ADDRESS-FAMILY IPV4 ====================
    "IOS-L2-1003": {
        "commands": [
            "configure terminal",
            "router eigrp {EIGRP_NAME}",
            "address-family ipv4 autonomous-system {AS_NUMBER}",
            "end",
            "write memory"
        ],
        "required_params": ["EIGRP_NAME", "AS_NUMBER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Named EIGRP mode — use if running EIGRP named configuration"
        ],
        "config_mode": True
    },

    # ==================== EIGRP: AF-INTERFACE DEFAULT ====================
    "IOS-L2-1004": {
        "commands": [
            "configure terminal",
            "router eigrp {EIGRP_NAME}",
            "address-family ipv4 autonomous-system {AS_NUMBER}",
            "af-interface default",
            "authentication mode md5",
            "authentication key-chain {KEY_CHAIN_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["EIGRP_NAME", "AS_NUMBER", "KEY_CHAIN_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== EIGRP: AUTHENTICATION KEY-CHAIN ====================
    "IOS-L2-1005": {
        "commands": [
            "configure terminal",
            "router eigrp {EIGRP_NAME}",
            "address-family ipv4 autonomous-system {AS_NUMBER}",
            "af-interface default",
            "authentication key-chain {KEY_CHAIN_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["EIGRP_NAME", "AS_NUMBER", "KEY_CHAIN_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== EIGRP: AUTHENTICATION MODE MD5 ====================
    "IOS-L2-1006": {
        "commands": [
            "configure terminal",
            "router eigrp {EIGRP_NAME}",
            "address-family ipv4 autonomous-system {AS_NUMBER}",
            "af-interface default",
            "authentication mode md5",
            "end",
            "write memory"
        ],
        "required_params": ["EIGRP_NAME", "AS_NUMBER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== EIGRP: IP AUTH KEY-CHAIN (CLASSIC) ====================
    "IOS-L2-1007": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip authentication key-chain eigrp {AS_NUMBER} {KEY_CHAIN_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME", "AS_NUMBER", "KEY_CHAIN_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Classic EIGRP authentication — use on interfaces running classic EIGRP"
        ],
        "config_mode": True
    },

    # ==================== EIGRP: IP AUTH MODE (CLASSIC) ====================
    "IOS-L2-1008": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip authentication mode eigrp {AS_NUMBER} md5",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME", "AS_NUMBER"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Classic EIGRP authentication — use on interfaces running classic EIGRP"
        ],
        "config_mode": True
    },

    # ==================== OSPF: AREA AUTHENTICATION MESSAGE-DIGEST ====================
    "IOS-L2-101": {
        "commands": [
            "configure terminal",
            "router ospf {OSPF_PROCESS_ID}",
            "area {OSPF_AREA} authentication message-digest",
            "end",
            "write memory"
        ],
        "required_params": ["OSPF_PROCESS_ID", "OSPF_AREA"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Ensure all OSPF neighbors in this area are configured with MD5 authentication"
        ],
        "config_mode": True
    },

    # ==================== OSPF: IP OSPF MESSAGE-DIGEST-KEY ====================
    "IOS-L2-1011": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip ospf message-digest-key {KEY_ID} md5 {KEY_STRING}",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME", "KEY_ID", "KEY_STRING"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Key ID and key string must match on all OSPF neighbors"
        ],
        "config_mode": True
    },

    # ==================== RIPv2: KEY CHAIN ====================
    "IOS-L2-102": {
        "commands": [
            "configure terminal",
            "key chain {KEY_CHAIN_NAME}",
            "key {KEY_ID}",
            "key-string {KEY_STRING}",
            "end",
            "write memory"
        ],
        "required_params": ["KEY_CHAIN_NAME", "KEY_ID", "KEY_STRING"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== RIPv2: KEY ====================
    "IOS-L2-1021": {
        "commands": [
            "configure terminal",
            "key chain {KEY_CHAIN_NAME}",
            "key {KEY_ID}",
            "end",
            "write memory"
        ],
        "required_params": ["KEY_CHAIN_NAME", "KEY_ID"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== RIPv2: KEY-STRING ====================
    "IOS-L2-1022": {
        "commands": [
            "configure terminal",
            "key chain {KEY_CHAIN_NAME}",
            "key {KEY_ID}",
            "key-string {KEY_STRING}",
            "end",
            "write memory"
        ],
        "required_params": ["KEY_CHAIN_NAME", "KEY_ID", "KEY_STRING"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== RIPv2: IP RIP AUTH KEY-CHAIN ====================
    "IOS-L2-1023": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip rip authentication key-chain {KEY_CHAIN_NAME}",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME", "KEY_CHAIN_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== RIPv2: IP RIP AUTH MODE MD5 ====================
    "IOS-L2-1024": {
        "commands": [
            "configure terminal",
            "interface {INTERFACE_NAME}",
            "ip rip authentication mode md5",
            "end",
            "write memory"
        ],
        "required_params": ["INTERFACE_NAME"],
        "optional_params": [],
        "defaults": {},
        "warnings": [],
        "config_mode": True
    },

    # ==================== AAA ACCOUNTING COMMANDS 15 ====================
    "IOS-L1-0225": {
        "commands": [
            "configure terminal",
            "aaa accounting commands 15 default start-stop group {ACCT_GROUP}",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": ["ACCT_GROUP"],
        "defaults": {"ACCT_GROUP": "tacacs+"},
        "warnings": [
            "Logs all privileged EXEC (level 15) commands to accounting server",
            "Ensure TACACS+/RADIUS server is reachable before enabling"
        ],
        "config_mode": True
    },

    # ==================== TRANSPORT INPUT SSH FOR VTY ====================
    "IOS-L1-0033": {
        "commands": [
            "configure terminal",
            "line vty 0 4",
            "transport input ssh",
            "line vty 5 15",
            "transport input ssh",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "This restricts VTY access to SSH only — Telnet will be disabled",
            "Ensure SSH is working before applying to avoid lockout"
        ],
        "config_mode": True
    },

    # ==================== USERNAME SECRET ====================
    "IOS-L1-0062": {
        "commands": [
            "configure terminal",
            "username {USERNAME} secret {USER_SECRET}",
            "end",
            "write memory"
        ],
        "required_params": ["USERNAME", "USER_SECRET"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Uses type 5 (MD5) secret — stronger than 'password'",
            "Replaces any existing password for this user"
        ],
        "config_mode": True
    },

    # ==================== INTERFACE LOOPBACK ====================
    "IOS-L1-0248": {
        "commands": [
            "configure terminal",
            "interface Loopback{LOOPBACK_NUMBER}",
            "ip address {LOOPBACK_IP} {LOOPBACK_MASK}",
            "no shutdown",
            "end",
            "write memory"
        ],
        "required_params": ["LOOPBACK_IP", "LOOPBACK_MASK"],
        "optional_params": ["LOOPBACK_NUMBER"],
        "defaults": {"LOOPBACK_NUMBER": "0"},
        "warnings": [
            "Loopback interface is used as a stable management source address"
        ],
        "config_mode": True
    },

    # ==================== BGP: NEIGHBOR PASSWORD ====================
    "IOS-L2-103": {
        "commands": [
            "configure terminal",
            "router bgp {AS_NUMBER}",
            "neighbor {NEIGHBOR_IP} password {BGP_PASSWORD}",
            "end",
            "write memory"
        ],
        "required_params": ["AS_NUMBER", "NEIGHBOR_IP", "BGP_PASSWORD"],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "BGP neighbor must also be configured with the same password",
            "Changing this may temporarily disrupt the BGP session"
        ],
        "config_mode": True
    },

    # ==================== SSH CIPHER/MAC HARDENING ====================
    "IOS-L2-0114": {
        "commands": [
            "configure terminal",
            "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr",
            "ip ssh server algorithm mac hmac-sha2-256 hmac-sha1",
            "end",
            "write memory"
        ],
        "required_params": [],
        "optional_params": [],
        "defaults": {},
        "warnings": [
            "Verify your IOS version supports these algorithm keywords before applying",
            "Older IOS versions may not support 'ip ssh server algorithm' commands"
        ],
        "config_mode": True
    },
}


# Mapping from CIS section numbers (e.g. "CIS-1.1.1") to internal IOS template IDs.
# Corrected to match actual template commands to CIS benchmark requirements.
CIS_SECTION_TO_IOS: Dict[str, str] = {
    # 1.1 AAA
    "CIS-1.1.1":  "IOS-L1-012",    # aaa new-model
    "CIS-1.1.2":  "IOS-L1-013",    # aaa authentication login
    "CIS-1.1.3":  "IOS-L1-0211",   # aaa authentication enable default
    "CIS-1.1.4":  "IOS-L1-0212",   # line con 0 / login authentication
    "CIS-1.1.5":  "IOS-L1-0213",   # line tty / login authentication
    "CIS-1.1.6":  "IOS-L1-013",    # line vty / login authentication (was IOS-L1-004 'transport input ssh', which never satisfied the vty login-authentication check)
    "CIS-1.1.7":  "IOS-L1-0225",   # aaa accounting commands 15
    "CIS-1.1.8":  "IOS-L1-0221",   # aaa accounting connection
    "CIS-1.1.9":  "IOS-L1-0222",   # aaa accounting exec
    "CIS-1.1.10": "IOS-L1-0223",   # aaa accounting network
    "CIS-1.1.11": "IOS-L1-0224",   # aaa accounting system
    # 1.2 Access Rules
    "CIS-1.2.1":  "IOS-L1-0061",   # username privilege 1
    "CIS-1.2.2":  "IOS-L1-0033",   # line vty transport input ssh
    "CIS-1.2.4":  "IOS-L1-0031",   # access-list for VTY
    "CIS-1.2.5":  "IOS-L1-003",    # access-class for VTY
    # 1.3 Banners
    "CIS-1.3.1":  "IOS-L1-0052",   # banner exec
    "CIS-1.3.2":  "IOS-L1-0051",   # banner login
    "CIS-1.3.3":  "IOS-L1-005",    # banner motd
    # 1.4 Passwords
    "CIS-1.4.1":  "IOS-L1-001",    # enable secret
    "CIS-1.4.2":  "IOS-L1-070",    # service password-encryption
    "CIS-1.4.3":  "IOS-L1-0062",   # username secret
    # 1.5 SNMP
    "CIS-1.5.1":  "IOS-L1-0301",   # no snmp-server
    "CIS-1.5.2":  "IOS-L1-0302",   # no snmp community private
    "CIS-1.5.3":  "IOS-L1-0303",   # no snmp community public
    "CIS-1.5.4":  "IOS-L1-0304",   # no snmp RW
    "CIS-1.5.5":  "IOS-L1-030B",   # snmp community with read-only ACL
    "CIS-1.5.6":  "IOS-L1-0305",   # ACL for SNMP
    "CIS-1.5.7":  "IOS-L1-0306",   # snmp-server host
    "CIS-1.5.8":  "IOS-L1-0307",   # snmp enable traps
    "CIS-1.5.9":  "IOS-L1-030A",   # snmp group v3 priv
    "CIS-1.5.10": "IOS-L1-0308",   # snmp user aes128
    # 2.1.1 SSH prerequisites
    "CIS-2.1.1.1.1": "IOS-L1-0010",  # hostname
    "CIS-2.1.1.1.2": "IOS-L1-0011",  # ip domain-name
    "CIS-2.1.1.1.3": "IOS-L1-0120",  # crypto key generate rsa modulus >= 2048
    "CIS-2.1.1.1.4": "IOS-L1-008",   # ip ssh time-out
    "CIS-2.1.1.1.5": "IOS-L1-0113",  # ip ssh authentication-retries
    "CIS-2.1.1.2":   "IOS-L1-007",   # ip ssh version 2
    # 2.1 Services
    "CIS-2.1.2": "IOS-L1-018",    # no cdp run
    "CIS-2.1.3": "IOS-L1-081",    # no ip bootp server
    "CIS-2.1.4": "IOS-L1-082",    # no service dhcp
    "CIS-2.1.5": "IOS-L1-083",    # no ip identd
    "CIS-2.1.6": "IOS-L1-084",    # service tcp-keepalives-in
    "CIS-2.1.8": "IOS-L1-085",    # no service pad
    # 2.2 Logging
    "CIS-2.2.1": "IOS-L1-0240",   # logging on
    "CIS-2.2.2": "IOS-L1-0242",   # logging buffered
    "CIS-2.2.3": "IOS-L1-0245",   # logging console critical
    "CIS-2.2.4": "IOS-L1-024",    # logging host
    "CIS-2.2.5": "IOS-L1-0243",   # logging trap informational
    "CIS-2.2.6": "IOS-L1-0241",   # service timestamps debug datetime
    "CIS-2.2.7": "IOS-L1-0246",   # logging source-interface
    # 2.3 NTP
    "CIS-2.3.1.1": "IOS-L1-080",   # ntp authenticate
    "CIS-2.3.1.2": "IOS-L1-0611",  # ntp authentication-key
    "CIS-2.3.1.3": "IOS-L1-0612",  # ntp trusted-key
    "CIS-2.3.1.4": "IOS-L1-0613",  # ntp server key
    "CIS-2.3.2":   "IOS-L1-017",   # ntp server IP address
    # 2.4 Loopback
    "CIS-2.4.1": "IOS-L1-0248",   # interface Loopback
    "CIS-2.4.2": "IOS-L2-1101",   # AAA source-interface loopback
    "CIS-2.4.3": "IOS-L2-1102",   # ntp source loopback
    "CIS-2.4.4": "IOS-L2-1103",   # ip tftp source-interface loopback
    # 3.1 Routing
    "CIS-3.1.1": "IOS-L1-019",    # no ip source-route
    "CIS-3.1.2": "IOS-L1-091",    # no ip proxy-arp
    "CIS-3.1.3": "IOS-L1-092",    # no interface tunnel
    "CIS-3.1.4": "IOS-L1-093",    # ip verify unicast source reachable-via
    # 3.2 Border Filtering
    "CIS-3.2.1": "IOS-L1-094",    # ip access-list extended block private
    "CIS-3.2.2": "IOS-L1-095",    # ip access-group inbound
    # 3.3.1 EIGRP
    "CIS-3.3.1.1": "IOS-L2-100",   # key chain
    "CIS-3.3.1.2": "IOS-L2-1001",  # key
    "CIS-3.3.1.3": "IOS-L2-1002",  # key-string
    "CIS-3.3.1.4": "IOS-L2-1003",  # address-family ipv4 autonomous-system
    "CIS-3.3.1.5": "IOS-L2-1004",  # af-interface default
    "CIS-3.3.1.6": "IOS-L2-1005",  # authentication key-chain
    "CIS-3.3.1.7": "IOS-L2-1006",  # authentication mode md5
    "CIS-3.3.1.8": "IOS-L2-1007",  # ip authentication key-chain eigrp
    "CIS-3.3.1.9": "IOS-L2-1008",  # ip authentication mode eigrp
    # 3.3.2 OSPF
    "CIS-3.3.2.1": "IOS-L2-101",   # area authentication message-digest
    "CIS-3.3.2.2": "IOS-L2-1011",  # ip ospf message-digest-key
    # 3.3.3 RIPv2
    "CIS-3.3.3.1": "IOS-L2-102",   # key chain
    "CIS-3.3.3.2": "IOS-L2-1021",  # key
    "CIS-3.3.3.3": "IOS-L2-1022",  # key-string
    "CIS-3.3.3.4": "IOS-L2-1023",  # ip rip authentication key-chain
    "CIS-3.3.3.5": "IOS-L2-1024",  # ip rip authentication mode md5
    # 3.3.4 BGP
    "CIS-3.3.4.1": "IOS-L2-103",   # neighbor password
}


def _resolve_id(check_number: str) -> str:
    """Resolve a CIS section ID (e.g. 'CIS-1.1.1') to an IOS template ID."""
    if check_number in COMMAND_TEMPLATES:
        return check_number
    return CIS_SECTION_TO_IOS.get(check_number, check_number)


def get_template(check_number: str) -> Dict[str, Any]:
    """
    Get command template for a check number.

    Accepts both IOS-L1-XXX format and CIS-X.X.X section format.

    Args:
        check_number: IOS template ID (e.g. "IOS-L1-001") or CIS section ID (e.g. "CIS-1.1.1")

    Returns:
        Command template dict

    Raises:
        KeyError: If check_number not found in templates
    """
    ios_id = _resolve_id(check_number)
    if ios_id not in COMMAND_TEMPLATES:
        raise KeyError(f"No command template found for {check_number}")
    return COMMAND_TEMPLATES[ios_id]


def has_template(check_number: str) -> bool:
    """Check if a template exists for the given check number (IOS or CIS format)."""
    return _resolve_id(check_number) in COMMAND_TEMPLATES


def get_all_templated_checks() -> List[str]:
    """Get list of all check numbers that have templates."""
    return list(COMMAND_TEMPLATES.keys())
