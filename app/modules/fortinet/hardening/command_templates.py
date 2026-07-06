"""
FortiGate hardening command templates.

Auto-remediation command blocks for the CIS controls that can be safely fixed
without operator judgement. Each template holds **only the inner config block**
(``config <section>`` / ``set ...`` / ``end``); the executor adds the correct
scope wrapper (``config global`` or ``config vdom`` / ``edit <name>``) based on
the control's ``scope`` in ``audit/rules.py`` and whether the device runs VDOMs.

Controls that are Manual, or whose remediation needs operator judgement (e.g.
removing specific SNMP communities, rewriting firewall policies, enabling HA or
the Security Fabric), intentionally have no template and are reported as
"manual remediation required".

Template fields:
  - commands:        inner config commands (with {PARAM} placeholders)
  - required_params: params the user must supply
  - optional_params: params with defaults
  - defaults:        default values for optional params
  - warnings:        safety notes for the UI
"""

from typing import Any, Dict, List


FORTIGATE_COMMAND_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ---- 1 Network Settings ----
    "FG-BL-043": {  # 1.1 DNS server
        "commands": ["config system dns", "set primary {DNS_PRIMARY}", "end"],
        "required_params": ["DNS_PRIMARY"], "optional_params": [], "defaults": {},
        "warnings": ["Sets the primary DNS server."],
    },

    # ---- 2.1 General Settings ----
    "FG-BL-092": {  # 2.1.1 pre-login banner
        "commands": ["config system global", "set pre-login-banner enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables the pre-login banner (banner text is set via replacement messages)."],
    },
    "FG-SYS-001": {  # 2.1.2 post-login banner
        "commands": ["config system global", "set post-login-banner enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables the post-login banner."],
    },
    "FG-BL-040": {  # 2.1.4 NTP
        "commands": ["config system ntp", "set ntpsync enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables NTP synchronization (configure a custom NTP server separately if required)."],
    },
    "FG-SYS-003": {  # 2.1.5 hostname
        "commands": ["config system global", "set hostname {HOSTNAME}", "end"],
        "required_params": ["HOSTNAME"], "optional_params": [], "defaults": {},
        "warnings": ["Sets the device hostname."],
    },
    "FG-SYS-005": {  # 2.1.7 USB install
        "commands": ["config system auto-install",
                     "set auto-install-config disable",
                     "set auto-install-image disable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Disables automatic config/firmware installation from USB."],
    },
    "FG-SYS-006": {  # 2.1.8 static TLS keys
        "commands": ["config system global", "set ssl-static-key-ciphers disable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Disables static key ciphers for TLS."],
    },
    "FG-BL-090": {  # 2.1.9 strong crypto
        "commands": ["config system global", "set strong-crypto enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables global strong cryptography; weak ciphers are disabled."],
    },

    # ---- 2.2 Password Policy ----
    "FG-BL-030": {  # 2.2.1 password policy (vdom_root scope)
        "commands": ["config system password-policy", "set status enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables password policy enforcement."],
    },
    "FG-PW-001": {  # 2.2.2 admin lockout
        "commands": ["config system global",
                     "set admin-lockout-threshold {ADMIN_LOCKOUT_THRESHOLD}",
                     "set admin-lockout-duration {ADMIN_LOCKOUT_DURATION}", "end"],
        "required_params": [], "optional_params": ["ADMIN_LOCKOUT_THRESHOLD", "ADMIN_LOCKOUT_DURATION"],
        "defaults": {"ADMIN_LOCKOUT_THRESHOLD": "3", "ADMIN_LOCKOUT_DURATION": "60"},
        "warnings": ["Sets admin login retry threshold and lockout duration."],
    },

    # ---- 2.4 Administrators ----
    "FG-BL-004": {  # 2.4.4 idle timeout
        "commands": ["config system global", "set admintimeout {ADMIN_TIMEOUT}", "end"],
        "required_params": [], "optional_params": ["ADMIN_TIMEOUT"],
        "defaults": {"ADMIN_TIMEOUT": "10"},
        "warnings": ["Sets the admin idle timeout in minutes."],
    },
    "FG-BL-002": {  # 2.4.5 encrypted channels only
        "commands": ["config system global",
                     "set admin-telnet disable",
                     "set admin-http disable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Disables Telnet and HTTP admin access. Ensure SSH/HTTPS work first."],
    },

    # ---- 2.5 High Availability ----
    "FG-HA-005": {  # 2.5.2 HA monitor interfaces
        "commands": ["config system ha", "set monitor {HA_MONITOR_INTERFACE}", "end"],
        "required_params": ["HA_MONITOR_INTERFACE"], "optional_params": [], "defaults": {},
        "warnings": ["Sets HA monitored interfaces. Apply only on HA-configured devices."],
    },

    # ---- 4.2 Antivirus ----
    "FG-AV-001": {  # 4.2.1 push updates (global)
        "commands": ["config system autoupdate push-update", "set status enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables FortiGuard antivirus definition push updates."],
    },
    "FG-AV-003": {  # 4.2.4 AI/heuristic detection (per-VDOM)
        # Two build spellings: newer builds use `machine-learning-detection` under
        # antivirus settings; 60F/older builds have no such field and use
        # `config antivirus heuristic` (mode). Apply BOTH — the executor tolerates
        # the block that doesn't exist on a given build, and verify
        # (rule_combine="any") passes if EITHER took effect.
        "commands": ["config antivirus settings", "set machine-learning-detection enable", "end",
                     "config antivirus heuristic", "set mode pass", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables AI/heuristic malware detection (machine-learning-detection, or the "
                     "antivirus heuristic node on builds without that field)."],
    },
    "FG-AV-004": {  # 4.2.5 grayware (per-VDOM)
        "commands": ["config antivirus settings", "set grayware enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables grayware detection in antivirus."],
    },

    # ---- 4.3 DNS Filter ----
    "FG-DNS-001": {  # 4.3.1 botnet C&C blocking (per-VDOM)
        "commands": ["config dnsfilter profile", "edit {DNSFILTER_PROFILE}",
                     "set block-botnet enable", "next", "end"],
        "required_params": [], "optional_params": ["DNSFILTER_PROFILE"],
        "defaults": {"DNSFILTER_PROFILE": "default"},
        "warnings": ["Enables Botnet C&C domain blocking on the DNS filter profile."],
    },

    # ---- 4.4 Application Control ----
    # FG-APP-002 (4.4.2, enforce default app ports) has NO template on purpose:
    # the `enforce-default-app-port` field is build-specific and absent on some
    # models (e.g. 60F), where pushing it fails with "command parse error". It is
    # a Manual/review-only control (see rules.py review_required), so it is audited
    # best-effort but never auto-hardened. Add a template back only once the field
    # is confirmed present across the supported build matrix.

    # ---- 7 Users and Authentication ----
    "FG-USER-001": {  # 7.1 login attempts/lockout (per-VDOM)
        "commands": ["config user setting",
                     "set auth-lockout-threshold {AUTH_LOCKOUT_THRESHOLD}",
                     "set auth-lockout-duration {AUTH_LOCKOUT_DURATION}", "end"],
        "required_params": [], "optional_params": ["AUTH_LOCKOUT_THRESHOLD", "AUTH_LOCKOUT_DURATION"],
        "defaults": {"AUTH_LOCKOUT_THRESHOLD": "3", "AUTH_LOCKOUT_DURATION": "60"},
        "warnings": ["Sets user authentication lockout threshold and duration."],
    },

    # ---- 8 Logs and Reports ----
    "FG-LOG-001": {  # 8.1.1 event logging (per-VDOM)
        "commands": ["config log eventfilter", "set event enable", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables event logging."],
    },
    "FG-LOG-002": {  # 8.2.1 encrypt log transmission to FAZ (global)
        "commands": ["config log fortianalyzer setting",
                     "set reliable enable", "set enc-algorithm high", "end"],
        "required_params": [], "optional_params": [], "defaults": {},
        "warnings": ["Enables reliable (TCP) and encrypted log transmission to FortiAnalyzer.",
                     "FortiAnalyzer must be configured to accept encrypted/reliable logging."],
    },
    "FG-FAZ-001": {  # 8.3.1 centralized logging (global)
        "commands": ["config log fortianalyzer setting",
                     "set status enable", "set server {FAZ_SERVER}", "end"],
        "required_params": ["FAZ_SERVER"], "optional_params": [], "defaults": {},
        "warnings": ["Enables FortiAnalyzer logging. Ensure the FortiAnalyzer accepts this device."],
    },
}


def get_fortigate_template(check_id: str) -> Dict[str, Any]:
    """Return the command template for ``check_id`` (raises KeyError if absent)."""
    if check_id not in FORTIGATE_COMMAND_TEMPLATES:
        raise KeyError(f"No command template found for {check_id}")
    return FORTIGATE_COMMAND_TEMPLATES[check_id]


def has_fortigate_template(check_id: str) -> bool:
    """Whether an auto-remediation template exists for ``check_id``."""
    return check_id in FORTIGATE_COMMAND_TEMPLATES


def get_all_fortigate_templated_checks() -> List[str]:
    """All FortiGate check IDs that can be auto-remediated."""
    return list(FORTIGATE_COMMAND_TEMPLATES.keys())
