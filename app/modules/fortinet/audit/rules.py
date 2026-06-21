"""
FortiGate Security Control Definitions

Comprehensive catalog of 65+ FortiGate security controls covering:
- BASELINE: Core security controls (management, crypto, IAM, logging, etc.)
- HA: High Availability configuration checks
- SDWAN: SD-WAN configuration validation
- VPN_SSL/VPN_IPSEC: VPN security hardening
- CENTRAL_NAT: NAT configuration review
- LOCAL_IN: Management plane access controls
- EXPOSURE: WAN/VIP exposure risks
- UTM: Unified Threat Management coverage
- FAZ: FortiAnalyzer integration

Based on CIS Benchmarks and enterprise best practices.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import re


# Data Classes


@dataclass
class FortiGateRule:
    """Individual rule evaluation logic"""
    type: str  # set_bool, set_eq, set_int_le, set_int_ge, regex_present, regex_absent, set_in
    cmd: str  # FortiGate CLI command to execute
    key: Optional[str] = None  # Config key to check
    expected: Any = None  # Expected value
    any_of: Optional[List[Any]] = None  # List of acceptable values
    pattern: Optional[str] = None  # Regex pattern to match


@dataclass
class FortiGateControl:
    """Security control definition"""
    id: str  # Control ID (e.g., FG-BL-001)
    title: str  # Short description
    pack: str  # Control pack (BASELINE, HA, SDWAN, etc.)
    domain: str  # Security domain
    severity: str  # Critical, High, Medium, Low
    level: str  # L1 or L2
    rules: List[FortiGateRule]  # Evaluation rules
    remediation: str  # Fix instructions
    min_version: Optional[str] = None  # Minimum FortiOS version
    max_version: Optional[str] = None  # Maximum FortiOS version
    cis_id: Optional[str] = None  # CIS Benchmark ID
    cis_section: Optional[str] = None  # CIS Benchmark section name
    cis_profile: Optional[str] = None  # CIS profile (L1 or L2)
    cis_type: str = "Automated"  # CIS recommendation type: "Automated" or "Manual"
    tags: List[str] = field(default_factory=list)  # Tags for filtering

    @property
    def is_manual(self) -> bool:
        """Manual controls are evidence-only and excluded from the compliance score."""
        return self.cis_type == "Manual"


# Helper Functions

def _mk_set_bool(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, key: str, expected: bool, remediation: str,
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """Create a boolean set check control"""
    cis = cis or {}
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="set_bool", cmd=cmd, key=key, expected=expected)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type=cis.get("type", "Automated"),
        tags=list(tags or [])
    )


def _mk_re_abs(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, pattern: str, remediation: str,
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """Create a regex absence check control"""
    cis = cis or {}
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="regex_absent", cmd=cmd, pattern=pattern)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type=cis.get("type", "Automated"),
        tags=list(tags or [])
    )


def _mk_re_pre(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, pattern: str, remediation: str,
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """Create a regex presence check control"""
    cis = cis or {}
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="regex_present", cmd=cmd, pattern=pattern)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type=cis.get("type", "Automated"),
        tags=list(tags or [])
    )


def _mk_int_le(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, key: str, expected: int, remediation: str,
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """Create an integer less-than-or-equal check control"""
    cis = cis or {}
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="set_int_le", cmd=cmd, key=key, expected=expected)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type=cis.get("type", "Automated"),
        tags=list(tags or [])
    )


def _mk_int_ge(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, key: str, expected: int, remediation: str,
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """Create an integer greater-than-or-equal check control"""
    cis = cis or {}
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="set_int_ge", cmd=cmd, key=key, expected=expected)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type=cis.get("type", "Automated"),
        tags=list(tags or [])
    )


def _mk_set_eq(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, key: str, expected: str, remediation: str,
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """Create a string equality check control"""
    cis = cis or {}
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="set_eq", cmd=cmd, key=key, expected=expected)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type=cis.get("type", "Automated"),
        tags=list(tags or [])
    )


def _mk_manual(
    id: str, title: str, pack: str, domain: str, severity: str, level: str,
    cmd: str, remediation: str, pattern: str = r".+",
    cis: Optional[Dict] = None, tags: Optional[List[str]] = None
) -> FortiGateControl:
    """
    Create a Manual (non-scoring) control.

    CIS 'Manual' recommendations cannot be reliably verified by config parsing,
    so these are excluded from the compliance score. The audit still runs `cmd`
    and captures its output as evidence for the auditor to review. `pattern`
    only controls which lines are highlighted as evidence.
    """
    cis = dict(cis or {})
    cis["type"] = "Manual"
    return FortiGateControl(
        id=id, title=title, pack=pack, domain=domain, severity=severity, level=level,
        rules=[FortiGateRule(type="regex_present", cmd=cmd, pattern=pattern)],
        remediation=remediation,
        cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
        cis_type="Manual",
        tags=list(tags or []) + ["manual"]
    )



# Official CIS FortiGate Benchmark section mapping
# Single source of truth mapping each control to its benchmark section number.


_CIS_SECTION_NAMES: Dict[str, str] = {
    "1": "Network Settings",
    "2": "System Settings",
    "3": "Policy and Objects",
    "4": "Security Profiles",
    "5": "Security Fabric",
    "6": "VPN",
    "7": "Users and Authentication",
    "8": "Logs and Reports",
}

_CIS_SECTION_BY_CONTROL: Dict[str, str] = {
    # 1 Network Settings
    "FG-BL-043": "1.1", "FG-BL-044": "1.1",        # DNS server configured
    "FG-NET-001": "1.2",                            # intra-zone traffic
    "FG-BL-WAN-HTTP": "1.3", "FG-BL-WAN-HTTPS": "1.3", "FG-BL-WAN-SSH": "1.3",
    "FG-BL-WAN-TELNET": "1.3", "FG-BL-WAN-SNMP": "1.3", "FG-BL-WAN-FGFM": "1.3",
    "FG-BL-WAN-PING": "1.3", "FG-BL-WAN-FABRIC": "1.3",
    # 2.1 General Settings
    "FG-BL-092": "2.1.1",                           # pre-login banner
    "FG-SYS-001": "2.1.2",                          # post-login banner
    "FG-SYS-002": "2.1.3",                          # timezone
    "FG-BL-040": "2.1.4", "FG-BL-041": "2.1.4",     # NTP
    "FG-SYS-003": "2.1.5",                          # hostname
    "FG-SYS-004": "2.1.6",                          # firmware
    "FG-SYS-005": "2.1.7",                          # USB install
    "FG-SYS-006": "2.1.8",                          # static TLS keys
    "FG-BL-090": "2.1.9",                           # strong encryption
    "FG-BL-005": "2.1.10",                          # GUI TLS version
    # 2.2 Password Policy
    "FG-BL-030": "2.2.1", "FG-BL-031": "2.2.1", "FG-BL-032": "2.2.1",
    "FG-BL-033": "2.2.1", "FG-BL-034": "2.2.1", "FG-BL-035": "2.2.1", "FG-BL-036": "2.2.1",
    "FG-PW-001": "2.2.2",                           # retries / lockout
    # 2.3 SNMP
    "FG-BL-050": "2.3.1", "FG-BL-051": "2.3.1",     # only SNMPv3
    "FG-SNMP-001": "2.3.2",                         # trusted hosts
    # 2.4 Administrators
    "FG-BL-021": "2.4.1",                           # default admin password
    "FG-BL-020": "2.4.2",                           # trusted hosts
    "FG-ADM-001": "2.4.3",                          # profiles assigned
    "FG-BL-004": "2.4.4",                           # idle timeout
    "FG-BL-001": "2.4.5", "FG-BL-002": "2.4.5", "FG-BL-003": "2.4.5",  # encrypted channels
    "FG-LIP-001": "2.4.6",                          # local-in policies
    "FG-BL-007": "2.4.7",                           # admin ports
    # 2.5 High Availability
    "FG-HA-004": "2.5.1",                           # HA enabled
    "FG-HA-005": "2.5.2",                           # monitor interfaces
    "FG-HA-006": "2.5.3",                           # reserved mgmt interface
    # 3 Policy and Objects
    "FG-POL-001": "3.1",                            # unused policies
    "FG-BL-080": "3.2",                             # no ALL service
    "FG-POL-002": "3.3",                            # ISDB deny
    "FG-BL-082": "3.4",                             # policy logging
    # 4.1 IPS
    "FG-IPS-001": "4.1.1",                          # botnet connections
    "FG-UTM-003": "4.1.2",                          # apply IPS
    # 4.2 Antivirus
    "FG-AV-001": "4.2.1",                           # push updates
    "FG-UTM-002": "4.2.2",                          # apply AV
    "FG-AV-002": "4.2.3",                           # outbreak prevention
    "FG-AV-003": "4.2.4",                           # AI/heuristic
    "FG-AV-004": "4.2.5",                           # grayware
    # 4.3 DNS Filter
    "FG-DNS-001": "4.3.1", "FG-DNS-002": "4.3.2", "FG-DNS-003": "4.3.3",
    # 4.4 Application Control
    "FG-APP-001": "4.4.1", "FG-APP-002": "4.4.2", "FG-APP-003": "4.4.3", "FG-APP-004": "4.4.4",
    # 5 Security Fabric
    "FG-FAB-001": "5.1.1", "FG-FAB-002": "5.2.1.1",
    # 6 VPN
    "FG-VPN-SSL-003": "6.1.1", "FG-VPN-SSL-001": "6.1.2",
    # 7 Users and Authentication
    "FG-USER-001": "7.1",
    # 8 Logs and Reports
    "FG-BL-065": "8.1.1", "FG-LOG-001": "8.1.1",
    "FG-LOG-002": "8.2.1",
    "FG-BL-060": "8.3.1", "FG-BL-061": "8.3.1", "FG-FAZ-001": "8.3.1",
}



# Control Catalog


def get_fortinet_controls() -> List[FortiGateControl]:
    """
    Returns all 65+ FortiGate security controls.

    Organized into packs:
    - BASELINE: Core security controls (~45 checks)
    - HA: High Availability (4 checks)
    - SDWAN: SD-WAN configuration (2 checks)
    - VPN_SSL: SSL-VPN security (2 checks)
    - VPN_IPSEC: IPsec VPN security (2 checks)
    - CENTRAL_NAT: NAT configuration (1 check)
    - LOCAL_IN: Management access control (1 check)
    - EXPOSURE: WAN/VIP exposure (2 checks)
    - UTM: Security profiles (4 checks)
    - FAZ: FortiAnalyzer logging (2 checks)
    """
    # Command shortcuts
    SG = "show system global"
    SP = "show system password-policy"
    SA = "show system admin"
    NTP = "show system ntp"
    DNS = "show system dns"
    IFACE = "show system interface"
    SYSLOG = "show log syslogd setting"
    LOGSET = "show log setting"
    SNMPC = "show system snmp community"
    SNMPU = "show system snmp user"
    SNMPH = "show system snmp sysinfo"
    AUTO = "show system auto-script"
    FCT = "show system central-management"
    FGT = "get system status"
    POL = "show firewall policy"
    LOCALIN = "show firewall local-in-policy"
    VIP = "show firewall vip"
    CNAT = "show firewall central-snat-map"
    HA_S = "get system ha status"
    HA_C = "show system ha"
    SDWAN_NEW = "show system sdwan"
    SDWAN_OLD = "show system virtual-wan-link"
    SSL = "show vpn ssl settings"
    IPSEC = "show vpn ipsec phase1-interface"
    FAZ = "show log fortianalyzer setting"
    SETTINGS = "show system settings"

    controls: List[FortiGateControl] = []

    # BASELINE PACK (Enhanced) 
    controls += [
        # Management Plane Security
        # FortiOS "show" omits settings at their default value. "admin-https enable" is the
        # default, so it never appears in "show system global" output. Check for the absence
        # of "set admin-https disable" instead — if that line is missing, HTTPS is enabled.
        _mk_re_abs("FG-BL-001", "Admin HTTPS enabled", "BASELINE", "Management Plane", "High", "L1", SG,
                    r"set\s+admin-https\s+disable",
                    "config system global\\n set admin-https enable\\nend",
                    cis={"id": "1.1.1", "section": "Management Access", "profile": "L1"}, tags=["mgmt", "cis"]),
        _mk_set_bool("FG-BL-002", "Admin HTTP disabled", "BASELINE", "Management Plane", "Critical", "L1", SG, "admin-http", False,
                    "config system global\\n set admin-http disable\\nend",
                    cis={"id": "1.1.2", "section": "Management Access", "profile": "L1"}, tags=["mgmt", "cis"]),
        _mk_set_bool("FG-BL-003", "Admin Telnet disabled", "BASELINE", "Management Plane", "Critical", "L1", SG, "admin-telnet", False,
                    "config system global\\n set admin-telnet disable\\nend",
                    cis={"id": "1.1.3", "section": "Management Access", "profile": "L1"}, tags=["mgmt", "cis"]),
        _mk_int_le("FG-BL-004", "Admin idle timeout <= 10 minutes", "BASELINE", "Management Plane", "Medium", "L1", SG, "admintimeout", 10,
                  "config system global\\n set admintimeout 10\\nend",
                  cis={"id": "1.2.1", "section": "Session Management", "profile": "L1"}, tags=["mgmt", "session"]),
        _mk_re_abs("FG-BL-005", "Admin GUI TLS 1.0/1.1 disabled", "BASELINE", "Management Plane", "High", "L2", SG,
                   r"set\s+(admin-https-ssl-versions|admin-ssl-min-proto-version)\s+.*\b(tlsv1-0|tlsv1-1)\b",
                   "config system global\\n set admin-https-ssl-versions tlsv1-2 tlsv1-3\\nend",
                   cis={"id": "1.3.1", "section": "Cryptography", "profile": "L1"}, tags=["tls", "mgmt", "cis"]),

        # Strong Ciphers
        _mk_re_abs("FG-BL-006", "Weak SSH ciphers disabled", "BASELINE", "Management Plane", "High", "L2", SG,
                   r"set\s+ssh-enc-algo\s+.*\b(des|3des|arcfour|rc4)\b",
                   "config system global\\n set ssh-enc-algo aes256-ctr aes192-ctr aes128-ctr\\nend",
                   cis={"id": "1.3.2", "section": "Cryptography", "profile": "L2"}, tags=["ssh", "crypto"]),

        # Management Port Restrictions
        _mk_int_le("FG-BL-007", "Admin sport restricted (not default 443)", "BASELINE", "Management Plane", "Medium", "L2", SG, "admin-sport", 10443,
                  "config system global\\n set admin-sport 10443\\nend", tags=["mgmt", "hardening"]),
        _mk_set_bool("FG-BL-008", "Admin SSH enabled for CLI access", "BASELINE", "Management Plane", "Low", "L1", SG, "admin-ssh", True,
                    "config system global\\n set admin-ssh enable\\nend", tags=["mgmt"]),

        # Inventory
        _mk_re_pre("FG-BL-010", "System status readable", "BASELINE", "Inventory", "Low", "L1", FGT, r"^\s*Version:",
                  "Ensure operator can read system status", tags=["inventory"]),

        # Identity & Access Management
        _mk_re_pre("FG-BL-020", "Admin trusthost configured", "BASELINE", "Identity & Access", "High", "L1", SA,
                  r"set\s+trusthost[1-9]\s+(?!0\.0\.0\.0\s+0\.0\.0\.0)",
                  "config system admin\\n edit <admin>\\n set trusthost1 <mgmt-subnet> <netmask>\\nend",
                  cis={"id": "2.1.1", "section": "Access Control", "profile": "L1"}, tags=["iam", "cis"]),
        _mk_re_abs("FG-BL-021", "Default 'admin' account disabled/renamed", "BASELINE", "Identity & Access", "High", "L2", SA,
                  r'^\s*edit\s+"?admin"?\s*$',
                  "Disable or rename default admin account; use named accounts with proper roles",
                  cis={"id": "2.1.2", "section": "Access Control", "profile": "L2"}, tags=["iam", "cis"]),
        _mk_re_pre("FG-BL-022", "Multi-factor authentication configured", "BASELINE", "Identity & Access", "High", "L2", SA,
                  r"set\s+two-factor\s+(fortitoken|email|sms)",
                  "config system admin\\n edit <admin>\\n set two-factor fortitoken\\nend",
                  cis={"id": "2.2.1", "section": "Authentication", "profile": "L2"}, tags=["iam", "mfa"]),

        # Password Policy
        _mk_set_bool("FG-BL-030", "Password policy enabled", "BASELINE", "Identity & Access", "High", "L1", SP, "status", True,
                    "config system password-policy\\n set status enable\\nend",
                    cis={"id": "2.3.1", "section": "Password Policy", "profile": "L1"}, tags=["password", "cis"]),
        _mk_int_ge("FG-BL-031", "Password min length >= 12", "BASELINE", "Identity & Access", "High", "L1", SP, "minimum-length", 12,
                  "config system password-policy\\n set minimum-length 12\\nend",
                  cis={"id": "2.3.2", "section": "Password Policy", "profile": "L1"}, tags=["password", "cis"]),
        _mk_set_bool("FG-BL-032", "Password must contain uppercase", "BASELINE", "Identity & Access", "Medium", "L1", SP, "must-contain-uppercase", True,
                    "config system password-policy\\n set must-contain-uppercase enable\\nend",
                    cis={"id": "2.3.3", "section": "Password Policy", "profile": "L1"}, tags=["password"]),
        _mk_set_bool("FG-BL-033", "Password must contain lowercase", "BASELINE", "Identity & Access", "Medium", "L1", SP, "must-contain-lowercase", True,
                    "config system password-policy\\n set must-contain-lowercase enable\\nend",
                    cis={"id": "2.3.4", "section": "Password Policy", "profile": "L1"}, tags=["password"]),
        _mk_set_bool("FG-BL-034", "Password must contain numbers", "BASELINE", "Identity & Access", "Medium", "L1", SP, "must-contain-number", True,
                    "config system password-policy\\n set must-contain-number enable\\nend",
                    cis={"id": "2.3.5", "section": "Password Policy", "profile": "L1"}, tags=["password"]),
        _mk_set_bool("FG-BL-035", "Password must contain special chars", "BASELINE", "Identity & Access", "Medium", "L1", SP, "must-contain-non-alphanumeric", True,
                    "config system password-policy\\n set must-contain-non-alphanumeric enable\\nend",
                    cis={"id": "2.3.6", "section": "Password Policy", "profile": "L1"}, tags=["password"]),
        _mk_int_ge("FG-BL-036", "Password min changed characters >= 4", "BASELINE", "Identity & Access", "Medium", "L2", SP, "min-changed-characters", 4,
                  "config system password-policy\\n set min-changed-characters 4\\nend",
                  cis={"id": "2.3.7", "section": "Password Policy", "profile": "L2"}, tags=["password"]),

        # Time & Sync
        _mk_set_bool("FG-BL-040", "NTP enabled", "BASELINE", "Time & Sync", "Medium", "L1", NTP, "status", True,
                    "config system ntp\\n set status enable\\nend",
                    cis={"id": "3.1.1", "section": "Time Services", "profile": "L1"}, tags=["ntp", "cis"]),
        _mk_re_pre("FG-BL-041", "NTP server configured", "BASELINE", "Time & Sync", "Medium", "L1", NTP,
                  r"config\s+ntpserver[\s\S]*?edit\s+\d+",
                  "config system ntp\\n config ntpserver\\n edit 1\\n set server <ntp-server>\\nend",
                  cis={"id": "3.1.2", "section": "Time Services", "profile": "L1"}, tags=["ntp", "cis"]),
        _mk_set_eq("FG-BL-042", "NTP sync interface specified", "BASELINE", "Time & Sync", "Low", "L2", NTP, "interface", "port1",
                  "config system ntp\\n set interface <mgmt-interface>\\nend", tags=["ntp"]),

        # DNS
        _mk_re_pre("FG-BL-043", "DNS primary configured", "BASELINE", "Network Services", "Low", "L1", DNS,
                  r"set\s+primary\s+\d+\.\d+\.\d+\.\d+",
                  "config system dns\\n set primary <dns-ip>\\nend", tags=["dns"]),
        _mk_re_pre("FG-BL-044", "DNS secondary configured", "BASELINE", "Network Services", "Low", "L1", DNS,
                  r"set\s+secondary\s+\d+\.\d+\.\d+\.\d+",
                  "config system dns\\n set secondary <dns-ip>\\nend", tags=["dns"]),

        # SNMP Security
        _mk_re_abs("FG-BL-050", "SNMPv2 community disabled", "BASELINE", "Network Services", "High", "L1", SNMPC,
                  r"^\s*edit\s+\d+\s*$",
                  "Remove SNMP v1/v2c communities; use SNMPv3 with auth-priv only",
                  cis={"id": "4.1.1", "section": "SNMP", "profile": "L1"}, tags=["snmp", "cis"]),
        _mk_re_pre("FG-BL-051", "SNMPv3 user exists", "BASELINE", "Network Services", "Medium", "L1", SNMPU,
                  r"^\s*edit\s+",
                  "config system snmp user\\n edit <user>\\n set security-level auth-priv\\nend",
                  cis={"id": "4.1.2", "section": "SNMP", "profile": "L1"}, tags=["snmp", "cis"]),
        _mk_re_pre("FG-BL-052", "SNMP contact/location set", "BASELINE", "Network Services", "Low", "L2", SNMPH,
                  r"set\s+(contact-info|location)\s+",
                  "config system snmp sysinfo\\n set contact-info <contact>\\n set location <location>\\nend",
                  tags=["snmp", "inventory"]),

        # Logging & Monitoring
        _mk_set_bool("FG-BL-060", "Remote syslog enabled", "BASELINE", "Logging & Monitoring", "High", "L1", SYSLOG, "status", True,
                    "config log syslogd setting\\n set status enable\\n set server <syslog-ip>\\nend",
                    cis={"id": "5.1.1", "section": "Logging", "profile": "L1"}, tags=["logging", "cis"]),
        _mk_re_pre("FG-BL-061", "Remote syslog server set", "BASELINE", "Logging & Monitoring", "High", "L1", SYSLOG,
                  r"set\s+server\s+\d+\.\d+\.\d+\.\d+",
                  "config log syslogd setting\\n set server <syslog-ip>\\nend",
                  cis={"id": "5.1.2", "section": "Logging", "profile": "L1"}, tags=["logging", "cis"]),
        _mk_set_eq("FG-BL-062", "Syslog facility set to local7", "BASELINE", "Logging & Monitoring", "Low", "L2", SYSLOG, "facility", "local7",
                  "config log syslogd setting\\n set facility local7\\nend", tags=["logging"]),
        _mk_re_pre("FG-BL-063", "Local disk logging enabled", "BASELINE", "Logging & Monitoring", "Medium", "L2", LOGSET,
                  r"set\s+local-disk-enable\s+enable",
                  "config log setting\\n set local-disk-enable enable\\nend", tags=["logging"]),

        # Event Logging
        _mk_set_bool("FG-BL-064", "Log invalid traffic enabled", "BASELINE", "Logging & Monitoring", "Medium", "L2", LOGSET, "log-invalid-packet", True,
                    "config log setting\\n set log-invalid-packet enable\\nend", tags=["logging"]),
        _mk_set_bool("FG-BL-065", "User event logging enabled", "BASELINE", "Logging & Monitoring", "Low", "L2", LOGSET, "user-event-logging", True,
                    "config log setting\\n set user-event-logging enable\\nend", tags=["logging"]),

        # Automation & Central Management
        _mk_re_abs("FG-BL-070", "Auto-script disabled (unless required)", "BASELINE", "Automation", "Low", "L2", AUTO,
                  r"set\s+status\s+enable",
                  "Review auto-scripts; disable unused: config system auto-script\\n edit <script>\\n set status disable\\nend",
                  tags=["automation"]),
        _mk_re_pre("FG-BL-071", "Central management reviewed", "BASELINE", "Management Plane", "Low", "L2", FCT,
                  r"config\s+system\s+central-management",
                  "Review FortiManager/FortiCloud integration settings", tags=["mgmt", "inventory"]),

        # Firewall Policy Best Practices
        _mk_re_abs("FG-BL-080", "No Any/Any/ALL ACCEPT policy", "BASELINE", "Firewall Policy", "Critical", "L1", POL,
                  r"set\s+srcaddr\s+all[\s\S]*?set\s+dstaddr\s+all[\s\S]*?set\s+service\s+ALL[\s\S]*?set\s+action\s+accept",
                  "Replace Any/Any/ALL accept policies with least-privilege rules",
                  cis={"id": "6.1.1", "section": "Firewall Policy", "profile": "L1"}, tags=["policy", "cis"]),
        _mk_re_pre("FG-BL-081", "Explicit deny rule at end of policy", "BASELINE", "Firewall Policy", "Medium", "L2", POL,
                  r"set\s+action\s+deny[\s\S]*?set\s+srcaddr\s+all[\s\S]*?set\s+dstaddr\s+all",
                  "Add explicit deny-all rule at end of policy table", tags=["policy"]),
        _mk_re_pre("FG-BL-082", "Policy logging enabled for critical rules", "BASELINE", "Firewall Policy", "Medium", "L1", POL,
                  r"set\s+logtraffic\s+(all|utm)",
                  "Enable logging on firewall policies: set logtraffic all",
                  cis={"id": "6.2.1", "section": "Policy Logging", "profile": "L1"}, tags=["policy", "logging"]),

        # Global Settings
        _mk_set_bool("FG-BL-090", "Strong encryption required", "BASELINE", "Cryptography", "High", "L1", SG, "strong-crypto", True,
                    "config system global\\n set strong-crypto enable\\nend",
                    cis={"id": "1.4.1", "section": "Cryptography", "profile": "L1"}, tags=["crypto", "cis"]),
        _mk_re_abs("FG-BL-091", "FGFM auto-update disabled (manual preferred)", "BASELINE", "System Updates", "Low", "L2", SG,
                  r"set\s+fgfm-auto-update\s+enable",
                  "config system global\\n set fgfm-auto-update disable\\nend (Manual update recommended for production)",
                  tags=["updates"]),
        _mk_set_bool("FG-BL-092", "Pre-login banner configured", "BASELINE", "Compliance", "Low", "L2", SG, "pre-login-banner", True,
                    "config system global\\n set pre-login-banner enable\\n set pre-login-banner-message <banner>\\nend",
                    tags=["compliance"]),

        # System Settings
        _mk_set_bool("FG-BL-093", "GUI display hostname enabled", "BASELINE", "Management Plane", "Low", "L2", SETTINGS, "gui-display-hostname", True,
                    "config system settings\\n set gui-display-hostname enable\\nend", tags=["mgmt", "usability"]),
    ]

    # WAN Interface Exposure Controls (Enhanced)
    exposure_protos = [
        ("http", "Critical"), ("https", "Critical"), ("ssh", "Critical"),
        ("telnet", "High"), ("snmp", "High"), ("fgfm", "High"),
        ("ping", "Medium"), ("fabric", "High")
    ]
    for proto, sev in exposure_protos:
        controls.append(_mk_re_abs(
            f"FG-BL-WAN-{proto.upper()}",
            f"Disallow {proto} on WAN allowaccess",
            "BASELINE", "Management Exposure", sev, "L1", IFACE,
            rf'edit\s+"?wan[^"]*"?[\s\S]*?set\s+allowaccess\s+.*\b{re.escape(proto)}\b',
            f"Remove {proto} from WAN interface allowaccess; use dedicated mgmt VLAN + local-in-policy",
            cis={"id": "7.1.1", "section": "Interface Security", "profile": "L1"},
            tags=["exposure", "wan", "cis"]
        ))

    # HA PACK 
    controls += [
        _mk_re_pre("FG-HA-001", "HA status readable", "HA", "High Availability", "Medium", "L1", HA_S,
                  r"(Mode:|mode:|Group:|group:|Master|Primary|role)",
                  "Verify HA configuration: get system ha status", tags=["ha"]),
        _mk_set_bool("FG-HA-002", "HA override disabled", "HA", "High Availability", "Low", "L2", HA_C, "override", False,
                    "config system ha\\n set override disable\\nend (Recommended for stable failover)", tags=["ha"]),
        _mk_re_pre("FG-HA-003", "HA heartbeat encryption enabled", "HA", "High Availability", "High", "L2", HA_C,
                  r"set\s+password\s+",
                  "config system ha\\n set password <strong-password>\\nend", tags=["ha", "crypto"]),
        _mk_set_eq("FG-HA-004", "HA mode configured (a-p or a-a)", "HA", "High Availability", "Low", "L1", HA_C, "mode", "a-p",
                  "config system ha\\n set mode a-p\\nend", tags=["ha"]),
    ]

    # SD-WAN PACK 
    controls += [
        _mk_re_pre("FG-SDW-001", "SD-WAN configuration present", "SDWAN", "SD-WAN", "Medium", "L1", SDWAN_OLD,
                  r"config\s+system\s+(virtual-wan-link|sdwan)",
                  "Review SD-WAN configuration for optimal routing", tags=["sdwan"]),
        _mk_re_pre("FG-SDW-002", "SD-WAN health-check configured", "SDWAN", "SD-WAN", "Medium", "L1", SDWAN_NEW,
                  r"config\s+health-check",
                  "config system sdwan\\n config health-check\\n edit <name>\\nend", tags=["sdwan"]),
    ]

    # VPN PACKS 
    controls += [
        _mk_re_abs("FG-VPN-SSL-001", "SSL-VPN TLS 1.0/1.1 disabled", "VPN_SSL", "VPN (SSL)", "High", "L2", SSL,
                  r"set\s+(ssl-min-proto-version|tls-min-version)\s+(tlsv1-0|tlsv1-1)",
                  "config vpn ssl settings\\n set ssl-min-proto-version tlsv1-2\\nend",
                  cis={"id": "8.1.1", "section": "VPN", "profile": "L1"}, tags=["vpn", "tls", "cis"]),
        _mk_re_abs("FG-VPN-SSL-002", "SSL-VPN weak ciphers disabled", "VPN_SSL", "VPN (SSL)", "High", "L2", SSL,
                  r"set\s+ssl-cipher-suites\s+.*\b(des|3des|rc4|md5)\b",
                  "Use only strong cipher suites in SSL-VPN settings", tags=["vpn", "crypto"]),

        _mk_re_abs("FG-VPN-IPSEC-001", "IPsec Phase1 weak proposals disabled", "VPN_IPSEC", "VPN (IPsec)", "High", "L2", IPSEC,
                  r"set\s+proposal\s+.*\b(des|3des|md5)\b",
                  "config vpn ipsec phase1-interface\\n edit <name>\\n set proposal aes256-sha256 aes256-sha512\\nend",
                  cis={"id": "8.2.1", "section": "VPN", "profile": "L1"}, tags=["vpn", "crypto", "cis"]),
        _mk_re_pre("FG-VPN-IPSEC-002", "IPsec DPD enabled", "VPN_IPSEC", "VPN (IPsec)", "Low", "L2", IPSEC,
                  r"set\s+dpd\s+enable",
                  "config vpn ipsec phase1-interface\\n edit <name>\\n set dpd enable\\nend", tags=["vpn"]),
    ]

    # ===== NAT & EXPOSURE PACKS =====
    controls += [
        _mk_re_pre("FG-CNAT-001", "Central SNAT map reviewed", "CENTRAL_NAT", "NAT", "Low", "L1", CNAT,
                  r"^\s*edit\s+\d+\s*$",
                  "Review central SNAT rules for proper NAT configuration", tags=["nat"]),

        _mk_re_pre("FG-LIP-001", "Local-in-policy rules configured", "LOCAL_IN", "Management Exposure", "Medium", "L2", LOCALIN,
                  r"^\s*edit\s+\d+\s*$",
                  "Implement local-in-policy to restrict management plane access",
                  cis={"id": "7.2.1", "section": "Management Security", "profile": "L2"}, tags=["local-in", "cis"]),

        _mk_re_pre("FG-EXP-001", "VIP objects reviewed", "EXPOSURE", "Exposure", "Medium", "L1", VIP,
                  r"^\s*edit\s+",
                  "Review VIP (virtual IP) exposure and port forwarding rules", tags=["vip", "exposure"]),
        _mk_re_abs("FG-EXP-002", "VIP extintf not 'any'", "EXPOSURE", "Exposure", "High", "L2", VIP,
                  r'set\s+extintf\s+"?any"?',
                  "Bind VIP to specific WAN interface, not 'any'", tags=["vip", "exposure"]),
    ]

    # UTM PACK 
    controls += [
        _mk_re_abs("FG-UTM-001", "WAN inbound UTM-status not disabled", "UTM", "Security Profiles", "High", "L2", POL,
                  r"set\s+srcintf\s+\"?wan[^\" ]*\"?[\s\S]*?set\s+action\s+accept[\s\S]*?set\s+utm-status\s+disable",
                  "Enable UTM profiles on WAN inbound accept policies",
                  cis={"id": "9.1.1", "section": "UTM", "profile": "L2"}, tags=["utm", "cis"]),
        _mk_re_pre("FG-UTM-002", "Antivirus profile in use", "UTM", "Security Profiles", "Medium", "L2", POL,
                  r"set\s+av-profile\s+",
                  "Apply AV profiles to policies: set av-profile <profile>", tags=["utm", "av"]),
        _mk_re_pre("FG-UTM-003", "IPS sensor in use", "UTM", "Security Profiles", "Medium", "L2", POL,
                  r"set\s+ips-sensor\s+",
                  "Apply IPS sensors to policies: set ips-sensor <sensor>", tags=["utm", "ips"]),
        _mk_re_pre("FG-UTM-004", "Web filter profile in use", "UTM", "Security Profiles", "Medium", "L2", POL,
                  r"set\s+webfilter-profile\s+",
                  "Apply web filter profiles to policies: set webfilter-profile <profile>", tags=["utm", "webfilter"]),
    ]

    # FAZ PACK 
    controls += [
        _mk_set_bool("FG-FAZ-001", "FortiAnalyzer logging enabled", "FAZ", "Logging & Monitoring", "Medium", "L1", FAZ, "status", True,
                    "config log fortianalyzer setting\\n set status enable\\n set server <faz-ip>\\nend", tags=["faz", "logging"]),
        _mk_re_pre("FG-FAZ-002", "FortiAnalyzer server configured", "FAZ", "Logging & Monitoring", "Medium", "L1", FAZ,
                  r"set\s+server\s+\d+\.\d+\.\d+\.\d+",
                  "config log fortianalyzer setting\\n set server <faz-ip>\\nend", tags=["faz", "logging"]),
    ]


    # CIS FORTIGATE BENCHMARK COVERAGE
    # New controls added to complete coverage of the official CIS FortiGate
    # Benchmark checklist. Section numbers are assigned centrally below in
    # _CIS_SECTION_BY_CONTROL. 'Manual' recommendations use _mk_manual and are
    # excluded from the compliance score (evidence-only).
    
    USB = "show system auto-install"
    AVSET = "show antivirus settings"
    AVPROF = "show antivirus profile"
    DNSF = "show dnsfilter profile"
    APPL = "show application list"
    CSF = "show system csf"
    STITCH = "show system automation-stitch"
    USRSET = "show user setting"
    EVENTF = "show log eventfilter"
    ZONE = "show system zone"
    PUSHUPD = "show system autoupdate push-update"

    controls += [
        # --- 1 Network Settings ---
        _mk_manual("FG-NET-001", "Intra-zone traffic is not always allowed", "BASELINE", "Network", "Medium", "L1",
                   ZONE, "config system zone\\n edit <zone>\\n set intrazone deny\\nend",
                   pattern=r"set\s+intrazone\s+\w+", tags=["network", "cis"]),

        # --- 2.1 General Settings ---
        _mk_re_pre("FG-SYS-001", "Post-Login Banner enabled", "BASELINE", "System", "Low", "L1", SG,
                   r"set\s+post-login-banner\s+enable",
                   "config system global\\n set post-login-banner enable\\nend", tags=["banner", "cis"]),
        _mk_manual("FG-SYS-002", "Timezone is properly configured", "BASELINE", "System", "Low", "L1", SG,
                   "config system global\\n set timezone <id>\\nend",
                   pattern=r"set\s+timezone\s+\S+", tags=["system", "cis"]),
        _mk_re_pre("FG-SYS-003", "Hostname is set", "BASELINE", "System", "Low", "L1", SG,
                   r"set\s+hostname\s+\S+",
                   "config system global\\n set hostname <name>\\nend", tags=["system", "cis"]),
        _mk_manual("FG-SYS-004", "Latest firmware is installed", "BASELINE", "System", "Medium", "L1", FGT,
                   "Review FortiGuard for the latest recommended firmware and upgrade.",
                   pattern=r"Version:\s*.+", tags=["firmware", "cis"]),
        _mk_re_pre("FG-SYS-005", "USB firmware/configuration auto-install disabled", "BASELINE", "System", "High", "L1", USB,
                   r"set\s+auto-install-config\s+disable",
                   "config system auto-install\\n set auto-install-config disable\\n set auto-install-image disable\\nend",
                   tags=["system", "cis"]),
        _mk_re_pre("FG-SYS-006", "Static keys for TLS disabled", "BASELINE", "Cryptography", "High", "L1", SG,
                   r"set\s+ssl-static-key-ciphers\s+disable",
                   "config system global\\n set ssl-static-key-ciphers disable\\nend", tags=["tls", "crypto", "cis"]),

        # --- 2.2 Password Policy ---
        _mk_re_pre("FG-PW-001", "Admin password retries and lockout time configured", "BASELINE", "Authentication", "Medium", "L1", SG,
                   r"set\s+admin-lockout-(threshold|duration)\s+\d+",
                   "config system global\\n set admin-lockout-threshold 3\\n set admin-lockout-duration 60\\nend",
                   tags=["password", "cis"]),

        # --- 2.3 SNMP ---
        _mk_manual("FG-SNMP-001", "Only trusted hosts allowed in SNMPv3", "BASELINE", "Management Plane", "Medium", "L1", SNMPU,
                   "config system snmp user\\n edit <name>\\n set notify-hosts <trusted-ip>\\nend",
                   pattern=r"set\s+(notify-hosts|ha-direct|security-level)\s+\S+", tags=["snmp", "cis"]),

        # --- 2.4 Administrators ---
        _mk_manual("FG-ADM-001", "Admin accounts have correct profiles assigned", "BASELINE", "Identity & Access", "Medium", "L1", SA,
                   "config system admin\\n edit <user>\\n set accprofile <profile>\\nend",
                   pattern=r"set\s+accprofile\s+\S+", tags=["iam", "cis"]),

        # --- 2.5 High Availability ---
        _mk_re_pre("FG-HA-005", "Monitor Interfaces for HA enabled", "HA", "High Availability", "Medium", "L1", HA_C,
                   r"set\s+monitor\s+\S+",
                   "config system ha\\n set monitor <port>\\nend", tags=["ha", "cis"]),
        _mk_manual("FG-HA-006", "HA Reserved Management Interface configured", "HA", "High Availability", "Low", "L1", HA_C,
                   "config system ha\\n set ha-mgmt-status enable\\n config ha-mgmt-interfaces ...\\nend",
                   pattern=r"set\s+ha-mgmt-(status|interface)\b", tags=["ha", "cis"]),

        # --- 3 Policy and Objects ---
        _mk_manual("FG-POL-001", "Unused policies are reviewed regularly", "BASELINE", "Firewall Policy", "Low", "L1", POL,
                   "Review hit counts and remove or disable unused firewall policies.",
                   pattern=r"edit\s+\d+", tags=["policy", "cis"]),
        _mk_manual("FG-POL-002", "Deny traffic to/from Tor, malicious or scanner IPs via ISDB", "BASELINE", "Firewall Policy", "Medium", "L1", POL,
                   "Create deny policies using Internet Service DB (Tor/Botnet/Scanner) objects.",
                   pattern=r"set\s+internet-service(-src)?(-name)?\s+\S+", tags=["policy", "cis"]),

        # --- 4.1 IPS ---
        _mk_manual("FG-IPS-001", "Detect Botnet connections", "UTM", "Security Profiles", "Medium", "L1", POL,
                   "On each policy: set scan-botnet-connections block.",
                   pattern=r"set\s+scan-botnet-connections\s+\w+", tags=["ips", "cis"]),

        # --- 4.2 Antivirus ---
        _mk_re_pre("FG-AV-001", "Antivirus definition push updates configured", "UTM", "Security Profiles", "Medium", "L1", PUSHUPD,
                   r"set\s+status\s+enable",
                   "config system autoupdate push-update\\n set status enable\\nend", tags=["antivirus", "cis"]),
        _mk_re_pre("FG-AV-002", "Outbreak Prevention database enabled", "UTM", "Security Profiles", "Medium", "L2", AVPROF,
                   r"outbreak-prevention\s+(block|monitor|enable)",
                   "config antivirus profile\\n edit <profile>\\n config http\\n set outbreak-prevention block\\nend",
                   tags=["antivirus", "cis"]),
        _mk_re_pre("FG-AV-003", "AI/heuristic based malware detection enabled", "UTM", "Security Profiles", "Medium", "L2", AVSET,
                   r"set\s+machine-learning-detection\s+enable",
                   "config antivirus settings\\n set machine-learning-detection enable\\nend", tags=["antivirus", "cis"]),
        _mk_re_abs("FG-AV-004", "Grayware detection enabled", "UTM", "Security Profiles", "Low", "L2", AVSET,
                   r"set\s+grayware\s+disable",
                   "config antivirus settings\\n set grayware enable\\nend", tags=["antivirus", "cis"]),

        # --- 4.3 DNS Filter ---
        _mk_re_pre("FG-DNS-001", "Botnet C&C domain blocking enabled in DNS Filter", "UTM", "Security Profiles", "High", "L1", DNSF,
                   r"set\s+block-botnet\s+enable",
                   "config dnsfilter profile\\n edit <profile>\\n set block-botnet enable\\nend", tags=["dnsfilter", "cis"]),
        _mk_manual("FG-DNS-002", "DNS Filter logs all DNS queries and responses", "UTM", "Security Profiles", "Low", "L1", DNSF,
                   "config dnsfilter profile\\n edit <profile>\\n set log-all-domain enable\\nend",
                   pattern=r"set\s+log-all-domain\s+\w+", tags=["dnsfilter", "cis"]),
        _mk_manual("FG-DNS-003", "DNS Filter security profile applied to policies", "UTM", "Security Profiles", "Medium", "L1", POL,
                   "Apply a DNS filter profile to relevant firewall policies.",
                   pattern=r"set\s+dnsfilter-profile\s+\S+", tags=["dnsfilter", "cis"]),

        # --- 4.4 Application Control ---
        _mk_manual("FG-APP-001", "Block high risk categories on Application Control", "UTM", "Security Profiles", "Medium", "L1", APPL,
                   "config application list\\n edit <list>\\n config entries\\n ... set action block (high risk)\\nend",
                   pattern=r"set\s+(category|risk|application)\s+\S+", tags=["appctrl", "cis"]),
        _mk_re_pre("FG-APP-002", "Block applications running on non-default ports", "UTM", "Security Profiles", "Medium", "L2", APPL,
                   r"set\s+enforce-default-app-port\s+enable",
                   "config application list\\n edit <list>\\n set enforce-default-app-port enable\\nend", tags=["appctrl", "cis"]),
        _mk_manual("FG-APP-003", "Application Control related traffic is logged", "UTM", "Security Profiles", "Low", "L1", APPL,
                   "config application list\\n edit <list>\\n set other-application-log enable\\nend",
                   pattern=r"set\s+(other-application-log|log)\s+\w+", tags=["appctrl", "cis"]),
        _mk_manual("FG-APP-004", "Application Control security profile applied to policies", "UTM", "Security Profiles", "Medium", "L1", POL,
                   "Apply an application-list profile to relevant firewall policies.",
                   pattern=r"set\s+application-list\s+\S+", tags=["appctrl", "cis"]),

        # --- 5 Security Fabric ---
        _mk_re_pre("FG-FAB-001", "Compromised Host Quarantine automation enabled", "BASELINE", "Security Fabric", "Medium", "L2", STITCH,
                   r"quarantine",
                   "Create an automation stitch with a 'Quarantine FortiClient via EMS' / quarantine action.",
                   tags=["fabric", "cis"]),
        _mk_re_pre("FG-FAB-002", "Security Fabric is configured", "BASELINE", "Security Fabric", "Medium", "L2", CSF,
                   r"set\s+status\s+enable",
                   "config system csf\\n set status enable\\n set group-name <name>\\nend", tags=["fabric", "cis"]),

        # --- 6 VPN ---
        _mk_manual("FG-VPN-SSL-003", "Trusted signed certificate applied for SSL-VPN portal", "VPN_SSL", "VPN", "High", "L1", SSL,
                   "config vpn ssl settings\\n set servercert <trusted-cert>\\nend",
                   pattern=r"set\s+servercert\s+\S+", tags=["vpn", "ssl", "cis"]),

        # --- 7 Users and Authentication ---
        _mk_re_pre("FG-USER-001", "Maximum login attempts and lockout period configured", "BASELINE", "Authentication", "Medium", "L1", USRSET,
                   r"set\s+auth-lockout-(threshold|duration)\s+\d+",
                   "config user setting\\n set auth-lockout-threshold 3\\n set auth-lockout-duration 60\\nend",
                   tags=["auth", "cis"]),

        # --- 8 Logs and Reports ---
        _mk_re_abs("FG-LOG-001", "Event logging enabled", "BASELINE", "Logging & Monitoring", "Medium", "L1", EVENTF,
                   r"set\s+event\s+disable",
                   "config log eventfilter\\n set event enable\\nend", tags=["logging", "cis"]),
        _mk_re_pre("FG-LOG-002", "Log transmission to FortiAnalyzer/FortiManager encrypted", "FAZ", "Logging & Monitoring", "Medium", "L1", FAZ,
                   r"set\s+(reliable\s+enable|enc-algorithm\s+(high|default))",
                   "config log fortianalyzer setting\\n set reliable enable\\n set enc-algorithm high\\nend", tags=["faz", "logging", "cis"]),
    ]

    # Assign official CIS FortiGate Benchmark section numbers from a single
    # source of truth so cis_id stays consistent across the catalog.
    for _c in controls:
        _sec = _CIS_SECTION_BY_CONTROL.get(_c.id)
        if _sec:
            _c.cis_id = _sec
            _c.cis_section = _CIS_SECTION_NAMES.get(_sec.split(".")[0], _c.cis_section)

    return controls


def get_controls_by_pack(pack: str) -> List[FortiGateControl]:
    """Filter controls by pack name"""
    return [c for c in get_fortinet_controls() if c.pack == pack]


def get_controls_by_level(level: str) -> List[FortiGateControl]:
    """Filter controls by CIS level (L1 or L2)"""
    return [c for c in get_fortinet_controls() if c.level == level]


def get_all_packs() -> List[str]:
    """Get list of all control packs"""
    return [
        "BASELINE", "HA", "SDWAN", "VPN_SSL", "VPN_IPSEC",
        "CENTRAL_NAT", "LOCAL_IN", "EXPOSURE", "UTM", "FAZ"
    ]


def get_unique_commands(controls: List[FortiGateControl]) -> List[str]:
    """Extract unique commands from controls"""
    seen = set()
    commands = []
    for control in controls:
        for rule in control.rules:
            if rule.cmd not in seen:
                seen.add(rule.cmd)
                commands.append(rule.cmd)
    return commands
