# بر اساس فایل بنچمارک CIS CISCO
"""
Cisco IOS/IOS-XE CIS Benchmark Rules

This module contains ~50+ predefined CIS security checks for Cisco devices.
Each rule includes:
- Unique ID (e.g., IOS-L1-001)
- Title and description
- Severity level (high/medium/low/info)
- Level (L1/L2/INFO)
- Check function (returns True if compliant)
- Evidence extraction function
- Rationale and remediation guidance

Based on CIS Cisco IOS Benchmark guidelines.
"""

import re
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass


# ========================= COMPILED REGEX PATTERNS =========================

class CiscoRegex:
    """Pre-compiled regex patterns for efficient matching."""

    # Enable/Privilege
    enable_secret = re.compile(r"^enable secret\s+\S+", re.M)
    enable_password = re.compile(r"^enable password\s+\S+", re.M)

    # VTY/Console
    vty_header = re.compile(r"^line vty.*", re.M)
    console_block = re.compile(r"^line console 0[\s\S]*?(?=^!|^line|\Z)", re.M)
    transport_ssh = re.compile(r"^\s*transport input\s+.*\bssh\b", re.M)
    transport_telnet = re.compile(r"^\s*transport input\s+.*\btelnet\b", re.M)
    access_class_in = re.compile(r"^\s*access-class\s+\S+\s+in", re.M)
    login_method = re.compile(r"^\s*(login local|login authentication\s+\S+)", re.M)
    exec_timeout_line = re.compile(r"^\s*exec-timeout\s+(\d+)\s+(\d+)", re.M)

    # Banners
    banner_motd = re.compile(r"^banner motd", re.M)
    banner_login = re.compile(r"^banner login", re.M)

    # SSH
    ssh_v2 = re.compile(r"^ip ssh version 2", re.M)
    ssh_timeout = re.compile(r"^ip ssh timeout\s+(\d+)", re.M)
    ssh_retries = re.compile(r"^ip ssh authentication-retries\s+(\d+)", re.M)
    ssh_algo_line = re.compile(r"^ip ssh server algorithm .*$", re.M)
    ssh_key_bits = re.compile(r"\b(\d{3,4})\s*bit\b", re.I)

    # Services
    svc_pwd_enc = re.compile(r"^service password-encryption", re.M)
    ip_http_any = re.compile(r"^ip http (?:server|secure-server)", re.M)

    # AAA
    aaa_new_model = re.compile(r"^aaa new-model", re.M)
    aaa_auth_login = re.compile(r"^aaa authentication login\s+\S+", re.M)
    aaa_acc_cmd15 = re.compile(r"^aaa accounting commands 15\s+", re.M)

    # Login controls
    login_block_for = re.compile(r"^login block-for\s+\d+\s+attempts\s+\d+\s+within\s+\d+", re.M)
    login_log_any = re.compile(r"^login on-(?:failure|success)\s+log", re.M)

    # Logging
    logging_host = re.compile(r"^logging host\s+\S+", re.M)
    logging_any = re.compile(r"^logging .+", re.M)
    logging_buffered = re.compile(r"^logging buffered\s+\d+(?:\s+\S+)?", re.M)
    logging_trap = re.compile(r"^logging trap\s+\S+", re.M)
    timestamps = re.compile(r"^service timestamps log datetime.*", re.M)
    archive_block = re.compile(r"^archive\b[\s\S]*?(?=^\S|\Z)", re.M)

    # SNMP
    snmp_any = re.compile(r"^snmp-server .+", re.M)
    snmp_v3_group = re.compile(r"^snmp-server group .* v3 ", re.M)
    snmp_v2c_bare = re.compile(r"^snmp-server community\s+\S+\s+(RO|RW)\s*$", re.M)
    snmp_v2c_has_extra = re.compile(r"^snmp-server community\s+\S+\s+(RO|RW)\s+\S+", re.M)

    # Users
    username_password = re.compile(r"^username\s+\S+\s+password\s+\S+", re.M)

    # NTP
    ntp_server = re.compile(r"^ntp server\s+\S+", re.M)
    ntp_auth = re.compile(r"^ntp authenticate", re.M)
    ntp_auth_key = re.compile(r"^ntp authentication-key\s+\d+\s+md5\s+\S+", re.M)
    clock_tz = re.compile(r"^clock timezone\s+\S+", re.M)

    # L2/L3
    cdp_any = re.compile(r"^(?:no )?cdp run", re.M)
    lldp_any = re.compile(r"^(?:no )?lldp run", re.M)
    no_directed_brdcst = re.compile(r"^no ip directed-broadcast", re.M)
    no_source_route = re.compile(r"^no ip source-route", re.M)

    # Interfaces
    if_acl_in = re.compile(r"^\s*ip access-group\s+\S+\s+in", re.M)
    if_no_proxy_arp = re.compile(r"^\s*no ip proxy-arp", re.M)

    # Identity
    hostname = re.compile(r"^hostname\s+\S+", re.M)
    domain_name = re.compile(r"^ip domain-name\s+\S+", re.M)
    no_domain_lookup = re.compile(r"^no ip domain-lookup", re.M)

    # Boot/Version
    conf_reg = re.compile(r"Configuration register is ([0-9a-fx]+)", re.I)
    secure_boot = re.compile(r"^secure boot-(image|config)", re.M)

    # Additional AAA patterns
    aaa_auth_enable = re.compile(r"^aaa authentication enable default", re.M)
    aaa_acc_connection = re.compile(r"^aaa accounting connection\s+", re.M)
    aaa_acc_exec = re.compile(r"^aaa accounting exec\s+", re.M)
    aaa_acc_network = re.compile(r"^aaa accounting network\s+", re.M)
    aaa_acc_system = re.compile(r"^aaa accounting system\s+", re.M)

    # Line patterns
    line_con = re.compile(r"^line con(?:sole)?\s+0[\s\S]*?(?=^line|\Z)", re.M)
    line_tty = re.compile(r"^line tty\s+\d+[\s\S]*?(?=^line|\Z)", re.M)
    login_authentication = re.compile(r"^\s*login authentication\s+\S+", re.M)

    # User patterns
    username_priv = re.compile(r"^username\s+\S+\s+privilege\s+(\d+)", re.M)
    username_secret = re.compile(r"^username\s+\S+\s+secret\s+\S+", re.M)

    # Banner patterns
    banner_exec = re.compile(r"^banner exec", re.M)

    # SNMP patterns
    snmp_community_private = re.compile(r"^snmp-server community\s+private\b", re.M)
    snmp_community_public = re.compile(r"^snmp-server community\s+public\b", re.M)
    snmp_community_rw = re.compile(r"^snmp-server community\s+\S+\s+RW\b", re.M)
    snmp_community_acl = re.compile(r"^snmp-server community\s+\S+\s+(?:RO|RW)\s+\S+", re.M)
    snmp_host = re.compile(r"^snmp-server host\s+\S+", re.M)
    snmp_traps = re.compile(r"^snmp-server enable traps\s+snmp", re.M)
    snmp_v3_priv = re.compile(r"^snmp-server group\s+\S+\s+v3\s+priv", re.M)
    snmp_user_aes = re.compile(r"^snmp-server user\s+\S+.*\s+aes\s*(128|192|256)", re.M)

    # Service patterns
    no_cdp_run = re.compile(r"^no cdp run", re.M)
    no_bootp = re.compile(r"^no ip bootp server", re.M)
    no_dhcp = re.compile(r"^no service dhcp", re.M)
    no_identd = re.compile(r"^no ip identd", re.M)
    tcp_keepalives_in = re.compile(r"^service tcp-keepalives-in", re.M)
    no_service_pad = re.compile(r"^no service pad", re.M)

    # Logging patterns
    logging_on = re.compile(r"^logging on", re.M)
    logging_console = re.compile(r"^logging console\s+\S+", re.M)
    logging_source_if = re.compile(r"^logging source-interface\s+\S+", re.M)
    timestamps_debug = re.compile(r"^service timestamps debug datetime", re.M)

    # NTP patterns
    ntp_trusted_key = re.compile(r"^ntp trusted-key\s+\d+", re.M)
    ntp_server_key = re.compile(r"^ntp server\s+\S+\s+key\s+\d+", re.M)
    ntp_source = re.compile(r"^ntp source\s+\S+", re.M)

    # Loopback patterns
    interface_loopback = re.compile(r"^interface [Ll]oopback\d+", re.M)
    aaa_source_interface = re.compile(r"^ip (?:radius|tacacs)\s+source-interface\s+\S+", re.M)
    tftp_source_interface = re.compile(r"^ip tftp source-interface\s+\S+", re.M)

    # Aux line patterns
    line_aux = re.compile(r"^line aux\s+0[\s\S]*?(?=^line|\Z)", re.M)
    no_exec = re.compile(r"^\s*no exec\b", re.M)
    transport_input_none = re.compile(r"^\s*transport input\s+none", re.M)
    tcp_keepalives_out = re.compile(r"^service tcp-keepalives-out", re.M)

    # IP hardening patterns
    interface_tunnel = re.compile(r"^interface [Tt]unnel\d+", re.M)
    ip_verify_unicast = re.compile(r"^\s*ip verify unicast source reachable-via", re.M)

    # Access list patterns
    ip_access_list_ext = re.compile(r"^ip access-list extended\s+\S+", re.M)
    ip_access_group_in = re.compile(r"^\s*ip access-group\s+\S+\s+in", re.M)

    # Routing authentication patterns
    key_chain = re.compile(r"^key chain\s+\S+", re.M)
    key_block = re.compile(r"^key chain\s+\S+[\s\S]*?(?=^!|\Z)", re.M)
    key_id = re.compile(r"^\s*key\s+\d+", re.M)
    key_string = re.compile(r"^\s*key-string\s+\S+", re.M)

    # EIGRP patterns
    router_eigrp = re.compile(r"^router eigrp\s+\S+", re.M)
    eigrp_af_ipv4 = re.compile(r"^\s*address-family ipv4 autonomous-system", re.M)
    eigrp_af_interface = re.compile(r"^\s*af-interface default", re.M)
    eigrp_auth_keychain = re.compile(r"^\s*authentication key-chain\s+\S+", re.M)
    eigrp_auth_mode_md5 = re.compile(r"^\s*authentication mode md5", re.M)
    ip_auth_keychain_eigrp = re.compile(r"^\s*ip authentication key-chain eigrp", re.M)
    ip_auth_mode_eigrp = re.compile(r"^\s*ip authentication mode eigrp\s+\S+\s+md5", re.M)

    # OSPF patterns
    router_ospf = re.compile(r"^router ospf\s+\d+", re.M)
    ospf_auth_md = re.compile(r"^\s*area\s+\S+\s+authentication message-digest", re.M)
    ip_ospf_md_key = re.compile(r"^\s*ip ospf message-digest-key\s+\d+\s+md5", re.M)

    # RIP patterns
    router_rip = re.compile(r"^router rip", re.M)
    ip_rip_auth_keychain = re.compile(r"^\s*ip rip authentication key-chain", re.M)
    ip_rip_auth_mode_md5 = re.compile(r"^\s*ip rip authentication mode md5", re.M)

    # BGP patterns
    router_bgp = re.compile(r"^router bgp\s+\d+", re.M)
    bgp_neighbor_password = re.compile(r"^\s*neighbor\s+\S+\s+password", re.M)


RE = CiscoRegex()


# ========================= HELPER FUNCTIONS =========================

def _iter_blocks(text: str, header_re: re.Pattern) -> List[str]:
    """Extract configuration blocks based on header pattern."""
    blocks = []
    matches = list(header_re.finditer(text))
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i+1].start() if i+1 < len(matches) else len(text)
        blocks.append(text[start:end])
    return blocks


def _vty_blocks(text: str) -> List[str]:
    """Extract all VTY line blocks."""
    return _iter_blocks(text, RE.vty_header)


def _console_block(text: str) -> Optional[str]:
    """Extract console line block."""
    m = RE.console_block.search(text)
    return m.group(0) if m else None


def _has_exec_timeout_configured(block: str) -> bool:
    """Check if exec-timeout is configured (not 0 0)."""
    m = RE.exec_timeout_line.search(block)
    if not m:
        return False
    mins = int(m.group(1))
    secs = int(m.group(2))
    return not (mins == 0 and secs == 0)


def _extract_ssh_key_bits(text: str) -> Optional[int]:
    """Extract SSH RSA key size from show ip ssh output."""
    bits = [int(m.group(1)) for m in RE.ssh_key_bits.finditer(text)]
    if not bits:
        return None
    # Filter valid key sizes
    bits = [b for b in bits if 512 <= b <= 8192]
    return max(bits) if bits else None


# ========================= RULE DATACLASS =========================

@dataclass
class CISRule:
    """Represents a single CIS compliance check."""

    id: str                          # "IOS-L1-001"
    title: str                       # Short description
    severity: str                    # high/medium/low/info
    level: str                       # L1/L2/INFO
    rationale: str                   # Why this matters
    remediation: str                 # How to fix
    check: Callable[[str], bool]     # Function: returns True if compliant
    evidence: Callable[[str], str]   # Function: returns evidence text


# ========================= SEVERITY WEIGHTS =========================

SEVERITY_WEIGHT = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0  # INFO rules don't affect compliance score
}


# ========================= RULE DEFINITIONS =========================

def build_all_cisco_cis_rules() -> List[CISRule]:
    """
    Build complete set of Cisco CIS compliance rules.

    Returns:
        List[CISRule]: All CIS rules for Cisco IOS/IOS-XE
    """
    rules: List[CISRule] = []

    # ==================== IDENTITY & DNS ====================

    rules.append(CISRule(
        id="IOS-L1-0010",
        title="Hostname configured",
        severity="low",
        level="L1",
        rationale="Identify the device in logs and management systems.",
        remediation="Configure: hostname <NAME>",
        check=lambda c: bool(RE.hostname.search(c)),
        evidence=lambda c: RE.hostname.search(c).group(0) if RE.hostname.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0011",
        title="IP domain-name configured",
        severity="low",
        level="L1",
        rationale="Required for SSH key generation and FQDN services.",
        remediation="Configure: ip domain-name <DOMAIN>",
        check=lambda c: bool(RE.domain_name.search(c)),
        evidence=lambda c: RE.domain_name.search(c).group(0) if RE.domain_name.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0012",
        title="DNS lookup disabled in exec mode",
        severity="low",
        level="L1",
        rationale="Prevent unwanted DNS lookups that slow down CLI.",
        remediation="Configure: no ip domain-lookup",
        check=lambda c: bool(RE.no_domain_lookup.search(c)),
        evidence=lambda c: RE.no_domain_lookup.search(c).group(0) if RE.no_domain_lookup.search(c) else "not present"
    ))

    # ==================== ENABLE SECRET ====================

    rules.append(CISRule(
        id="IOS-L1-001",
        title="Use 'enable secret' only (no 'enable password')",
        severity="high",
        level="L1",
        rationale="Enable secret uses strong hashing (SHA-256) vs weak Type 7 encryption.",
        remediation="Remove 'enable password' and configure 'enable secret <STRONG_SECRET>'",
        check=lambda c: bool(RE.enable_secret.search(c)) and not bool(RE.enable_password.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^enable (secret|password).*$", c, re.M)]) or "not set"
    ))

    # ==================== VTY & CONSOLE ====================

    rules.append(CISRule(
        id="IOS-L1-002",
        title="Console & VTY exec-timeout configured (not 0 0)",
        severity="medium",
        level="L1",
        rationale="Prevent abandoned sessions from remaining logged in.",
        remediation="Configure 'exec-timeout 5 0' (or policy value) on console and all VTYs",
        check=lambda c: (
            (lambda blks: bool(blks) and all(_has_exec_timeout_configured(b) for b in blks))(_vty_blocks(c))
            and (lambda cb: (cb is None) or _has_exec_timeout_configured(cb))(_console_block(c))
        ),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^line (?:vty|console).*|^\s+exec-timeout .*$", c, re.M)])
    ))

    rules.append(CISRule(
        id="IOS-L1-003",
        title="VTY restricted by access-class",
        severity="high",
        level="L1",
        rationale="Restrict management access to authorized networks/hosts only.",
        remediation="Configure 'access-class <ACL> in' on all VTY lines",
        check=lambda c: (lambda blks: bool(blks) and all(bool(RE.access_class_in.search(b)) for b in blks))(_vty_blocks(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^line vty .*|^\s+access-class .*", c, re.M)])
    ))

    rules.append(CISRule(
        id="IOS-L1-004",
        title="Explicit login method on VTY (AAA or login local)",
        severity="high",
        level="L1",
        rationale="Define authentication explicitly to prevent default/weak login.",
        remediation="Configure 'login local' or 'login authentication <AAA_LIST>' on all VTYs",
        check=lambda c: (lambda blks: bool(blks) and all(bool(RE.login_method.search(b)) for b in blks))(_vty_blocks(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^line vty .*|^\s+login.*", c, re.M)])
    ))

    rules.append(CISRule(
        id="IOS-L1-005",
        title="MOTD banner configured",
        severity="low",
        level="L1",
        rationale="Display legal notice/warning to users.",
        remediation="Configure: banner motd ^C Authorized access only ^C",
        check=lambda c: bool(RE.banner_motd.search(c)),
        evidence=lambda c: RE.banner_motd.search(c).group(0) if RE.banner_motd.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0051",
        title="Login banner configured",
        severity="low",
        level="L1",
        rationale="Display legal notice/warning before login.",
        remediation="Configure: banner login ^C Authorized access only ^C",
        check=lambda c: bool(RE.banner_login.search(c)),
        evidence=lambda c: RE.banner_login.search(c).group(0) if RE.banner_login.search(c) else "not set"
    ))

    # ==================== SSH HARDENING ====================

    rules.append(CISRule(
        id="IOS-L1-010",
        title="Telnet disabled; SSH only on VTY",
        severity="high",
        level="L1",
        rationale="Telnet transmits credentials in cleartext. SSH provides encryption.",
        remediation="Configure 'transport input ssh' and remove telnet from all VTYs",
        check=lambda c: (lambda blks: bool(blks) and all(RE.transport_ssh.search(b) and not RE.transport_telnet.search(b) for b in blks))(_vty_blocks(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^line vty .*|^\s+transport input .*", c, re.M)])
    ))

    rules.append(CISRule(
        id="IOS-L1-011",
        title="SSH version 2 enforced",
        severity="high",
        level="L1",
        rationale="SSHv1 has known cryptographic vulnerabilities.",
        remediation="Configure: ip ssh version 2",
        check=lambda c: bool(RE.ssh_v2.search(c)),
        evidence=lambda c: RE.ssh_v2.search(c).group(0) if RE.ssh_v2.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0112",
        title="SSH timeout configured (5-120 seconds)",
        severity="medium",
        level="L1",
        rationale="Reduce exposure window for SSH connections.",
        remediation="Configure: ip ssh timeout 60",
        check=lambda c: (m:=RE.ssh_timeout.search(c)) is not None and 5 <= int(m.group(1)) <= 120,
        evidence=lambda c: RE.ssh_timeout.search(c).group(0) if RE.ssh_timeout.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0113",
        title="SSH auth-retries configured (1-3)",
        severity="medium",
        level="L1",
        rationale="Limit brute-force authentication attempts.",
        remediation="Configure: ip ssh authentication-retries 2",
        check=lambda c: (m:=RE.ssh_retries.search(c)) is not None and 1 <= int(m.group(1)) <= 3,
        evidence=lambda c: RE.ssh_retries.search(c).group(0) if RE.ssh_retries.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L2-0114",
        title="Avoid weak SSH ciphers/MACs (best-effort)",
        severity="medium",
        level="L2",
        rationale="Legacy ciphers (3DES, CBC mode) have known weaknesses.",
        remediation="Configure modern algorithms (aes256-ctr, hmac-sha2-256) where supported",
        check=lambda c: not bool(re.search(r"ip ssh server algorithm .* (3des|cbc)\b", c, re.I)),
        evidence=lambda c: "\n".join([m.group(0) for m in RE.ssh_algo_line.finditer(c)]) or "no explicit algo lines"
    ))

    rules.append(CISRule(
        id="IOS-L1-0120",
        title="SSH/RSA key size >= 2048 bits (best-effort)",
        severity="high",
        level="L1",
        rationale="Smaller key sizes are vulnerable to modern attacks.",
        remediation="Generate: crypto key generate rsa modulus 2048",
        check=lambda c: (bits := _extract_ssh_key_bits(c)) is not None and bits >= 2048,
        evidence=lambda c: f"Detected key size: {_extract_ssh_key_bits(c) or 'unknown'} bit\n" +
                          ("\n".join([m.group(0) for m in re.finditer(r"^!! show ip ssh[\s\S]*?(?=^!!|\Z)", c, re.M)])[:800] or "show ip ssh not found")
    ))

    # ==================== LOGIN CONTROLS ====================

    rules.append(CISRule(
        id="IOS-L1-0130",
        title="Login block-for configured",
        severity="medium",
        level="L1",
        rationale="Slow down brute-force login attempts.",
        remediation="Configure: login block-for 120 attempts 3 within 60",
        check=lambda c: bool(RE.login_block_for.search(c)),
        evidence=lambda c: RE.login_block_for.search(c).group(0) if RE.login_block_for.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0131",
        title="Login on-failure/on-success logging",
        severity="low",
        level="L1",
        rationale="Track successful and failed login attempts.",
        remediation="Configure: login on-failure log, login on-success log",
        check=lambda c: bool(RE.login_log_any.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^login on-(?:failure|success)\s+log.*$", c, re.M)]) or "not set"
    ))

    # ==================== AAA ====================

    rules.append(CISRule(
        id="IOS-L1-020",
        title="AAA new-model enabled",
        severity="high",
        level="L1",
        rationale="Enable centralized authentication, authorization, and accounting.",
        remediation="Configure: aaa new-model",
        check=lambda c: bool(RE.aaa_new_model.search(c)),
        evidence=lambda c: RE.aaa_new_model.search(c).group(0) if RE.aaa_new_model.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-021",
        title="AAA authentication for login defined",
        severity="high",
        level="L1",
        rationale="Define centralized authentication method.",
        remediation="Configure: aaa authentication login default group radius local",
        check=lambda c: bool(RE.aaa_auth_login.search(c)),
        evidence=lambda c: RE.aaa_auth_login.search(c).group(0) if RE.aaa_auth_login.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-022",
        title="AAA accounting commands 15 configured",
        severity="medium",
        level="L1",
        rationale="Track privileged command execution for auditing.",
        remediation="Configure: aaa accounting commands 15 default start-stop group tacacs+",
        check=lambda c: bool(RE.aaa_acc_cmd15.search(c)),
        evidence=lambda c: RE.aaa_acc_cmd15.search(c).group(0) if RE.aaa_acc_cmd15.search(c) else "not set"
    ))

    # ==================== LOGGING ====================

    rules.append(CISRule(
        id="IOS-L1-024",
        title="Remote syslog configured",
        severity="medium",
        level="L1",
        rationale="Send logs to central syslog server for retention and analysis.",
        remediation="Configure: logging host <SYSLOG_IP>",
        check=lambda c: bool(RE.logging_host.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in RE.logging_any.finditer(c)]) or "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0241",
        title="Log timestamps configured",
        severity="low",
        level="L1",
        rationale="Include timestamps in logs for correlation and forensics.",
        remediation="Configure: service timestamps log datetime msec localtime show-timezone",
        check=lambda c: bool(RE.timestamps.search(c)),
        evidence=lambda c: RE.timestamps.search(c).group(0) if RE.timestamps.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0242",
        title="Logging buffered size configured",
        severity="low",
        level="L1",
        rationale="Store sufficient local logs for troubleshooting.",
        remediation="Configure: logging buffered 16384 warnings",
        check=lambda c: bool(RE.logging_buffered.search(c)),
        evidence=lambda c: RE.logging_buffered.search(c).group(0) if RE.logging_buffered.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0243",
        title="Logging trap level configured",
        severity="low",
        level="L1",
        rationale="Filter which log levels are sent to remote syslog.",
        remediation="Configure: logging trap warnings",
        check=lambda c: bool(RE.logging_trap.search(c)),
        evidence=lambda c: RE.logging_trap.search(c).group(0) if RE.logging_trap.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-0244",
        title="Archive config logging enabled",
        severity="medium",
        level="L1",
        rationale="Track configuration changes for auditing.",
        remediation="Configure: archive -> log config -> logging enable",
        check=lambda c: bool(re.search(r"^archive[\s\S]*?\blog config\b[\s\S]*?\blogging enable\b", c, re.M)),
        evidence=lambda c: (RE.archive_block.search(c).group(0) if RE.archive_block.search(c) else "not set")
    ))

    # ==================== SNMP ====================

    rules.append(CISRule(
        id="IOS-L1-030A",
        title="If SNMP used: SNMPv3 configured (preferred)",
        severity="high",
        level="L1",
        rationale="SNMPv3 provides authentication and encryption vs cleartext SNMPv2c.",
        remediation="Configure SNMPv3 users/groups with auth and priv",
        check=lambda c: (not bool(RE.snmp_any.search(c))) or bool(RE.snmp_v3_group.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in RE.snmp_any.finditer(c)]) or "snmp not configured"
    ))

    rules.append(CISRule(
        id="IOS-L1-030B",
        title="If SNMP community exists: must not be 'bare' (require ACL)",
        severity="high",
        level="L1",
        rationale="Bare communities without ACL restriction are accessible from any source.",
        remediation="Bind communities to ACL: snmp-server community <STRING> RO <ACL>",
        check=lambda c: (not bool(re.search(r"^snmp-server community\s+\S+\s+(RO|RW)\b", c, re.M))) or (not bool(RE.snmp_v2c_bare.search(c))),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^snmp-server community .*$", c, re.M)]) or "no communities"
    ))

    # ==================== PASSWORD HANDLING ====================

    rules.append(CISRule(
        id="IOS-L1-070",
        title="Service password-encryption enabled",
        severity="low",
        level="L1",
        rationale="Obfuscate legacy plaintext passwords in config (Type 7).",
        remediation="Configure: service password-encryption",
        check=lambda c: bool(RE.svc_pwd_enc.search(c)),
        evidence=lambda c: RE.svc_pwd_enc.search(c).group(0) if RE.svc_pwd_enc.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="IOS-L1-071",
        title="No plaintext/weak password lines (Type 0/7 patterns)",
        severity="high",
        level="L1",
        rationale="Weak Type 7 passwords are easily reversible.",
        remediation="Use 'secret' instead of 'password' for all accounts",
        check=lambda c: not bool(RE.username_password.search(c)) and not bool(RE.enable_password.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^(username \S+ password.*|enable password .*)", c, re.M)]) or "none"
    ))

    # ==================== NTP ====================

    rules.append(CISRule(
        id="IOS-L1-080",
        title="If NTP used: NTP authentication configured",
        severity="low",
        level="L1",
        rationale="Authenticate NTP sources to prevent time manipulation.",
        remediation="Configure: ntp authenticate, ntp authentication-key <ID> md5 <KEY>",
        check=lambda c: (not bool(RE.ntp_server.search(c))) or (bool(RE.ntp_auth.search(c)) and bool(RE.ntp_auth_key.search(c))),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^ntp .*|^clock timezone.*", c, re.M)]) or "ntp not configured"
    ))

    rules.append(CISRule(
        id="IOS-L1-081",
        title="Timezone configured",
        severity="low",
        level="L1",
        rationale="Accurate timezone for log correlation.",
        remediation="Configure: clock timezone <NAME> <OFFSET>",
        check=lambda c: bool(RE.clock_tz.search(c)),
        evidence=lambda c: RE.clock_tz.search(c).group(0) if RE.clock_tz.search(c) else "not set"
    ))

    # ==================== INTERFACE SECURITY ====================

    rules.append(CISRule(
        id="IOS-L1-061",
        title="At least one interface has ingress ACL",
        severity="high",
        level="L1",
        rationale="Filter ingress traffic on sensitive interfaces.",
        remediation="Apply 'ip access-group <ACL> in' on mgmt/edge interfaces",
        check=lambda c: bool(RE.if_acl_in.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^interface .*|^\s+ip access-group .* in", c, re.M)]) or "no interface ACL evidence"
    ))

    rules.append(CISRule(
        id="IOS-L2-042",
        title="Proxy ARP disabled on at least one interface",
        severity="medium",
        level="L2",
        rationale="Reduce ARP spoofing/man-in-the-middle risk.",
        remediation="Configure: no ip proxy-arp (on sensitive interfaces)",
        check=lambda c: bool(RE.if_no_proxy_arp.search(c)),
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^interface .*|^\s+no ip proxy-arp", c, re.M)]) or "no proxy-arp evidence"
    ))

    # ==================== BOOT & CONFIG ====================

    rules.append(CISRule(
        id="IOS-L1-090",
        title="Config-register is 0x2102 (recommended)",
        severity="low",
        level="L1",
        rationale="Standard boot behavior (load startup-config, normal boot).",
        remediation="Verify: config-register 0x2102",
        check=lambda c: (m:=RE.conf_reg.search(c)) is not None and m.group(1).lower() in {"0x2102", "2102"},
        evidence=lambda c: "\n".join(re.findall(r"Configuration register is .*", c)) or "not found"
    ))

    rules.append(CISRule(
        id="IOS-L2-091",
        title="Secure boot image/config present (platform dependent)",
        severity="medium",
        level="L2",
        rationale="Protect boot image and config integrity.",
        remediation="Configure: secure boot-image, secure boot-config",
        check=lambda c: bool(RE.secure_boot.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^secure boot-(image|config).*$", c, re.M)) or "not present"
    ))

    # ==================== CONTROL PLANE ====================

    rules.append(CISRule(
        id="IOS-L2-110",
        title="Control-plane policing policy present",
        severity="medium",
        level="L2",
        rationale="Protect device CPU from DoS attacks.",
        remediation="Configure: policy-map type control-plane ...",
        check=lambda c: bool(re.search(r"^policy-map type control-plane", c, re.M)),
        evidence=lambda c: (re.search(r"^policy-map type control-plane[\s\S]*?(?=^!|\Z)", c, re.M).group(0)
                           if re.search(r"^policy-map type control-plane", c, re.M) else "not found")
    ))

    # ==================== INFO RULES (Evidence Only) ====================

    rules.append(CISRule(
        id="IOS-INFO-040",
        title="CDP/LLDP policy (evidence)",
        severity="info",
        level="INFO",
        rationale="CDP/LLDP can leak device info to attackers.",
        remediation="Disable globally or on untrusted links per policy",
        check=lambda c: True,  # INFO rule - always passes
        evidence=lambda c: ("CDP: " + ("\n".join([m.group(0) for m in RE.cdp_any.finditer(c)]) or "no CDP evidence"))
                          + "\n"
                          + ("LLDP: " + ("\n".join([m.group(0) for m in RE.lldp_any.finditer(c)]) or "no LLDP evidence"))
    ))

    rules.append(CISRule(
        id="IOS-INFO-043",
        title="Directed broadcast disabled (evidence)",
        severity="info",
        level="INFO",
        rationale="Prevent Smurf amplification attacks.",
        remediation="Ensure 'no ip directed-broadcast' (often default)",
        check=lambda c: True,
        evidence=lambda c: RE.no_directed_brdcst.search(c).group(0) if RE.no_directed_brdcst.search(c) else "(default/implicit or not shown)"
    ))

    rules.append(CISRule(
        id="IOS-INFO-050",
        title="Source routing disabled (evidence)",
        severity="info",
        level="INFO",
        rationale="Prevent source-routed packet attacks.",
        remediation="Ensure 'no ip source-route' (often default)",
        check=lambda c: True,
        evidence=lambda c: RE.no_source_route.search(c).group(0) if RE.no_source_route.search(c) else "(default/implicit or not shown)"
    ))

    return rules


# ========================= COMPLIANCE EVALUATION =========================

def evaluate_compliance(config_text: str, rules: List[CISRule]) -> Dict[str, Any]:
    """
    Evaluate device configuration against CIS rules.

    Args:
        config_text: Raw turbo dump from device
        rules: List of CIS rules to check

    Returns:
        Dict containing:
        - summary: Compliance statistics
        - findings: List of individual rule results
    """
    findings = []
    check_errors = 0

    for rule in rules:
        try:
            compliant = bool(rule.check(config_text))
        except Exception:
            compliant = False
            check_errors += 1

        try:
            evidence = rule.evidence(config_text)
            if evidence is None:
                evidence = "(no evidence)"
            else:
                evidence = str(evidence).strip()
        except Exception:
            evidence = "(error extracting evidence)"
            check_errors += 1

        # Truncate long evidence
        if len(evidence) > 2500:
            evidence = evidence[:2500] + " ...[truncated]"

        findings.append({
            "id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "level": rule.level,
            "compliant": compliant,
            "evidence": evidence,
            "rationale": rule.rationale,
            "remediation": None if compliant else rule.remediation
        })

    # Calculate compliance scores (exclude INFO rules)
    scored = [f for f in findings if SEVERITY_WEIGHT.get(f["severity"], 0) > 0]
    total = len(scored)
    passed = sum(1 for f in scored if f["compliant"])
    failed = total - passed

    simple_pct = round(100.0 * passed / total, 2) if total else 0.0

    # Weighted score (severity-based)
    w_total = sum(SEVERITY_WEIGHT[f["severity"]] for f in scored)
    w_pass = sum(SEVERITY_WEIGHT[f["severity"]] for f in scored if f["compliant"])
    weighted_pct = round(100.0 * w_pass / w_total, 2) if w_total else 0.0

    return {
        "summary": {
            "total_rules_scored": total,
            "passed_scored": passed,
            "failed_scored": failed,
            "compliance_pct": simple_pct,
            "weighted_compliance_pct": weighted_pct,
            "total_findings_including_info": len(findings),
            "check_errors": check_errors
        },
        "findings": findings
    }


# ========================= PROFILE FILTERING =========================

def filter_rules_by_profile(all_rules: List[CISRule], profile: str = "L1") -> List[CISRule]:
    """
    Filter rules by compliance profile.

    Args:
        all_rules: Complete rule set
        profile: "L1" (basic) or "FULL" (L1 + L2 + INFO)

    Returns:
        Filtered list of rules
    """
    profile = profile.upper()

    if profile == "L1":
        return [r for r in all_rules if r.level == "L1"]
    elif profile == "FULL":
        return all_rules
    else:
        return [r for r in all_rules if r.level == "L1"]


# ========================= CIS BENCHMARK TABLE RULES =========================

def _has_key_chain_complete(text: str) -> bool:
    """Check if key chain has key and key-string configured."""
    blocks = RE.key_block.findall(text)
    for block in blocks:
        if RE.key_id.search(block) and RE.key_string.search(block):
            return True
    return False


def _get_line_con_block(text: str) -> str:
    """Extract line console 0 block."""
    m = RE.line_con.search(text)
    return m.group(0) if m else ""


def _get_line_tty_blocks(text: str) -> List[str]:
    """Extract all line tty blocks."""
    return RE.line_tty.findall(text)


def _get_line_aux_block(text: str) -> str:
    """Extract line aux 0 block."""
    m = RE.line_aux.search(text)
    return m.group(0) if m else ""


def _has_exec_timeout_le10(block: str) -> bool:
    """Check if exec-timeout is configured and <= 10 minutes."""
    m = RE.exec_timeout_line.search(block)
    if not m:
        return False
    return int(m.group(1)) <= 10


def build_cis_benchmark_rules() -> List[CISRule]:
    """
    Build CIS Benchmark rules that match the official CIS Cisco IOS 15 Benchmark v4.1.1.

    These rules use CIS section numbers (1.1.1, 1.1.2, etc.) as IDs.
    Based on Appendix: CIS Controls v8 IG 3 Mapped Recommendations.

    Returns:
        List[CISRule]: All CIS benchmark rules with proper section IDs
    """
    rules: List[CISRule] = []

    # ============================================
    # SECTION 1: MANAGEMENT PLANE
    # ============================================

    # 1.1 - AAA Configuration
    rules.append(CISRule(
        id="CIS-1.1.1",
        title="Enable 'aaa new-model'",
        severity="high",
        level="L1",
        rationale="AAA new-model enables centralized authentication and authorization.",
        remediation="Configure: aaa new-model",
        check=lambda c: bool(RE.aaa_new_model.search(c)),
        evidence=lambda c: RE.aaa_new_model.search(c).group(0) if RE.aaa_new_model.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.2",
        title="Enable 'aaa authentication login'",
        severity="high",
        level="L1",
        rationale="Define authentication methods for login sessions.",
        remediation="Configure: aaa authentication login default group tacacs+ local",
        check=lambda c: bool(RE.aaa_auth_login.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^aaa authentication login.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.3",
        title="Enable 'aaa authentication enable default'",
        severity="high",
        level="L1",
        rationale="Define authentication methods for enable mode access.",
        remediation="Configure: aaa authentication enable default group tacacs+ enable",
        check=lambda c: bool(RE.aaa_auth_enable.search(c)),
        evidence=lambda c: RE.aaa_auth_enable.search(c).group(0) if RE.aaa_auth_enable.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.4",
        title="Set 'login authentication for 'line con 0'",
        severity="high",
        level="L1",
        rationale="Apply authentication to console line.",
        remediation="Configure: line con 0 -> login authentication <list>",
        check=lambda c: bool(RE.login_authentication.search(_get_line_con_block(c))),
        evidence=lambda c: _get_line_con_block(c) or "line console not found"
    ))

    rules.append(CISRule(
        id="CIS-1.1.5",
        title="Set 'login authentication for 'line tty'",
        severity="medium",
        level="L1",
        rationale="Apply authentication to TTY lines if present.",
        remediation="Configure: line tty X -> login authentication <list>",
        check=lambda c: (not _get_line_tty_blocks(c)) or all(RE.login_authentication.search(b) for b in _get_line_tty_blocks(c)),
        evidence=lambda c: "\n".join(_get_line_tty_blocks(c)) or "no tty lines configured"
    ))

    rules.append(CISRule(
        id="CIS-1.1.6",
        title="Set 'login authentication for 'line vty'",
        severity="high",
        level="L1",
        rationale="Apply authentication to VTY lines.",
        remediation="Configure: line vty 0 15 -> login authentication <list>",
        check=lambda c: all(RE.login_authentication.search(b) or RE.login_method.search(b) for b in _vty_blocks(c)) if _vty_blocks(c) else False,
        evidence=lambda c: "\n".join([b[:500] for b in _vty_blocks(c)]) or "no vty lines found"
    ))

    rules.append(CISRule(
        id="CIS-1.1.7",
        title="Set 'aaa accounting' to log all privileged use commands using 'commands 15'",
        severity="medium",
        level="L2",
        rationale="Log all privilege level 15 commands for auditing.",
        remediation="Configure: aaa accounting commands 15 default start-stop group tacacs+",
        check=lambda c: bool(RE.aaa_acc_cmd15.search(c)),
        evidence=lambda c: RE.aaa_acc_cmd15.search(c).group(0) if RE.aaa_acc_cmd15.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.8",
        title="Set 'aaa accounting connection'",
        severity="medium",
        level="L2",
        rationale="Log connection accounting for auditing.",
        remediation="Configure: aaa accounting connection default start-stop group tacacs+",
        check=lambda c: bool(RE.aaa_acc_connection.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^aaa accounting connection.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.9",
        title="Set 'aaa accounting exec'",
        severity="medium",
        level="L2",
        rationale="Log exec session accounting for auditing.",
        remediation="Configure: aaa accounting exec default start-stop group tacacs+",
        check=lambda c: bool(RE.aaa_acc_exec.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^aaa accounting exec.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.10",
        title="Set 'aaa accounting network'",
        severity="medium",
        level="L2",
        rationale="Log network service accounting for auditing.",
        remediation="Configure: aaa accounting network default start-stop group tacacs+",
        check=lambda c: bool(RE.aaa_acc_network.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^aaa accounting network.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.1.11",
        title="Set 'aaa accounting system'",
        severity="medium",
        level="L2",
        rationale="Log system events accounting for auditing.",
        remediation="Configure: aaa accounting system default start-stop group tacacs+",
        check=lambda c: bool(RE.aaa_acc_system.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^aaa accounting system.*$", c, re.M)) or "not set"
    ))

    # 1.2 - Access Control
    rules.append(CISRule(
        id="CIS-1.2.1",
        title="Set 'privilege 1' for local users",
        severity="medium",
        level="L1",
        rationale="Local users should have minimum required privileges.",
        remediation="Configure: username <user> privilege 1 secret <pass>",
        check=lambda c: (not RE.username_secret.search(c)) or bool(RE.username_priv.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^username\s+\S+\s+privilege.*$", c, re.M)) or "no users with explicit privilege"
    ))

    rules.append(CISRule(
        id="CIS-1.2.2",
        title="Set 'transport input ssh' for 'line vty' connections",
        severity="high",
        level="L1",
        rationale="Use SSH only, disable telnet for secure remote access.",
        remediation="Configure: line vty 0 15 -> transport input ssh",
        check=lambda c: all(RE.transport_ssh.search(b) and not RE.transport_telnet.search(b) for b in _vty_blocks(c)) if _vty_blocks(c) else False,
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^line vty .*|^\s+transport input .*", c, re.M)])
    ))

    rules.append(CISRule(
        id="CIS-1.2.4",
        title="Create 'access-list' for use with 'line vty'",
        severity="high",
        level="L1",
        rationale="Define an ACL to restrict VTY access to authorized hosts.",
        remediation="Configure: ip access-list standard VTY-ACL -> permit <authorized-hosts>",
        check=lambda c: bool(re.search(r"^(?:ip )?access-list\s+(?:standard|extended)\s+\S+", c, re.M)),
        evidence=lambda c: "\n".join(re.findall(r"^(?:ip )?access-list\s+(?:standard|extended)\s+\S+.*$", c, re.M)[:5]) or "no access-list found"
    ))

    rules.append(CISRule(
        id="CIS-1.2.5",
        title="Set 'access-class' for 'line vty'",
        severity="high",
        level="L1",
        rationale="Apply ACL to VTY lines to restrict management access.",
        remediation="Configure: line vty 0 15 -> access-class <ACL> in",
        check=lambda c: all(RE.access_class_in.search(b) for b in _vty_blocks(c)) if _vty_blocks(c) else False,
        evidence=lambda c: "\n".join([m.group(0) for m in re.finditer(r"^line vty .*|^\s+access-class .*", c, re.M)])
    ))

    # 1.3 - Banners
    rules.append(CISRule(
        id="CIS-1.3.1",
        title="Set the 'banner-text' for 'banner exec'",
        severity="low",
        level="L1",
        rationale="Display legal notice after user authentication.",
        remediation="Configure: banner exec ^C <legal notice> ^C",
        check=lambda c: bool(RE.banner_exec.search(c)),
        evidence=lambda c: RE.banner_exec.search(c).group(0) if RE.banner_exec.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.3.2",
        title="Set the 'banner-text' for 'banner login'",
        severity="low",
        level="L1",
        rationale="Display legal notice before login prompt.",
        remediation="Configure: banner login ^C <legal notice> ^C",
        check=lambda c: bool(RE.banner_login.search(c)),
        evidence=lambda c: RE.banner_login.search(c).group(0) if RE.banner_login.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.3.3",
        title="Set the 'banner-text' for 'banner motd'",
        severity="low",
        level="L1",
        rationale="Display message of the day banner.",
        remediation="Configure: banner motd ^C <legal notice> ^C",
        check=lambda c: bool(RE.banner_motd.search(c)),
        evidence=lambda c: RE.banner_motd.search(c).group(0) if RE.banner_motd.search(c) else "not set"
    ))

    # 1.4 - Passwords
    rules.append(CISRule(
        id="CIS-1.4.1",
        title="Set 'password' for 'enable secret'",
        severity="high",
        level="L1",
        rationale="Use enable secret (SHA-256) instead of enable password (Type 7).",
        remediation="Configure: enable secret <strong-password>",
        check=lambda c: bool(RE.enable_secret.search(c)),
        evidence=lambda c: RE.enable_secret.search(c).group(0) if RE.enable_secret.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.4.2",
        title="Enable 'service password-encryption'",
        severity="low",
        level="L1",
        rationale="Obfuscate passwords in running config.",
        remediation="Configure: service password-encryption",
        check=lambda c: bool(RE.svc_pwd_enc.search(c)),
        evidence=lambda c: RE.svc_pwd_enc.search(c).group(0) if RE.svc_pwd_enc.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-1.4.3",
        title="Set 'username secret' for all local users",
        severity="high",
        level="L1",
        rationale="Use secret (SHA-256) instead of password (Type 7) for local users.",
        remediation="Configure: username <user> secret <pass>",
        check=lambda c: bool(RE.username_secret.search(c)) and not bool(RE.username_password.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^username\s+\S+\s+(?:secret|password).*$", c, re.M)) or "no local users"
    ))

    # 1.5 - SNMP
    rules.append(CISRule(
        id="CIS-1.5.1",
        title="Set 'no snmp-server' to disable SNMP when unused",
        severity="medium",
        level="L1",
        rationale="Disable SNMP if not required to reduce attack surface.",
        remediation="Remove all snmp-server commands or configure SNMPv3 with auth+priv",
        check=lambda c: not bool(RE.snmp_any.search(c)) or bool(RE.snmp_v3_group.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server.*$", c, re.M)[:10]) or "SNMP not configured"
    ))

    rules.append(CISRule(
        id="CIS-1.5.2",
        title="Unset 'private' for 'snmp-server community'",
        severity="high",
        level="L1",
        rationale="Default 'private' community string is well-known and insecure.",
        remediation="Remove: no snmp-server community private",
        check=lambda c: not bool(RE.snmp_community_private.search(c)),
        evidence=lambda c: RE.snmp_community_private.search(c).group(0) if RE.snmp_community_private.search(c) else "not present (good)"
    ))

    rules.append(CISRule(
        id="CIS-1.5.3",
        title="Unset 'public' for 'snmp-server community'",
        severity="high",
        level="L1",
        rationale="Default 'public' community string is well-known and insecure.",
        remediation="Remove: no snmp-server community public",
        check=lambda c: not bool(RE.snmp_community_public.search(c)),
        evidence=lambda c: RE.snmp_community_public.search(c).group(0) if RE.snmp_community_public.search(c) else "not present (good)"
    ))

    rules.append(CISRule(
        id="CIS-1.5.4",
        title="Do not set 'RW' for any 'snmp-server community'",
        severity="high",
        level="L1",
        rationale="Read-write SNMP communities allow configuration changes.",
        remediation="Use RO communities or SNMPv3 with auth+priv",
        check=lambda c: not bool(RE.snmp_community_rw.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server community.*RW.*$", c, re.M)) or "no RW community (good)"
    ))

    rules.append(CISRule(
        id="CIS-1.5.5",
        title="Set the ACL for each 'snmp-server community'",
        severity="high",
        level="L1",
        rationale="Restrict SNMP access to authorized management stations.",
        remediation="Configure: snmp-server community <string> RO <ACL>",
        check=lambda c: (not bool(re.search(r"^snmp-server community\s+\S+\s+(?:RO|RW)\b", c, re.M))) or bool(RE.snmp_community_acl.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server community.*$", c, re.M)) or "no SNMP communities"
    ))

    rules.append(CISRule(
        id="CIS-1.5.6",
        title="Create an 'access-list' for use with SNMP",
        severity="medium",
        level="L1",
        rationale="Define ACL to restrict SNMP polling sources.",
        remediation="Configure: ip access-list standard SNMP-ACL -> permit <authorized-hosts>",
        check=lambda c: (not bool(RE.snmp_any.search(c))) or bool(re.search(r"^(?:ip )?access-list\s+\S+\s+SNMP", c, re.M | re.I)) or bool(RE.snmp_community_acl.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^(?:ip )?access-list.*SNMP.*$", c, re.M | re.I)) or "no SNMP ACL found"
    ))

    rules.append(CISRule(
        id="CIS-1.5.7",
        title="Set 'snmp-server host' when using SNMP",
        severity="medium",
        level="L1",
        rationale="Define trap destinations for SNMP notifications.",
        remediation="Configure: snmp-server host <IP> <community>",
        check=lambda c: (not bool(RE.snmp_any.search(c))) or bool(RE.snmp_host.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server host.*$", c, re.M)) or "no SNMP host configured"
    ))

    rules.append(CISRule(
        id="CIS-1.5.8",
        title="Set 'snmp-server enable traps snmp'",
        severity="low",
        level="L1",
        rationale="Enable SNMP traps for device notifications.",
        remediation="Configure: snmp-server enable traps snmp",
        check=lambda c: (not bool(RE.snmp_any.search(c))) or bool(RE.snmp_traps.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server enable traps.*$", c, re.M)) or "no SNMP traps enabled"
    ))

    rules.append(CISRule(
        id="CIS-1.5.9",
        title="Set 'priv' for each 'snmp-server group' using SNMPv3",
        severity="high",
        level="L1",
        rationale="Use SNMPv3 with privacy (encryption) for secure SNMP.",
        remediation="Configure: snmp-server group <group> v3 priv",
        check=lambda c: (not bool(RE.snmp_v3_group.search(c))) or bool(RE.snmp_v3_priv.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server group.*v3.*$", c, re.M)) or "no SNMPv3 groups"
    ))

    rules.append(CISRule(
        id="CIS-1.5.10",
        title="Require 'aes 128' as minimum for 'snmp-server user' when using SNMPv3",
        severity="high",
        level="L1",
        rationale="Use AES encryption for SNMPv3 user privacy.",
        remediation="Configure: snmp-server user <user> <group> v3 auth sha <pass> priv aes 128 <pass>",
        check=lambda c: (not bool(re.search(r"^snmp-server user", c, re.M))) or bool(RE.snmp_user_aes.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^snmp-server user.*$", c, re.M)) or "no SNMPv3 users"
    ))

    # ============================================
    # SECTION 2: CONTROL PLANE
    # ============================================

    # 2.1.1 - SSH Configuration
    rules.append(CISRule(
        id="CIS-2.1.1.1.1",
        title="Set the 'hostname'",
        severity="low",
        level="L1",
        rationale="Hostname identifies the device in logs and management.",
        remediation="Configure: hostname <NAME>",
        check=lambda c: bool(RE.hostname.search(c)),
        evidence=lambda c: RE.hostname.search(c).group(0) if RE.hostname.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.1.1.1.2",
        title="Set the 'ip domain-name'",
        severity="low",
        level="L1",
        rationale="Domain name required for SSH key generation.",
        remediation="Configure: ip domain-name <DOMAIN>",
        check=lambda c: bool(RE.domain_name.search(c)),
        evidence=lambda c: RE.domain_name.search(c).group(0) if RE.domain_name.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.1.1.1.3",
        title="Set 'modulus' to greater than or equal to 2048 for 'crypto key generate rsa'",
        severity="high",
        level="L1",
        rationale="RSA key size >= 2048 bits provides adequate security.",
        remediation="Configure: crypto key generate rsa modulus 2048",
        check=lambda c: (bits := _extract_ssh_key_bits(c)) is not None and bits >= 2048,
        evidence=lambda c: f"Detected key size: {_extract_ssh_key_bits(c) or 'unknown'} bit"
    ))

    rules.append(CISRule(
        id="CIS-2.1.1.1.4",
        title="Set 'seconds' for 'ip ssh timeout'",
        severity="medium",
        level="L1",
        rationale="Limit SSH authentication timeout to prevent hanging sessions.",
        remediation="Configure: ip ssh timeout 60",
        check=lambda c: bool(RE.ssh_timeout.search(c)),
        evidence=lambda c: RE.ssh_timeout.search(c).group(0) if RE.ssh_timeout.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.1.1.1.5",
        title="Set maximimum value for 'ip ssh authentication-retries'",
        severity="medium",
        level="L1",
        rationale="Limit authentication retries to slow brute-force attacks.",
        remediation="Configure: ip ssh authentication-retries 3",
        check=lambda c: bool(RE.ssh_retries.search(c)),
        evidence=lambda c: RE.ssh_retries.search(c).group(0) if RE.ssh_retries.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.1.1.2",
        title="Set version 2 for 'ip ssh version'",
        severity="high",
        level="L1",
        rationale="SSH version 1 has known vulnerabilities.",
        remediation="Configure: ip ssh version 2",
        check=lambda c: bool(RE.ssh_v2.search(c)),
        evidence=lambda c: RE.ssh_v2.search(c).group(0) if RE.ssh_v2.search(c) else "not set"
    ))

    # 2.1 - Services
    rules.append(CISRule(
        id="CIS-2.1.2",
        title="Set 'no cdp run'",
        severity="medium",
        level="L1",
        rationale="CDP can leak device information to attackers.",
        remediation="Configure: no cdp run",
        check=lambda c: bool(RE.no_cdp_run.search(c)),
        evidence=lambda c: RE.no_cdp_run.search(c).group(0) if RE.no_cdp_run.search(c) else "CDP may be enabled"
    ))

    rules.append(CISRule(
        id="CIS-2.1.3",
        title="Set 'no ip bootp server'",
        severity="low",
        level="L1",
        rationale="BOOTP server not needed on most devices.",
        remediation="Configure: no ip bootp server",
        check=lambda c: bool(RE.no_bootp.search(c)),
        evidence=lambda c: RE.no_bootp.search(c).group(0) if RE.no_bootp.search(c) else "BOOTP may be enabled"
    ))

    rules.append(CISRule(
        id="CIS-2.1.4",
        title="Set 'no service dhcp'",
        severity="low",
        level="L1",
        rationale="DHCP service not needed on most network devices.",
        remediation="Configure: no service dhcp",
        check=lambda c: bool(RE.no_dhcp.search(c)),
        evidence=lambda c: RE.no_dhcp.search(c).group(0) if RE.no_dhcp.search(c) else "DHCP may be enabled"
    ))

    rules.append(CISRule(
        id="CIS-2.1.5",
        title="Set 'no ip identd'",
        severity="low",
        level="L1",
        rationale="Ident protocol can leak user information.",
        remediation="Configure: no ip identd",
        check=lambda c: bool(RE.no_identd.search(c)),
        evidence=lambda c: RE.no_identd.search(c).group(0) if RE.no_identd.search(c) else "identd may be enabled"
    ))

    rules.append(CISRule(
        id="CIS-2.1.6",
        title="Set 'service tcp-keepalives-in'",
        severity="low",
        level="L1",
        rationale="TCP keepalives detect dead sessions.",
        remediation="Configure: service tcp-keepalives-in",
        check=lambda c: bool(RE.tcp_keepalives_in.search(c)),
        evidence=lambda c: RE.tcp_keepalives_in.search(c).group(0) if RE.tcp_keepalives_in.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.1.8",
        title="Set 'no service pad'",
        severity="low",
        level="L1",
        rationale="PAD service not needed on modern networks.",
        remediation="Configure: no service pad",
        check=lambda c: bool(RE.no_service_pad.search(c)),
        evidence=lambda c: RE.no_service_pad.search(c).group(0) if RE.no_service_pad.search(c) else "PAD may be enabled"
    ))

    # 2.2 - Logging
    rules.append(CISRule(
        id="CIS-2.2.1",
        title="Set 'logging on'",
        severity="medium",
        level="L1",
        rationale="Enable logging for security monitoring.",
        remediation="Configure: logging on",
        check=lambda c: bool(RE.logging_on.search(c)) or bool(RE.logging_host.search(c)),
        evidence=lambda c: RE.logging_on.search(c).group(0) if RE.logging_on.search(c) else "logging on not explicit"
    ))

    rules.append(CISRule(
        id="CIS-2.2.2",
        title="Set 'buffer size' for 'logging buffered'",
        severity="low",
        level="L1",
        rationale="Buffer sufficient logs for troubleshooting.",
        remediation="Configure: logging buffered 16384",
        check=lambda c: bool(RE.logging_buffered.search(c)),
        evidence=lambda c: RE.logging_buffered.search(c).group(0) if RE.logging_buffered.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.2.3",
        title="Set 'logging console critical'",
        severity="low",
        level="L1",
        rationale="Limit console logging to critical messages only.",
        remediation="Configure: logging console critical",
        check=lambda c: bool(RE.logging_console.search(c)),
        evidence=lambda c: RE.logging_console.search(c).group(0) if RE.logging_console.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.2.4",
        title="Set IP address for 'logging host'",
        severity="medium",
        level="L1",
        rationale="Send logs to central syslog server for retention.",
        remediation="Configure: logging host <SYSLOG-IP>",
        check=lambda c: bool(RE.logging_host.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^logging host.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.2.5",
        title="Set 'logging trap informational'",
        severity="low",
        level="L1",
        rationale="Set appropriate trap level for syslog.",
        remediation="Configure: logging trap informational",
        check=lambda c: bool(RE.logging_trap.search(c)),
        evidence=lambda c: RE.logging_trap.search(c).group(0) if RE.logging_trap.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.2.6",
        title="Set 'service timestamps debug datetime'",
        severity="low",
        level="L1",
        rationale="Include timestamps in debug messages.",
        remediation="Configure: service timestamps debug datetime msec localtime show-timezone",
        check=lambda c: bool(RE.timestamps_debug.search(c)),
        evidence=lambda c: RE.timestamps_debug.search(c).group(0) if RE.timestamps_debug.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.2.7",
        title="Set 'logging source interface'",
        severity="low",
        level="L1",
        rationale="Use consistent source interface for syslog.",
        remediation="Configure: logging source-interface Loopback0",
        check=lambda c: bool(RE.logging_source_if.search(c)),
        evidence=lambda c: RE.logging_source_if.search(c).group(0) if RE.logging_source_if.search(c) else "not set"
    ))

    # 2.3 - NTP
    rules.append(CISRule(
        id="CIS-2.3.1.1",
        title="Set 'ntp authenticate'",
        severity="medium",
        level="L1",
        rationale="Enable NTP authentication to prevent time manipulation.",
        remediation="Configure: ntp authenticate",
        check=lambda c: (not bool(RE.ntp_server.search(c))) or bool(RE.ntp_auth.search(c)),
        evidence=lambda c: RE.ntp_auth.search(c).group(0) if RE.ntp_auth.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.3.1.2",
        title="Set 'ntp authentication-key'",
        severity="medium",
        level="L1",
        rationale="Define NTP authentication key.",
        remediation="Configure: ntp authentication-key <ID> md5 <KEY>",
        check=lambda c: (not bool(RE.ntp_server.search(c))) or bool(RE.ntp_auth_key.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^ntp authentication-key.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.3.1.3",
        title="Set the 'ntp trusted-key'",
        severity="medium",
        level="L1",
        rationale="Mark NTP keys as trusted.",
        remediation="Configure: ntp trusted-key <ID>",
        check=lambda c: (not bool(RE.ntp_server.search(c))) or bool(RE.ntp_trusted_key.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^ntp trusted-key.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.3.1.4",
        title="Set 'key' for each 'ntp server'",
        severity="medium",
        level="L1",
        rationale="Associate authentication key with NTP servers.",
        remediation="Configure: ntp server <IP> key <ID>",
        check=lambda c: (not bool(RE.ntp_server.search(c))) or bool(RE.ntp_server_key.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^ntp server.*$", c, re.M)) or "no NTP servers"
    ))

    rules.append(CISRule(
        id="CIS-2.3.2",
        title="Set 'ip address' for 'ntp server'",
        severity="low",
        level="L1",
        rationale="Configure at least one NTP server for time sync.",
        remediation="Configure: ntp server <IP>",
        check=lambda c: bool(RE.ntp_server.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^ntp server.*$", c, re.M)) or "no NTP servers"
    ))

    # 2.4 - Loopback
    rules.append(CISRule(
        id="CIS-2.4.1",
        title="Create a single 'interface loopback'",
        severity="medium",
        level="L1",
        rationale="Loopback interface provides stable management IP.",
        remediation="Configure: interface Loopback0 -> ip address <IP> <MASK>",
        check=lambda c: bool(RE.interface_loopback.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^interface [Ll]oopback.*$", c, re.M)) or "no loopback"
    ))

    rules.append(CISRule(
        id="CIS-2.4.2",
        title="Set AAA 'source-interface'",
        severity="low",
        level="L1",
        rationale="Use loopback as source for AAA traffic.",
        remediation="Configure: ip radius source-interface Loopback0",
        check=lambda c: (not bool(RE.interface_loopback.search(c))) or bool(RE.aaa_source_interface.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^ip (?:radius|tacacs)\s+source-interface.*$", c, re.M)) or "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.4.3",
        title="Set 'ntp source' to Loopback Interface",
        severity="low",
        level="L1",
        rationale="Use loopback as source for NTP traffic.",
        remediation="Configure: ntp source Loopback0",
        check=lambda c: (not bool(RE.ntp_server.search(c))) or bool(RE.ntp_source.search(c)),
        evidence=lambda c: RE.ntp_source.search(c).group(0) if RE.ntp_source.search(c) else "not set"
    ))

    rules.append(CISRule(
        id="CIS-2.4.4",
        title="Set 'ip tftp source-interface' to the Loopback Interface",
        severity="low",
        level="L1",
        rationale="Use loopback as source for TFTP traffic.",
        remediation="Configure: ip tftp source-interface Loopback0",
        check=lambda c: (not bool(RE.interface_loopback.search(c))) or bool(RE.tftp_source_interface.search(c)),
        evidence=lambda c: RE.tftp_source_interface.search(c).group(0) if RE.tftp_source_interface.search(c) else "not set"
    ))

    # ============================================
    # SECTION 3: DATA PLANE
    # ============================================

    # 3.1 - IP Hardening
    rules.append(CISRule(
        id="CIS-3.1.1",
        title="Set 'no ip source-route'",
        severity="medium",
        level="L1",
        rationale="Disable IP source routing to prevent routing attacks.",
        remediation="Configure: no ip source-route",
        check=lambda c: bool(RE.no_source_route.search(c)),
        evidence=lambda c: RE.no_source_route.search(c).group(0) if RE.no_source_route.search(c) else "source-route may be enabled"
    ))

    rules.append(CISRule(
        id="CIS-3.1.2",
        title="Set 'no ip proxy-arp'",
        severity="medium",
        level="L1",
        rationale="Disable proxy ARP to prevent ARP spoofing.",
        remediation="Configure: interface <IF> -> no ip proxy-arp",
        check=lambda c: bool(RE.if_no_proxy_arp.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^interface .*|^\s+no ip proxy-arp", c, re.M)[:20]) or "no explicit no ip proxy-arp"
    ))

    rules.append(CISRule(
        id="CIS-3.1.3",
        title="Set 'no interface tunnel'",
        severity="medium",
        level="L1",
        rationale="Disable unused tunnel interfaces.",
        remediation="Remove: no interface Tunnel<X>",
        check=lambda c: not bool(RE.interface_tunnel.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^interface [Tt]unnel.*$", c, re.M)) or "no tunnel interfaces (good)"
    ))

    rules.append(CISRule(
        id="CIS-3.1.4",
        title="Set 'ip verify unicast source reachable-via'",
        severity="medium",
        level="L1",
        rationale="Enable uRPF to prevent spoofed source addresses.",
        remediation="Configure: interface <IF> -> ip verify unicast source reachable-via rx",
        check=lambda c: bool(RE.ip_verify_unicast.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*ip verify unicast.*$", c, re.M)) or "uRPF not configured"
    ))

    # 3.2 - Access Lists
    rules.append(CISRule(
        id="CIS-3.2.1",
        title="Set 'ip access-list extended' to Forbid Private Source Addresses from External Networks",
        severity="high",
        level="L1",
        rationale="Block RFC1918 addresses from external interfaces.",
        remediation="Configure ACL to deny 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 from external",
        check=lambda c: bool(RE.ip_access_list_ext.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^ip access-list extended.*$", c, re.M)[:5]) or "no extended ACL"
    ))

    rules.append(CISRule(
        id="CIS-3.2.2",
        title="Set inbound 'ip access-group' on the External Interface",
        severity="high",
        level="L1",
        rationale="Apply ingress ACL on external interfaces.",
        remediation="Configure: interface <external> -> ip access-group <ACL> in",
        check=lambda c: bool(RE.ip_access_group_in.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^interface .*|^\s+ip access-group .* in", c, re.M)[:20]) or "no ingress ACL"
    ))

    # 3.3.1 - EIGRP Authentication
    rules.append(CISRule(
        id="CIS-3.3.1.1",
        title="Set 'key chain'",
        severity="medium",
        level="L1",
        rationale="Define key chain for routing authentication.",
        remediation="Configure: key chain <NAME>",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.key_chain.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^key chain.*$", c, re.M)) or "no key chain"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.2",
        title="Set 'key'",
        severity="medium",
        level="L1",
        rationale="Define key ID within key chain.",
        remediation="Configure: key chain <NAME> -> key <ID>",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.key_id.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*key\s+\d+.*$", c, re.M)) or "no key defined"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.3",
        title="Set 'key-string'",
        severity="medium",
        level="L1",
        rationale="Define key string (password) for routing authentication.",
        remediation="Configure: key chain <NAME> -> key <ID> -> key-string <PASS>",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.key_string.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*key-string.*$", c, re.M)) or "no key-string"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.4",
        title="Set 'address-family ipv4 autonomous-system'",
        severity="medium",
        level="L1",
        rationale="Configure EIGRP named mode address family.",
        remediation="Configure: router eigrp <NAME> -> address-family ipv4 autonomous-system <AS>",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.eigrp_af_ipv4.search(c)) or bool(RE.ip_auth_keychain_eigrp.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*address-family ipv4.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.5",
        title="Set 'af-interface default'",
        severity="medium",
        level="L1",
        rationale="Configure EIGRP authentication on all interfaces by default.",
        remediation="Configure: router eigrp <NAME> -> af-interface default",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.eigrp_af_interface.search(c)) or bool(RE.ip_auth_keychain_eigrp.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*af-interface.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.6",
        title="Set 'authentication key-chain'",
        severity="medium",
        level="L1",
        rationale="Apply key chain to EIGRP authentication.",
        remediation="Configure: af-interface default -> authentication key-chain <NAME>",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.eigrp_auth_keychain.search(c)) or bool(RE.ip_auth_keychain_eigrp.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*authentication key-chain.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.7",
        title="Set 'authentication mode md5'",
        severity="medium",
        level="L1",
        rationale="Use MD5 authentication for EIGRP.",
        remediation="Configure: af-interface default -> authentication mode md5",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.eigrp_auth_mode_md5.search(c)) or bool(RE.ip_auth_mode_eigrp.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*authentication mode.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.8",
        title="Set 'ip authentication key-chain eigrp'",
        severity="medium",
        level="L1",
        rationale="Apply EIGRP authentication on interface (classic mode).",
        remediation="Configure: interface <IF> -> ip authentication key-chain eigrp <AS> <CHAIN>",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.ip_auth_keychain_eigrp.search(c)) or bool(RE.eigrp_auth_keychain.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*ip authentication key-chain eigrp.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.1.9",
        title="Set 'ip authentication mode eigrp'",
        severity="medium",
        level="L1",
        rationale="Set EIGRP authentication mode on interface (classic mode).",
        remediation="Configure: interface <IF> -> ip authentication mode eigrp <AS> md5",
        check=lambda c: (not bool(RE.router_eigrp.search(c))) or bool(RE.ip_auth_mode_eigrp.search(c)) or bool(RE.eigrp_auth_mode_md5.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*ip authentication mode eigrp.*$", c, re.M)) or "not configured"
    ))

    # 3.3.2 - OSPF Authentication
    rules.append(CISRule(
        id="CIS-3.3.2.1",
        title="Set 'authentication message-digest' for OSPF area",
        severity="medium",
        level="L1",
        rationale="Enable MD5 authentication for OSPF area.",
        remediation="Configure: router ospf <ID> -> area <AREA> authentication message-digest",
        check=lambda c: (not bool(RE.router_ospf.search(c))) or bool(RE.ospf_auth_md.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*area\s+\S+\s+authentication.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.2.2",
        title="Set 'ip ospf message-digest-key md5'",
        severity="medium",
        level="L1",
        rationale="Configure OSPF MD5 authentication key on interface.",
        remediation="Configure: interface <IF> -> ip ospf message-digest-key <ID> md5 <KEY>",
        check=lambda c: (not bool(RE.router_ospf.search(c))) or bool(RE.ip_ospf_md_key.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*ip ospf message-digest-key.*$", c, re.M)) or "not configured"
    ))

    # 3.3.3 - RIP Authentication
    rules.append(CISRule(
        id="CIS-3.3.3.1",
        title="Set 'key chain'",
        severity="medium",
        level="L1",
        rationale="Define key chain for RIP authentication.",
        remediation="Configure: key chain <NAME>",
        check=lambda c: (not bool(RE.router_rip.search(c))) or bool(RE.key_chain.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^key chain.*$", c, re.M)) or "no key chain"
    ))

    rules.append(CISRule(
        id="CIS-3.3.3.2",
        title="Set 'key'",
        severity="medium",
        level="L1",
        rationale="Define key ID for RIP authentication.",
        remediation="Configure: key chain <NAME> -> key <ID>",
        check=lambda c: (not bool(RE.router_rip.search(c))) or bool(RE.key_id.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*key\s+\d+.*$", c, re.M)) or "no key"
    ))

    rules.append(CISRule(
        id="CIS-3.3.3.3",
        title="Set 'key-string'",
        severity="medium",
        level="L1",
        rationale="Define key string for RIP authentication.",
        remediation="Configure: key chain <NAME> -> key <ID> -> key-string <PASS>",
        check=lambda c: (not bool(RE.router_rip.search(c))) or bool(RE.key_string.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*key-string.*$", c, re.M)) or "no key-string"
    ))

    rules.append(CISRule(
        id="CIS-3.3.3.4",
        title="Set 'ip rip authentication key-chain'",
        severity="medium",
        level="L1",
        rationale="Apply key chain to RIP interface.",
        remediation="Configure: interface <IF> -> ip rip authentication key-chain <NAME>",
        check=lambda c: (not bool(RE.router_rip.search(c))) or bool(RE.ip_rip_auth_keychain.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*ip rip authentication key-chain.*$", c, re.M)) or "not configured"
    ))

    rules.append(CISRule(
        id="CIS-3.3.3.5",
        title="Set 'ip rip authentication mode' to 'md5'",
        severity="medium",
        level="L1",
        rationale="Use MD5 authentication for RIP.",
        remediation="Configure: interface <IF> -> ip rip authentication mode md5",
        check=lambda c: (not bool(RE.router_rip.search(c))) or bool(RE.ip_rip_auth_mode_md5.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*ip rip authentication mode.*$", c, re.M)) or "not configured"
    ))

    # 3.3.4 - BGP Authentication
    rules.append(CISRule(
        id="CIS-3.3.4.1",
        title="Set 'neighbor password'",
        severity="high",
        level="L1",
        rationale="Use MD5 authentication for BGP neighbors.",
        remediation="Configure: router bgp <AS> -> neighbor <IP> password <PASS>",
        check=lambda c: (not bool(RE.router_bgp.search(c))) or bool(RE.bgp_neighbor_password.search(c)),
        evidence=lambda c: "\n".join(re.findall(r"^\s*neighbor\s+\S+\s+password.*$", c, re.M)) or "not configured"
    ))

    return rules


def evaluate_cis_benchmark(config_text: str) -> Dict[str, Any]:
    """
    Evaluate device configuration against CIS Benchmark rules.

    Args:
        config_text: Raw turbo dump from device

    Returns:
        Dict containing CIS benchmark table format results
    """
    rules = build_cis_benchmark_rules()
    return evaluate_compliance(config_text, rules)
