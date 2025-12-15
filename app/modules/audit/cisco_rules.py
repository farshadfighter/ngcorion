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
        remediation="Configure: ip ssh timeout <5-120>",
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

    for rule in rules:
        try:
            compliant = bool(rule.check(config_text))
        except Exception:
            compliant = False

        try:
            evidence = rule.evidence(config_text).strip()
        except Exception:
            evidence = "(no evidence)"

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
            "total_findings_including_info": len(findings)
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
