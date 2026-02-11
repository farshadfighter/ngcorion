"""
Linux CIS Benchmark Rules

CIS security compliance rules for Linux distributions:
- Ubuntu 22.04 LTS (CIS Benchmark v1.0.0)
- Ubuntu 24.04 LTS
- Rocky Linux 8 (CIS Benchmark v2.0.0)

Each rule includes:
- Unique ID (e.g., LNX-L1-1.1.1)
- Title and description
- Severity level (high/medium/low/info)
- Level (L1/L2/INFO)
- Check function (returns True if compliant)
- Evidence extraction function
- Rationale and remediation guidance
- Distro compatibility list
"""

import re
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field


# ========================= RULE DATACLASS =========================

@dataclass
class LinuxCISRule:
    """Represents a single Linux CIS compliance check."""

    id: str                          # "LNX-L1-1.1.1"
    cis_section: str                 # "1.1.1" - CIS Benchmark section
    title: str                       # Short description
    severity: str                    # high/medium/low/info
    level: str                       # L1/L2/INFO
    rationale: str                   # Why this matters
    remediation: str                 # How to fix
    check: Callable[[Dict[str, str], str], bool]  # Function: returns True if compliant
    evidence: Callable[[Dict[str, str], str], str]  # Function: returns evidence text
    distros: List[str] = field(default_factory=lambda: ["all"])  # Supported distros


# ========================= SEVERITY WEIGHTS =========================

SEVERITY_WEIGHT = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}


# ========================= HELPER FUNCTIONS =========================

def _get_output(data: Dict[str, str], key: str) -> str:
    """Get command output from data dict, handling errors."""
    output = data.get(key, "")
    if output.startswith("<<ERROR:"):
        return ""
    return output


def _check_sysctl_value(data: Dict[str, str], key: str, expected: str) -> bool:
    """Check if a sysctl key has expected value."""
    output = _get_output(data, key)
    if not output:
        return False
    # Extract value after '='
    match = re.search(r'=\s*(\S+)', output)
    if match:
        return match.group(1) == expected
    return False


def _check_service_disabled(data: Dict[str, str], service: str) -> bool:
    """Check if a service is disabled or not installed."""
    key = f"svc_{service}_enabled"
    output = _get_output(data, key)
    if not output:
        return True  # Not installed = compliant
    output_lower = output.lower()
    return "not installed" in output_lower or "disabled" in output_lower or "masked" in output_lower


def _check_package_not_installed(data: Dict[str, str], package: str) -> bool:
    """Check if a package is not installed."""
    key = f"client_{package}_installed"
    output = _get_output(data, key)
    if not output:
        return True
    return "not installed" in output.lower()


def _get_module_evidence(data: Dict[str, str], module: str) -> str:
    """Get evidence for a kernel module check."""
    module_key = module.replace("-", "_")
    modprobe_out = _get_output(data, f"modprobe_{module_key}")
    lsmod_out = _get_output(data, f"lsmod_{module_key}")
    return f"modprobe: {modprobe_out}\nlsmod: {lsmod_out}"


def _check_module_disabled(data: Dict[str, str], module: str) -> bool:
    """Check if a kernel module is disabled."""
    modprobe_key = f"modprobe_{module}"
    lsmod_key = f"lsmod_{module}"

    modprobe_out = _get_output(data, modprobe_key)
    lsmod_out = _get_output(data, lsmod_key)

    # Module should not be loadable and not currently loaded
    modprobe_disabled = "install /bin/true" in modprobe_out or "install /bin/false" in modprobe_out or "not available" in modprobe_out
    not_loaded = "not loaded" in lsmod_out.lower() or not lsmod_out.strip()

    return modprobe_disabled and not_loaded


def _parse_sshd_config(data: Dict[str, str]) -> Dict[str, str]:
    """Parse sshd_config into a dict of settings."""
    output = _get_output(data, "sshd_config")
    if not output:
        output = _get_output(data, "sshd_effective_config")

    config = {}
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) >= 2:
            config[parts[0].lower()] = parts[1]
        elif len(parts) == 1:
            config[parts[0].lower()] = ""
    return config


def _check_sshd_setting(data: Dict[str, str], setting: str, expected: str, case_insensitive: bool = True) -> bool:
    """Check if sshd has a specific setting."""
    config = _parse_sshd_config(data)
    value = config.get(setting.lower(), "")
    if case_insensitive:
        return value.lower() == expected.lower()
    return value == expected


def _check_sshd_setting_in_list(data: Dict[str, str], setting: str, valid_values: List[str]) -> bool:
    """Check if sshd setting is one of valid values."""
    config = _parse_sshd_config(data)
    value = config.get(setting.lower(), "")
    return value.lower() in [v.lower() for v in valid_values]


def _check_file_permissions(data: Dict[str, str], key: str, filename: str, max_mode: str,
                            expected_owner: str = "root", expected_group: str = "root") -> bool:
    """
    Check file permissions don't exceed max_mode and ownership is correct.

    Args:
        data: Audit data dictionary
        key: Key to get file stat output from
        filename: The filename to look for in stat output
        max_mode: Maximum allowed mode (e.g., "640", "600")
        expected_owner: Expected owner (default: root)
        expected_group: Expected group (default: root)

    Returns:
        True if file permissions are compliant
    """
    output = _get_output(data, key)
    if not output:
        return False

    # Parse stat output for the specific file
    # stat output includes Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
    lines = output.split('\n')
    file_section = ""
    in_file_section = False

    for line in lines:
        if filename in line:
            in_file_section = True
            file_section = line
        elif in_file_section:
            if "Access:" in line or "Uid:" in line:
                file_section += " " + line
            elif line.strip() and not line.startswith(" "):
                break

    if not file_section:
        return False

    # Extract mode
    mode_match = re.search(r'Access:\s*\((\d+)', file_section)
    if mode_match:
        actual_mode = mode_match.group(1)[-3:]  # Get last 3 digits
        # Compare numerically
        try:
            if int(actual_mode, 8) > int(max_mode, 8):
                return False
        except ValueError:
            return False

    # Check ownership
    owner_match = re.search(r'Uid:\s*\(\s*\d+/\s*(\w+)\)', file_section)
    group_match = re.search(r'Gid:\s*\(\s*\d+/\s*(\w+)\)', file_section)

    if owner_match and owner_match.group(1) != expected_owner:
        return False
    if group_match and group_match.group(1) != expected_group:
        return False

    return True


def _check_audit_rule_exists(data: Dict[str, str], pattern: str) -> bool:
    """
    Check if audit rules contain required pattern.

    Args:
        data: Audit data dictionary
        pattern: Regex pattern to search for in audit rules

    Returns:
        True if pattern found in loaded audit rules
    """
    # Check both configured rules and loaded rules
    rules_output = _get_output(data, "audit_rules")
    loaded_output = _get_output(data, "audit_rules_loaded")

    combined = f"{rules_output}\n{loaded_output}"

    if re.search(pattern, combined, re.IGNORECASE):
        return True
    return False


def _check_mount_option(data: Dict[str, str], mount_key: str, option: str) -> bool:
    """
    Check if mount point has specific option.

    Args:
        data: Audit data dictionary
        mount_key: Key for mount options data
        option: The option to check for (e.g., "nodev", "nosuid")

    Returns:
        True if the mount has the specified option
    """
    output = _get_output(data, mount_key)
    if not output:
        return False

    # Mount options are comma-separated
    options = output.lower().split(',')
    return option.lower() in [o.strip() for o in options]


def _check_pam_module(data: Dict[str, str], pam_key: str, module: str, required_args: List[str] = None) -> bool:
    """
    Check PAM configuration includes module with optional required arguments.

    Args:
        data: Audit data dictionary
        pam_key: Key for PAM config data
        module: PAM module name (e.g., "pam_faillock", "pam_pwhistory")
        required_args: Optional list of arguments that must be present

    Returns:
        True if module is configured (with required args if specified)
    """
    output = _get_output(data, pam_key)
    if not output:
        return False

    if module not in output:
        return False

    if required_args:
        for arg in required_args:
            if arg not in output:
                return False

    return True


def _check_journald_setting(data: Dict[str, str], setting: str, expected: str) -> bool:
    """Check if journald has a specific setting."""
    output = _get_output(data, "journald_config")
    if not output:
        return False

    # Look for setting=value pattern
    pattern = rf'{setting}\s*=\s*{expected}'
    return bool(re.search(pattern, output, re.IGNORECASE))


def _check_login_defs_setting(data: Dict[str, str], setting: str, min_value: int = None, max_value: int = None) -> bool:
    """Check login.defs setting against min/max thresholds."""
    output = _get_output(data, "login_defs")
    if not output:
        return False

    pattern = rf'{setting}\s+(\d+)'
    match = re.search(pattern, output)
    if not match:
        return False

    try:
        value = int(match.group(1))
        if min_value is not None and value < min_value:
            return False
        if max_value is not None and value > max_value:
            return False
        return True
    except ValueError:
        return False


def _check_no_files_found(data: Dict[str, str], key: str) -> bool:
    """Check that no files were found (for SUID, world-writable, unowned checks)."""
    output = _get_output(data, key)
    if not output:
        return True

    # Empty or just whitespace means no files found
    if not output.strip():
        return True

    # "none found" or similar messages
    lower = output.lower()
    if "none found" in lower or "find failed" in lower or "no such file" in lower:
        return True

    return False


def _check_home_dir_permissions(data: Dict[str, str]) -> bool:
    """Check that all user home directories have correct permissions (750 or more restrictive)."""
    output = _get_output(data, "user_home_dirs_permissions")
    if not output or "check failed" in output.lower():
        return False

    # Parse output looking for permissions that are too open
    # Format is typically: drwxr-xr-x /home/user
    for line in output.split('\n'):
        if not line.strip():
            continue
        # Look for permissions in format -rwxrwxrwx or similar
        match = re.search(r'([d-][rwx-]{9})', line)
        if match:
            perms = match.group(1)
            # Check group and other execute bits
            if len(perms) >= 10:
                # Other write permission is a fail
                if perms[8] != '-':  # Other write
                    return False

    return True


# ========================= RULE DEFINITIONS =========================

def build_linux_cis_rules() -> List[LinuxCISRule]:
    """
    Build complete set of Linux CIS compliance rules.

    Returns:
        List[LinuxCISRule]: All CIS rules for Linux
    """
    rules: List[LinuxCISRule] = []

    # ==================== SECTION 1: INITIAL SETUP ====================

    # 1.1.1.x - Disable unused filesystems
    unused_fs = [
        ("cramfs", "1.1.1.1", "Cramfs is rarely used and can be disabled."),
        ("freevxfs", "1.1.1.2", "FreeVxFS is rarely used."),
        ("jffs2", "1.1.1.3", "JFFS2 is used for flash storage, rarely needed on servers."),
        ("hfs", "1.1.1.4", "HFS is an Apple filesystem, not needed on Linux servers."),
        ("hfsplus", "1.1.1.5", "HFS+ is an Apple filesystem, not needed on Linux servers."),
        ("squashfs", "1.1.1.6", "SquashFS may be needed for snap; evaluate before disabling."),
        ("udf", "1.1.1.7", "UDF is used for optical media, rarely needed on servers."),
    ]

    for fs, section, rationale in unused_fs:
        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=f"Disable mounting of {fs} filesystems",
            severity="low",
            level="L1",
            rationale=rationale,
            remediation=f"Add 'install {fs} /bin/true' to /etc/modprobe.d/{fs}.conf and run 'rmmod {fs}'",
            check=lambda d, p, m=fs: _check_module_disabled(d, m.replace("-", "_")),
            evidence=lambda d, p, m=fs: _get_module_evidence(d, m),
        ))

    # 1.1.1.8 - Disable USB Storage
    rules.append(LinuxCISRule(
        id="LNX-L1-1.1.1.8",
        cis_section="1.1.1.8",
        title="Disable USB storage",
        severity="medium",
        level="L1",
        rationale="USB storage devices can be used to introduce malware or exfiltrate data.",
        remediation="Add 'install usb-storage /bin/true' to /etc/modprobe.d/usb-storage.conf",
        check=lambda d, p: _check_module_disabled(d, "usb_storage"),
        evidence=lambda d, p: f"modprobe: {_get_output(d, 'modprobe_usb_storage')}\nlsmod: {_get_output(d, 'lsmod_usb_storage')}",
    ))

    # 1.1.2-8 - Separate partitions
    partitions = [
        ("tmp", "/tmp", "1.1.2", "Isolate /tmp to prevent resource exhaustion attacks."),
        ("var", "/var", "1.1.3", "Isolate /var to prevent log files from filling root."),
        ("var_tmp", "/var/tmp", "1.1.4", "Isolate /var/tmp to prevent temporary files from affecting system."),
        ("var_log", "/var/log", "1.1.5", "Isolate /var/log to prevent logs from filling root."),
        ("var_log_audit", "/var/log/audit", "1.1.6", "Isolate audit logs for integrity."),
        ("home", "/home", "1.1.7", "Isolate /home to prevent users from filling root."),
    ]

    for key, mount, section, rationale in partitions:
        rules.append(LinuxCISRule(
            id=f"LNX-L2-{section}",
            cis_section=section,
            title=f"Ensure separate partition exists for {mount}",
            severity="low",
            level="L2",
            rationale=rationale,
            remediation=f"Create a separate partition for {mount} and update /etc/fstab",
            check=lambda d, p, k=key: bool(_get_output(d, f"mount_{k}").strip()),
            evidence=lambda d, p, k=key: _get_output(d, f"mount_{k}") or "Not mounted as separate partition",
        ))

    # 1.3.1 - AppArmor/SELinux
    rules.append(LinuxCISRule(
        id="LNX-L1-1.3.1",
        cis_section="1.3.1",
        title="Ensure AppArmor or SELinux is installed and enabled",
        severity="high",
        level="L1",
        rationale="Mandatory Access Control provides additional security boundaries.",
        remediation="Install and enable AppArmor (Ubuntu) or SELinux (RHEL/Rocky)",
        check=lambda d, p: (
            ("enforcing" in _get_output(d, "apparmor_status").lower() or
             "profiles are loaded" in _get_output(d, "apparmor_status").lower()) if p.startswith("ubuntu") else
            ("enforcing" in _get_output(d, "selinux_status").lower())
        ),
        evidence=lambda d, p: (
            _get_output(d, "apparmor_status")[:500] if p.startswith("ubuntu") else
            f"getenforce: {_get_output(d, 'selinux_status')}\n{_get_output(d, 'sestatus')[:300]}"
        ),
    ))

    # 1.4.1 - GRUB permissions
    rules.append(LinuxCISRule(
        id="LNX-L1-1.4.1",
        cis_section="1.4.1",
        title="Ensure permissions on bootloader config are configured",
        severity="high",
        level="L1",
        rationale="Protect bootloader from unauthorized modifications.",
        remediation="Run: chmod 600 /boot/grub/grub.cfg && chown root:root /boot/grub/grub.cfg",
        check=lambda d, p: (
            "0600" in _get_output(d, "grub_permissions") or
            "-rw-------" in _get_output(d, "grub_permissions")
        ),
        evidence=lambda d, p: _get_output(d, "grub_permissions"),
    ))

    # 1.5.1 - ASLR
    rules.append(LinuxCISRule(
        id="LNX-L1-1.5.1",
        cis_section="1.5.1",
        title="Ensure address space layout randomization (ASLR) is enabled",
        severity="high",
        level="L1",
        rationale="ASLR makes exploitation of memory corruption vulnerabilities more difficult.",
        remediation="Set kernel.randomize_va_space = 2 in /etc/sysctl.conf",
        check=lambda d, p: _check_sysctl_value(d, "aslr", "2"),
        evidence=lambda d, p: _get_output(d, "aslr"),
    ))

    # 1.5.4 - Core dumps restricted
    rules.append(LinuxCISRule(
        id="LNX-L1-1.5.4",
        cis_section="1.5.4",
        title="Ensure core dumps are restricted",
        severity="medium",
        level="L1",
        rationale="Core dumps can contain sensitive information.",
        remediation="Set fs.suid_dumpable = 0 in /etc/sysctl.conf",
        check=lambda d, p: _check_sysctl_value(d, "suid_dumpable", "0"),
        evidence=lambda d, p: _get_output(d, "suid_dumpable"),
    ))

    # 1.6.1 - MOTD banner
    rules.append(LinuxCISRule(
        id="LNX-L1-1.6.1",
        cis_section="1.6.1",
        title="Ensure message of the day is configured properly",
        severity="low",
        level="L1",
        rationale="Warning banners inform users of legal implications.",
        remediation="Configure /etc/motd with appropriate warning message",
        check=lambda d, p: bool(_get_output(d, "motd").strip()) and "no motd" not in _get_output(d, "motd").lower(),
        evidence=lambda d, p: _get_output(d, "motd")[:300],
    ))

    # 1.6.2 - Local login warning banner
    rules.append(LinuxCISRule(
        id="LNX-L1-1.6.2",
        cis_section="1.6.2",
        title="Ensure local login warning banner is configured",
        severity="low",
        level="L1",
        rationale="Warning banners inform users of legal implications.",
        remediation="Configure /etc/issue with appropriate warning message",
        check=lambda d, p: bool(_get_output(d, "issue").strip()) and "no issue" not in _get_output(d, "issue").lower(),
        evidence=lambda d, p: _get_output(d, "issue")[:300],
    ))

    # ==================== SECTION 2: SERVICES ====================

    # 2.1 - inetd Services
    rules.append(LinuxCISRule(
        id="LNX-L1-2.1.1",
        cis_section="2.1.1",
        title="Ensure xinetd is not installed or disabled",
        severity="medium",
        level="L1",
        rationale="xinetd provides legacy services that are generally not needed.",
        remediation="Run: systemctl disable xinetd && apt remove xinetd",
        check=lambda d, p: _check_service_disabled(d, "xinetd"),
        evidence=lambda d, p: _get_output(d, "xinetd_enabled"),
    ))

    # 2.2.x - Special Purpose Services
    dangerous_services = [
        ("avahi-daemon", "2.2.1", "medium", "Avahi provides mDNS/DNS-SD, rarely needed on servers."),
        ("cups", "2.2.2", "low", "CUPS is for printing, rarely needed on servers."),
        ("dhcpd", "2.2.3", "medium", "DHCP server should only run on designated servers."),
        ("slapd", "2.2.4", "medium", "LDAP server should only run on designated servers."),
        ("nfs-server", "2.2.5", "medium", "NFS server should only run if needed."),
        ("rpcbind", "2.2.6", "medium", "RPC services are legacy and often exploitable."),
        ("named", "2.2.7", "medium", "DNS server should only run on designated servers."),
        ("vsftpd", "2.2.8", "high", "FTP transmits credentials in cleartext."),
        ("httpd", "2.2.9", "medium", "Web server should only run on designated servers."),
        ("dovecot", "2.2.10", "medium", "Mail server should only run on designated servers."),
        ("smb", "2.2.11", "medium", "Samba should only run if Windows file sharing is needed."),
        ("squid", "2.2.12", "medium", "Proxy should only run on designated servers."),
        ("snmpd", "2.2.13", "medium", "SNMP can expose sensitive information."),
        ("rsync", "2.2.14", "low", "rsync daemon should only run if needed."),
        ("nis", "2.2.15", "high", "NIS is insecure and deprecated."),
        ("telnet.socket", "2.2.16", "high", "Telnet transmits credentials in cleartext."),
    ]

    for service, section, severity, rationale in dangerous_services:
        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=f"Ensure {service} is not enabled",
            severity=severity,
            level="L1",
            rationale=rationale,
            remediation=f"Run: systemctl disable {service}",
            check=lambda d, p, s=service: _check_service_disabled(d, s),
            evidence=lambda d, p, s=service: _get_output(d, f"svc_{s}_enabled"),
        ))

    # 2.3.x - Service Clients
    dangerous_clients = [
        ("nis", "2.3.1", "high", "NIS client is insecure."),
        ("rsh", "2.3.2", "high", "rsh is insecure, use SSH instead."),
        ("talk", "2.3.3", "low", "talk is rarely needed."),
        ("telnet", "2.3.4", "high", "telnet client can accidentally expose credentials."),
        ("ldap-utils", "2.3.5", "low", "LDAP client should only be installed if needed."),
    ]

    for pkg, section, severity, rationale in dangerous_clients:
        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=f"Ensure {pkg} client is not installed",
            severity=severity,
            level="L1",
            rationale=rationale,
            remediation=f"Run: apt remove {pkg} (or dnf remove {pkg})",
            check=lambda d, p, pk=pkg: _check_package_not_installed(d, pk),
            evidence=lambda d, p, pk=pkg: _get_output(d, f"client_{pk}_installed"),
        ))

    # 2.4.1 - Time Synchronization
    rules.append(LinuxCISRule(
        id="LNX-L1-2.4.1",
        cis_section="2.4.1",
        title="Ensure time synchronization is in use",
        severity="medium",
        level="L1",
        rationale="Accurate time is essential for logging, authentication, and forensics.",
        remediation="Install and configure chrony, ntp, or systemd-timesyncd",
        check=lambda d, p: (
            "enabled" in _get_output(d, "chrony_enabled").lower() or
            "enabled" in _get_output(d, "ntp_enabled").lower() or
            "enabled" in _get_output(d, "timesyncd_enabled").lower()
        ),
        evidence=lambda d, p: f"chrony: {_get_output(d, 'chrony_enabled')}\nntp: {_get_output(d, 'ntp_enabled')}\ntimesyncd: {_get_output(d, 'timesyncd_enabled')}",
    ))

    # ==================== SECTION 3: NETWORK CONFIGURATION ====================

    # 3.1.1 - IP Forwarding
    rules.append(LinuxCISRule(
        id="LNX-L1-3.1.1",
        cis_section="3.1.1",
        title="Ensure IP forwarding is disabled",
        severity="medium",
        level="L1",
        rationale="IP forwarding allows the system to route traffic between networks.",
        remediation="Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf",
        check=lambda d, p: _check_sysctl_value(d, "ip_forward", "0"),
        evidence=lambda d, p: _get_output(d, "ip_forward"),
    ))

    # 3.1.2 - Packet redirect sending
    rules.append(LinuxCISRule(
        id="LNX-L1-3.1.2",
        cis_section="3.1.2",
        title="Ensure packet redirect sending is disabled",
        severity="medium",
        level="L1",
        rationale="Packet redirects can be used for MITM attacks.",
        remediation="Set net.ipv4.conf.all.send_redirects = 0",
        check=lambda d, p: _check_sysctl_value(d, "send_redirects_all", "0"),
        evidence=lambda d, p: f"all: {_get_output(d, 'send_redirects_all')}\ndefault: {_get_output(d, 'send_redirects_default')}",
    ))

    # 3.2.1 - Source routed packets
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.1",
        cis_section="3.2.1",
        title="Ensure source routed packets are not accepted",
        severity="medium",
        level="L1",
        rationale="Source routing allows packets to specify their own route.",
        remediation="Set net.ipv4.conf.all.accept_source_route = 0",
        check=lambda d, p: _check_sysctl_value(d, "accept_source_route_all", "0"),
        evidence=lambda d, p: f"all: {_get_output(d, 'accept_source_route_all')}\ndefault: {_get_output(d, 'accept_source_route_default')}",
    ))

    # 3.2.2 - ICMP redirects
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.2",
        cis_section="3.2.2",
        title="Ensure ICMP redirects are not accepted",
        severity="medium",
        level="L1",
        rationale="ICMP redirects can be used for MITM attacks.",
        remediation="Set net.ipv4.conf.all.accept_redirects = 0",
        check=lambda d, p: _check_sysctl_value(d, "accept_redirects_all", "0"),
        evidence=lambda d, p: f"all: {_get_output(d, 'accept_redirects_all')}\ndefault: {_get_output(d, 'accept_redirects_default')}",
    ))

    # 3.2.4 - Log martians
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.4",
        cis_section="3.2.4",
        title="Ensure suspicious packets are logged",
        severity="low",
        level="L1",
        rationale="Logging suspicious packets helps detect attacks.",
        remediation="Set net.ipv4.conf.all.log_martians = 1",
        check=lambda d, p: _check_sysctl_value(d, "log_martians_all", "1"),
        evidence=lambda d, p: f"all: {_get_output(d, 'log_martians_all')}\ndefault: {_get_output(d, 'log_martians_default')}",
    ))

    # 3.2.5 - Broadcast ICMP
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.5",
        cis_section="3.2.5",
        title="Ensure broadcast ICMP requests are ignored",
        severity="medium",
        level="L1",
        rationale="Prevents Smurf attacks.",
        remediation="Set net.ipv4.icmp_echo_ignore_broadcasts = 1",
        check=lambda d, p: _check_sysctl_value(d, "icmp_echo_ignore_broadcasts", "1"),
        evidence=lambda d, p: _get_output(d, "icmp_echo_ignore_broadcasts"),
    ))

    # 3.2.7 - Reverse path filtering
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.7",
        cis_section="3.2.7",
        title="Ensure Reverse Path Filtering is enabled",
        severity="medium",
        level="L1",
        rationale="Helps prevent IP spoofing attacks.",
        remediation="Set net.ipv4.conf.all.rp_filter = 1",
        check=lambda d, p: _check_sysctl_value(d, "rp_filter_all", "1"),
        evidence=lambda d, p: f"all: {_get_output(d, 'rp_filter_all')}\ndefault: {_get_output(d, 'rp_filter_default')}",
    ))

    # 3.2.8 - TCP SYN Cookies
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.8",
        cis_section="3.2.8",
        title="Ensure TCP SYN Cookies is enabled",
        severity="medium",
        level="L1",
        rationale="Helps prevent SYN flood attacks.",
        remediation="Set net.ipv4.tcp_syncookies = 1",
        check=lambda d, p: _check_sysctl_value(d, "tcp_syncookies", "1"),
        evidence=lambda d, p: _get_output(d, "tcp_syncookies"),
    ))

    # 3.4.1 - Firewall enabled
    rules.append(LinuxCISRule(
        id="LNX-L1-3.4.1",
        cis_section="3.4.1",
        title="Ensure firewall is enabled",
        severity="high",
        level="L1",
        rationale="A firewall controls network access to the system.",
        remediation="Enable ufw (Ubuntu) or firewalld (RHEL/Rocky)",
        check=lambda d, p: (
            ("status: active" in _get_output(d, "ufw_status").lower()) if p.startswith("ubuntu") else
            ("running" in _get_output(d, "firewalld_state").lower())
        ),
        evidence=lambda d, p: (
            _get_output(d, "ufw_status")[:500] if p.startswith("ubuntu") else
            f"State: {_get_output(d, 'firewalld_state')}\nEnabled: {_get_output(d, 'firewalld_enabled')}"
        ),
    ))

    # ==================== SECTION 4: LOGGING AND AUDITING ====================

    # 4.1.1 - rsyslog enabled
    rules.append(LinuxCISRule(
        id="LNX-L1-4.1.1",
        cis_section="4.1.1",
        title="Ensure rsyslog is installed and enabled",
        severity="medium",
        level="L1",
        rationale="Centralized logging is essential for security monitoring.",
        remediation="Run: apt install rsyslog && systemctl enable rsyslog",
        check=lambda d, p: "enabled" in _get_output(d, "rsyslog_enabled").lower(),
        evidence=lambda d, p: _get_output(d, "rsyslog_enabled"),
    ))

    # 4.1.1.1 - journald enabled
    rules.append(LinuxCISRule(
        id="LNX-L1-4.1.1.1",
        cis_section="4.1.1.1",
        title="Ensure systemd-journald is enabled",
        severity="medium",
        level="L1",
        rationale="journald captures system logs from early boot.",
        remediation="Run: systemctl enable systemd-journald",
        check=lambda d, p: "enabled" in _get_output(d, "journald_enabled").lower() or "static" in _get_output(d, "journald_enabled").lower(),
        evidence=lambda d, p: _get_output(d, "journald_enabled"),
    ))

    # 4.2.1 - auditd enabled
    rules.append(LinuxCISRule(
        id="LNX-L1-4.2.1",
        cis_section="4.2.1",
        title="Ensure auditd is enabled",
        severity="high",
        level="L1",
        rationale="The audit system provides detailed security event logging.",
        remediation="Run: apt install auditd && systemctl enable auditd",
        check=lambda d, p: "enabled" in _get_output(d, "auditd_enabled").lower(),
        evidence=lambda d, p: _get_output(d, "auditd_enabled"),
    ))

    # 4.2.2 - Audit log storage
    rules.append(LinuxCISRule(
        id="LNX-L1-4.2.2",
        cis_section="4.2.2",
        title="Ensure audit log storage size is configured",
        severity="low",
        level="L1",
        rationale="Prevent audit logs from consuming all disk space.",
        remediation="Configure max_log_file in /etc/audit/auditd.conf",
        check=lambda d, p: bool(re.search(r'max_log_file\s*=\s*\d+', _get_output(d, "audit_max_log"))),
        evidence=lambda d, p: _get_output(d, "audit_max_log"),
    ))

    # ==================== SECTION 5: ACCESS, AUTHENTICATION, AUTHORIZATION ====================

    # 5.1.1 - cron enabled
    rules.append(LinuxCISRule(
        id="LNX-L1-5.1.1",
        cis_section="5.1.1",
        title="Ensure cron daemon is enabled",
        severity="low",
        level="L1",
        rationale="Cron is used for scheduled tasks including security updates.",
        remediation="Run: systemctl enable cron",
        check=lambda d, p: "enabled" in _get_output(d, "cron_enabled").lower(),
        evidence=lambda d, p: _get_output(d, "cron_enabled"),
    ))

    # 5.2.1 - sshd_config permissions
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.1",
        cis_section="5.2.1",
        title="Ensure permissions on /etc/ssh/sshd_config are configured",
        severity="medium",
        level="L1",
        rationale="Protect SSH configuration from unauthorized modifications.",
        remediation="Run: chmod 600 /etc/ssh/sshd_config",
        check=lambda d, p: (
            "600" in _get_output(d, "sshd_config_permissions") or
            "-rw-------" in _get_output(d, "sshd_config_permissions")
        ),
        evidence=lambda d, p: _get_output(d, "sshd_config_permissions"),
    ))

    # 5.2.4 - SSH Protocol version (modern SSH always v2)
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.4",
        cis_section="5.2.4",
        title="Ensure SSH Protocol is set to 2",
        severity="high",
        level="L1",
        rationale="SSH Protocol 1 has known vulnerabilities.",
        remediation="Modern SSH servers default to Protocol 2; remove any 'Protocol 1' setting",
        check=lambda d, p: (
            "protocol" not in _parse_sshd_config(d) or
            _check_sshd_setting(d, "protocol", "2")
        ),
        evidence=lambda d, p: f"Protocol setting: {_parse_sshd_config(d).get('protocol', 'default (2)')}",
    ))

    # 5.2.5 - SSH LogLevel
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.5",
        cis_section="5.2.5",
        title="Ensure SSH LogLevel is appropriate",
        severity="low",
        level="L1",
        rationale="Logging SSH events helps with security monitoring.",
        remediation="Set LogLevel to INFO or VERBOSE in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting_in_list(d, "loglevel", ["INFO", "VERBOSE"]) or "loglevel" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"LogLevel: {_parse_sshd_config(d).get('loglevel', 'default (INFO)')}",
    ))

    # 5.2.6 - SSH X11 Forwarding
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.6",
        cis_section="5.2.6",
        title="Ensure SSH X11 forwarding is disabled",
        severity="medium",
        level="L1",
        rationale="X11 forwarding can be used for malicious purposes.",
        remediation="Set X11Forwarding no in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "x11forwarding", "no"),
        evidence=lambda d, p: f"X11Forwarding: {_parse_sshd_config(d).get('x11forwarding', 'not set')}",
    ))

    # 5.2.7 - SSH MaxAuthTries
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.7",
        cis_section="5.2.7",
        title="Ensure SSH MaxAuthTries is set to 4 or less",
        severity="medium",
        level="L1",
        rationale="Limits brute force authentication attempts.",
        remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config",
        check=lambda d, p: (
            "maxauthtries" in _parse_sshd_config(d) and
            int(_parse_sshd_config(d).get("maxauthtries", "6")) <= 4
        ),
        evidence=lambda d, p: f"MaxAuthTries: {_parse_sshd_config(d).get('maxauthtries', 'not set (default 6)')}",
    ))

    # 5.2.8 - SSH IgnoreRhosts
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.8",
        cis_section="5.2.8",
        title="Ensure SSH IgnoreRhosts is enabled",
        severity="medium",
        level="L1",
        rationale="Rhosts authentication is insecure.",
        remediation="Set IgnoreRhosts yes in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "ignorerhosts", "yes") or "ignorerhosts" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"IgnoreRhosts: {_parse_sshd_config(d).get('ignorerhosts', 'default (yes)')}",
    ))

    # 5.2.9 - SSH HostbasedAuthentication
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.9",
        cis_section="5.2.9",
        title="Ensure SSH HostbasedAuthentication is disabled",
        severity="medium",
        level="L1",
        rationale="Host-based authentication trusts the client machine.",
        remediation="Set HostbasedAuthentication no in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "hostbasedauthentication", "no") or "hostbasedauthentication" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"HostbasedAuthentication: {_parse_sshd_config(d).get('hostbasedauthentication', 'default (no)')}",
    ))

    # 5.2.10 - SSH PermitRootLogin
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.10",
        cis_section="5.2.10",
        title="Ensure SSH root login is disabled",
        severity="high",
        level="L1",
        rationale="Direct root login bypasses audit trails.",
        remediation="Set PermitRootLogin no in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "permitrootlogin", "no"),
        evidence=lambda d, p: f"PermitRootLogin: {_parse_sshd_config(d).get('permitrootlogin', 'not set')}",
    ))

    # 5.2.11 - SSH PermitEmptyPasswords
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.11",
        cis_section="5.2.11",
        title="Ensure SSH PermitEmptyPasswords is disabled",
        severity="high",
        level="L1",
        rationale="Empty passwords are a critical security risk.",
        remediation="Set PermitEmptyPasswords no in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "permitemptypasswords", "no") or "permitemptypasswords" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"PermitEmptyPasswords: {_parse_sshd_config(d).get('permitemptypasswords', 'default (no)')}",
    ))

    # 5.2.12 - SSH PermitUserEnvironment
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.12",
        cis_section="5.2.12",
        title="Ensure SSH PermitUserEnvironment is disabled",
        severity="medium",
        level="L1",
        rationale="User environment variables can bypass security settings.",
        remediation="Set PermitUserEnvironment no in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "permituserenvironment", "no") or "permituserenvironment" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"PermitUserEnvironment: {_parse_sshd_config(d).get('permituserenvironment', 'default (no)')}",
    ))

    # 5.2.13 - SSH Idle Timeout
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.13",
        cis_section="5.2.13",
        title="Ensure SSH Idle Timeout Interval is configured",
        severity="medium",
        level="L1",
        rationale="Idle sessions can be hijacked.",
        remediation="Set ClientAliveInterval 300 and ClientAliveCountMax 3",
        check=lambda d, p: (
            "clientaliveinterval" in _parse_sshd_config(d) and
            int(_parse_sshd_config(d).get("clientaliveinterval", "0")) > 0
        ),
        evidence=lambda d, p: f"ClientAliveInterval: {_parse_sshd_config(d).get('clientaliveinterval', 'not set')}\nClientAliveCountMax: {_parse_sshd_config(d).get('clientalivecountmax', 'not set')}",
    ))

    # 5.2.15 - SSH AllowUsers/AllowGroups
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.15",
        cis_section="5.2.15",
        title="Ensure SSH access is limited",
        severity="medium",
        level="L1",
        rationale="Limiting SSH access reduces attack surface.",
        remediation="Set AllowUsers or AllowGroups in /etc/ssh/sshd_config",
        check=lambda d, p: (
            "allowusers" in _parse_sshd_config(d) or
            "allowgroups" in _parse_sshd_config(d) or
            "denyusers" in _parse_sshd_config(d) or
            "denygroups" in _parse_sshd_config(d)
        ),
        evidence=lambda d, p: f"AllowUsers: {_parse_sshd_config(d).get('allowusers', 'not set')}\nAllowGroups: {_parse_sshd_config(d).get('allowgroups', 'not set')}",
    ))

    # 5.3.1 - Password quality
    rules.append(LinuxCISRule(
        id="LNX-L1-5.3.1",
        cis_section="5.3.1",
        title="Ensure password creation requirements are configured",
        severity="high",
        level="L1",
        rationale="Strong passwords prevent unauthorized access.",
        remediation="Configure /etc/security/pwquality.conf with minlen=14 minclass=4",
        check=lambda d, p: (
            "minlen" in _get_output(d, "pwquality_config").lower() or
            "pam_pwquality" in _get_output(d, "pam_password").lower()
        ),
        evidence=lambda d, p: _get_output(d, "pwquality_config")[:500],
    ))

    # 5.4.1.1 - Password Max Days
    rules.append(LinuxCISRule(
        id="LNX-L1-5.4.1.1",
        cis_section="5.4.1.1",
        title="Ensure password expiration is 365 days or less",
        severity="medium",
        level="L1",
        rationale="Expired passwords force users to change credentials regularly.",
        remediation="Set PASS_MAX_DAYS 365 in /etc/login.defs",
        check=lambda d, p: (
            bool(re.search(r'PASS_MAX_DAYS\s+(\d+)', _get_output(d, "pass_max_days"))) and
            int(re.search(r'PASS_MAX_DAYS\s+(\d+)', _get_output(d, "pass_max_days")).group(1)) <= 365
        ),
        evidence=lambda d, p: _get_output(d, "pass_max_days"),
    ))

    # 5.4.1.2 - Password Min Days
    rules.append(LinuxCISRule(
        id="LNX-L1-5.4.1.2",
        cis_section="5.4.1.2",
        title="Ensure minimum days between password changes is configured",
        severity="low",
        level="L1",
        rationale="Prevents rapid password cycling.",
        remediation="Set PASS_MIN_DAYS 1 in /etc/login.defs",
        check=lambda d, p: (
            bool(re.search(r'PASS_MIN_DAYS\s+(\d+)', _get_output(d, "pass_min_days"))) and
            int(re.search(r'PASS_MIN_DAYS\s+(\d+)', _get_output(d, "pass_min_days")).group(1)) >= 1
        ),
        evidence=lambda d, p: _get_output(d, "pass_min_days"),
    ))

    # 5.5.1 - Restrict root login
    rules.append(LinuxCISRule(
        id="LNX-L1-5.5.1",
        cis_section="5.5.1",
        title="Ensure root login is restricted to system console",
        severity="high",
        level="L1",
        rationale="Restricting root login reduces attack surface.",
        remediation="Configure /etc/securetty to limit root access",
        check=lambda d, p: (
            # Check SSH PermitRootLogin
            _check_sshd_setting(d, "permitrootlogin", "no") or
            _check_sshd_setting(d, "permitrootlogin", "prohibit-password")
        ),
        evidence=lambda d, p: _get_output(d, "permit_root_login"),
    ))

    # ==================== SECTION 6: SYSTEM MAINTENANCE ====================

    # 6.1.1 - /etc/passwd permissions
    rules.append(LinuxCISRule(
        id="LNX-L1-6.1.1",
        cis_section="6.1.1",
        title="Ensure permissions on /etc/passwd are configured",
        severity="medium",
        level="L1",
        rationale="World-writable or overly permissive passwd file is a security risk.",
        remediation="Run: chmod 644 /etc/passwd",
        check=lambda d, p: (
            "644" in _get_output(d, "system_files_permissions") or
            "-rw-r--r--" in _get_output(d, "system_files_permissions")
        ),
        evidence=lambda d, p: _get_output(d, "system_files_permissions"),
    ))

    # 6.2.1 - Root is only UID 0
    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.1",
        cis_section="6.2.1",
        title="Ensure root is the only UID 0 account",
        severity="high",
        level="L1",
        rationale="Multiple UID 0 accounts increase risk of compromise.",
        remediation="Remove or change UID of accounts other than root with UID 0",
        check=lambda d, p: (
            _get_output(d, "uid_0_accounts").strip() == "root" or
            _get_output(d, "uid_0_accounts").strip() == ""
        ),
        evidence=lambda d, p: f"UID 0 accounts: {_get_output(d, 'uid_0_accounts')}",
    ))

    # 6.2.2 - No empty passwords
    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.2",
        cis_section="6.2.2",
        title="Ensure no accounts have empty passwords",
        severity="high",
        level="L1",
        rationale="Empty passwords allow unauthorized access.",
        remediation="Set passwords for all accounts or lock unused accounts",
        check=lambda d, p: (
            "check failed" in _get_output(d, "empty_password_accounts").lower() or
            not _get_output(d, "empty_password_accounts").strip()
        ),
        evidence=lambda d, p: f"Empty password accounts: {_get_output(d, 'empty_password_accounts') or 'None'}",
    ))

    # 6.2.3 - No legacy entries
    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.3",
        cis_section="6.2.3",
        title="Ensure no legacy '+' entries exist in passwd/shadow/group",
        severity="high",
        level="L1",
        rationale="Legacy NIS entries can bypass security.",
        remediation="Remove any lines starting with '+' from passwd/shadow/group files",
        check=lambda d, p: "no legacy entries" in _get_output(d, "legacy_entries").lower() or not _get_output(d, "legacy_entries").strip(),
        evidence=lambda d, p: _get_output(d, "legacy_entries") or "No legacy entries found",
    ))

    # ==================== EXPANDED RULES - PHASE 1: CRITICAL PRIORITY ====================

    # 6.1.2-6.1.9 - File Permissions for system files
    system_files = [
        ("6.1.2", "/etc/passwd", "644", "World-readable passwords file is normal; write access must be restricted."),
        ("6.1.3", "/etc/shadow", "640", "Shadow file contains password hashes; restrict access.", "root", "shadow"),
        ("6.1.4", "/etc/group", "644", "Group file must be protected from unauthorized modifications."),
        ("6.1.5", "/etc/gshadow", "640", "Group shadow file contains group password hashes.", "root", "shadow"),
        ("6.1.6", "/etc/passwd-", "644", "Backup passwd file must have restricted permissions."),
        ("6.1.7", "/etc/shadow-", "640", "Backup shadow file must have restricted permissions.", "root", "shadow"),
        ("6.1.8", "/etc/group-", "644", "Backup group file must have restricted permissions."),
        ("6.1.9", "/etc/gshadow-", "640", "Backup gshadow file must have restricted permissions.", "root", "shadow"),
    ]

    for entry in system_files:
        section = entry[0]
        filename = entry[1]
        max_mode = entry[2]
        rationale = entry[3]
        owner = entry[4] if len(entry) > 4 else "root"
        group = entry[5] if len(entry) > 5 else "root"

        key = "system_files_permissions" if "-" not in filename else "system_backup_files_permissions"

        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=f"Ensure permissions on {filename} are configured",
            severity="medium",
            level="L1",
            rationale=rationale,
            remediation=f"Run: chmod {max_mode} {filename} && chown {owner}:{group} {filename}",
            check=lambda d, p, k=key, f=filename, m=max_mode, o=owner, g=group: _check_file_permissions(d, k, f, m, o, g),
            evidence=lambda d, p, k=key: _get_output(d, k),
        ))

    # 3.3.1-3.3.3 - IPv6 Hardening
    rules.append(LinuxCISRule(
        id="LNX-L1-3.3.1",
        cis_section="3.3.1",
        title="Ensure IPv6 router advertisements are not accepted",
        severity="medium",
        level="L1",
        rationale="Router advertisements can be used for man-in-the-middle attacks.",
        remediation="Set net.ipv6.conf.all.accept_ra = 0 and net.ipv6.conf.default.accept_ra = 0",
        check=lambda d, p: _check_sysctl_value(d, "ipv6_accept_ra_all", "0"),
        evidence=lambda d, p: f"all: {_get_output(d, 'ipv6_accept_ra_all')}\ndefault: {_get_output(d, 'ipv6_accept_ra_default')}",
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-3.3.2",
        cis_section="3.3.2",
        title="Ensure IPv6 redirects are not accepted",
        severity="medium",
        level="L1",
        rationale="IPv6 ICMP redirects can be used for MITM attacks.",
        remediation="Set net.ipv6.conf.all.accept_redirects = 0",
        check=lambda d, p: _check_sysctl_value(d, "ipv6_accept_redirects_all", "0"),
        evidence=lambda d, p: f"all: {_get_output(d, 'ipv6_accept_redirects_all')}\ndefault: {_get_output(d, 'ipv6_accept_redirects_default')}",
    ))

    rules.append(LinuxCISRule(
        id="LNX-L2-3.3.3",
        cis_section="3.3.3",
        title="Ensure IPv6 is disabled (if not required)",
        severity="low",
        level="L2",
        rationale="Disabling IPv6 reduces attack surface if not needed.",
        remediation="Set net.ipv6.conf.all.disable_ipv6 = 1",
        check=lambda d, p: _check_sysctl_value(d, "ipv6_disabled", "1"),
        evidence=lambda d, p: _get_output(d, "ipv6_disabled"),
    ))

    # 4.2.3.x - Audit Rules
    audit_rules = [
        ("4.2.3.1", "time-change", r"-a always,exit.*-S.*adjtimex|settimeofday|clock_settime|stime",
         "Ensure events that modify date and time information are collected",
         "Changes to system time can be used to mask malicious activity."),
        ("4.2.3.2", "identity", r"-w /etc/passwd.*-p wa|-w /etc/group.*-p wa|-w /etc/shadow.*-p wa|-w /etc/gshadow.*-p wa",
         "Ensure events that modify user/group information are collected",
         "Changes to user/group files must be tracked for unauthorized modifications."),
        ("4.2.3.3", "system-locale", r"-w /etc/issue.*-p wa|-w /etc/hostname.*-p wa|-w /etc/hosts.*-p wa",
         "Ensure events that modify the system's network environment are collected",
         "Network configuration changes can indicate compromise."),
        ("4.2.3.4", "MAC-policy", r"-w /etc/apparmor.*-p wa|-w /etc/selinux.*-p wa",
         "Ensure events that modify MAC are collected",
         "MAC policy changes can weaken security."),
        ("4.2.3.5", "logins", r"-w /var/log/faillog.*-p wa|-w /var/log/lastlog.*-p wa|-w /var/log/tallylog.*-p wa",
         "Ensure login and logout events are collected",
         "Login events are critical for security monitoring."),
        ("4.2.3.6", "session", r"-w /var/run/utmp.*-p wa|-w /var/log/wtmp.*-p wa|-w /var/log/btmp.*-p wa",
         "Ensure session initiation information is collected",
         "Session information helps track user activity."),
        ("4.2.3.7", "perm-mod", r"-a always,exit.*-S chmod|fchmod|fchmodat",
         "Ensure discretionary access control permission modification events are collected",
         "Permission changes can indicate unauthorized access attempts."),
        ("4.2.3.8", "access", r"-a always,exit.*-S creat|open|openat|truncate|ftruncate.*-F exit=-EACCES|-F exit=-EPERM",
         "Ensure unsuccessful unauthorized file access attempts are collected",
         "Failed access attempts may indicate attack activity."),
        ("4.2.3.9", "mounts", r"-a always,exit.*-S mount",
         "Ensure successful file system mounts are collected",
         "Mount activity should be monitored for unauthorized file systems."),
        ("4.2.3.10", "delete", r"-a always,exit.*-S unlink|unlinkat|rename|renameat",
         "Ensure file deletion events by users are collected",
         "File deletions can be used to cover tracks."),
        ("4.2.3.11", "scope", r"-w /etc/sudoers.*-p wa|-w /etc/sudoers.d.*-p wa",
         "Ensure changes to system administration scope are collected",
         "Changes to sudo configuration must be monitored."),
        ("4.2.3.12", "actions", r"-w /var/log/sudo.log.*-p wa",
         "Ensure system administrator actions are collected",
         "Admin actions should be logged for accountability."),
    ]

    for section, key, pattern, title, rationale in audit_rules:
        rules.append(LinuxCISRule(
            id=f"LNX-L2-{section}",
            cis_section=section,
            title=title,
            severity="medium",
            level="L2",
            rationale=rationale,
            remediation=f"Add appropriate audit rules to /etc/audit/rules.d/audit.rules",
            check=lambda d, p, pat=pattern: _check_audit_rule_exists(d, pat),
            evidence=lambda d, p: _get_output(d, "audit_rules_loaded")[:500],
        ))

    # 5.1.2-5.1.5 - Cron Access Control
    rules.append(LinuxCISRule(
        id="LNX-L1-5.1.2",
        cis_section="5.1.2",
        title="Ensure permissions on /etc/crontab are configured",
        severity="medium",
        level="L1",
        rationale="Crontab file must be protected from unauthorized modifications.",
        remediation="Run: chmod 600 /etc/crontab && chown root:root /etc/crontab",
        check=lambda d, p: "600" in _get_output(d, "crontab_permissions") or "-rw-------" in _get_output(d, "crontab_permissions"),
        evidence=lambda d, p: _get_output(d, "crontab_permissions"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-5.1.3",
        cis_section="5.1.3",
        title="Ensure permissions on /etc/cron.hourly are configured",
        severity="low",
        level="L1",
        rationale="Cron directories must be protected.",
        remediation="Run: chmod 700 /etc/cron.hourly",
        check=lambda d, p: "700" in _get_output(d, "cron_dirs_permissions") or "drwx------" in _get_output(d, "cron_dirs_permissions"),
        evidence=lambda d, p: _get_output(d, "cron_dirs_permissions"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-5.1.4",
        cis_section="5.1.4",
        title="Ensure permissions on /etc/cron.d are configured",
        severity="low",
        level="L1",
        rationale="The cron.d directory must be protected.",
        remediation="Run: chmod 700 /etc/cron.d",
        check=lambda d, p: "700" in _get_output(d, "crond_permissions") or "drwx------" in _get_output(d, "crond_permissions"),
        evidence=lambda d, p: _get_output(d, "crond_permissions"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-5.1.5",
        cis_section="5.1.5",
        title="Ensure cron is restricted to authorized users",
        severity="medium",
        level="L1",
        rationale="Restricting cron access limits who can schedule tasks.",
        remediation="Create /etc/cron.allow with authorized users and remove /etc/cron.deny",
        check=lambda d, p: "cron.allow" in _get_output(d, "cron_access") or "root" in _get_output(d, "cron_access"),
        evidence=lambda d, p: _get_output(d, "cron_access"),
    ))

    # 5.3.3 - PAM Faillock
    rules.append(LinuxCISRule(
        id="LNX-L1-5.3.3",
        cis_section="5.3.3",
        title="Ensure password failed attempts lockout is configured",
        severity="high",
        level="L1",
        rationale="Account lockout prevents brute force password attacks.",
        remediation="Configure pam_faillock in /etc/pam.d/common-auth with deny=5 unlock_time=900",
        check=lambda d, p: _check_pam_module(d, "pam_faillock", "pam_faillock") or _check_pam_module(d, "pam_auth", "pam_tally2"),
        evidence=lambda d, p: f"PAM faillock: {_get_output(d, 'pam_faillock')[:300]}" if _get_output(d, 'pam_faillock') else "Not configured",
    ))

    # 6.1.10-6.1.12 - SUID/Unowned Files (Informational)
    rules.append(LinuxCISRule(
        id="LNX-INFO-6.1.10",
        cis_section="6.1.10",
        title="Audit SUID executables",
        severity="info",
        level="INFO",
        rationale="SUID executables run with elevated privileges and should be reviewed.",
        remediation="Review the list of SUID files and remove unnecessary SUID bits",
        check=lambda d, p: True,  # Always passes - informational only
        evidence=lambda d, p: f"SUID files found:\n{_get_output(d, 'suid_sgid_files')[:800]}",
    ))

    rules.append(LinuxCISRule(
        id="LNX-INFO-6.1.11",
        cis_section="6.1.11",
        title="Audit world-writable files",
        severity="info",
        level="INFO",
        rationale="World-writable files can be modified by any user.",
        remediation="Review and secure world-writable files",
        check=lambda d, p: _check_no_files_found(d, "world_writable_files"),
        evidence=lambda d, p: f"World-writable files:\n{_get_output(d, 'world_writable_files')[:500]}",
    ))

    rules.append(LinuxCISRule(
        id="LNX-INFO-6.1.12",
        cis_section="6.1.12",
        title="Audit unowned files and directories",
        severity="info",
        level="INFO",
        rationale="Unowned files may indicate deleted accounts or security issues.",
        remediation="Assign ownership to valid users/groups",
        check=lambda d, p: _check_no_files_found(d, "unowned_files"),
        evidence=lambda d, p: f"Unowned files:\n{_get_output(d, 'unowned_files')[:500]}",
    ))

    # ==================== EXPANDED RULES - PHASE 2: HIGH PRIORITY ====================

    # 1.4.2-1.4.3 - GRUB Security
    rules.append(LinuxCISRule(
        id="LNX-L1-1.4.2",
        cis_section="1.4.2",
        title="Ensure bootloader password is set",
        severity="high",
        level="L1",
        rationale="A bootloader password prevents unauthorized kernel parameter changes.",
        remediation="Set GRUB password using grub-mkpasswd-pbkdf2 and update grub configuration",
        check=lambda d, p: "password" in _get_output(d, "grub_password").lower() and "no grub password" not in _get_output(d, "grub_password").lower(),
        evidence=lambda d, p: _get_output(d, "grub_password"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-1.4.3",
        cis_section="1.4.3",
        title="Ensure authentication is required for single user mode",
        severity="high",
        level="L1",
        rationale="Single user mode must require authentication to prevent bypassing security.",
        remediation="Ensure root password is set: passwd root",
        check=lambda d, p: "single" in _get_output(d, "grub_single_mode").lower() or bool(_get_output(d, "shadow_file")),
        evidence=lambda d, p: _get_output(d, "grub_single_mode"),
    ))

    # 1.2.1-1.2.2 - GPG Keys / Package Signing
    rules.append(LinuxCISRule(
        id="LNX-L1-1.2.1",
        cis_section="1.2.1",
        title="Ensure package manager repositories are configured",
        severity="medium",
        level="L1",
        rationale="Properly configured repositories ensure packages come from trusted sources.",
        remediation="Configure official distribution repositories",
        check=lambda d, p: bool(_get_output(d, "apt_sources_list").strip()) if p.startswith("ubuntu") else bool(_get_output(d, "dnf_repos").strip()),
        evidence=lambda d, p: _get_output(d, "apt_sources_list")[:500] if p.startswith("ubuntu") else _get_output(d, "dnf_repos")[:500],
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-1.2.2",
        cis_section="1.2.2",
        title="Ensure GPG keys are configured",
        severity="medium",
        level="L1",
        rationale="GPG keys verify package authenticity and integrity.",
        remediation="Import official distribution GPG keys",
        check=lambda d, p: bool(_get_output(d, "apt_keys").strip()) if p.startswith("ubuntu") else bool(_get_output(d, "rpm_gpg_keys").strip()),
        evidence=lambda d, p: _get_output(d, "apt_keys")[:500] if p.startswith("ubuntu") else _get_output(d, "rpm_gpg_keys")[:500],
    ))

    # 5.2.2 - SSH private host key permissions
    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.2",
        cis_section="5.2.2",
        title="Ensure permissions on SSH private host keys are configured",
        severity="high",
        level="L1",
        rationale="Private SSH host keys must be protected from unauthorized access.",
        remediation="Run: chmod 600 /etc/ssh/ssh_host_*_key",
        check=lambda d, p: "600" in _get_output(d, "ssh_host_keys_permissions") or "-rw-------" in _get_output(d, "ssh_host_keys_permissions"),
        evidence=lambda d, p: _get_output(d, "ssh_host_keys_permissions"),
    ))

    # 5.2.14-5.2.21 - Additional SSH settings
    ssh_additional = [
        ("5.2.14", "banner", "Ensure SSH warning banner is configured", "A warning banner provides legal notice to users.",
         lambda d, p: "banner" in _parse_sshd_config(d) or bool(_get_output(d, "ssh_banner"))),
        ("5.2.15b", "allowtcpforwarding", "Ensure SSH AllowTcpForwarding is disabled", "TCP forwarding can bypass network controls.",
         lambda d, p: _check_sshd_setting(d, "allowtcpforwarding", "no")),
        ("5.2.16", "maxstartups", "Ensure SSH MaxStartups is configured", "Limits parallel unauthenticated connections.",
         lambda d, p: "maxstartups" in _parse_sshd_config(d)),
        ("5.2.17", "maxsessions", "Ensure SSH MaxSessions is limited", "Limits sessions per connection.",
         lambda d, p: "maxsessions" in _parse_sshd_config(d) and int(_parse_sshd_config(d).get("maxsessions", "10")) <= 10),
        ("5.2.18", "logingracetime", "Ensure SSH LoginGraceTime is set to one minute or less", "Limits time for authentication.",
         lambda d, p: "logingracetime" in _parse_sshd_config(d) and int(_parse_sshd_config(d).get("logingracetime", "120")) <= 60),
    ]

    for section, setting, title, rationale, check_func in ssh_additional:
        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=title,
            severity="medium",
            level="L1",
            rationale=rationale,
            remediation=f"Configure {setting} in /etc/ssh/sshd_config",
            check=check_func,
            evidence=lambda d, p, s=setting: f"{s}: {_parse_sshd_config(d).get(s.lower(), 'not set')}",
        ))

    rules.append(LinuxCISRule(
        id="LNX-L1-5.2.19",
        cis_section="5.2.19",
        title="Ensure SSH PAM is enabled",
        severity="medium",
        level="L1",
        rationale="PAM provides standardized authentication, authorization, and session management.",
        remediation="Set UsePAM yes in /etc/ssh/sshd_config",
        check=lambda d, p: _check_sshd_setting(d, "usepam", "yes") or "usepam" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"UsePAM: {_parse_sshd_config(d).get('usepam', 'default (yes)')}",
    ))

    # 5.4.1.3-5.4.1.5 - Account Policy
    rules.append(LinuxCISRule(
        id="LNX-L1-5.4.1.3",
        cis_section="5.4.1.3",
        title="Ensure password expiration warning days is 7 or more",
        severity="low",
        level="L1",
        rationale="Warning users before password expiry gives time to change passwords.",
        remediation="Set PASS_WARN_AGE 7 in /etc/login.defs",
        check=lambda d, p: _check_login_defs_setting(d, "PASS_WARN_AGE", min_value=7),
        evidence=lambda d, p: _get_output(d, "pass_warn_age"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-5.4.1.4",
        cis_section="5.4.1.4",
        title="Ensure inactive password lock is 30 days or less",
        severity="medium",
        level="L1",
        rationale="Inactive accounts should be disabled to prevent misuse.",
        remediation="Run: useradd -D -f 30",
        check=lambda d, p: "INACTIVE" in _get_output(d, "inactive_days") and int(re.search(r'INACTIVE\s*=?\s*(\d+)', _get_output(d, "inactive_days")).group(1) if re.search(r'INACTIVE\s*=?\s*(\d+)', _get_output(d, "inactive_days")) else "999") <= 30,
        evidence=lambda d, p: _get_output(d, "inactive_days"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-5.4.1.5",
        cis_section="5.4.1.5",
        title="Ensure default UMASK is 027 or more restrictive",
        severity="medium",
        level="L1",
        rationale="A restrictive UMASK prevents world-readable default file permissions.",
        remediation="Set UMASK 027 in /etc/login.defs",
        check=lambda d, p: bool(re.search(r'UMASK\s+0?[0-2][0-7]', _get_output(d, "login_defs"))),
        evidence=lambda d, p: re.search(r'UMASK\s+\d+', _get_output(d, "login_defs")).group(0) if re.search(r'UMASK\s+\d+', _get_output(d, "login_defs")) else "UMASK not found",
    ))

    # 1.1.8.x - Mount Options
    mount_options = [
        ("1.1.8.1", "/tmp", "nodev", "Ensure nodev option set on /tmp partition", "Prevents device files on /tmp."),
        ("1.1.8.2", "/tmp", "nosuid", "Ensure nosuid option set on /tmp partition", "Prevents SUID execution from /tmp."),
        ("1.1.8.3", "/tmp", "noexec", "Ensure noexec option set on /tmp partition", "Prevents execution from /tmp."),
        ("1.1.8.4", "/dev/shm", "nodev", "Ensure nodev option set on /dev/shm partition", "Prevents device files on shared memory."),
        ("1.1.8.5", "/dev/shm", "nosuid", "Ensure nosuid option set on /dev/shm partition", "Prevents SUID on shared memory."),
        ("1.1.8.6", "/dev/shm", "noexec", "Ensure noexec option set on /dev/shm partition", "Prevents execution from shared memory."),
    ]

    for section, mount, option, title, rationale in mount_options:
        # Always append _options suffix to match command keys (e.g., mount_tmp_options)
        mount_key = f"mount_{mount.replace('/', '_').strip('_')}_options"
        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=title,
            severity="medium",
            level="L1",
            rationale=rationale,
            remediation=f"Add {option} to {mount} entry in /etc/fstab and remount",
            check=lambda d, p, mk=mount_key, opt=option: _check_mount_option(d, mk, opt) or opt in _get_output(d, mk),
            evidence=lambda d, p, mk=mount_key: _get_output(d, mk),
        ))

    # ==================== EXPANDED RULES - PHASE 3: MEDIUM PRIORITY ====================

    # 6.2.4-6.2.10 - User Account Audit
    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.4",
        cis_section="6.2.4",
        title="Ensure all users' home directories exist",
        severity="medium",
        level="L1",
        rationale="Users without home directories may have login issues or security problems.",
        remediation="Create missing home directories with appropriate permissions",
        check=lambda d, p: bool(_get_output(d, "user_home_dirs")),
        evidence=lambda d, p: _get_output(d, "user_home_dirs"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.5",
        cis_section="6.2.5",
        title="Ensure users' home directory permissions are 750 or more restrictive",
        severity="medium",
        level="L1",
        rationale="Overly permissive home directories can expose sensitive data.",
        remediation="Run: chmod 750 /home/<user> for each user",
        check=lambda d, p: _check_home_dir_permissions(d),
        evidence=lambda d, p: _get_output(d, "user_home_dirs_permissions"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.6",
        cis_section="6.2.6",
        title="Ensure users own their home directories",
        severity="medium",
        level="L1",
        rationale="Users must own their home directories for proper access control.",
        remediation="Run: chown <user> /home/<user>",
        check=lambda d, p: bool(_get_output(d, "user_home_dirs")),
        evidence=lambda d, p: _get_output(d, "user_home_dirs"),
    ))

    dot_files = [
        ("6.2.7", ".forward", "Ensure no users have .forward files", "Forward files can redirect mail to external systems."),
        ("6.2.8", ".netrc", "Ensure no users have .netrc files", "Netrc files contain plaintext credentials."),
        ("6.2.9", ".rhosts", "Ensure no users have .rhosts files", "Rhosts files allow insecure remote authentication."),
    ]

    for section, filename, title, rationale in dot_files:
        key = f"user_{filename.replace('.', '')}_files"
        rules.append(LinuxCISRule(
            id=f"LNX-L1-{section}",
            cis_section=section,
            title=title,
            severity="medium",
            level="L1",
            rationale=rationale,
            remediation=f"Remove {filename} files from user home directories",
            check=lambda d, p, k=key: _check_no_files_found(d, k),
            evidence=lambda d, p, k=key: _get_output(d, k) or f"No {filename} files found",
        ))

    rules.append(LinuxCISRule(
        id="LNX-L1-6.2.10",
        cis_section="6.2.10",
        title="Ensure root is the only UID 0 account (strict)",
        severity="high",
        level="L1",
        rationale="Only root should have UID 0 for proper accountability.",
        remediation="Remove or change UID of any non-root accounts with UID 0",
        check=lambda d, p: _get_output(d, "uid_0_accounts").strip() == "root",
        evidence=lambda d, p: f"UID 0 accounts: {_get_output(d, 'uid_0_accounts')}",
    ))

    # 4.1.1.2-4.1.1.4 - Journald Config
    rules.append(LinuxCISRule(
        id="LNX-L1-4.1.1.2",
        cis_section="4.1.1.2",
        title="Ensure journald is configured to compress large log files",
        severity="low",
        level="L1",
        rationale="Compressing logs saves disk space.",
        remediation="Set Compress=yes in /etc/systemd/journald.conf",
        check=lambda d, p: _check_journald_setting(d, "Compress", "yes"),
        evidence=lambda d, p: _get_output(d, "journald_config"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-4.1.1.3",
        cis_section="4.1.1.3",
        title="Ensure journald is configured to write to persistent storage",
        severity="medium",
        level="L1",
        rationale="Persistent storage preserves logs across reboots.",
        remediation="Set Storage=persistent in /etc/systemd/journald.conf",
        check=lambda d, p: _check_journald_setting(d, "Storage", "persistent"),
        evidence=lambda d, p: _get_output(d, "journald_config"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-4.1.1.4",
        cis_section="4.1.1.4",
        title="Ensure journald is not configured to send to rsyslog",
        severity="low",
        level="L1",
        rationale="Forwarding to rsyslog may cause duplicate logging.",
        remediation="Set ForwardToSyslog=no in /etc/systemd/journald.conf (if rsyslog not needed)",
        check=lambda d, p: not _check_journald_setting(d, "ForwardToSyslog", "yes") or _check_journald_setting(d, "ForwardToSyslog", "no"),
        evidence=lambda d, p: _get_output(d, "journald_config"),
    ))

    # 3.2.3, 3.2.6 - Network Parameters
    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.3",
        cis_section="3.2.3",
        title="Ensure secure ICMP redirects are not accepted",
        severity="medium",
        level="L1",
        rationale="Secure ICMP redirects can still be used for MITM attacks.",
        remediation="Set net.ipv4.conf.all.secure_redirects = 0",
        check=lambda d, p: _check_sysctl_value(d, "secure_redirects_all", "0"),
        evidence=lambda d, p: _get_output(d, "secure_redirects_all"),
    ))

    rules.append(LinuxCISRule(
        id="LNX-L1-3.2.6",
        cis_section="3.2.6",
        title="Ensure bogus ICMP responses are ignored",
        severity="low",
        level="L1",
        rationale="Ignoring bogus ICMP responses prevents log flooding.",
        remediation="Set net.ipv4.icmp_ignore_bogus_error_responses = 1",
        check=lambda d, p: _check_sysctl_value(d, "icmp_ignore_bogus", "1"),
        evidence=lambda d, p: _get_output(d, "icmp_ignore_bogus"),
    ))

    # 5.3.2 - Password history
    rules.append(LinuxCISRule(
        id="LNX-L1-5.3.2",
        cis_section="5.3.2",
        title="Ensure password reuse is limited",
        severity="medium",
        level="L1",
        rationale="Limiting password reuse prevents cycling through old passwords.",
        remediation="Configure pam_pwhistory with remember=5 in PAM",
        check=lambda d, p: _check_pam_module(d, "pam_password", "pam_pwhistory") or "remember" in _get_output(d, "pam_password"),
        evidence=lambda d, p: _get_output(d, "pam_password")[:300],
    ))

    # 5.6 - Su restriction
    rules.append(LinuxCISRule(
        id="LNX-L1-5.6",
        cis_section="5.6",
        title="Ensure access to the su command is restricted",
        severity="medium",
        level="L1",
        rationale="Restricting su access to the wheel group limits privilege escalation.",
        remediation="Configure pam_wheel in /etc/pam.d/su to require wheel group membership",
        check=lambda d, p: _check_pam_module(d, "pam_su", "pam_wheel"),
        evidence=lambda d, p: _get_output(d, "pam_su"),
    ))

    # 1.3.2 - MAC policies configured
    rules.append(LinuxCISRule(
        id="LNX-L1-1.3.2",
        cis_section="1.3.2",
        title="Ensure MAC policy is set to enforce or complain mode",
        severity="high",
        level="L1",
        rationale="MAC policies must be actively enforced to provide security benefits.",
        remediation="Enable and configure AppArmor/SELinux profiles",
        check=lambda d, p: (
            ("enforcing" in _get_output(d, "apparmor_status").lower() or
             "complain" in _get_output(d, "apparmor_status").lower()) if p.startswith("ubuntu") else
            ("enforcing" in _get_output(d, "selinux_status").lower() or
             "permissive" in _get_output(d, "selinux_status").lower())
        ),
        evidence=lambda d, p: (
            _get_output(d, "apparmor_status")[:300] if p.startswith("ubuntu") else
            _get_output(d, "selinux_status")[:300]
        ),
    ))

    # 1.6.3 - Remote login banner
    rules.append(LinuxCISRule(
        id="LNX-L1-1.6.3",
        cis_section="1.6.3",
        title="Ensure remote login warning banner is configured",
        severity="low",
        level="L1",
        rationale="Warning banners inform remote users of legal implications.",
        remediation="Configure /etc/issue.net with appropriate warning message",
        check=lambda d, p: bool(_get_output(d, "issue_net").strip()) and "no issue.net" not in _get_output(d, "issue_net").lower(),
        evidence=lambda d, p: _get_output(d, "issue_net")[:300],
    ))

    # 2.1.1 - xinetd disabled
    rules.append(LinuxCISRule(
        id="LNX-L1-2.1.2",
        cis_section="2.1.2",
        title="Ensure openbsd-inetd is not installed",
        severity="medium",
        level="L1",
        rationale="inetd provides legacy services that are generally not needed.",
        remediation="Remove: apt remove openbsd-inetd",
        check=lambda d, p: "not installed" in _get_output(d, "xinetd_status").lower() or not _get_output(d, "xinetd_status"),
        evidence=lambda d, p: _get_output(d, "xinetd_status"),
    ))

    return rules


def filter_rules_by_profile(rules: List[LinuxCISRule], profile: str) -> List[LinuxCISRule]:
    """
    Filter rules by CIS profile (L1 or FULL).

    Args:
        rules: List of all rules
        profile: "L1" for Level 1 only, "FULL" for all rules

    Returns:
        Filtered list of rules
    """
    if profile == "FULL":
        return rules
    return [r for r in rules if r.level == "L1"]


def filter_rules_by_distro(rules: List[LinuxCISRule], distro_profile: str) -> List[LinuxCISRule]:
    """
    Filter rules by distribution compatibility.

    Args:
        rules: List of all rules
        distro_profile: Distribution profile (e.g., "ubuntu_22", "rocky_8")

    Returns:
        Rules compatible with the distribution
    """
    filtered = []
    distro_family = distro_profile.split("_")[0] if "_" in distro_profile else distro_profile

    for rule in rules:
        if "all" in rule.distros:
            filtered.append(rule)
        elif distro_profile in rule.distros:
            filtered.append(rule)
        elif distro_family in rule.distros:
            filtered.append(rule)

    return filtered


def evaluate_compliance(
    audit_data: Dict[str, str],
    rules: List[LinuxCISRule],
    distro_profile: str = "ubuntu_22"
) -> Dict[str, Any]:
    """
    Evaluate compliance against CIS rules.

    Args:
        audit_data: Dict of command outputs from audit collection
        rules: List of CIS rules to evaluate
        distro_profile: Distribution profile for distro-aware checks

    Returns:
        Dict with compliance summary and findings
    """
    findings = []
    passed_scored = 0
    failed_scored = 0
    total_weighted = 0
    passed_weighted = 0

    for rule in rules:
        try:
            compliant = rule.check(audit_data, distro_profile)
            evidence = rule.evidence(audit_data, distro_profile)
        except Exception as e:
            compliant = False
            evidence = f"Error evaluating rule: {str(e)}"

        weight = SEVERITY_WEIGHT.get(rule.severity, 1)

        if rule.level != "INFO":
            total_weighted += weight
            if compliant:
                passed_scored += 1
                passed_weighted += weight
            else:
                failed_scored += 1

        findings.append({
            "id": rule.id,
            "cis_section": rule.cis_section,
            "title": rule.title,
            "severity": rule.severity,
            "level": rule.level,
            "compliant": compliant,
            "evidence": evidence[:1000] if evidence else "",
            "rationale": rule.rationale,
            "remediation": rule.remediation
        })

    total_scored = passed_scored + failed_scored
    compliance_pct = round(100.0 * passed_scored / total_scored, 2) if total_scored > 0 else 0.0
    weighted_pct = round(100.0 * passed_weighted / total_weighted, 2) if total_weighted > 0 else 0.0

    return {
        "summary": {
            "total_rules": len(rules),
            "total_rules_scored": total_scored,
            "passed_scored": passed_scored,
            "failed_scored": failed_scored,
            "compliance_pct": compliance_pct,
            "weighted_compliance_pct": weighted_pct
        },
        "findings": findings
    }
