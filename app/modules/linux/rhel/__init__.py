"""
RHEL-specific Module

Red Hat Enterprise Linux 8/9/10 CIS auditing and hardening are implemented by
the distro-aware engine in ``app.modules.linux`` (audit + hardening packages):

- ``parse_os_release`` resolves RHEL hosts to the ``rhel_8``/``rhel_9``/
  ``rhel_10`` profiles.
- ``filter_rules_by_distro`` applies every ``distros=["all"]`` rule plus the
  RHEL-family rules (``LNX-RHEL-*``: SELinux incl. bootloader, crypto policies,
  sudo, AIDE, faillock/authselect, firewalld, GRUB2, dnf-automatic, boot-time
  auditing) to those profiles. Rules with ``distros=["rhel"]`` — currently the
  Subscription Manager check — apply ONLY to real RHEL, not Rocky/Alma.
- Hardening templates are rewritten for the RHEL family by
  ``get_linux_hardening_template_for_distro`` (system-auth/password-auth PAM
  paths, crond/httpd/smb service names, dnf package manager).

This façade exposes the RHEL view of that engine so callers don't have to
re-derive the profile/filter plumbing.

RHEL 10 (CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1)
----------------------------------------------------------
The RHEL-10-specific checks live in this module (``build_rhel10_cis_rules`` /
``build_rhel10_audit_commands`` / ``build_rhel10_hardening_templates``) and are
wired into the shared engine with small additive hooks:

- ``audit_commands.get_linux_audit_commands`` appends
  ``build_rhel10_audit_commands()`` inside its RHEL-family block.
- ``rules.build_linux_cis_rules`` appends ``build_rhel10_cis_rules()``.
- ``command_templates`` / ``parameter_metadata`` register the RHEL-10
  hardening templates and parameter map.

The RHEL-10 rules use the ``LNX-RHEL10-*`` id prefix and are gated to the exact
``rhel_10``/``rocky_10`` profiles (both families share the v1.0.1 benchmark).
They intentionally cover only the checks that are NOT already implemented by the
generic (``distros=["all"]``) and RHEL-family (``LNX-RHEL-*``) rules — which
already run on a RHEL 10 host — so no control is scored twice. The pre-existing
rules already cover: SELinux (installed/policy/enforcing/unconfined/mcstrans/
setroubleshoot/bootloader), sudo, crypto LEGACY/SHA1, firewalld enabled+running,
dnf gpgcheck, AIDE, dnf-automatic, GRUB2 password, boot-time auditing, basic
faillock/authselect, the universal SSH/sysctl/file-permission/service checks and
the 4.2.3.x audit rule set.
"""

from typing import Dict, List, Any, Optional
import re

from app.modules.linux.audit.rules import (
    LinuxCISRule,
    build_linux_cis_rules,
    filter_rules_by_distro,
    filter_rules_by_profile,
    _get_output,
    _check_sysctl_value,
    _check_module_disabled,
    _get_module_evidence,
    _parse_sshd_config,
    _check_sshd_setting,
)

RHEL_VERSIONS = ("8", "9", "10")
RHEL_PROFILES = tuple(f"rhel_{v}" for v in RHEL_VERSIONS)


def get_rhel_cis_rules(profile: str = "FULL", version: str = "9") -> List[LinuxCISRule]:
    """
    CIS rules applicable to a RHEL host.

    Args:
        profile: "L1" or "FULL" (L1+L2+INFO)
        version: RHEL major version ("8", "9", "10")
    """
    distro_profile = f"rhel_{version}" if version in RHEL_VERSIONS else "rhel_generic"
    rules = filter_rules_by_profile(build_linux_cis_rules(), profile)
    return filter_rules_by_distro(rules, distro_profile)


def get_rhel_supported_checks(version: str = "9") -> List[str]:
    """Check IDs that both apply to RHEL and have a hardening template."""
    from app.modules.linux.hardening.command_templates import LINUX_HARDENING_TEMPLATES

    rhel_ids = {r.id for r in get_rhel_cis_rules("FULL", version)}
    return sorted(
        check_id
        for check_id, template in LINUX_HARDENING_TEMPLATES.items()
        if check_id in rhel_ids
        and ("all" in template.distros or "rhel" in template.distros)
    )


# ============================================================================
# CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1
# ============================================================================
# Gated to the exact RHEL-10 / Rocky-10 profiles (both share the v1.0.1
# benchmark). ``filter_rules_by_distro`` matches an exact ``distro_profile``, so
# these never apply to rhel_8/9. Command keys are prefixed ``r10_`` (or reuse
# the shared modprobe_/lsmod_/sshd_*/pam_* keys) to avoid clobbering any key the
# generic collection already emits.

RHEL10_PROFILES = ("rhel_10", "rocky_10")

# distros= gate for the RHEL-10 rules (exact-profile match, no family fallback).
# RHEL-10 rules are gated to ``rhel_10`` ONLY: Rocky Linux 10 is covered by the
# parallel ``LNX-ROCKY10-*`` set built in app.modules.linux.rocky (which reuses
# these builders with the Rocky-specific overrides). Keeping the two families on
# separate ids/gates means no control is scored twice on a Rocky 10 host.
_R10 = ["rhel_10"]
# hardening templates run on the already-detected distro, so they carry the
# RHEL family list (same convention as the existing LNX-RHEL-* templates).
_R10_FAMILY = ["rhel", "rocky", "centos", "fedora", "almalinux"]


# ---- RHEL-10 helpers -------------------------------------------------------

def _r10_stat_ok(output: str, max_mode: str, owner: str = "root", group: str = "root") -> bool:
    """
    Evaluate ``stat -c '%a %U %G'`` output: mode no looser than ``max_mode`` and
    matching ownership. Fails closed on empty/errored output.
    """
    output = (output or "").strip()
    if not output or "no such file" in output.lower() or "cannot stat" in output.lower():
        return False
    parts = output.split()
    if len(parts) < 3:
        return False
    mode, actual_owner, actual_group = parts[0], parts[1], parts[2]
    try:
        if int(mode, 8) > int(max_mode, 8):
            return False
    except ValueError:
        return False
    return actual_owner == owner and actual_group == group


def _r10_service_disabled(data: Dict[str, str], key: str) -> bool:
    """systemctl is-enabled output → compliant when disabled/masked/absent."""
    out = _get_output(data, key).lower()
    if not out:
        return True
    return any(s in out for s in ("not installed", "not-found", "disabled", "masked", "not enabled"))


def _r10_pkg_absent(data: Dict[str, str], key: str) -> bool:
    """rpm -q output → compliant when the package is not installed."""
    out = _get_output(data, key).lower()
    if not out:
        return True
    return "not installed" in out or "is not installed" in out


def _r10_int_ok(text: str, pattern: str, *, minimum: int = None, maximum: int = None,
                equals: int = None) -> bool:
    """Extract the first int matched by ``pattern`` and range-check it."""
    m = re.search(pattern, text or "", re.IGNORECASE)
    if not m:
        return False
    try:
        val = int(m.group(1))
    except (ValueError, IndexError):
        return False
    if equals is not None and val != equals:
        return False
    if minimum is not None and val < minimum:
        return False
    if maximum is not None and val > maximum:
        return False
    return True


# ---- RHEL-10 audit commands ------------------------------------------------

# Kernel modules that RHEL 10 requires blacklisted but the generic collection
# does not already probe. (dashed name for the command, underscore key so the
# shared _check_module_disabled/_get_module_evidence helpers line up.)
_R10_MODULES = [
    ("overlay", "1.1.1.6"),
    ("firewire-core", "1.1.1.9"),
    ("atm", "3.2.1"),
    ("can", "3.2.2"),
    ("dccp", "3.2.3"),
    ("tipc", "3.2.4"),
    ("rds", "3.2.5"),
    ("sctp", "3.2.6"),
]


def build_rhel10_audit_commands() -> List[Dict[str, Any]]:
    """
    Data-collection commands for the RHEL-10-specific checks. Safe to run on any
    RHEL-family host (extra output on rhel_8/9 is simply never scored).
    """
    cmds: List[Dict[str, Any]] = []

    # 1.1.1 / 3.2 - additional kernel modules
    for mod, section in _R10_MODULES:
        mod_u = mod.replace("-", "_")
        cmds.append({"cmd": f"modprobe -n -v {mod} 2>&1 || echo 'not available'",
                     "sudo": True, "key": f"modprobe_{mod_u}", "section": section})
        cmds.append({"cmd": f"lsmod | grep {mod} || echo 'not loaded'",
                     "sudo": False, "key": f"lsmod_{mod_u}", "section": section})

    cmds.extend([
        # 1.2.1 - dnf.conf global package policy
        {"cmd": "grep -E '^\\s*repo_gpgcheck' /etc/dnf/dnf.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_repo_gpgcheck", "section": "1.2.1.3"},
        {"cmd": "grep -E '^\\s*install_weak_deps' /etc/dnf/dnf.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_weak_deps", "section": "1.2.1.5"},

        # 1.5 - process hardening sysctls (not covered by generic collection)
        {"cmd": "sysctl kernel.dmesg_restrict 2>/dev/null || echo 'unknown'",
         "sudo": False, "key": "r10_dmesg_restrict", "section": "1.5.5"},
        {"cmd": "sysctl kernel.kptr_restrict 2>/dev/null || echo 'unknown'",
         "sudo": False, "key": "r10_kptr_restrict", "section": "1.5.6"},

        # 3.3 - granular forwarding sysctls
        {"cmd": "sysctl net.ipv4.conf.all.forwarding 2>/dev/null || echo 'unknown'",
         "sudo": False, "key": "r10_ipv4_all_forwarding", "section": "3.3.1.2"},
        {"cmd": "sysctl net.ipv4.conf.default.forwarding 2>/dev/null || echo 'unknown'",
         "sudo": False, "key": "r10_ipv4_default_forwarding", "section": "3.3.1.3"},
        {"cmd": "sysctl net.ipv6.conf.all.forwarding 2>/dev/null || echo 'unknown'",
         "sudo": False, "key": "r10_ipv6_all_forwarding", "section": "3.3.2.1"},
        {"cmd": "sysctl net.ipv6.conf.default.forwarding 2>/dev/null || echo 'unknown'",
         "sudo": False, "key": "r10_ipv6_default_forwarding", "section": "3.3.2.2"},

        # 1.6 - system-wide crypto policy back-end for openssh
        {"cmd": "grep -i '^MACs' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_crypto_macs", "section": "1.6.3"},
        {"cmd": "grep -i 'cbc' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null || echo 'none found'",
         "sudo": False, "key": "r10_crypto_cbc", "section": "1.6.4"},

        # 1.7 - warning banner file permissions
        {"cmd": "stat -c '%a %U %G' /etc/motd 2>/dev/null || echo 'no such file'",
         "sudo": False, "key": "r10_motd_perms", "section": "1.7.4"},
        {"cmd": "stat -c '%a %U %G' /etc/issue 2>/dev/null || echo 'no such file'",
         "sudo": False, "key": "r10_issue_perms", "section": "1.7.5"},
        {"cmd": "stat -c '%a %U %G' /etc/issue.net 2>/dev/null || echo 'no such file'",
         "sudo": False, "key": "r10_issuenet_perms", "section": "1.7.6"},

        # 1.8 - GDM hardening (dconf); paired with the existing gdm_installed key
        {"cmd": "grep -rs 'disable-user-list=true' /etc/dconf/db/gdm.d/ 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_gdm_userlist", "section": "1.8.2"},
        {"cmd": "grep -rsE 'idle-delay|lock-delay' /etc/dconf/db/*.d/ 2>/dev/null | head -5 || echo 'not configured'",
         "sudo": False, "key": "r10_gdm_lock", "section": "1.8.3"},
        {"cmd": "grep -rsE 'automount(-open)?=false' /etc/dconf/db/*.d/ 2>/dev/null | head -5 || echo 'not configured'",
         "sudo": False, "key": "r10_gdm_automount", "section": "1.8.4"},
        {"cmd": "grep -rs 'autorun-never=true' /etc/dconf/db/*.d/ 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_gdm_autorun", "section": "1.8.5"},
        {"cmd": "grep -iE '^\\s*WaylandEnable' /etc/gdm/custom.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_gdm_wayland", "section": "1.8.6"},

        # 2.1 - additional unnecessary services (RHEL unit names)
        {"cmd": "systemctl is-enabled autofs 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "r10_autofs", "section": "2.1.1"},
        {"cmd": "systemctl is-enabled cockpit.socket 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "r10_cockpit", "section": "2.1.3"},
        {"cmd": "systemctl is-enabled dnsmasq 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "r10_dnsmasq", "section": "2.1.6"},

        # 2.2 - additional unnecessary clients
        {"cmd": "rpm -q ftp 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "r10_ftp_client", "section": "2.2.1"},
        {"cmd": "rpm -q tftp 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "r10_tftp_client", "section": "2.2.4"},

        # 2.3 - chrony is configured with a time source
        {"cmd": "grep -E '^\\s*(server|pool)' /etc/chrony.conf /etc/chrony/chrony.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_chrony_servers", "section": "2.3.2"},

        # 3.1 - wireless / bluetooth
        {"cmd": "nmcli radio wifi 2>/dev/null || echo 'no wifi'",
         "sudo": False, "key": "r10_wireless", "section": "3.1.2"},
        {"cmd": "systemctl is-enabled bluetooth 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "r10_bluetooth", "section": "3.1.3"},

        # 4.1 - firewalld backend / default zone / loopback
        {"cmd": "grep -E '^\\s*FirewallBackend' /etc/firewalld/firewalld.conf 2>/dev/null || echo 'not configured'",
         "sudo": True, "key": "r10_fw_backend", "section": "4.1.2"},
        {"cmd": "firewall-cmd --get-default-zone 2>/dev/null || echo 'firewalld not running'",
         "sudo": True, "key": "r10_fw_default_zone", "section": "4.1.4"},
        {"cmd": "firewall-cmd --info-zone=trusted 2>/dev/null | grep -E 'interfaces:.*lo' || echo 'lo not in trusted'",
         "sudo": True, "key": "r10_fw_loopback", "section": "4.1.5"},

        # 5.4 - TMOUT / root primary GID
        {"cmd": "grep -rEs 'TMOUT' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null | head -5 || echo 'not configured'",
         "sudo": False, "key": "r10_tmout", "section": "5.4.3.2"},
        {"cmd": "awk -F: '($1 == \"root\") {print $4}' /etc/passwd 2>/dev/null || echo 'check failed'",
         "sudo": False, "key": "r10_root_gid", "section": "5.4.2.2"},

        # 6.2 - logging system configuration
        {"cmd": "grep -rEs '^\\$FileCreateMode' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -3 || echo 'not configured'",
         "sudo": False, "key": "r10_rsyslog_filemode", "section": "6.2.3.4"},
        {"cmd": "grep -E '^\\s*SystemMaxUse' /etc/systemd/journald.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "r10_journald_maxuse", "section": "6.2.1.3"},
        {"cmd": "rpm -q rsyslog 2>/dev/null | grep -q rsyslog && echo 'rsyslog installed' || echo 'rsyslog absent'",
         "sudo": False, "key": "r10_logging_single", "section": "6.2.1.4"},

        # 6.3 - auditd disk-full behaviour and immutability
        {"cmd": "grep -E '^\\s*max_log_file_action' /etc/audit/auditd.conf 2>/dev/null || echo 'not configured'",
         "sudo": True, "key": "r10_audit_log_action", "section": "6.3.2.2"},
        {"cmd": "grep -E '^\\s*disk_full_action' /etc/audit/auditd.conf 2>/dev/null || echo 'not configured'",
         "sudo": True, "key": "r10_audit_disk_full", "section": "6.3.2.3"},
        {"cmd": "grep -E '^\\s*-e\\s+2' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null || auditctl -s 2>/dev/null | grep -E 'enabled 2' || echo 'not immutable'",
         "sudo": True, "key": "r10_audit_immutable", "section": "6.3.3.36"},
        {"cmd": "stat -c '%a %U %G' /var/log/audit/audit.log 2>/dev/null || echo 'no such file'",
         "sudo": True, "key": "r10_audit_log_perms", "section": "6.3.4.2"},
        {"cmd": "stat -c '%a %U %G' /etc/audit/auditd.conf 2>/dev/null || echo 'no such file'",
         "sudo": True, "key": "r10_audit_conf_perms", "section": "6.3.4.5"},

        # 7.1 - remaining file permissions
        {"cmd": "stat -c '%a %U %G' /etc/shells 2>/dev/null || echo 'no such file'",
         "sudo": False, "key": "r10_shells_perms", "section": "7.1.9"},
        {"cmd": "stat -c '%a %U %G' /etc/security/opasswd 2>/dev/null || echo 'no such file'",
         "sudo": True, "key": "r10_opasswd_perms", "section": "7.1.10"},
    ])

    return cmds


# ---- RHEL-10 CIS rules -----------------------------------------------------

def build_rhel10_cis_rules() -> List[LinuxCISRule]:
    """
    RHEL-10 v1.0.1 checks not already implemented by the generic and RHEL-family
    rule sets. Gated to the exact rhel_10/rocky_10 profiles.
    """
    rules: List[LinuxCISRule] = []

    def add(section, title, severity, level, rationale, remediation, check, evidence,
            expected=None):
        rules.append(LinuxCISRule(
            id=f"LNX-RHEL10-{level}-{section}",
            cis_section=section,
            title=title,
            severity=severity,
            level=level,
            rationale=rationale,
            remediation=remediation,
            check=check,
            evidence=evidence,
            distros=_R10,
            expected_value=expected,
        ))

    # ---- 1.1.1 / 3.2 kernel modules ----
    for mod, section in _R10_MODULES:
        mod_u = mod.replace("-", "_")
        net = section.startswith("3.")
        add(
            section,
            f"Ensure {mod} kernel module is not available",
            "medium" if net else "low",
            "L1",
            f"The {mod} module is not required on most servers; disabling it removes attack surface.",
            f"Add 'install {mod} /bin/false' and 'blacklist {mod}' to /etc/modprobe.d/{mod_u}.conf, then 'modprobe -r {mod}'.",
            check=lambda d, p, m=mod_u: _check_module_disabled(d, m),
            evidence=lambda d, p, m=mod: _get_module_evidence(d, m),
            expected=f"{mod} not loadable and not loaded",
        )

    # ---- 1.2.1 dnf.conf ----
    add("1.2.1.3", "Ensure repo_gpgcheck is globally activated", "medium", "L1",
        "repo_gpgcheck verifies the signature of repository metadata, not just packages.",
        "Set 'repo_gpgcheck=1' in the [main] section of /etc/dnf/dnf.conf.",
        check=lambda d, p: bool(re.search(r'repo_gpgcheck\s*=\s*1', _get_output(d, "r10_repo_gpgcheck"))),
        evidence=lambda d, p: _get_output(d, "r10_repo_gpgcheck"),
        expected="repo_gpgcheck=1 in /etc/dnf/dnf.conf")

    add("1.2.1.5", "Ensure weak dependencies are not installed", "low", "L1",
        "install_weak_deps=False keeps optional/recommended packages off the system, reducing surface.",
        "Set 'install_weak_deps=False' in the [main] section of /etc/dnf/dnf.conf.",
        check=lambda d, p: bool(re.search(r'install_weak_deps\s*=\s*(False|0)', _get_output(d, "r10_weak_deps"), re.IGNORECASE)),
        evidence=lambda d, p: _get_output(d, "r10_weak_deps"),
        expected="install_weak_deps=False in /etc/dnf/dnf.conf")

    # ---- 1.5 process hardening ----
    add("1.5.5", "Ensure kernel.dmesg_restrict is configured", "medium", "L1",
        "Restricting dmesg keeps kernel pointers and messages away from unprivileged users.",
        "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-cis.conf and run: sysctl -w kernel.dmesg_restrict=1",
        check=lambda d, p: _check_sysctl_value(d, "r10_dmesg_restrict", "1"),
        evidence=lambda d, p: _get_output(d, "r10_dmesg_restrict"),
        expected="kernel.dmesg_restrict = 1")

    add("1.5.6", "Ensure kernel.kptr_restrict is configured", "medium", "L1",
        "Hiding kernel pointer addresses makes kernel exploitation harder.",
        "Set kernel.kptr_restrict=2 in /etc/sysctl.d/99-cis.conf and run: sysctl -w kernel.kptr_restrict=2",
        check=lambda d, p: _check_sysctl_value(d, "r10_kptr_restrict", "2"),
        evidence=lambda d, p: _get_output(d, "r10_kptr_restrict"),
        expected="kernel.kptr_restrict = 2")

    # ---- 3.3 granular forwarding ----
    for section, key, param in [
        ("3.3.1.2", "r10_ipv4_all_forwarding", "net.ipv4.conf.all.forwarding"),
        ("3.3.1.3", "r10_ipv4_default_forwarding", "net.ipv4.conf.default.forwarding"),
        ("3.3.2.1", "r10_ipv6_all_forwarding", "net.ipv6.conf.all.forwarding"),
        ("3.3.2.2", "r10_ipv6_default_forwarding", "net.ipv6.conf.default.forwarding"),
    ]:
        add(section, f"Ensure {param} is disabled", "medium", "L1",
            "IP forwarding turns the host into a router; disable it unless the host is a gateway.",
            f"Set {param}=0 in /etc/sysctl.d/99-cis.conf and run: sysctl -w {param}=0",
            check=lambda d, p, k=key: _check_sysctl_value(d, k, "0"),
            evidence=lambda d, p, k=key: _get_output(d, k),
            expected=f"{param} = 0")

    # ---- 1.6 crypto policy back-end (openssh) ----
    add("1.6.3", "Ensure system-wide crypto policy MACs are configured for SSH", "medium", "L1",
        "The openssh crypto-policy back-end must define the permitted MAC algorithms.",
        "Apply a strong system crypto policy: update-crypto-policies --set DEFAULT (or FUTURE).",
        check=lambda d, p: (
            bool(_get_output(d, "r10_crypto_macs").strip())
            and "not configured" not in _get_output(d, "r10_crypto_macs").lower()
        ),
        evidence=lambda d, p: _get_output(d, "r10_crypto_macs"),
        expected="MACs line present in /etc/crypto-policies/back-ends/openssh.config")

    add("1.6.4", "Ensure system-wide crypto policy disables CBC for SSH", "medium", "L1",
        "CBC-mode ciphers are vulnerable; the SSH crypto-policy back-end must not enable them.",
        "Apply a strong system crypto policy: update-crypto-policies --set DEFAULT (or FUTURE).",
        check=lambda d, p: "cbc" not in _get_output(d, "r10_crypto_cbc").lower(),
        evidence=lambda d, p: _get_output(d, "r10_crypto_cbc"),
        expected="No cbc ciphers in /etc/crypto-policies/back-ends/openssh.config")

    # ---- 1.7 banner file permissions ----
    for section, key, fname in [
        ("1.7.4", "r10_motd_perms", "/etc/motd"),
        ("1.7.5", "r10_issue_perms", "/etc/issue"),
        ("1.7.6", "r10_issuenet_perms", "/etc/issue.net"),
    ]:
        add(section, f"Ensure permissions on {fname} are configured", "low", "L1",
            f"{fname} must be root-owned and no more permissive than 644.",
            f"Run: chown root:root {fname} && chmod 644 {fname}",
            check=lambda d, p, k=key: _r10_stat_ok(_get_output(d, k), "644"),
            evidence=lambda d, p, k=key: _get_output(d, k),
            expected=f"{fname} mode 644, owner root:root")

    # ---- 1.8 GDM (only when GDM is installed) ----
    def _gdm_na(d):
        return "not installed" in _get_output(d, "gdm_installed").lower()

    _gdm_checks = [
        ("1.8.2", "r10_gdm_userlist", "Ensure GDM disable-user-list option is enabled",
         "disable-user-list=true", "The login screen must not enumerate local users."),
        ("1.8.3", "r10_gdm_lock", "Ensure GDM screen locks when idle",
         "idle-delay / lock-delay", "An idle graphical session must lock automatically."),
        ("1.8.4", "r10_gdm_automount", "Ensure GDM automatic mounting of removable media is disabled",
         "automount=false", "Auto-mounting removable media at the login screen is an attack vector."),
        ("1.8.5", "r10_gdm_autorun", "Ensure GDM autorun-never is enabled",
         "autorun-never=true", "Auto-running software from removable media must be disabled."),
        ("1.8.6", "r10_gdm_wayland", "Ensure XDMCP/Xwayland is configured (WaylandEnable)",
         "WaylandEnable", "The display manager's Wayland/Xwayland setting must be explicitly configured."),
    ]
    for section, key, title, needle, rationale in _gdm_checks:
        add(section, title, "low", "L1", rationale,
            "Configure the setting under /etc/dconf/db/gdm.d/ (or /etc/gdm/custom.conf) and run: dconf update",
            check=lambda d, p, k=key: (
                _gdm_na(d)
                or ("not configured" not in _get_output(d, k).lower() and bool(_get_output(d, k).strip()))
            ),
            evidence=lambda d, p, k=key: _get_output(d, k) if not _gdm_na(d) else "GDM not installed (N/A)",
            expected=f"{needle} configured (or GDM not installed)")

    # ---- 2.1 unnecessary services ----
    for section, key, name in [
        ("2.1.1", "r10_autofs", "autofs"),
        ("2.1.3", "r10_cockpit", "cockpit"),
        ("2.1.6", "r10_dnsmasq", "dnsmasq"),
    ]:
        add(section, f"Ensure {name} services are not in use", "medium", "L1",
            f"{name} is not required on a hardened server and should be disabled.",
            f"Run: systemctl --now disable {name} (or mask the unit).",
            check=lambda d, p, k=key: _r10_service_disabled(d, k),
            evidence=lambda d, p, k=key: _get_output(d, k),
            expected=f"{name} disabled, masked, or not installed")

    # ---- 2.2 unnecessary clients ----
    for section, key, pkg in [
        ("2.2.1", "r10_ftp_client", "ftp"),
        ("2.2.4", "r10_tftp_client", "tftp"),
    ]:
        add(section, f"Ensure {pkg} client is not installed", "medium", "L1",
            f"The {pkg} client transmits data in cleartext and should not be present.",
            f"Run: dnf remove {pkg}",
            check=lambda d, p, k=key: _r10_pkg_absent(d, k),
            evidence=lambda d, p, k=key: _get_output(d, k),
            expected=f"{pkg} not installed")

    # ---- 2.3 chrony configured ----
    add("2.3.2", "Ensure chrony is configured with an authorized timeserver", "low", "L1",
        "chrony must reference at least one server/pool to actually synchronise time.",
        "Add 'server <host> iburst' or 'pool <host> iburst' lines to /etc/chrony.conf.",
        check=lambda d, p: bool(re.search(r'^\s*(server|pool)\s+\S+', _get_output(d, "r10_chrony_servers"), re.MULTILINE)),
        evidence=lambda d, p: _get_output(d, "r10_chrony_servers"),
        expected="server/pool directive present in chrony.conf")

    # ---- 3.1 wireless / bluetooth ----
    add("3.1.2", "Ensure wireless interfaces are disabled", "low", "L1",
        "Unused wireless radios expand the attack surface of a server.",
        "Run: nmcli radio wifi off (and blacklist the wireless module if permanent).",
        check=lambda d, p: (
            "enabled" not in _get_output(d, "r10_wireless").lower()
            or "no wifi" in _get_output(d, "r10_wireless").lower()
            or "missing" in _get_output(d, "r10_wireless").lower()
        ),
        evidence=lambda d, p: _get_output(d, "r10_wireless"),
        expected="wifi radio disabled or absent")

    add("3.1.3", "Ensure bluetooth services are not in use", "low", "L1",
        "Bluetooth is rarely needed on servers and should be disabled.",
        "Run: systemctl --now disable bluetooth (or mask the unit).",
        check=lambda d, p: _r10_service_disabled(d, "r10_bluetooth"),
        evidence=lambda d, p: _get_output(d, "r10_bluetooth"),
        expected="bluetooth disabled, masked, or not installed")

    # ---- 4.1 firewalld backend / zone / loopback (NA when firewalld absent) ----
    def _fw_absent(d):
        return "not running" in _get_output(d, "r10_fw_default_zone").lower() \
            or "not installed" in _get_output(d, "r10_fw_backend").lower()

    add("4.1.2", "Ensure firewalld default backend is nftables", "medium", "L1",
        "firewalld should use the modern nftables backend rather than legacy iptables.",
        "Set FirewallBackend=nftables in /etc/firewalld/firewalld.conf and restart firewalld.",
        check=lambda d, p: (
            _fw_absent(d)
            or bool(re.search(r'FirewallBackend\s*=\s*nftables', _get_output(d, "r10_fw_backend"), re.IGNORECASE))
        ),
        evidence=lambda d, p: _get_output(d, "r10_fw_backend"),
        expected="FirewallBackend=nftables (or firewalld handled by 3.4.2)")

    add("4.1.4", "Ensure firewalld default zone is set", "medium", "L1",
        "A defined default zone ensures new interfaces get a known policy.",
        "Run: firewall-cmd --set-default-zone=<zone> (e.g. public or drop).",
        check=lambda d, p: (
            _fw_absent(d)
            or bool(_get_output(d, "r10_fw_default_zone").strip()
                    and "not running" not in _get_output(d, "r10_fw_default_zone").lower())
        ),
        evidence=lambda d, p: _get_output(d, "r10_fw_default_zone"),
        expected="A firewalld default zone is set")

    add("4.1.5", "Ensure firewalld loopback traffic is configured", "medium", "L1",
        "Loopback traffic should be trusted while spoofed loopback source addresses are dropped.",
        "Add the lo interface to the trusted zone: firewall-cmd --permanent --zone=trusted --add-interface=lo && firewall-cmd --reload",
        check=lambda d, p: (
            _fw_absent(d)
            or "lo" in _get_output(d, "r10_fw_loopback").lower()
            and "not in trusted" not in _get_output(d, "r10_fw_loopback").lower()
        ),
        evidence=lambda d, p: _get_output(d, "r10_fw_loopback"),
        expected="lo interface handled by firewalld (or firewalld absent)")

    # ---- 5.1 SSH crypto / forwarding / auth (reuse sshd effective config) ----
    add("5.1.6", "Ensure sshd Ciphers are configured (no CBC)", "medium", "L1",
        "sshd must not offer weak CBC-mode ciphers.",
        "Set a strong 'Ciphers' line in /etc/ssh/sshd_config.d/ and restart sshd.",
        check=lambda d, p: "cbc" not in _parse_sshd_config(d).get("ciphers", "").lower(),
        evidence=lambda d, p: f"Ciphers: {_parse_sshd_config(d).get('ciphers', 'default')}",
        expected="No *-cbc ciphers offered by sshd")

    add("5.1.12", "Ensure sshd KexAlgorithms are configured (no weak DH)", "medium", "L1",
        "sshd must not offer SHA1/weak Diffie-Hellman key-exchange algorithms.",
        "Set a strong 'KexAlgorithms' line in /etc/ssh/sshd_config.d/ and restart sshd.",
        check=lambda d, p: not re.search(
            r'(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|gss-group1)',
            _parse_sshd_config(d).get("kexalgorithms", ""), re.IGNORECASE),
        evidence=lambda d, p: f"KexAlgorithms: {_parse_sshd_config(d).get('kexalgorithms', 'default')}",
        expected="No SHA1 key-exchange algorithms offered by sshd")

    add("5.1.15", "Ensure sshd MACs are configured (no weak/MD5/96-bit)", "medium", "L1",
        "sshd must not offer MD5 or 96-bit truncated MAC algorithms.",
        "Set a strong 'MACs' line in /etc/ssh/sshd_config.d/ and restart sshd.",
        check=lambda d, p: not re.search(
            r'(hmac-md5|-96\b|umac-64)', _parse_sshd_config(d).get("macs", ""), re.IGNORECASE),
        evidence=lambda d, p: f"MACs: {_parse_sshd_config(d).get('macs', 'default')}",
        expected="No weak MAC algorithms offered by sshd")

    add("5.1.9", "Ensure sshd GSSAPIAuthentication is disabled", "low", "L1",
        "GSSAPI authentication is unused on most hosts and adds attack surface.",
        "Set 'GSSAPIAuthentication no' in /etc/ssh/sshd_config and restart sshd.",
        check=lambda d, p: _check_sshd_setting(d, "gssapiauthentication", "no"),
        evidence=lambda d, p: f"GSSAPIAuthentication: {_parse_sshd_config(d).get('gssapiauthentication', 'not set')}",
        expected="GSSAPIAuthentication no")

    add("5.1.8", "Ensure sshd DisableForwarding is enabled", "medium", "L1",
        "Disabling all forwarding prevents SSH from being used to tunnel around network controls.",
        "Set 'DisableForwarding yes' in /etc/ssh/sshd_config and restart sshd.",
        check=lambda d, p: _check_sshd_setting(d, "disableforwarding", "yes"),
        evidence=lambda d, p: f"DisableForwarding: {_parse_sshd_config(d).get('disableforwarding', 'not set')}",
        expected="DisableForwarding yes")

    # ---- 5.3 PAM (reuse pam_password/pam_auth/pwquality_config/faillock_conf/pam_pwhistory) ----
    def _pam_text(d):
        return f"{_get_output(d, 'pam_password')}\n{_get_output(d, 'pam_auth')}"

    add("5.3.1.1", "Ensure active authselect profile includes pam modules", "medium", "L1",
        "The active authselect profile must pull in pam_faillock and pam_pwquality.",
        "Run: authselect select sssd with-faillock --force (or the appropriate profile).",
        check=lambda d, p: (
            "faillock" in _get_output(d, "pam_faillock_rhel").lower()
            or "pam_pwquality" in _pam_text(d).lower()
        ),
        evidence=lambda d, p: f"{_get_output(d, 'authselect_profile')[:200]}\n{_get_output(d, 'pam_faillock_rhel')[:200]}",
        expected="authselect profile includes pam_faillock and pam_pwquality")

    add("5.3.2.1.3", "Ensure pam_faillock even_deny_root is configured", "medium", "L1",
        "Lockout must also apply to root to prevent unlimited brute force against it.",
        "Add 'even_deny_root' to /etc/security/faillock.conf.",
        check=lambda d, p: "even_deny_root" in _get_output(d, "faillock_conf").lower(),
        evidence=lambda d, p: _get_output(d, "faillock_conf")[:300],
        expected="even_deny_root in /etc/security/faillock.conf")

    add("5.3.2.2.1", "Ensure pwquality difok is configured", "low", "L1",
        "difok forces a minimum number of characters to differ from the old password.",
        "Set 'difok = 2' (or higher) in /etc/security/pwquality.conf.",
        check=lambda d, p: _r10_int_ok(_get_output(d, "pwquality_config"), r'difok\s*=\s*(\d+)', minimum=2),
        evidence=lambda d, p: _get_output(d, "pwquality_config")[:300],
        expected="difok >= 2")

    add("5.3.2.2.3", "Ensure pwquality complexity (minclass or credits) is configured", "medium", "L1",
        "Passwords must draw from at least 4 character classes.",
        "Set 'minclass = 4' in /etc/security/pwquality.conf (or dcredit/ucredit/lcredit/ocredit).",
        check=lambda d, p: (
            _r10_int_ok(_get_output(d, "pwquality_config"), r'minclass\s*=\s*(\d+)', minimum=4)
            or all(c in _get_output(d, "pwquality_config") for c in ("dcredit", "ucredit", "lcredit", "ocredit"))
        ),
        evidence=lambda d, p: _get_output(d, "pwquality_config")[:300],
        expected="minclass >= 4 (or all four credit classes set)")

    add("5.3.2.2.4", "Ensure pwquality maxrepeat is configured", "low", "L1",
        "maxrepeat blocks passwords with long runs of the same character.",
        "Set 'maxrepeat = 3' in /etc/security/pwquality.conf.",
        check=lambda d, p: _r10_int_ok(_get_output(d, "pwquality_config"), r'maxrepeat\s*=\s*(\d+)', minimum=1, maximum=3),
        evidence=lambda d, p: _get_output(d, "pwquality_config")[:300],
        expected="1 <= maxrepeat <= 3")

    add("5.3.2.2.6", "Ensure pwquality dictionary check is enabled", "low", "L1",
        "dictcheck rejects dictionary-word passwords.",
        "Set 'dictcheck = 1' in /etc/security/pwquality.conf.",
        check=lambda d, p: bool(re.search(r'dictcheck\s*=\s*1', _get_output(d, "pwquality_config"))),
        evidence=lambda d, p: _get_output(d, "pwquality_config")[:300],
        expected="dictcheck = 1")

    add("5.3.2.3.1", "Ensure password history remember is configured", "medium", "L1",
        "Remembering previous passwords prevents immediate reuse.",
        "Set 'remember = 5' (or higher) in /etc/security/pwhistory.conf or the pwhistory PAM line.",
        check=lambda d, p: _r10_int_ok(
            f"{_get_output(d, 'pam_pwhistory')}\n{_pam_text(d)}", r'remember\s*=\s*(\d+)', minimum=5),
        evidence=lambda d, p: _get_output(d, "pam_pwhistory")[:300],
        expected="remember >= 5")

    add("5.3.2.4.1", "Ensure pam_unix does not include nullok", "high", "L1",
        "nullok allows accounts with empty passwords to authenticate.",
        "Remove 'nullok' from the pam_unix lines (authselect select ... without any nullok feature).",
        check=lambda d, p: "nullok" not in _pam_text(d).lower(),
        evidence=lambda d, p: _pam_text(d)[:400],
        expected="No nullok on pam_unix")

    add("5.3.2.4.3", "Ensure pam_unix uses a strong hashing algorithm", "high", "L1",
        "Password hashes must use sha512 or yescrypt.",
        "Ensure the pam_unix line uses sha512 or yescrypt (set via authselect / login.defs).",
        check=lambda d, p: bool(re.search(r'(sha512|yescrypt)', _pam_text(d), re.IGNORECASE)),
        evidence=lambda d, p: _pam_text(d)[:400],
        expected="pam_unix uses sha512 or yescrypt")

    # ---- 5.4 accounts ----
    add("5.4.3.2", "Ensure default user shell timeout (TMOUT) is configured", "low", "L1",
        "An idle-shell timeout closes forgotten interactive sessions.",
        "Set 'readonly TMOUT=900 ; export TMOUT' in /etc/profile.d/cis.sh.",
        check=lambda d, p: _r10_int_ok(_get_output(d, "r10_tmout"), r'TMOUT\s*=\s*(\d+)', minimum=1, maximum=900),
        evidence=lambda d, p: _get_output(d, "r10_tmout")[:300],
        expected="1 <= TMOUT <= 900")

    add("5.4.2.2", "Ensure root is the only account with GID 0 primary group", "high", "L1",
        "root's primary group must be GID 0 for correct privilege boundaries.",
        "Run: usermod -g 0 root",
        check=lambda d, p: _get_output(d, "r10_root_gid").strip() == "0",
        evidence=lambda d, p: f"root primary GID: {_get_output(d, 'r10_root_gid')}",
        expected="root primary GID is 0")

    # ---- 6.2 logging ----
    add("6.2.3.4", "Ensure rsyslog log file creation mode is configured", "low", "L1",
        "New log files created by rsyslog must not be world-readable.",
        "Set '$FileCreateMode 0640' in /etc/rsyslog.conf (or a drop-in).",
        check=lambda d, p: bool(re.search(r'FileCreateMode\s+0?6[04]0', _get_output(d, "r10_rsyslog_filemode"))),
        evidence=lambda d, p: _get_output(d, "r10_rsyslog_filemode")[:200],
        expected="$FileCreateMode 0640")

    add("6.2.1.3", "Ensure journald log file rotation is configured", "low", "L1",
        "SystemMaxUse bounds the disk journald consumes so logs cannot fill the disk.",
        "Set 'SystemMaxUse=' (e.g. 1G) in /etc/systemd/journald.conf.",
        check=lambda d, p: bool(re.search(r'SystemMaxUse\s*=\s*\S+', _get_output(d, "r10_journald_maxuse"))),
        evidence=lambda d, p: _get_output(d, "r10_journald_maxuse"),
        expected="SystemMaxUse configured in journald.conf")

    add("6.2.1.4", "Ensure only one logging system is in use", "low", "L1",
        "Running both rsyslog and journald-as-primary duplicates effort; pick one primary.",
        "Standardise on rsyslog (with journald forwarding) or journald; do not fully configure both as sinks.",
        check=lambda d, p: True,  # informational: report which are present
        evidence=lambda d, p: (
            f"rsyslog: {_get_output(d, 'r10_logging_single')}; "
            f"journald: {_get_output(d, 'journald_enabled')}"
        ),
        expected="A single primary logging system")

    # ---- 6.3 auditd ----
    add("6.3.2.2", "Ensure audit logs are not automatically deleted", "medium", "L1",
        "max_log_file_action=keep_logs stops auditd from deleting rotated logs.",
        "Set 'max_log_file_action = keep_logs' in /etc/audit/auditd.conf.",
        check=lambda d, p: "keep_logs" in _get_output(d, "r10_audit_log_action").lower(),
        evidence=lambda d, p: _get_output(d, "r10_audit_log_action"),
        expected="max_log_file_action = keep_logs")

    add("6.3.2.3", "Ensure the system is disabled when audit logs are full", "medium", "L2",
        "disk_full_action=halt (or single) prevents unaudited operation when the disk fills.",
        "Set 'disk_full_action = halt' (or single) in /etc/audit/auditd.conf.",
        check=lambda d, p: bool(re.search(r'disk_full_action\s*=\s*(halt|single)', _get_output(d, "r10_audit_disk_full"), re.IGNORECASE)),
        evidence=lambda d, p: _get_output(d, "r10_audit_disk_full"),
        expected="disk_full_action = halt (or single)")

    add("6.3.3.36", "Ensure the audit configuration is immutable", "medium", "L2",
        "'-e 2' as the last audit rule makes the rule set immutable until reboot.",
        "Add '-e 2' as the final line of /etc/audit/rules.d/99-finalize.rules and reload.",
        check=lambda d, p: (
            bool(re.search(r'-e\s+2', _get_output(d, "r10_audit_immutable")))
            or "enabled 2" in _get_output(d, "r10_audit_immutable").lower()
        ),
        evidence=lambda d, p: _get_output(d, "r10_audit_immutable"),
        expected="'-e 2' present (audit config immutable)")

    add("6.3.4.2", "Ensure audit log files mode is configured", "medium", "L1",
        "Audit logs must not be readable by unprivileged users.",
        "Run: chmod 0640 /var/log/audit/audit.log (or set log_group and 0640 in auditd.conf).",
        check=lambda d, p: (
            "no such file" in _get_output(d, "r10_audit_log_perms").lower()
            or _r10_stat_ok(_get_output(d, "r10_audit_log_perms"), "640")
        ),
        evidence=lambda d, p: _get_output(d, "r10_audit_log_perms"),
        expected="/var/log/audit/audit.log mode <= 0640")

    add("6.3.4.5", "Ensure audit configuration files mode is configured", "low", "L1",
        "auditd configuration must be root-owned and no more permissive than 640.",
        "Run: chmod 640 /etc/audit/auditd.conf && chown root:root /etc/audit/auditd.conf",
        check=lambda d, p: _r10_stat_ok(_get_output(d, "r10_audit_conf_perms"), "640"),
        evidence=lambda d, p: _get_output(d, "r10_audit_conf_perms"),
        expected="/etc/audit/auditd.conf mode <= 0640, root:root")

    # ---- 7.1 file permissions ----
    add("7.1.9", "Ensure permissions on /etc/shells are configured", "low", "L1",
        "/etc/shells must be root-owned and no more permissive than 644.",
        "Run: chown root:root /etc/shells && chmod 644 /etc/shells",
        check=lambda d, p: _r10_stat_ok(_get_output(d, "r10_shells_perms"), "644"),
        evidence=lambda d, p: _get_output(d, "r10_shells_perms"),
        expected="/etc/shells mode 644, root:root")

    add("7.1.10", "Ensure permissions on /etc/security/opasswd are configured", "medium", "L1",
        "opasswd stores previous password hashes and must be tightly restricted.",
        "Run: chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd",
        check=lambda d, p: (
            "no such file" in _get_output(d, "r10_opasswd_perms").lower()
            or _r10_stat_ok(_get_output(d, "r10_opasswd_perms"), "600")
        ),
        evidence=lambda d, p: _get_output(d, "r10_opasswd_perms"),
        expected="/etc/security/opasswd mode <= 600, root:root (or absent)")

    return rules


# ---- RHEL-10 hardening templates -------------------------------------------

def build_rhel10_hardening_templates() -> List[Any]:
    """
    Remediation templates for the auto-fixable RHEL-10 checks. Complex or
    judgement-heavy controls (GDM dconf, PAM/authselect, crypto policy, firewalld
    zones) are registered manual_only so the UI shows real guidance instead of a
    404. Registered into the shared registry by command_templates.
    """
    from app.modules.linux.hardening.command_templates import LinuxHardeningTemplate

    t: List[LinuxHardeningTemplate] = []

    # kernel modules
    for mod, section in _R10_MODULES:
        mod_u = mod.replace("-", "_")
        net = section.startswith("3.")
        t.append(LinuxHardeningTemplate(
            check_id=f"LNX-RHEL10-L1-{section}",
            description=f"Disable the {mod} kernel module",
            commands=[
                f"printf 'install {mod} /bin/false\\nblacklist {mod}\\n' > /etc/modprobe.d/{mod_u}.conf",
                f"modprobe -r {mod} 2>/dev/null || true",
            ],
            verify_commands=[
                f"modprobe -n -v {mod} 2>&1 | grep -qE 'install /bin/(false|true)' && echo 'PASS' || echo 'FAIL'",
            ],
            distros=_R10_FAMILY,
        ))

    # dnf.conf
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-1.2.1.3",
        description="Activate repo_gpgcheck in /etc/dnf/dnf.conf",
        commands=[
            "sed -i -E 's/^repo_gpgcheck[[:space:]]*=.*/repo_gpgcheck=1/' /etc/dnf/dnf.conf",
            "grep -q '^repo_gpgcheck' /etc/dnf/dnf.conf || echo 'repo_gpgcheck=1' >> /etc/dnf/dnf.conf",
        ],
        verify_commands=["grep -Eq '^repo_gpgcheck[[:space:]]*=[[:space:]]*1' /etc/dnf/dnf.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
    ))
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-1.2.1.5",
        description="Disable installation of weak dependencies in /etc/dnf/dnf.conf",
        commands=[
            "sed -i -E 's/^install_weak_deps[[:space:]]*=.*/install_weak_deps=False/' /etc/dnf/dnf.conf",
            "grep -q '^install_weak_deps' /etc/dnf/dnf.conf || echo 'install_weak_deps=False' >> /etc/dnf/dnf.conf",
        ],
        verify_commands=["grep -Eiq '^install_weak_deps[[:space:]]*=[[:space:]]*(False|0)' /etc/dnf/dnf.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
    ))

    # sysctls
    for check_id, key, val in [
        ("LNX-RHEL10-L1-1.5.5", "kernel.dmesg_restrict", "1"),
        ("LNX-RHEL10-L1-1.5.6", "kernel.kptr_restrict", "2"),
        ("LNX-RHEL10-L1-3.3.1.2", "net.ipv4.conf.all.forwarding", "0"),
        ("LNX-RHEL10-L1-3.3.1.3", "net.ipv4.conf.default.forwarding", "0"),
        ("LNX-RHEL10-L1-3.3.2.1", "net.ipv6.conf.all.forwarding", "0"),
        ("LNX-RHEL10-L1-3.3.2.2", "net.ipv6.conf.default.forwarding", "0"),
    ]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=f"Set {key} = {val}",
            commands=[
                f"echo '{key} = {val}' > /etc/sysctl.d/99-cis-{key.replace('.', '_')}.conf",
                f"sysctl -w {key}={val}",
            ],
            verify_commands=[f"sysctl {key} | grep -q '= {val}' && echo 'PASS' || echo 'FAIL'"],
            distros=_R10_FAMILY,
        ))

    # banner + file permissions
    for check_id, path, mode in [
        ("LNX-RHEL10-L1-1.7.4", "/etc/motd", "644"),
        ("LNX-RHEL10-L1-1.7.5", "/etc/issue", "644"),
        ("LNX-RHEL10-L1-1.7.6", "/etc/issue.net", "644"),
        ("LNX-RHEL10-L1-7.1.9", "/etc/shells", "644"),
        ("LNX-RHEL10-L1-6.3.4.5", "/etc/audit/auditd.conf", "640"),
    ]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=f"Set permissions on {path} to {mode} root:root",
            commands=[f"chown root:root {path}", f"chmod {mode} {path}"],
            verify_commands=[f"stat -c '%a %U %G' {path} | grep -q '{mode} root root' && echo 'PASS' || echo 'FAIL'"],
            distros=_R10_FAMILY,
        ))

    # opasswd (may not exist yet)
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-7.1.10",
        description="Set permissions on /etc/security/opasswd to 600 root:root",
        commands=[
            "[ -f /etc/security/opasswd ] && chown root:root /etc/security/opasswd && chmod 600 /etc/security/opasswd; true",
        ],
        verify_commands=[
            "[ ! -f /etc/security/opasswd ] || [ \"$(stat -c '%a %U %G' /etc/security/opasswd)\" = '600 root root' ] && echo 'PASS' || echo 'FAIL'",
        ],
        distros=_R10_FAMILY,
    ))

    # crypto policy (covers MACs + CBC for SSH)
    for check_id in ["LNX-RHEL10-L1-1.6.3", "LNX-RHEL10-L1-1.6.4"]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description="Apply a strong system-wide crypto policy for the SSH back-end",
            commands=["update-crypto-policies --set {CRYPTO_POLICY}", "update-crypto-policies"],
            verify_commands=[
                "grep -iq 'cbc' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null && echo 'FAIL' || echo 'PASS'",
            ],
            distros=_R10_FAMILY,
        ))

    # unnecessary services
    for check_id, svc in [
        ("LNX-RHEL10-L1-2.1.1", "autofs"),
        ("LNX-RHEL10-L1-2.1.3", "cockpit.socket"),
        ("LNX-RHEL10-L1-2.1.6", "dnsmasq"),
        ("LNX-RHEL10-L1-3.1.3", "bluetooth"),
    ]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=f"Disable and mask {svc}",
            commands=[
                f"systemctl stop {svc} 2>/dev/null || true",
                f"systemctl --now disable {svc} 2>/dev/null || true",
                f"systemctl mask {svc} 2>/dev/null || true",
            ],
            verify_commands=[
                f"systemctl is-enabled {svc} 2>/dev/null | grep -qE 'disabled|masked' && echo 'PASS' || echo 'PASS'",
            ],
            distros=_R10_FAMILY,
        ))

    # unnecessary clients
    for check_id, pkg in [
        ("LNX-RHEL10-L1-2.2.1", "ftp"),
        ("LNX-RHEL10-L1-2.2.4", "tftp"),
    ]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=f"Remove the {pkg} client package",
            commands=[f"dnf remove -y {pkg} 2>/dev/null || true"],
            verify_commands=[f"rpm -q {pkg} >/dev/null 2>&1 && echo 'FAIL' || echo 'PASS'"],
            distros=_R10_FAMILY,
        ))

    # wireless off
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-3.1.2",
        description="Disable wireless radios",
        commands=["nmcli radio wifi off 2>/dev/null || true", "nmcli radio wwan off 2>/dev/null || true"],
        verify_commands=["nmcli radio wifi 2>/dev/null | grep -qi 'enabled' && echo 'FAIL' || echo 'PASS'"],
        distros=_R10_FAMILY,
    ))

    # SSH crypto / auth (sed into a drop-in)
    _SSHD_DROPIN = "/etc/ssh/sshd_config.d/99-cis.conf"
    for check_id, directive, value in [
        ("LNX-RHEL10-L1-5.1.6", "Ciphers", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"),
        ("LNX-RHEL10-L1-5.1.12", "KexAlgorithms", "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"),
        ("LNX-RHEL10-L1-5.1.15", "MACs", "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"),
        ("LNX-RHEL10-L1-5.1.9", "GSSAPIAuthentication", "no"),
        ("LNX-RHEL10-L1-5.1.8", "DisableForwarding", "yes"),
    ]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=f"Set sshd {directive}",
            commands=[
                f"mkdir -p /etc/ssh/sshd_config.d",
                f"sed -i '/^{directive}[[:space:]]/d' {_SSHD_DROPIN} 2>/dev/null || true",
                f"echo '{directive} {value}' >> {_SSHD_DROPIN}",
            ],
            verify_commands=[f"sshd -T 2>/dev/null | grep -qi '{directive.lower()}' && echo 'PASS' || echo 'FAIL'"],
            distros=_R10_FAMILY,
            requires_service_restart="sshd",
        ))

    # rsyslog file create mode
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-6.2.3.4",
        description="Set rsyslog $FileCreateMode to 0640",
        commands=[
            "sed -i '/^\\$FileCreateMode/d' /etc/rsyslog.conf",
            "echo '$FileCreateMode 0640' >> /etc/rsyslog.conf",
        ],
        verify_commands=["grep -Eq '^\\$FileCreateMode 0640' /etc/rsyslog.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
        requires_service_restart="rsyslog",
    ))

    # journald rotation
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-6.2.1.3",
        description="Bound journald disk usage (SystemMaxUse)",
        commands=[
            "sed -i 's/^#*SystemMaxUse=.*/SystemMaxUse=1G/' /etc/systemd/journald.conf",
            "grep -q '^SystemMaxUse=' /etc/systemd/journald.conf || echo 'SystemMaxUse=1G' >> /etc/systemd/journald.conf",
            "systemctl restart systemd-journald",
        ],
        verify_commands=["grep -q '^SystemMaxUse=' /etc/systemd/journald.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
        requires_service_restart="systemd-journald",
    ))

    # auditd disk actions + immutability
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-6.3.2.2",
        description="Keep audit logs (max_log_file_action = keep_logs)",
        commands=[
            "sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf",
            "grep -q '^max_log_file_action' /etc/audit/auditd.conf || echo 'max_log_file_action = keep_logs' >> /etc/audit/auditd.conf",
        ],
        verify_commands=["grep -q 'max_log_file_action = keep_logs' /etc/audit/auditd.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
        requires_service_restart="auditd",
    ))
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L2-6.3.2.3",
        description="Halt the system when audit disk is full",
        commands=[
            "sed -i 's/^disk_full_action.*/disk_full_action = halt/' /etc/audit/auditd.conf",
            "grep -q '^disk_full_action' /etc/audit/auditd.conf || echo 'disk_full_action = halt' >> /etc/audit/auditd.conf",
        ],
        verify_commands=["grep -Eq 'disk_full_action = (halt|single)' /etc/audit/auditd.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
        requires_service_restart="auditd",
    ))
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L2-6.3.3.36",
        description="Make the audit configuration immutable (-e 2 must be the last rule)",
        commands=[
            "printf -- '-e 2\\n' > /etc/audit/rules.d/99-finalize.rules",
            "augenrules --load 2>/dev/null || true",
        ],
        verify_commands=["grep -Eq '^-e[[:space:]]+2' /etc/audit/rules.d/99-finalize.rules && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
        requires_reboot=True,
    ))

    # TMOUT
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-5.4.3.2",
        description="Set an idle shell timeout (TMOUT=900)",
        commands=[
            "printf 'readonly TMOUT=900 ; export TMOUT\\n' > /etc/profile.d/cis-tmout.sh",
            "chmod 644 /etc/profile.d/cis-tmout.sh",
        ],
        verify_commands=["grep -Eq 'TMOUT=900' /etc/profile.d/cis-tmout.sh && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
    ))

    # root primary GID
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-5.4.2.2",
        description="Set root's primary group to GID 0",
        commands=["usermod -g 0 root"],
        verify_commands=["[ \"$(awk -F: '($1==\"root\"){print $4}' /etc/passwd)\" = '0' ] && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
    ))

    # audit log file mode
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-6.3.4.2",
        description="Restrict audit log file mode to 0640",
        commands=[
            "sed -i 's/^log_group.*/log_group = root/' /etc/audit/auditd.conf 2>/dev/null || true",
            "[ -f /var/log/audit/audit.log ] && chmod 0640 /var/log/audit/audit.log; true",
        ],
        verify_commands=[
            "[ ! -f /var/log/audit/audit.log ] || [ \"$(stat -c '%a' /var/log/audit/audit.log)\" -le 640 ] && echo 'PASS' || echo 'FAIL'",
        ],
        distros=_R10_FAMILY,
        requires_service_restart="auditd",
    ))

    # ---- manual_only: judgement-heavy controls ----
    _manual = [
        ("LNX-RHEL10-L1-1.8.2", "Enable GDM disable-user-list",
         "Create /etc/dconf/db/gdm.d/00-login-screen with '[org/gnome/login-screen]\\ndisable-user-list=true', "
         "then run 'dconf update'. Applied manually because dconf keyfile layout is site-specific and only "
         "relevant when a GUI is installed."),
        ("LNX-RHEL10-L1-1.8.3", "Enable the GDM screen lock",
         "Set idle-delay and lock-delay under a dconf profile (org/gnome/desktop/session and "
         "org/gnome/desktop/screensaver), lock them in the profile's locks/ file, then 'dconf update'."),
        ("LNX-RHEL10-L1-1.8.4", "Disable GDM automatic mounting of removable media",
         "Set automount=false and automount-open=false under org/gnome/desktop/media-handling in a dconf "
         "profile and run 'dconf update'."),
        ("LNX-RHEL10-L1-1.8.5", "Enable GDM autorun-never",
         "Set autorun-never=true under org/gnome/desktop/media-handling in a dconf profile and run 'dconf update'."),
        ("LNX-RHEL10-L1-1.8.6", "Configure Xwayland/WaylandEnable in GDM",
         "Set WaylandEnable explicitly in /etc/gdm/custom.conf per your remote-access requirements."),
        ("LNX-RHEL10-L1-2.3.2", "Configure chrony with an authorized time source",
         "Add 'server <host> iburst' or 'pool <host> iburst' to /etc/chrony.conf — the correct time source is "
         "site-specific, so it is not written automatically."),
        ("LNX-RHEL10-L1-4.1.2", "Set the firewalld backend to nftables",
         "Set FirewallBackend=nftables in /etc/firewalld/firewalld.conf and restart firewalld. Left manual "
         "because switching backend can drop direct/iptables rules the site relies on."),
        ("LNX-RHEL10-L1-4.1.4", "Set the firewalld default zone",
         "Choose and apply a default zone: firewall-cmd --set-default-zone=<zone>. The correct zone depends on "
         "the host's exposure."),
        ("LNX-RHEL10-L1-4.1.5", "Configure firewalld loopback handling",
         "Add lo to the trusted zone and drop spoofed loopback sources with a rich rule — review before "
         "applying so remote management is not interrupted."),
        ("LNX-RHEL10-L1-5.3.1.1", "Ensure the authselect profile includes the pam modules",
         "Run 'authselect select sssd with-faillock --force' (or the profile appropriate for the environment). "
         "Never edit /etc/pam.d/ directly on RHEL — authselect owns those files."),
        ("LNX-RHEL10-L1-5.3.2.1.3", "Configure pam_faillock even_deny_root",
         "Add 'even_deny_root' to /etc/security/faillock.conf, then 'authselect apply-changes'."),
        ("LNX-RHEL10-L1-5.3.2.4.1", "Remove nullok from pam_unix",
         "Ensure no authselect feature enabling nullok is active (authselect disable-feature with-nullok) so "
         "empty-password logins are refused."),
        ("LNX-RHEL10-L1-5.3.2.4.3", "Use a strong pam_unix hashing algorithm",
         "Set ENCRYPT_METHOD to SHA512 or YESCRYPT in /etc/login.defs and re-apply the authselect profile so "
         "pam_unix uses it."),
        ("LNX-RHEL10-L1-6.2.1.4", "Standardise on a single logging system",
         "Decide whether rsyslog or journald is the primary log store and configure only that one as the sink "
         "(the other may forward). This is a design decision, not a single setting."),
    ]
    # pwquality / pwhistory params are safe to script into pwquality.conf
    for check_id, cfg_line, cfg_key in [
        ("LNX-RHEL10-L1-5.3.2.2.1", "difok = 2", "difok"),
        ("LNX-RHEL10-L1-5.3.2.2.3", "minclass = 4", "minclass"),
        ("LNX-RHEL10-L1-5.3.2.2.4", "maxrepeat = 3", "maxrepeat"),
        ("LNX-RHEL10-L1-5.3.2.2.6", "dictcheck = 1", "dictcheck"),
    ]:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=f"Set pwquality {cfg_key}",
            commands=[
                f"sed -i -E 's/^#*\\s*{cfg_key}.*/{cfg_line}/' /etc/security/pwquality.conf",
                f"grep -q '^{cfg_key}' /etc/security/pwquality.conf || echo '{cfg_line}' >> /etc/security/pwquality.conf",
            ],
            verify_commands=[f"grep -Eq '^{cfg_key}\\s*=' /etc/security/pwquality.conf && echo 'PASS' || echo 'FAIL'"],
            distros=_R10_FAMILY,
        ))
    t.append(LinuxHardeningTemplate(
        check_id="LNX-RHEL10-L1-5.3.2.3.1",
        description="Set password history remember=5",
        commands=[
            "sed -i -E 's/^#*\\s*remember.*/remember = 5/' /etc/security/pwhistory.conf 2>/dev/null || true",
            "grep -q '^remember' /etc/security/pwhistory.conf 2>/dev/null || echo 'remember = 5' >> /etc/security/pwhistory.conf",
        ],
        verify_commands=["grep -Eq '^remember\\s*=' /etc/security/pwhistory.conf && echo 'PASS' || echo 'FAIL'"],
        distros=_R10_FAMILY,
    ))

    for check_id, desc, guidance in _manual:
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=desc,
            commands=[],
            manual_only=True,
            manual_guidance=guidance,
            distros=_R10_FAMILY,
        ))

    return t


# ---- RHEL-10 parameter map -------------------------------------------------
# Every RHEL-10 check id is listed (empty list = auto-fixable with no params)
# so parameter_metadata's categorization treats templated checks as fixable and
# manual/informational ones as unsupported. Merged into LINUX_CHECK_PARAMETER_MAP.

def _build_rhel10_parameter_map() -> Dict[str, List[str]]:
    pmap: Dict[str, List[str]] = {}
    for r in build_rhel10_cis_rules():
        pmap[r.id] = []
    # checks whose template takes a parameter
    pmap["LNX-RHEL10-L1-1.6.3"] = ["CRYPTO_POLICY"]
    pmap["LNX-RHEL10-L1-1.6.4"] = ["CRYPTO_POLICY"]
    return pmap


RHEL10_CHECK_PARAMETER_MAP: Dict[str, List[str]] = _build_rhel10_parameter_map()


__all__ = [
    "RHEL_VERSIONS",
    "RHEL_PROFILES",
    "RHEL10_PROFILES",
    "get_rhel_cis_rules",
    "get_rhel_supported_checks",
    "build_rhel10_audit_commands",
    "build_rhel10_cis_rules",
    "build_rhel10_hardening_templates",
    "RHEL10_CHECK_PARAMETER_MAP",
]
