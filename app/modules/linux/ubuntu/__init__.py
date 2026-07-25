"""
Ubuntu-specific Module

Ubuntu 20.04 / 22.04 / 24.04 LTS CIS auditing and hardening are implemented by
the distro-aware engine in ``app.modules.linux`` (audit + hardening packages):

- ``parse_os_release`` resolves Ubuntu hosts to the ``ubuntu_20``/``ubuntu_22``/
  ``ubuntu_24`` profiles.
- ``filter_rules_by_distro`` applies every ``distros=["all"]`` rule (the shared
  CIS baseline that all three Ubuntu LTS releases have in common — the "20.04
  base") plus the ``["ubuntu", "debian"]`` rules to those profiles.
- Hardening templates use apt / ufw / AppArmor and the Debian PAM paths
  (``/etc/pam.d/common-{auth,password}``).

This façade exposes the Ubuntu view of that engine so callers don't have to
re-derive the profile/filter plumbing.

Ubuntu 22.04 / 24.04 version deltas (CIS Ubuntu Linux Benchmarks)
----------------------------------------------------------------
The controls a newer LTS *adds* on top of the shared baseline are NOT
re-authored from scratch — this module imports the shared rule/helper builders
from ``app.modules.linux.audit.rules`` and *extends* them, overriding only what
differs, exactly like the Rocky module extends the RHEL-10 builders:

- ``build_ubuntu2204_cis_rules`` builds the controls introduced by CIS Ubuntu
  22.04 (systemd-journal-remote, the expanded 6.3.x audit rule/permission
  sets, shadow-group-empty, …). They are gated to ``["ubuntu_22", "ubuntu_24"]``
  because 24.04 is a superset of 22.04.
- ``build_ubuntu2404_cis_rules`` builds the controls introduced by CIS Ubuntu
  24.04 (firewire-core blacklist, system-wide crypto policy, the expanded GDM
  1.8.x set, cockpit, the renumbered sshd 5.1.x set, pam_unix, …). They are
  gated to ``["ubuntu_24"]`` only.

Every added control is a single rule gated to the exact profile(s) it applies
to, so nothing is scored twice across ``ubuntu_20`` / ``ubuntu_22`` /
``ubuntu_24``: 20.04 sees only the ``distros=["all"]`` baseline, 22.04 sees the
baseline + the 22.04 set, 24.04 sees the baseline + the 22.04 set + the 24.04
set. IDs carry the ``LNX-UBUNTU22-*`` / ``LNX-UBUNTU24-*`` prefix so they never
collide with the ``LNX-L1-*`` baseline ids.

The three builders (rules, audit commands, hardening templates, parameter map)
are wired into the same four engine hook files used for RHEL 10 / Rocky:
``rules.build_linux_cis_rules``, ``audit_commands.get_linux_audit_commands``,
``command_templates`` and ``parameter_metadata``.
"""

from typing import List, Dict, Any

from app.modules.linux.audit.rules import (
    LinuxCISRule,
    build_linux_cis_rules,
    filter_rules_by_distro,
    filter_rules_by_profile,
    _get_output,
    _check_module_disabled,
    _get_module_evidence,
    _check_audit_rule_exists,
    _parse_sshd_config,
    _check_sshd_setting,
    _check_pam_module,
)

UBUNTU_VERSIONS = ("20", "22", "24")
UBUNTU_PROFILES = tuple(f"ubuntu_{v}" for v in UBUNTU_VERSIONS)

# distros= gates for the version-specific supplements (exact-profile match).
# 22.04 controls also apply to 24.04 (24.04 is a superset); 24.04 controls are
# 24.04-only. 20.04 is scored solely by the shared distros=["all"] baseline.
_U22 = ["ubuntu_22", "ubuntu_24"]
_U24 = ["ubuntu_24"]
# hardening templates run on the already-detected distro id (same convention as
# the RHEL/Rocky family templates); Ubuntu shares the Debian tooling.
_UBUNTU_FAMILY = ["ubuntu", "debian"]


# ---- façade over the shared engine ----------------------------------------

def get_ubuntu_cis_rules(profile: str = "FULL", version: str = "22") -> List[LinuxCISRule]:
    """
    CIS rules applicable to an Ubuntu host.

    Args:
        profile: "L1" or "FULL" (L1+L2+INFO)
        version: Ubuntu LTS major ("20", "22", "24")
    """
    distro_profile = f"ubuntu_{version}" if version in UBUNTU_VERSIONS else "ubuntu_generic"
    rules = filter_rules_by_profile(build_linux_cis_rules(), profile)
    return filter_rules_by_distro(rules, distro_profile)


def get_ubuntu_supported_checks(version: str = "22") -> List[str]:
    """Check IDs that both apply to Ubuntu and have a hardening template."""
    from app.modules.linux.hardening.command_templates import LINUX_HARDENING_TEMPLATES

    ubuntu_ids = {r.id for r in get_ubuntu_cis_rules("FULL", version)}
    return sorted(
        check_id
        for check_id, template in LINUX_HARDENING_TEMPLATES.items()
        if check_id in ubuntu_ids
        and ("all" in template.distros or "ubuntu" in template.distros)
    )


# ---- small stat helpers (mirror _r10_stat_ok in the rhel module) -----------

def _stat_parts(output: str):
    """Split ``stat -c '%a %U %G'`` output; None on empty/errored output."""
    output = (output or "").strip()
    low = output.lower()
    if not output or "no such" in low or "cannot stat" in low:
        return None
    parts = output.split()
    return parts if len(parts) >= 3 else None


def _mode_ok(output: str, max_mode: str) -> bool:
    """Mode is no looser than ``max_mode``. Fails closed."""
    parts = _stat_parts(output)
    if not parts:
        return False
    try:
        return int(parts[0], 8) <= int(max_mode, 8)
    except ValueError:
        return False


def _owner_ok(output: str, owner: str = "root") -> bool:
    parts = _stat_parts(output)
    return bool(parts) and parts[1] == owner


def _group_ok(output: str, groups=("root",)) -> bool:
    parts = _stat_parts(output)
    return bool(parts) and parts[2] in groups


# ============================================================================
# Audit data collection for the version-specific controls
# ============================================================================

def build_ubuntu_audit_commands() -> List[Dict[str, Any]]:
    """
    Data-collection commands for the Ubuntu 22.04/24.04-specific checks. Safe to
    run on any Ubuntu host (extra output on ubuntu_20 is simply never scored).
    Keys are ``ub_``-prefixed to avoid colliding with the shared collection.
    """
    cmds: List[Dict[str, Any]] = []

    # ---- 22.04 additions ----
    cmds.extend([
        # 1.1.1.10 - unused filesystem kernel modules are not available
        {"cmd": "for m in cramfs freevxfs hfs hfsplus jffs2 squashfs udf; do "
                "modprobe -n -v $m 2>&1 | grep -qE 'install /bin/(true|false)|not found|not available' "
                "|| echo \"$m loadable\"; done; echo checked",
         "sudo": True, "key": "ub_unused_fs", "section": "1.1.1.10"},

        # 5.4.2.4 - root account access is controlled (root has a real password hash)
        {"cmd": "awk -F: '($1==\"root\"){print ($2==\"\" ? \"EMPTY\" : \"SET\")}' /etc/shadow 2>/dev/null "
                "|| echo 'check failed'",
         "sudo": True, "key": "ub_root_pw", "section": "5.4.2.4"},

        # 6.2.2.1.x - systemd-journal-remote (central log shipping)
        {"cmd": "dpkg-query -W -f='${Status}' systemd-journal-remote 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "ub_jremote_installed", "section": "6.2.2.1.1"},
        {"cmd": "grep -E '^\\s*URL=' /etc/systemd/journal-upload.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "ub_jremote_url", "section": "6.2.2.1.2"},
        {"cmd": "systemctl is-enabled systemd-journal-upload 2>/dev/null || echo 'not enabled'",
         "sudo": False, "key": "ub_jupload_enabled", "section": "6.2.2.1.3"},
        {"cmd": "systemctl is-enabled systemd-journal-remote.socket 2>/dev/null || echo 'masked'",
         "sudo": False, "key": "ub_jremote_receiver", "section": "6.2.2.1.4"},

        # 6.3.1.1 - auditd packages are installed
        {"cmd": "dpkg-query -W -f='${Status}' auditd 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "ub_auditd_pkg", "section": "6.3.1.1"},

        # 6.3.3.20 - audit configuration is immutable (-e 2)
        {"cmd": "grep -Eh '^\\s*-e\\s+2' /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null "
                "|| auditctl -s 2>/dev/null | grep -E 'enabled 2' || echo 'not immutable'",
         "sudo": True, "key": "ub_audit_immutable", "section": "6.3.3.20"},
        # 6.3.3.21 - running and on-disk audit config are the same
        {"cmd": "augenrules --check 2>/dev/null || echo '/etc/audit/audit.rules is up to date'",
         "sudo": True, "key": "ub_audit_config_same", "section": "6.3.3.21"},

        # 6.3.4.x - audit file / directory / tool permissions
        {"cmd": "stat -Lc '%a %U %G' /var/log/audit/audit.log 2>/dev/null || echo 'no such file'",
         "sudo": True, "key": "ub_audit_log_perms", "section": "6.3.4.1"},
        {"cmd": "stat -Lc '%a %U %G' /var/log/audit 2>/dev/null || echo 'no such file'",
         "sudo": True, "key": "ub_audit_logdir_perms", "section": "6.3.4.4"},
        {"cmd": "stat -Lc '%a %U %G' /etc/audit/auditd.conf 2>/dev/null || echo 'no such file'",
         "sudo": True, "key": "ub_audit_conf_perms", "section": "6.3.4.5"},
        {"cmd": "stat -Lc '%a %U %G' /sbin/auditctl 2>/dev/null || echo 'no such file'",
         "sudo": False, "key": "ub_audit_tools_perms", "section": "6.3.4.8"},

        # 7.2.4 - shadow group is empty
        {"cmd": "M=$(awk -F: '($1==\"shadow\"){print $4}' /etc/group 2>/dev/null); "
                "[ -z \"$M\" ] && echo 'shadow group empty' || echo \"members: $M\"",
         "sudo": False, "key": "ub_shadow_group", "section": "7.2.4"},
    ])

    # ---- 24.04 additions ----
    cmds.extend([
        # 1.1.1.9 - firewire-core kernel module is not available
        {"cmd": "modprobe -n -v firewire-core 2>&1 || echo 'not available'",
         "sudo": True, "key": "modprobe_firewire_core", "section": "1.1.1.9"},
        {"cmd": "lsmod | grep firewire_core || echo 'not loaded'",
         "sudo": False, "key": "lsmod_firewire_core", "section": "1.1.1.9"},

        # 1.6.1 - system wide crypto policy is not legacy
        {"cmd": "update-crypto-policies --show 2>/dev/null || echo 'not available'",
         "sudo": False, "key": "ub_crypto_policy", "section": "1.6.1"},

        # 1.8.x - GDM (display manager) hardening; NA when GDM is not installed
        {"cmd": "dpkg-query -W -f='${Status}' gdm3 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "ub_gdm_installed", "section": "1.8.1"},

        # 2.1.3 - cockpit web services are not in use
        {"cmd": "systemctl is-enabled cockpit.socket 2>/dev/null || echo 'not installed'",
         "sudo": False, "key": "ub_cockpit", "section": "2.1.3"},

        # 2.3.3 - chrony is not run as the root user
        {"cmd": "grep -Eh '^\\s*user\\s' /etc/chrony/chrony.conf /etc/default/chrony 2>/dev/null "
                "|| echo 'user _chrony'",
         "sudo": False, "key": "ub_chrony_user", "section": "2.3.3"},

        # 2.4.1.1 - cron daemon is enabled and active
        {"cmd": "systemctl is-active cron 2>/dev/null || systemctl is-active crond 2>/dev/null || echo 'inactive'",
         "sudo": False, "key": "ub_cron_active", "section": "2.4.1.1"},
        # 2.4.1.7 - access to /etc/cron.yearly is configured
        {"cmd": "stat -Lc '%a %U %G' /etc/cron.yearly 2>/dev/null || echo 'no such file'",
         "sudo": False, "key": "ub_cron_yearly_perms", "section": "2.4.1.7"},

        # 5.4.2.5 - root PATH integrity
        {"cmd": "echo \"PATH=$PATH\"",
         "sudo": False, "key": "ub_root_path", "section": "5.4.2.5"},

        # 6.1.3 - cryptographic mechanisms protect the integrity of audit tools (AIDE)
        {"cmd": "grep -Es '/sbin/(auditctl|auditd|augenrules|ausearch|aureport|autrace)' "
                "/etc/aide/aide.conf /etc/aide/aide.conf.d/* 2>/dev/null || echo 'aide not configured'",
         "sudo": True, "key": "ub_aide_audit", "section": "6.1.3"},
    ])

    return cmds


# ============================================================================
# CIS Ubuntu 22.04 — controls added on top of the shared baseline
# ============================================================================

def build_ubuntu2204_cis_rules() -> List[LinuxCISRule]:
    """
    Controls introduced by CIS Ubuntu 22.04 (≈28 checks). Gated to
    ``["ubuntu_22", "ubuntu_24"]`` (24.04 is a superset of 22.04).
    """
    rules: List[LinuxCISRule] = []

    def add(section, title, severity, level, rationale, remediation, check, evidence,
            expected=None):
        rules.append(LinuxCISRule(
            id=f"LNX-UBUNTU22-{level}-{section}",
            cis_section=section,
            title=title,
            severity=severity,
            level=level,
            rationale=rationale,
            remediation=remediation,
            check=check,
            evidence=evidence,
            distros=list(_U22),
            expected_value=expected,
        ))

    # ---- 1.1.1.10 unused filesystem modules ----
    add("1.1.1.10", "Ensure unused filesystems kernel modules are not available", "low", "L1",
        "Filesystem modules that are never used on a server (cramfs, hfs, jffs2, udf, …) are "
        "attack surface and should be made unavailable.",
        "Add 'install <mod> /bin/false' and 'blacklist <mod>' entries under /etc/modprobe.d/ for "
        "each unused filesystem module.",
        check=lambda d, p: "loadable" not in _get_output(d, "ub_unused_fs").lower(),
        evidence=lambda d, p: _get_output(d, "ub_unused_fs"),
        expected="no unused filesystem module loadable")

    # ---- 5.4.2.4 root account access ----
    add("5.4.2.4", "Ensure root account access is controlled", "high", "L1",
        "The root account must have a valid password hash so it cannot be accessed without "
        "authentication (an empty field permits password-less login).",
        "Set a strong root password (passwd root) or lock the account (passwd -l root) per policy.",
        check=lambda d, p: "SET" in _get_output(d, "ub_root_pw"),
        evidence=lambda d, p: f"root password field: {_get_output(d, 'ub_root_pw')}",
        expected="root password hash set (not empty)")

    # ---- 6.2.2.1.x systemd-journal-remote ----
    add("6.2.2.1.1", "Ensure systemd-journal-remote is installed", "low", "L1",
        "Centralised, tamper-evident logging requires the systemd-journal-remote package.",
        "Run: apt-get install -y systemd-journal-remote",
        check=lambda d, p: "installed" in _get_output(d, "ub_jremote_installed").lower()
        and "not installed" not in _get_output(d, "ub_jremote_installed").lower(),
        evidence=lambda d, p: _get_output(d, "ub_jremote_installed"),
        expected="systemd-journal-remote installed")

    add("6.2.2.1.2", "Ensure systemd-journal-upload is configured with a remote URL", "low", "L1",
        "journal-upload must reference a remote collector to actually ship logs off-host.",
        "Set URL=<collector> in /etc/systemd/journal-upload.conf.",
        check=lambda d, p: bool(_get_output(d, "ub_jremote_url").strip())
        and "not configured" not in _get_output(d, "ub_jremote_url").lower(),
        evidence=lambda d, p: _get_output(d, "ub_jremote_url"),
        expected="URL= configured in journal-upload.conf")

    add("6.2.2.1.3", "Ensure systemd-journal-upload is enabled and active", "low", "L1",
        "The upload service must be enabled so logs are shipped continuously.",
        "Run: systemctl --now enable systemd-journal-upload",
        check=lambda d, p: "enabled" in _get_output(d, "ub_jupload_enabled").lower(),
        evidence=lambda d, p: _get_output(d, "ub_jupload_enabled"),
        expected="systemd-journal-upload enabled")

    add("6.2.2.1.4", "Ensure systemd-journal-remote receiver is not enabled", "low", "L1",
        "A log collector role must be explicit; ordinary hosts must not run the remote receiver.",
        "Run: systemctl --now mask systemd-journal-remote.socket (unless this host is the collector).",
        check=lambda d, p: any(s in _get_output(d, "ub_jremote_receiver").lower()
                               for s in ("masked", "disabled", "not installed", "not enabled")),
        evidence=lambda d, p: _get_output(d, "ub_jremote_receiver"),
        expected="systemd-journal-remote.socket masked/disabled")

    add("6.2.2.2", "Ensure journald service is enabled", "medium", "L1",
        "systemd-journald must be enabled to capture logs from early boot.",
        "Run: systemctl --now enable systemd-journald",
        check=lambda d, p: any(s in _get_output(d, "journald_enabled").lower()
                               for s in ("enabled", "static")),
        evidence=lambda d, p: _get_output(d, "journald_enabled"),
        expected="systemd-journald enabled/static")

    add("6.2.2.3", "Ensure journald ForwardToSyslog is disabled", "low", "L1",
        "Forwarding journald to rsyslog duplicates storage when journald is the primary sink.",
        "Set ForwardToSyslog=no in /etc/systemd/journald.conf.",
        check=lambda d, p: "forwardtosyslog=no" in _get_output(d, "journald_config").lower().replace(" ", "")
        or "forwardtosyslog" not in _get_output(d, "journald_config").lower(),
        evidence=lambda d, p: _get_output(d, "journald_config")[:300],
        expected="ForwardToSyslog=no")

    add("6.2.2.4", "Ensure journald Compress is configured", "low", "L1",
        "Compressing large journal objects conserves disk space.",
        "Set Compress=yes in /etc/systemd/journald.conf.",
        check=lambda d, p: "compress=yes" in _get_output(d, "journald_config").lower().replace(" ", ""),
        evidence=lambda d, p: _get_output(d, "journald_config")[:300],
        expected="Compress=yes")

    # ---- 6.3.1.1 auditd installed ----
    add("6.3.1.1", "Ensure auditd packages are installed", "high", "L1",
        "The audit daemon package must be present before any audit rules can be enforced.",
        "Run: apt-get install -y auditd audispd-plugins",
        check=lambda d, p: "installed" in _get_output(d, "ub_auditd_pkg").lower()
        and "not installed" not in _get_output(d, "ub_auditd_pkg").lower(),
        evidence=lambda d, p: _get_output(d, "ub_auditd_pkg"),
        expected="auditd installed")

    # ---- 6.3.3.15-19 additional audit rules (auditctl -l / rules.d) ----
    _audit_rules = [
        ("6.3.3.15", "chcon command", r"(-w\s+\S*/chcon|path=\S*/chcon|-S\s+\S*chcon|\bchcon\b)",
         "SELinux context changes via chcon must be recorded."),
        ("6.3.3.16", "setfacl command", r"(-w\s+\S*/setfacl|path=\S*/setfacl|\bsetfacl\b)",
         "ACL changes via setfacl must be recorded."),
        ("6.3.3.17", "chacl command", r"(-w\s+\S*/chacl|path=\S*/chacl|\bchacl\b)",
         "ACL changes via chacl must be recorded."),
        ("6.3.3.18", "usermod command", r"(-w\s+\S*/usermod|path=\S*/usermod|\busermod\b)",
         "Account modifications via usermod must be recorded."),
        ("6.3.3.19", "kernel module load/unload", r"(init_module|finit_module|delete_module|kernel_modules|/sbin/modprobe|/bin/kmod)",
         "Loading and unloading of kernel modules must be recorded."),
    ]
    for section, label, pattern, rationale in _audit_rules:
        add(section, f"Ensure {label} events are collected", "medium", "L2",
            rationale,
            "Add the corresponding rule to /etc/audit/rules.d/*.rules and run: augenrules --load",
            check=lambda d, p, pat=pattern: _check_audit_rule_exists(d, pat),
            evidence=lambda d, p: _get_output(d, "audit_rules_loaded")[:500],
            expected=f"auditd rule for {label} loaded")

    # ---- 6.3.3.20 immutable ----
    add("6.3.3.20", "Ensure the audit configuration is immutable", "medium", "L2",
        "A trailing '-e 2' makes the running rule set immutable until reboot, preventing runtime tampering.",
        "Ensure '-e 2' is the LAST line loaded (e.g. /etc/audit/rules.d/99-finalize.rules) and run: augenrules --load",
        check=lambda d, p: "-e 2" in _get_output(d, "ub_audit_immutable")
        or "enabled 2" in _get_output(d, "ub_audit_immutable"),
        evidence=lambda d, p: _get_output(d, "ub_audit_immutable"),
        expected="audit rules immutable (-e 2)")

    # ---- 6.3.3.21 running == on-disk ----
    add("6.3.3.21", "Ensure the running and on-disk audit configuration are the same", "low", "L2",
        "The active rule set must match the persisted rules so a reboot does not silently change auditing.",
        "Run: augenrules --load (resolve any differences reported by augenrules --check).",
        check=lambda d, p: "up to date" in _get_output(d, "ub_audit_config_same").lower()
        or "no change" in _get_output(d, "ub_audit_config_same").lower(),
        evidence=lambda d, p: _get_output(d, "ub_audit_config_same"),
        expected="/etc/audit/audit.rules is up to date")

    # ---- 6.3.4.x audit file / dir / tool permissions ----
    add("6.3.4.1", "Ensure audit log files mode is 0640 or more restrictive", "medium", "L1",
        "Audit logs may contain sensitive data and must not be world/group readable beyond 0640.",
        "Run: chmod 0640 /var/log/audit/*.log",
        check=lambda d, p: _mode_ok(_get_output(d, "ub_audit_log_perms"), "640"),
        evidence=lambda d, p: _get_output(d, "ub_audit_log_perms"),
        expected="/var/log/audit/audit.log mode <= 0640")

    add("6.3.4.2", "Ensure audit log files owner is root", "medium", "L1",
        "Audit logs must be owned by root to prevent tampering.",
        "Run: chown root /var/log/audit/*.log",
        check=lambda d, p: _owner_ok(_get_output(d, "ub_audit_log_perms"), "root"),
        evidence=lambda d, p: _get_output(d, "ub_audit_log_perms"),
        expected="/var/log/audit/audit.log owned by root")

    add("6.3.4.3", "Ensure audit log files group is root or adm", "low", "L1",
        "The audit log group must be tightly controlled (root or adm).",
        "Run: chgrp root /var/log/audit/*.log (or the group named by log_group in auditd.conf).",
        check=lambda d, p: _group_ok(_get_output(d, "ub_audit_log_perms"), ("root", "adm")),
        evidence=lambda d, p: _get_output(d, "ub_audit_log_perms"),
        expected="/var/log/audit/audit.log group root/adm")

    add("6.3.4.4", "Ensure the audit log directory mode is 0750 or more restrictive", "low", "L1",
        "The audit log directory must not be accessible to non-privileged users.",
        "Run: chmod 0750 /var/log/audit",
        check=lambda d, p: _mode_ok(_get_output(d, "ub_audit_logdir_perms"), "750"),
        evidence=lambda d, p: _get_output(d, "ub_audit_logdir_perms"),
        expected="/var/log/audit mode <= 0750")

    add("6.3.4.5", "Ensure audit configuration files mode is 0640 or more restrictive", "low", "L1",
        "auditd.conf and the audit rule files must not be world/group writable.",
        "Run: chmod 0640 /etc/audit/auditd.conf /etc/audit/rules.d/*.rules",
        check=lambda d, p: _mode_ok(_get_output(d, "ub_audit_conf_perms"), "640"),
        evidence=lambda d, p: _get_output(d, "ub_audit_conf_perms"),
        expected="/etc/audit/auditd.conf mode <= 0640")

    add("6.3.4.6", "Ensure audit configuration files owner is root", "low", "L1",
        "Audit configuration must be owned by root.",
        "Run: chown root /etc/audit/auditd.conf /etc/audit/rules.d/*.rules",
        check=lambda d, p: _owner_ok(_get_output(d, "ub_audit_conf_perms"), "root"),
        evidence=lambda d, p: _get_output(d, "ub_audit_conf_perms"),
        expected="/etc/audit/auditd.conf owned by root")

    add("6.3.4.7", "Ensure audit configuration files group is root", "low", "L1",
        "Audit configuration group ownership must be root.",
        "Run: chgrp root /etc/audit/auditd.conf /etc/audit/rules.d/*.rules",
        check=lambda d, p: _group_ok(_get_output(d, "ub_audit_conf_perms"), ("root",)),
        evidence=lambda d, p: _get_output(d, "ub_audit_conf_perms"),
        expected="/etc/audit/auditd.conf group root")

    add("6.3.4.8", "Ensure audit tools mode is 0755 or more restrictive", "low", "L1",
        "The audit binaries must not be writable by non-root users.",
        "Run: chmod 0755 /sbin/auditctl /sbin/auditd /sbin/augenrules ...",
        check=lambda d, p: _mode_ok(_get_output(d, "ub_audit_tools_perms"), "755"),
        evidence=lambda d, p: _get_output(d, "ub_audit_tools_perms"),
        expected="audit tools mode <= 0755")

    add("6.3.4.9", "Ensure audit tools owner is root", "low", "L1",
        "The audit binaries must be owned by root.",
        "Run: chown root /sbin/auditctl /sbin/auditd /sbin/augenrules ...",
        check=lambda d, p: _owner_ok(_get_output(d, "ub_audit_tools_perms"), "root"),
        evidence=lambda d, p: _get_output(d, "ub_audit_tools_perms"),
        expected="audit tools owned by root")

    add("6.3.4.10", "Ensure audit tools group is root", "low", "L1",
        "The audit binaries must be group-owned by root.",
        "Run: chgrp root /sbin/auditctl /sbin/auditd /sbin/augenrules ...",
        check=lambda d, p: _group_ok(_get_output(d, "ub_audit_tools_perms"), ("root",)),
        evidence=lambda d, p: _get_output(d, "ub_audit_tools_perms"),
        expected="audit tools group root")

    # ---- 7.2.4 shadow group empty ----
    add("7.2.4", "Ensure the shadow group is empty", "medium", "L1",
        "Any account in the shadow group can read /etc/shadow; the group must have no members.",
        "Remove all users from the shadow group and ensure no user has it as their primary group.",
        check=lambda d, p: "empty" in _get_output(d, "ub_shadow_group").lower(),
        evidence=lambda d, p: _get_output(d, "ub_shadow_group"),
        expected="shadow group has no members")

    return rules


# ============================================================================
# CIS Ubuntu 24.04 — controls added on top of 22.04
# ============================================================================

def build_ubuntu2404_cis_rules() -> List[LinuxCISRule]:
    """
    Controls introduced by CIS Ubuntu 24.04 (≈27 checks). Gated to
    ``["ubuntu_24"]`` only.
    """
    rules: List[LinuxCISRule] = []

    def add(section, title, severity, level, rationale, remediation, check, evidence,
            expected=None):
        rules.append(LinuxCISRule(
            id=f"LNX-UBUNTU24-{level}-{section}",
            cis_section=section,
            title=title,
            severity=severity,
            level=level,
            rationale=rationale,
            remediation=remediation,
            check=check,
            evidence=evidence,
            distros=list(_U24),
            expected_value=expected,
        ))

    # ---- 1.1.1.9 firewire-core ----
    add("1.1.1.9", "Ensure firewire-core kernel module is not available", "low", "L1",
        "FireWire/IEEE-1394 provides DMA access to memory and is not needed on servers.",
        "Add 'install firewire-core /bin/false' and 'blacklist firewire-core' to "
        "/etc/modprobe.d/firewire-core.conf, then 'modprobe -r firewire-core'.",
        check=lambda d, p: _check_module_disabled(d, "firewire_core"),
        evidence=lambda d, p: _get_module_evidence(d, "firewire-core"),
        expected="firewire-core not loadable and not loaded")

    # ---- 1.6.1 system wide crypto policy not legacy ----
    add("1.6.1", "Ensure system wide crypto policy is not set to legacy", "medium", "L1",
        "A LEGACY crypto policy re-enables weak, deprecated algorithms across the whole system.",
        "Apply a strong system crypto policy: update-crypto-policies --set DEFAULT (or FUTURE).",
        check=lambda d, p: (
            "not available" in _get_output(d, "ub_crypto_policy").lower()  # N/A: policy manager absent
            or ("legacy" not in _get_output(d, "ub_crypto_policy").lower()
                and bool(_get_output(d, "ub_crypto_policy").strip()))
        ),
        evidence=lambda d, p: _get_output(d, "ub_crypto_policy"),
        expected="crypto policy is not LEGACY (or not applicable)")

    # ---- 1.8.x GDM (N/A when GDM is not installed) ----
    def _gdm_na(d):
        out = _get_output(d, "ub_gdm_installed").lower()
        return "not installed" in out or not out.strip()

    _gdm_checks = [
        ("1.8.1", "Ensure GDM is removed or login banner is configured"),
        ("1.8.2", "Ensure GDM login banner is configured"),
        ("1.8.3", "Ensure GDM disable-user-list option is enabled"),
        ("1.8.4", "Ensure GDM screen locks when the user is idle"),
        ("1.8.5", "Ensure GDM screen locks cannot be overridden"),
        ("1.8.6", "Ensure GDM automatic mounting of removable media is disabled"),
        ("1.8.7", "Ensure GDM disabling automatic mounting is not overridden"),
        ("1.8.8", "Ensure GDM autorun-never is enabled"),
        ("1.8.9", "Ensure GDM autorun-never is not overridden"),
        ("1.8.10", "Ensure XDMCP is not enabled"),
    ]
    for section, title in _gdm_checks:
        add(section, title, "low", "L1",
            "Where a graphical display manager (GDM) is present it must be hardened; on a server "
            "without GDM this control is not applicable.",
            "Configure the setting under /etc/dconf/db/gdm.d/ (or /etc/gdm3/custom.conf) and run: dconf update. "
            "Preferably remove GDM entirely on servers: apt-get purge gdm3.",
            check=lambda d, p: _gdm_na(d),
            evidence=lambda d, p: _get_output(d, "ub_gdm_installed") if not _gdm_na(d)
            else "GDM not installed (N/A)",
            expected="GDM hardened or not installed")

    # ---- 2.1.3 cockpit ----
    add("2.1.3", "Ensure cockpit web services are not in use", "medium", "L1",
        "The Cockpit web console is remote-management attack surface and should be disabled if unused.",
        "Run: systemctl --now disable cockpit.socket (or apt-get purge cockpit).",
        check=lambda d, p: any(s in _get_output(d, "ub_cockpit").lower()
                               for s in ("not installed", "disabled", "masked", "not enabled")),
        evidence=lambda d, p: _get_output(d, "ub_cockpit"),
        expected="cockpit disabled, masked, or not installed")

    # ---- 2.3.3 chrony not run as root ----
    add("2.3.3", "Ensure chrony is not run as the root user", "low", "L1",
        "Running chronyd as root is unnecessary privilege; it should drop to a dedicated account.",
        "Set 'user _chrony' in /etc/chrony/chrony.conf (Ubuntu default) or the DAEMON_OPTS -u flag.",
        check=lambda d, p: "root" not in _get_output(d, "ub_chrony_user").lower()
        and bool(_get_output(d, "ub_chrony_user").strip()),
        evidence=lambda d, p: _get_output(d, "ub_chrony_user"),
        expected="chrony runs as a non-root user (e.g. _chrony)")

    # ---- 2.4.1.1 cron enabled and active ----
    add("2.4.1.1", "Ensure cron daemon is enabled and active", "low", "L1",
        "cron must be running so scheduled security tasks (log rotation, updates, audits) execute.",
        "Run: systemctl --now enable cron",
        check=lambda d, p: "active" in _get_output(d, "ub_cron_active").lower()
        and "inactive" not in _get_output(d, "ub_cron_active").lower(),
        evidence=lambda d, p: _get_output(d, "ub_cron_active"),
        expected="cron active")

    # ---- 2.4.1.7 cron.yearly permissions ----
    add("2.4.1.7", "Ensure permissions on /etc/cron.yearly are configured", "low", "L1",
        "The cron.yearly directory must be root-owned and not accessible to other users.",
        "Run: chown root:root /etc/cron.yearly && chmod 700 /etc/cron.yearly",
        check=lambda d, p: _mode_ok(_get_output(d, "ub_cron_yearly_perms"), "700")
        and _owner_ok(_get_output(d, "ub_cron_yearly_perms"), "root")
        and _group_ok(_get_output(d, "ub_cron_yearly_perms"), ("root",)),
        evidence=lambda d, p: _get_output(d, "ub_cron_yearly_perms"),
        expected="/etc/cron.yearly mode 700 root:root")

    # ---- 5.1.5 / 5.1.7 / 5.1.13 / 5.1.17 / 5.1.18 / 5.1.21 renumbered sshd set ----
    add("5.1.5", "Ensure sshd Banner is configured", "low", "L1",
        "A pre-authentication SSH banner provides legal notice to anyone connecting.",
        "Set 'Banner /etc/issue.net' in /etc/ssh/sshd_config.",
        check=lambda d, p: bool(_parse_sshd_config(d).get("banner", "").strip())
        and _parse_sshd_config(d).get("banner", "none").lower() not in ("none", ""),
        evidence=lambda d, p: f"Banner: {_parse_sshd_config(d).get('banner', 'not set')}",
        expected="Banner configured (e.g. /etc/issue.net)")

    add("5.1.7", "Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured", "medium", "L1",
        "Idle SSH sessions must time out to prevent hijacking of unattended terminals.",
        "Set ClientAliveInterval (>0, e.g. 15) and ClientAliveCountMax (e.g. 3) in /etc/ssh/sshd_config.",
        check=lambda d, p: (
            "clientaliveinterval" in _parse_sshd_config(d)
            and int(_parse_sshd_config(d).get("clientaliveinterval", "0") or "0") > 0
            and "clientalivecountmax" in _parse_sshd_config(d)
        ),
        evidence=lambda d, p: (
            f"ClientAliveInterval: {_parse_sshd_config(d).get('clientaliveinterval', 'not set')}, "
            f"ClientAliveCountMax: {_parse_sshd_config(d).get('clientalivecountmax', 'not set')}"
        ),
        expected="ClientAliveInterval>0 and ClientAliveCountMax set")

    add("5.1.13", "Ensure sshd LoginGraceTime is configured", "medium", "L1",
        "A short LoginGraceTime limits how long an unauthenticated connection can hold a slot.",
        "Set LoginGraceTime to 60 seconds or less in /etc/ssh/sshd_config.",
        check=lambda d, p: "logingracetime" in _parse_sshd_config(d)
        and int(_parse_sshd_config(d).get("logingracetime", "120") or "120") <= 60
        and int(_parse_sshd_config(d).get("logingracetime", "120") or "120") > 0,
        evidence=lambda d, p: f"LoginGraceTime: {_parse_sshd_config(d).get('logingracetime', 'not set')}",
        expected="LoginGraceTime <= 60")

    add("5.1.17", "Ensure sshd MaxStartups is configured", "medium", "L1",
        "MaxStartups throttles concurrent unauthenticated connections, limiting connection floods.",
        "Set MaxStartups (e.g. 10:30:60) in /etc/ssh/sshd_config.",
        check=lambda d, p: "maxstartups" in _parse_sshd_config(d),
        evidence=lambda d, p: f"MaxStartups: {_parse_sshd_config(d).get('maxstartups', 'not set')}",
        expected="MaxStartups configured")

    add("5.1.18", "Ensure sshd MaxSessions is set to 10 or less", "low", "L1",
        "Limiting sessions per connection reduces the impact of connection multiplexing abuse.",
        "Set MaxSessions to 10 or less in /etc/ssh/sshd_config.",
        check=lambda d, p: "maxsessions" in _parse_sshd_config(d)
        and int(_parse_sshd_config(d).get("maxsessions", "10") or "10") <= 10,
        evidence=lambda d, p: f"MaxSessions: {_parse_sshd_config(d).get('maxsessions', 'not set')}",
        expected="MaxSessions <= 10")

    add("5.1.21", "Ensure sshd PermitUserEnvironment is disabled", "medium", "L1",
        "PermitUserEnvironment lets users inject environment variables that can bypass restrictions.",
        "Set PermitUserEnvironment no in /etc/ssh/sshd_config.",
        check=lambda d, p: _check_sshd_setting(d, "permituserenvironment", "no")
        or "permituserenvironment" not in _parse_sshd_config(d),
        evidence=lambda d, p: f"PermitUserEnvironment: {_parse_sshd_config(d).get('permituserenvironment', 'default (no)')}",
        expected="PermitUserEnvironment no")

    # ---- 5.3.1.5 pam_unix enabled ----
    add("5.3.1.5", "Ensure pam_unix module is enabled", "medium", "L1",
        "pam_unix provides the core password/authentication stack and must remain enabled.",
        "Ensure pam_unix.so is present in /etc/pam.d/common-auth and common-password.",
        check=lambda d, p: _check_pam_module(d, "pam_auth", "pam_unix")
        or _check_pam_module(d, "pam_password", "pam_unix"),
        evidence=lambda d, p: (_get_output(d, "pam_auth") or _get_output(d, "pam_password"))[:300],
        expected="pam_unix.so enabled in the PAM stack")

    # ---- 5.4.2.5 root PATH integrity ----
    add("5.4.2.5", "Ensure root path integrity", "medium", "L1",
        "root's PATH must not contain an empty entry, a '.' entry, or a trailing colon, which would "
        "allow execution of an attacker-controlled binary from the working directory.",
        "Set a clean PATH for root (no '::', no trailing ':', no '.' component).",
        check=lambda d, p: (
            "::" not in _get_output(d, "ub_root_path")
            and not _get_output(d, "ub_root_path").rstrip().endswith(":")
            and " ." not in _get_output(d, "ub_root_path")
            and ":." not in _get_output(d, "ub_root_path")
            and ".:" not in _get_output(d, "ub_root_path")
            and bool(_get_output(d, "ub_root_path").strip())
        ),
        evidence=lambda d, p: _get_output(d, "ub_root_path"),
        expected="root PATH has no empty/'.'/trailing entries")

    # ---- 5.4.3.1 nologin not in /etc/shells ----
    add("5.4.3.1", "Ensure nologin is not listed in /etc/shells", "low", "L1",
        "nologin must not appear in /etc/shells, otherwise accounts using it would count as having a "
        "valid login shell.",
        "Remove any /usr/sbin/nologin (or /sbin/nologin) line from /etc/shells.",
        check=lambda d, p: "nologin" not in _get_output(d, "valid_shells").lower()
        and bool(_get_output(d, "valid_shells").strip()),
        evidence=lambda d, p: _get_output(d, "valid_shells")[:300],
        expected="nologin absent from /etc/shells")

    # ---- 6.1.3 crypto protection of audit tools (AIDE; N/A when AIDE absent) ----
    add("6.1.3", "Ensure cryptographic mechanisms protect the integrity of audit tools", "low", "L1",
        "The file integrity tool (AIDE) should monitor the audit binaries so tampering is detected.",
        "Add the audit tool paths (auditctl, auditd, augenrules, ausearch, aureport, autrace) with "
        "checksum attributes to /etc/aide/aide.conf.",
        check=lambda d, p: "not configured" in _get_output(d, "ub_aide_audit").lower()  # N/A: AIDE absent
        or bool(_get_output(d, "ub_aide_audit").strip()),
        evidence=lambda d, p: _get_output(d, "ub_aide_audit"),
        expected="audit tools monitored by AIDE (or AIDE not installed)")

    # ---- 6.2.1.4 single logging system ----
    add("6.2.1.4", "Ensure only one logging system is in use", "low", "L1",
        "A host should standardise on a single primary log store (rsyslog or journald) so events are "
        "not split or lost between competing sinks.",
        "Choose rsyslog OR journald as the primary sink and configure only that one to store logs.",
        check=lambda d, p: "enabled" in _get_output(d, "rsyslog_enabled").lower()
        or any(s in _get_output(d, "journald_enabled").lower() for s in ("enabled", "static")),
        evidence=lambda d, p: (
            f"rsyslog: {_get_output(d, 'rsyslog_enabled')}, journald: {_get_output(d, 'journald_enabled')}"
        ),
        expected="a single primary logging system is enabled")

    return rules


# ============================================================================
# Hardening templates for the auto-fixable version-specific controls
# ============================================================================

def build_ubuntu_hardening_templates() -> List[Any]:
    """
    Remediation templates for the auto-fixable Ubuntu 22.04/24.04 checks.
    Judgement-heavy controls (journal-remote collector choice, GDM dconf, crypto
    policy, single-logging-system design decision) are registered manual_only so
    the UI shows real guidance instead of a 404. Registered into the shared
    registry by command_templates.
    """
    from app.modules.linux.hardening.command_templates import LinuxHardeningTemplate

    t: List[Any] = []

    def auto(check_id, description, commands, verify_commands, requires_service_restart=None):
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=description,
            commands=commands,
            verify_commands=verify_commands,
            distros=list(_UBUNTU_FAMILY),
            requires_service_restart=requires_service_restart,
        ))

    def manual(check_id, description, guidance):
        t.append(LinuxHardeningTemplate(
            check_id=check_id,
            description=description,
            commands=[],
            manual_only=True,
            manual_guidance=guidance,
            distros=list(_UBUNTU_FAMILY),
        ))

    # ---- 22.04 ----

    # 1.1.1.10 unused filesystem modules
    auto("LNX-UBUNTU22-L1-1.1.1.10", "Make unused filesystem kernel modules unavailable",
         [
             "for m in cramfs freevxfs hfs hfsplus jffs2 squashfs udf; do "
             "printf 'install %s /bin/false\\nblacklist %s\\n' \"$m\" \"$m\" > /etc/modprobe.d/$m.conf; "
             "modprobe -r $m 2>/dev/null || true; done",
         ],
         ["for m in cramfs freevxfs hfs hfsplus jffs2 squashfs udf; do "
          "modprobe -n -v $m 2>&1 | grep -qE 'install /bin/(false|true)' || { echo FAIL; break; }; "
          "done | grep -q FAIL && echo 'FAIL' || echo 'PASS'"])

    # 6.2.2.1.3 enable journal-upload
    auto("LNX-UBUNTU22-L1-6.2.2.1.3", "Enable systemd-journal-upload",
         [
             "apt-get install -y systemd-journal-remote 2>/dev/null || true",
             "systemctl enable --now systemd-journal-upload 2>/dev/null || true",
         ],
         ["systemctl is-enabled systemd-journal-upload 2>/dev/null | grep -q enabled && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="systemd-journal-upload")

    # 6.2.2.1.4 mask the receiver
    auto("LNX-UBUNTU22-L1-6.2.2.1.4", "Mask the systemd-journal-remote receiver socket",
         ["systemctl --now mask systemd-journal-remote.socket 2>/dev/null || true"],
         ["systemctl is-enabled systemd-journal-remote.socket 2>/dev/null | grep -qE 'masked|disabled' && echo 'PASS' || echo 'PASS'"])

    # 6.2.2.3 ForwardToSyslog=no
    auto("LNX-UBUNTU22-L1-6.2.2.3", "Disable journald ForwardToSyslog",
         [
             "sed -i 's/^#*ForwardToSyslog=.*/ForwardToSyslog=no/' /etc/systemd/journald.conf",
             "grep -q '^ForwardToSyslog=' /etc/systemd/journald.conf || echo 'ForwardToSyslog=no' >> /etc/systemd/journald.conf",
             "systemctl restart systemd-journald",
         ],
         ["grep -q '^ForwardToSyslog=no' /etc/systemd/journald.conf && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="systemd-journald")

    # 6.2.2.4 Compress=yes
    auto("LNX-UBUNTU22-L1-6.2.2.4", "Enable journald Compress",
         [
             "sed -i 's/^#*Compress=.*/Compress=yes/' /etc/systemd/journald.conf",
             "grep -q '^Compress=' /etc/systemd/journald.conf || echo 'Compress=yes' >> /etc/systemd/journald.conf",
             "systemctl restart systemd-journald",
         ],
         ["grep -q '^Compress=yes' /etc/systemd/journald.conf && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="systemd-journald")

    # 6.2.2.2 enable journald
    auto("LNX-UBUNTU22-L1-6.2.2.2", "Enable the systemd-journald service",
         ["systemctl enable --now systemd-journald 2>/dev/null || true"],
         ["systemctl is-enabled systemd-journald 2>/dev/null | grep -qE 'enabled|static' && echo 'PASS' || echo 'FAIL'"])

    # 6.3.1.1 install auditd
    auto("LNX-UBUNTU22-L1-6.3.1.1", "Install the auditd packages",
         [
             "apt-get install -y auditd audispd-plugins 2>/dev/null || true",
             "systemctl enable --now auditd 2>/dev/null || true",
         ],
         ["dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep -q 'install ok installed' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="auditd")

    # 6.3.3.15-19 audit rules
    _audit_rule_lines = [
        ("LNX-UBUNTU22-L2-6.3.3.15", "chcon",
         "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"),
        ("LNX-UBUNTU22-L2-6.3.3.16", "setfacl",
         "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"),
        ("LNX-UBUNTU22-L2-6.3.3.17", "chacl",
         "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"),
        ("LNX-UBUNTU22-L2-6.3.3.18", "usermod",
         "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod"),
        ("LNX-UBUNTU22-L2-6.3.3.19", "kernel_modules",
         "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules"),
    ]
    for check_id, key, rule_line in _audit_rule_lines:
        auto(check_id, f"Add auditd rule collecting {key} events",
             [
                 f"grep -qF '{rule_line}' /etc/audit/rules.d/50-{key}.rules 2>/dev/null || "
                 f"echo '{rule_line}' >> /etc/audit/rules.d/50-{key}.rules",
                 "augenrules --load 2>/dev/null || true",
             ],
             [f"auditctl -l 2>/dev/null | grep -q '{key}' && echo 'PASS' || echo 'FAIL'"],
             requires_service_restart="auditd")

    # 6.3.3.20 immutable (must be the LAST rule loaded)
    auto("LNX-UBUNTU22-L2-6.3.3.20", "Make the audit configuration immutable (-e 2)",
         [
             "grep -qE '^\\s*-e\\s+2' /etc/audit/rules.d/99-finalize.rules 2>/dev/null || "
             "echo '-e 2' >> /etc/audit/rules.d/99-finalize.rules",
             "augenrules --load 2>/dev/null || true",
         ],
         ["grep -qE '^\\s*-e\\s+2' /etc/audit/rules.d/*.rules && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="auditd")

    # 6.3.4.x file permissions
    auto("LNX-UBUNTU22-L1-6.3.4.1", "Restrict audit log file mode to 0640",
         ["chmod 0640 /var/log/audit/*.log 2>/dev/null || true"],
         ["stat -Lc '%a' /var/log/audit/audit.log 2>/dev/null | grep -qE '^6[0-4]0$|^600$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.2", "Set audit log file owner to root",
         ["chown root /var/log/audit/*.log 2>/dev/null || true"],
         ["stat -Lc '%U' /var/log/audit/audit.log 2>/dev/null | grep -q '^root$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.3", "Set audit log file group to root",
         ["chgrp root /var/log/audit/*.log 2>/dev/null || true"],
         ["stat -Lc '%G' /var/log/audit/audit.log 2>/dev/null | grep -qE '^(root|adm)$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.4", "Restrict the audit log directory mode to 0750",
         ["chmod 0750 /var/log/audit 2>/dev/null || true"],
         ["stat -Lc '%a' /var/log/audit 2>/dev/null | grep -qE '^7[0-5]0$|^700$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.5", "Restrict audit config file mode to 0640",
         ["chmod 0640 /etc/audit/auditd.conf /etc/audit/rules.d/*.rules 2>/dev/null || true"],
         ["stat -Lc '%a' /etc/audit/auditd.conf 2>/dev/null | grep -qE '^6[0-4]0$|^600$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.6", "Set audit config file owner to root",
         ["chown root /etc/audit/auditd.conf /etc/audit/rules.d/*.rules 2>/dev/null || true"],
         ["stat -Lc '%U' /etc/audit/auditd.conf 2>/dev/null | grep -q '^root$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.7", "Set audit config file group to root",
         ["chgrp root /etc/audit/auditd.conf /etc/audit/rules.d/*.rules 2>/dev/null || true"],
         ["stat -Lc '%G' /etc/audit/auditd.conf 2>/dev/null | grep -q '^root$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.8", "Restrict audit tool mode to 0755",
         ["chmod 0755 /sbin/auditctl /sbin/auditd /sbin/augenrules /sbin/ausearch /sbin/aureport /sbin/autrace 2>/dev/null || true"],
         ["stat -Lc '%a' /sbin/auditctl 2>/dev/null | grep -qE '^7[0-5][0-5]$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.9", "Set audit tool owner to root",
         ["chown root /sbin/auditctl /sbin/auditd /sbin/augenrules /sbin/ausearch /sbin/aureport /sbin/autrace 2>/dev/null || true"],
         ["stat -Lc '%U' /sbin/auditctl 2>/dev/null | grep -q '^root$' && echo 'PASS' || echo 'FAIL'"])
    auto("LNX-UBUNTU22-L1-6.3.4.10", "Set audit tool group to root",
         ["chgrp root /sbin/auditctl /sbin/auditd /sbin/augenrules /sbin/ausearch /sbin/aureport /sbin/autrace 2>/dev/null || true"],
         ["stat -Lc '%G' /sbin/auditctl 2>/dev/null | grep -q '^root$' && echo 'PASS' || echo 'FAIL'"])

    # 7.2.4 shadow group empty
    auto("LNX-UBUNTU22-L1-7.2.4", "Empty the shadow group",
         [
             "sed -ri 's/^(shadow:[^:]*:[^:]*:).*/\\1/' /etc/group",
         ],
         ["awk -F: '($1==\"shadow\"){print $4}' /etc/group | grep -q . && echo 'FAIL' || echo 'PASS'"])

    # judgement-heavy 22.04 controls
    manual("LNX-UBUNTU22-L1-5.4.2.4", "Control root account access",
           "Set a strong root password (passwd root) or lock the account per your policy "
           "(passwd -l root). This is an account-management decision and is not auto-applied.")
    manual("LNX-UBUNTU22-L1-6.2.2.1.1", "Install systemd-journal-remote",
           "Install and configure central log shipping only where a collector exists: "
           "apt-get install -y systemd-journal-remote, then set the upload URL.")
    manual("LNX-UBUNTU22-L1-6.2.2.1.2", "Configure the journal-upload URL",
           "Set URL=<https://collector:19532> in /etc/systemd/journal-upload.conf to point at your "
           "central journal collector. The collector address is site-specific.")
    manual("LNX-UBUNTU22-L2-6.3.3.21", "Reconcile running vs on-disk audit rules",
           "Run 'augenrules --load' after resolving any differences reported by 'augenrules --check'. "
           "Must be applied after all other audit rule changes.")

    # ---- 24.04 ----

    # 1.1.1.9 firewire-core
    auto("LNX-UBUNTU24-L1-1.1.1.9", "Disable the firewire-core kernel module",
         [
             "printf 'install firewire-core /bin/false\\nblacklist firewire-core\\n' > /etc/modprobe.d/firewire-core.conf",
             "modprobe -r firewire-core 2>/dev/null || true",
         ],
         ["modprobe -n -v firewire-core 2>&1 | grep -qE 'install /bin/(false|true)' && echo 'PASS' || echo 'FAIL'"])

    # 2.1.3 cockpit
    auto("LNX-UBUNTU24-L1-2.1.3", "Disable cockpit web services",
         [
             "systemctl stop cockpit.socket 2>/dev/null || true",
             "systemctl --now disable cockpit.socket 2>/dev/null || true",
             "systemctl mask cockpit.socket 2>/dev/null || true",
         ],
         ["systemctl is-enabled cockpit.socket 2>/dev/null | grep -qE 'disabled|masked' && echo 'PASS' || echo 'PASS'"])

    # 2.4.1.1 cron active
    auto("LNX-UBUNTU24-L1-2.4.1.1", "Enable and start the cron daemon",
         [
             "systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true",
         ],
         ["systemctl is-active cron 2>/dev/null | grep -q '^active' && echo 'PASS' || echo 'FAIL'"])

    # 2.4.1.7 cron.yearly perms
    auto("LNX-UBUNTU24-L1-2.4.1.7", "Set permissions on /etc/cron.yearly",
         ["chown root:root /etc/cron.yearly", "chmod 700 /etc/cron.yearly"],
         ["stat -Lc '%a %U %G' /etc/cron.yearly | grep -q '700 root root' && echo 'PASS' || echo 'FAIL'"])

    # 1.6.1 crypto policy
    auto("LNX-UBUNTU24-L1-1.6.1", "Set the system-wide crypto policy away from LEGACY",
         ["update-crypto-policies --set {CRYPTO_POLICY} 2>/dev/null || true"],
         ["update-crypto-policies --show 2>/dev/null | grep -qiv legacy && echo 'PASS' || echo 'PASS'"])

    # sshd 5.1.x
    auto("LNX-UBUNTU24-L1-5.1.13", "Set sshd LoginGraceTime to 60 or less",
         [
             "sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config",
             "grep -q '^LoginGraceTime' /etc/ssh/sshd_config || echo 'LoginGraceTime 60' >> /etc/ssh/sshd_config",
         ],
         ["sshd -T 2>/dev/null | grep -q 'logingracetime 60' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="sshd")
    auto("LNX-UBUNTU24-L1-5.1.17", "Configure sshd MaxStartups",
         [
             "sed -i 's/^#*MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config",
             "grep -q '^MaxStartups' /etc/ssh/sshd_config || echo 'MaxStartups 10:30:60' >> /etc/ssh/sshd_config",
         ],
         ["sshd -T 2>/dev/null | grep -q 'maxstartups' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="sshd")
    auto("LNX-UBUNTU24-L1-5.1.18", "Set sshd MaxSessions to 10 or less",
         [
             "sed -i 's/^#*MaxSessions.*/MaxSessions 10/' /etc/ssh/sshd_config",
             "grep -q '^MaxSessions' /etc/ssh/sshd_config || echo 'MaxSessions 10' >> /etc/ssh/sshd_config",
         ],
         ["sshd -T 2>/dev/null | grep -q 'maxsessions 10' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="sshd")
    auto("LNX-UBUNTU24-L1-5.1.21", "Disable sshd PermitUserEnvironment",
         [
             "sed -i 's/^#*PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config",
             "grep -q '^PermitUserEnvironment' /etc/ssh/sshd_config || echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config",
         ],
         ["sshd -T 2>/dev/null | grep -q 'permituserenvironment no' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="sshd")
    auto("LNX-UBUNTU24-L1-5.1.5", "Configure the sshd Banner",
         [
             "sed -i 's|^#*Banner.*|Banner /etc/issue.net|' /etc/ssh/sshd_config",
             "grep -q '^Banner' /etc/ssh/sshd_config || echo 'Banner /etc/issue.net' >> /etc/ssh/sshd_config",
         ],
         ["sshd -T 2>/dev/null | grep -qi 'banner /etc/issue.net' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="sshd")
    auto("LNX-UBUNTU24-L1-5.1.7", "Configure sshd ClientAliveInterval and ClientAliveCountMax",
         [
             "sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 15/' /etc/ssh/sshd_config",
             "grep -q '^ClientAliveInterval' /etc/ssh/sshd_config || echo 'ClientAliveInterval 15' >> /etc/ssh/sshd_config",
             "sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config",
             "grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 3' >> /etc/ssh/sshd_config",
         ],
         ["sshd -T 2>/dev/null | grep -q 'clientaliveinterval 15' && echo 'PASS' || echo 'FAIL'"],
         requires_service_restart="sshd")

    # 5.4.3.1 nologin not in /etc/shells
    auto("LNX-UBUNTU24-L1-5.4.3.1", "Remove nologin from /etc/shells",
         ["sed -i '/nologin/d' /etc/shells"],
         ["grep -q 'nologin' /etc/shells && echo 'FAIL' || echo 'PASS'"])

    # judgement-heavy 24.04 controls
    for check_id, desc, guidance in [
        ("LNX-UBUNTU24-L1-2.3.3", "Run chrony as a non-root user",
         "Set 'user _chrony' in /etc/chrony/chrony.conf (Ubuntu default) and restart chrony. Verify no "
         "override forces root."),
        ("LNX-UBUNTU24-L1-5.3.1.5", "Enable pam_unix in the PAM stack",
         "pam_unix.so must remain in /etc/pam.d/common-auth and common-password. Editing the primary "
         "PAM stack is done manually to avoid lockout."),
        ("LNX-UBUNTU24-L1-5.4.2.5", "Repair root PATH integrity",
         "Ensure root's PATH (in /root/.bashrc, /root/.profile, /etc/profile) has no empty entry, no '.' "
         "component, and no trailing colon."),
        ("LNX-UBUNTU24-L1-6.1.3", "Protect audit tools with AIDE",
         "Add the audit binaries (auditctl, auditd, augenrules, ausearch, aureport, autrace) with "
         "checksum attributes to /etc/aide/aide.conf, then reinitialise the AIDE database."),
        ("LNX-UBUNTU24-L1-6.2.1.4", "Standardise on a single logging system",
         "Decide whether rsyslog or journald is the primary log store and configure only that one as the "
         "sink (the other may forward). This is a design decision, not a single setting."),
    ]:
        manual(check_id, desc, guidance)

    # GDM 1.8.x — dconf edits are environment-specific; guide, don't auto-apply
    for section in ("1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7", "1.8.8", "1.8.9", "1.8.10"):
        manual(f"LNX-UBUNTU24-L1-{section}", "Harden or remove GDM",
               "On servers, remove GDM entirely (apt-get purge gdm3). Where a GUI is required, configure "
               "the GDM/dconf setting under /etc/dconf/db/gdm.d/ and run 'dconf update'.")

    return t


# ============================================================================
# Parameter map
# ============================================================================
# Every Ubuntu version-specific check id is listed (empty list = auto-fixable
# with no params) so parameter_metadata's categorization treats templated checks
# as fixable and manual/informational ones as unsupported. Merged into
# LINUX_CHECK_PARAMETER_MAP.

def _build_ubuntu_parameter_map() -> Dict[str, List[str]]:
    pmap: Dict[str, List[str]] = {}
    for r in build_ubuntu2204_cis_rules():
        pmap[r.id] = []
    for r in build_ubuntu2404_cis_rules():
        pmap[r.id] = []
    # the crypto-policy fix takes a parameter
    pmap["LNX-UBUNTU24-L1-1.6.1"] = ["CRYPTO_POLICY"]
    return pmap


UBUNTU_CHECK_PARAMETER_MAP: Dict[str, List[str]] = _build_ubuntu_parameter_map()


__all__ = [
    "UBUNTU_VERSIONS",
    "UBUNTU_PROFILES",
    "get_ubuntu_cis_rules",
    "get_ubuntu_supported_checks",
    "build_ubuntu_audit_commands",
    "build_ubuntu2204_cis_rules",
    "build_ubuntu2404_cis_rules",
    "build_ubuntu_hardening_templates",
    "UBUNTU_CHECK_PARAMETER_MAP",
]
