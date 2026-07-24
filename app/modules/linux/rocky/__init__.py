"""
Rocky Linux-specific Module

Rocky Linux 8/9/10 CIS auditing and hardening are implemented by the
distro-aware engine in ``app.modules.linux`` (audit + hardening packages):

- ``parse_os_release`` resolves Rocky hosts to the ``rocky_8``/``rocky_9``/
  ``rocky_10`` profiles.
- ``filter_rules_by_distro`` applies every ``distros=["all"]`` rule plus the
  RHEL-family rules (``LNX-RHEL-*``: SELinux, crypto policies, sudo, AIDE,
  faillock/authselect, firewalld, GRUB2) to those profiles.
- Hardening templates are rewritten for the RHEL family by
  ``get_linux_hardening_template_for_distro`` (system-auth/password-auth PAM
  paths, crond/httpd/smb service names, dnf package manager).

This façade exposes the Rocky view of that engine so callers don't have to
re-derive the profile/filter plumbing.

Rocky Linux 8 / 9 / 10 (CIS Rocky Linux Benchmarks)
---------------------------------------------------
Rocky shares ~95% of its controls with RHEL, so the version-specific checks are
NOT re-authored here — ``build_rocky_cis_rules`` imports the RHEL-10 builders
(``build_rhel10_cis_rules`` / ``build_rhel10_hardening_templates``) and extends
them: it re-badges each ``LNX-RHEL10-*`` rule to the ``LNX-ROCKY{8,9,10}-*`` id
prefix, gates it to the exact ``rocky_8``/``rocky_9``/``rocky_10`` profile, drops
the controls a given Rocky version does not ship, and overrides only what
genuinely differs from Red Hat (GPG key origin, rockylinux.org repo URLs,
/etc/yum.conf on Rocky 8, no subscription-manager).

The RHEL-10 rules themselves are gated to ``rhel_10`` ONLY (see
``app.modules.linux.rhel._R10``), so a Rocky 10 host is scored by the
``LNX-ROCKY10-*`` set and never double-scored by the ``LNX-RHEL10-*`` set.

These four Rocky controls are unmapped in the shared RHEL-10 builder and are
guaranteed present in the Rocky sets: 1.5.6, 2.4.1.7, 5.3.1.5, 6.2.1.4 (1.5.6
and 6.2.1.4 already carry those numbers upstream; 2.3.2 and 5.3.1.1 are
renumbered here via ``_ROCKY_SECTION_RENAME``).

The three sets are wired into the same four engine hook files used for RHEL 10:
``rules.build_linux_cis_rules``, ``audit_commands.get_linux_audit_commands``,
``command_templates`` and ``parameter_metadata``.
"""

from typing import List, Dict, Any
from dataclasses import replace
import re

from app.modules.linux.audit.rules import (
    LinuxCISRule,
    build_linux_cis_rules,
    filter_rules_by_distro,
    filter_rules_by_profile,
    _get_output,
)
from app.modules.linux.rhel import (
    build_rhel10_cis_rules,
    build_rhel10_hardening_templates,
)

ROCKY_VERSIONS = ("8", "9", "10")
ROCKY_PROFILES = tuple(f"rocky_{v}" for v in ROCKY_VERSIONS)


def get_rocky_cis_rules(profile: str = "FULL", version: str = "9") -> List[LinuxCISRule]:
    """
    CIS rules applicable to a Rocky Linux host.

    Args:
        profile: "L1" or "FULL" (L1+L2+INFO)
        version: Rocky major version ("8", "9", "10")
    """
    distro_profile = f"rocky_{version}" if version in ROCKY_VERSIONS else "rocky_generic"
    rules = filter_rules_by_profile(build_linux_cis_rules(), profile)
    return filter_rules_by_distro(rules, distro_profile)


def get_rocky_supported_checks(version: str = "9") -> List[str]:
    """Check IDs that both apply to Rocky and have a hardening template."""
    from app.modules.linux.hardening.command_templates import LINUX_HARDENING_TEMPLATES

    rocky_ids = {r.id for r in get_rocky_cis_rules("FULL", version)}
    return sorted(
        check_id
        for check_id, template in LINUX_HARDENING_TEMPLATES.items()
        if check_id in rocky_ids
        and ("all" in template.distros or "rocky" in template.distros)
    )


# ============================================================================
# CIS Rocky Linux 8 / 9 / 10 Benchmarks (extends the shared RHEL-10 builders)
# ============================================================================

# hardening templates run on the already-detected distro id (Rocky / AlmaLinux
# share the Rocky benchmark), same convention as the RHEL family templates.
_ROCKY_FAMILY = ["rocky", "almalinux"]

# Rocky renumbers a couple of RHEL controls; applying the rename makes the four
# Rocky-"unmapped" controls (1.5.6, 2.4.1.7, 5.3.1.5, 6.2.1.4) all present in the
# Rocky 10 set. (1.5.6 and 6.2.1.4 already carry those numbers in the shared
# RHEL-10 builder; 2.3.2 and 5.3.1.1 are renumbered here.)
_ROCKY_SECTION_RENAME = {
    "2.3.2": "2.4.1.7",     # chrony configured with an authorized timeserver
    "5.3.1.1": "5.3.1.5",   # active authselect profile includes pam modules
}

# Sections dropped going from Rocky 10 -> Rocky 9 (versioned CIS deltas), keyed
# by the ORIGINAL RHEL-10 section number (before _ROCKY_SECTION_RENAME):
#   1.6.3 / 1.6.4          system-wide crypto policy CBC/SHA1 subpolicy (not in v9)
#   5.1.8 / 5.1.15         sshd DisableForwarding / MACs (Rocky 9 sshd set is smaller)
#   5.4.3.2               default shell TMOUT (user-environment control added in v10)
#   6.3.2.3 / 6.3.3.36    disk-full halt, immutable finalize (added in v10)
#   6.3.4.5               audit configuration file mode (added in v10)
_ROCKY9_DROP = {"1.6.3", "1.6.4", "5.1.8", "5.1.15", "5.4.3.2",
                "6.3.2.3", "6.3.3.36", "6.3.4.5"}

# Sections dropped going from Rocky 9 -> Rocky 8 (in ADDITION to _ROCKY9_DROP):
#   5.3.1.1               authselect profile (Rocky 8 edits /etc/pam.d directly)
#   5.3.2.1.3             faillock even_deny_root via authselect apply-changes
#   5.1.9 / 5.1.12        sshd GSSAPI / KexAlgorithms (Rocky 8 sshd set smaller still)
#   1.2.1.5               dnf install_weak_deps (Rocky 8 uses yum, no dnf.conf key)
#   6.3.2.2 / 6.3.4.2     keep_logs / audit-log mode (fewer 6.3.x rules on Rocky 8)
#   1.8.5 / 1.8.6         GDM autorun-never / WaylandEnable (fewer GDM controls)
#   7.1.10                /etc/security/opasswd permissions
_ROCKY8_DROP = {"5.3.1.1", "5.3.2.1.3", "5.1.9", "5.1.12", "1.2.1.5",
                "6.3.2.2", "6.3.4.2", "1.8.5", "1.8.6", "7.1.10"}


def _dropped_sections(version: str) -> set:
    """Sections removed from the RHEL-10 supplement for a given Rocky version."""
    if version == "8":
        return _ROCKY9_DROP | _ROCKY8_DROP
    if version == "9":
        return set(_ROCKY9_DROP)
    return set()


def _split_rhel10_id(check_id: str):
    """``LNX-RHEL10-L1-2.3.2`` -> ("L1", "2.3.2")."""
    body = check_id[len("LNX-RHEL10-"):]
    level, _, section = body.partition("-")
    return level, section


def _rocky_id(level: str, section: str, version: str):
    """Build the Rocky id + renamed section for a given RHEL-10 (level, section)."""
    new_section = _ROCKY_SECTION_RENAME.get(section, section)
    return f"LNX-ROCKY{version}-{level}-{new_section}", new_section


def _apply_rocky_overrides(rule: LinuxCISRule, orig_section: str) -> LinuxCISRule:
    """Override only the controls that genuinely differ from Red Hat."""
    if orig_section == "1.2.1.3":
        # Repo signature policy: Rocky repos are signed with the Rocky Linux GPG
        # key and served from mirrors of rockylinux.org; Rocky 8 keeps this in
        # /etc/yum.conf rather than /etc/dnf/dnf.conf (rocky_repo_gpgcheck greps
        # both, see build_rocky_audit_commands).
        return replace(
            rule,
            rationale="repo_gpgcheck verifies the signature of repository metadata. Rocky "
                      "Linux repositories are signed with the Rocky Linux GPG key "
                      "(RPM-GPG-KEY-Rocky-*), so it must stay enabled.",
            remediation="Set 'repo_gpgcheck=1' in the [main] section of /etc/dnf/dnf.conf "
                        "(Rocky 8: /etc/yum.conf). Ensure repo baseurls point at mirrors of "
                        "rockylinux.org and the Rocky Linux GPG key is imported.",
            check=lambda d, p: bool(re.search(r'repo_gpgcheck\s*=\s*1', _get_output(d, "rocky_repo_gpgcheck"))),
            evidence=lambda d, p: _get_output(d, "rocky_repo_gpgcheck"),
            expected_value="repo_gpgcheck=1 (Rocky repos signed with the Rocky Linux GPG key)",
        )
    return rule


def _build_rocky_version_rules(version: str) -> List[LinuxCISRule]:
    """Re-badge + gate + trim the shared RHEL-10 rules for one Rocky version."""
    dropped = _dropped_sections(version)
    out: List[LinuxCISRule] = []
    for rule in build_rhel10_cis_rules():
        level, section = _split_rhel10_id(rule.id)
        if section in dropped:
            continue
        new_id, new_section = _rocky_id(level, section, version)
        rebadged = replace(
            rule,
            id=new_id,
            cis_section=new_section,
            distros=[f"rocky_{version}"],
        )
        out.append(_apply_rocky_overrides(rebadged, section))
    return out


def build_rocky_cis_rules() -> List[LinuxCISRule]:
    """
    Rocky Linux 8/9/10 version-specific checks (~45 / ~55 / ~63 respectively).
    Gated to the exact rocky_8/rocky_9/rocky_10 profiles.
    """
    rules: List[LinuxCISRule] = []
    for version in ("10", "9", "8"):
        rules.extend(_build_rocky_version_rules(version))
    return rules


# ---- Rocky audit commands --------------------------------------------------

def build_rocky_audit_commands() -> List[Dict[str, Any]]:
    """
    Rocky-specific data collection. The RHEL-10 collection (r10_* keys) already
    runs on Rocky hosts (Rocky is in the RHEL family), so this only adds the keys
    that differ: repo_gpgcheck lives in /etc/yum.conf on Rocky 8 and
    /etc/dnf/dnf.conf on Rocky 9/10 — grep both.
    """
    return [
        {"cmd": "grep -Es '^\\s*repo_gpgcheck' /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null || echo 'not configured'",
         "sudo": False, "key": "rocky_repo_gpgcheck", "section": "1.2.1.3"},
    ]


# ---- Rocky hardening templates ---------------------------------------------

def build_rocky_hardening_templates() -> List[Any]:
    """
    Re-badge the RHEL-10 remediation templates to the LNX-ROCKY{8,9,10}-* ids,
    trimmed to the sections each Rocky version keeps. Registered into the shared
    registry by command_templates.
    """
    templates = build_rhel10_hardening_templates()
    out: List[Any] = []
    for version in ("10", "9", "8"):
        dropped = _dropped_sections(version)
        for t in templates:
            level, section = _split_rhel10_id(t.check_id)
            if section in dropped:
                continue
            new_id, _new_section = _rocky_id(level, section, version)
            out.append(replace(t, check_id=new_id, distros=list(_ROCKY_FAMILY)))
    return out


# ---- Rocky parameter map ---------------------------------------------------
# Every Rocky check id is listed (empty list = auto-fixable with no params) so
# parameter_metadata's categorization treats templated checks as fixable and
# manual/informational ones as unsupported. Merged into LINUX_CHECK_PARAMETER_MAP.

def _build_rocky_parameter_map() -> Dict[str, List[str]]:
    pmap: Dict[str, List[str]] = {}
    for r in build_rocky_cis_rules():
        pmap[r.id] = []
    # crypto-policy checks only survive on Rocky 10 (dropped on 9/8); their
    # template takes the CRYPTO_POLICY parameter.
    for check_id in ("LNX-ROCKY10-L1-1.6.3", "LNX-ROCKY10-L1-1.6.4"):
        if check_id in pmap:
            pmap[check_id] = ["CRYPTO_POLICY"]
    return pmap


ROCKY_CHECK_PARAMETER_MAP: Dict[str, List[str]] = _build_rocky_parameter_map()


__all__ = [
    "ROCKY_VERSIONS",
    "ROCKY_PROFILES",
    "get_rocky_cis_rules",
    "get_rocky_supported_checks",
    "build_rocky_cis_rules",
    "build_rocky_audit_commands",
    "build_rocky_hardening_templates",
    "ROCKY_CHECK_PARAMETER_MAP",
]
