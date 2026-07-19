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
"""

from typing import List

from app.modules.linux.audit.rules import (
    LinuxCISRule,
    build_linux_cis_rules,
    filter_rules_by_distro,
    filter_rules_by_profile,
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


__all__ = [
    "RHEL_VERSIONS",
    "RHEL_PROFILES",
    "get_rhel_cis_rules",
    "get_rhel_supported_checks",
]
