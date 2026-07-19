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
"""

from typing import List

from app.modules.linux.audit.rules import (
    LinuxCISRule,
    build_linux_cis_rules,
    filter_rules_by_distro,
    filter_rules_by_profile,
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


__all__ = [
    "ROCKY_VERSIONS",
    "ROCKY_PROFILES",
    "get_rocky_cis_rules",
    "get_rocky_supported_checks",
]
