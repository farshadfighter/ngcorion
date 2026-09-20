"""
Version matching between a real asset's os_version and a CveRecord's
affected-version bounds.

Vendor version strings are not reliably semver (FortiOS is close to it;
Cisco IOS's "15.2(4)M3" train-style versioning is not), so this parses
leniently: real semver first (via `packaging.version`), falling back to
just the leading run of dot-separated numeric groups when that fails. A
version that cannot be parsed at all never matches - silently claiming an
unparseable version is "in range" (or not) would be worse than reporting
nothing for it.
"""
import re
from typing import Optional

from packaging.version import Version, InvalidVersion

from app.models.asset import Asset
from app.models.cve import CveRecord

_LEADING_NUMERIC = re.compile(r"^\s*(\d+(?:\.\d+)*)")


def parse_version(version_str: Optional[str]) -> Optional[tuple[int, ...]]:
    """Best-effort parse into a comparable tuple of ints, or None."""
    if not version_str:
        return None
    try:
        return tuple(Version(version_str.strip()).release)
    except InvalidVersion:
        pass
    match = _LEADING_NUMERIC.match(version_str)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def version_in_range(version_str: str, min_str: Optional[str], max_str: Optional[str]) -> bool:
    version = parse_version(version_str)
    if version is None:
        return False
    if min_str is not None:
        lower = parse_version(min_str)
        if lower is not None and version < lower:
            return False
    if max_str is not None:
        upper = parse_version(max_str)
        if upper is not None and version > upper:
            return False
    return True


def asset_matches_cve(asset: Asset, cve: CveRecord) -> bool:
    """A CVE applies to an asset when its product_keyword appears in the
    asset's os_name (the field meant to carry e.g. "FortiOS", "Apache HTTP
    Server") and the asset's os_version falls within the CVE's affected
    range. An asset with no os_name/os_version recorded never matches -
    there is nothing to compare against."""
    if not asset.os_name or not asset.os_version:
        return False
    if cve.product_keyword.lower() not in asset.os_name.lower():
        return False
    return version_in_range(asset.os_version, cve.affected_version_min, cve.affected_version_max)
