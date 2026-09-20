"""
Classification for asset types that must record which server hosts them
(VM, Application, Database) - keyword-matched against the free-text asset
type name, the same convention already used elsewhere in this app for
asset-type classification (e.g. front/src/components/shared/DeviceIcon.jsx's
icon rules) since asset types have no fixed code enum, just an
operator-managed name.
"""
import re

# Letter-adjacency lookaround instead of \b: \b treats underscores/digits as
# word characters, so "VM_01" or "database2" would fail to match with \b at
# the boundary. Only an adjacent *letter* (e.g. "VMware", "application" is
# fine since "app" would still match earlier in a different word, but
# "grappler" must not match "app") should block a match.
_HOSTED_TYPE_PATTERN = re.compile(
    r"(?<![A-Za-z])(vm|virtual\s*machine|application|app|database|db)(?![A-Za-z])",
    re.IGNORECASE,
)


def requires_hosting(asset_type_name: str) -> bool:
    """True when this asset type name looks like a VM/Application/Database -
    something that necessarily runs inside a physical or virtual server,
    rather than being network/compute hardware itself."""
    if not asset_type_name:
        return False
    return bool(_HOSTED_TYPE_PATTERN.search(asset_type_name))
