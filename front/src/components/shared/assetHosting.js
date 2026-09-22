// Mirrors app/modules/assets/hosting.py's requires_hosting() exactly - asset
// types have no fixed code enum, just an operator-managed free-text name, so
// both sides classify the same way: keyword-match against the type name.
// Letter-adjacency lookaround instead of \b: \b treats underscores/digits as
// word characters, so "VM_01" would fail to match at a \b boundary. Only an
// adjacent *letter* (e.g. "VMware") should block a match.
const HOSTED_TYPE_PATTERN = /(?<![A-Za-z])(vm|virtual\s*machine|application|app|database|db)(?![A-Za-z])/i;

export function requiresHosting(typeName) {
    if (!typeName) return false;
    return HOSTED_TYPE_PATTERN.test(typeName);
}
