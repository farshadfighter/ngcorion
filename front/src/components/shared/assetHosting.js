// Mirrors app/modules/assets/hosting.py's requires_hosting() exactly - asset
// types have no fixed code enum, just an operator-managed free-text name, so
// both sides classify the same way: keyword-match against the type name.
// Letter-adjacency lookaround instead of \b: \b treats underscores/digits as
// word characters, so "VM_01" would fail to match at a \b boundary. Only an
// adjacent *letter* (e.g. "VMware") should block a match.
const HOSTED_TYPE_PATTERN = /(?<![A-Za-z])(vm|virtual\s*machine|application|app|database|db)(?![A-Za-z])/i;

/**
 * Whether assets of this type must name their host: a virtual type (asset type `is_virtual`), or a
 * type whose name reads as a VM, application or database (types created before the flag). Takes the
 * asset type or its name.
 */
export function requiresHosting(type) {
    if (!type) return false;
    if (typeof type === "object") return !!type.is_virtual || requiresHosting(type.type_name);
    return HOSTED_TYPE_PATTERN.test(type);
}

/** A virtual type: its assets run on a physical server. */
export const isVirtualType = (type) => !!type?.is_virtual;

/**
 * The assets an asset may name as its host: never itself, and for a virtual asset only a physical one
 * (the API refuses a virtual host for it).
 */
export function hostChoices(assets, types, { virtual = false, selfId } = {}) {
    const virtualTypes = new Set((types || []).filter((t) => t.is_virtual).map((t) => t.id));
    return (assets || []).filter((a) => a.id !== selfId && !(virtual && virtualTypes.has(a.asset_type_id)));
}
