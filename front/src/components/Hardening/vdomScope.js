/**
 * Display helpers for the FortiGate scope/VDOM context in the hardening UI.
 *
 * The backend reports which VDOM a fix targets (`target_vdom`:
 * "global" / "root" / <vdom name>, or null on flat non-VDOM devices) and the
 * control's scope ("global" / "vdom" / "vdom_root"). The SSH engine adds the
 * scope wrapper itself — these helpers only VISUALIZE it so the operator sees
 * exactly where the commands will land.
 */

export const vdomBadgeLabel = (targetVdom) =>
    targetVdom === 'global' ? 'global (device-wide)' : targetVdom;

/**
 * Partition audit-result rows into Global vs per-VDOM groups for the
 * hardening tables. Rows carry `vdom` ("global" / "root" / <name>) on
 * VDOM-enabled FortiGates and null on flat devices / other vendors — when no
 * row has a vdom, a single unlabeled group is returned so the table renders
 * exactly as before.
 */
export const groupChecksByScope = (checks) => {
    const list = checks || [];
    const hasVdom = list.some((c) => c.vdom);
    if (!hasVdom) return { hasVdom: false, groups: [{ key: 'all', label: null, checks: list }] };

    const isGlobal = (c) => !c.vdom || c.vdom === 'global';
    const globals = list.filter(isGlobal);
    const vdoms = list.filter((c) => !isGlobal(c));

    const groups = [];
    if (globals.length) groups.push({ key: 'global', label: 'Global checks — device-wide', checks: globals });
    if (vdoms.length)   groups.push({ key: 'vdom',   label: 'VDOM checks — per virtual domain', checks: vdoms });
    return { hasVdom: true, groups };
};

/**
 * The wrapper block the SSH engine adds around the check's commands on
 * VDOM-enabled devices. Returns null when no VDOM context applies (flat
 * device) so callers can skip the wrapper entirely.
 */
export const scopeWrapper = (scope, targetVdom) => {
    if (!targetVdom) return null;
    if (scope === 'global' || targetVdom === 'global') {
        return { open: ['config global'], close: ['end'] };
    }
    return { open: ['config vdom', `edit ${targetVdom}`], close: ['end'] };
};

/** Wrap plain command lines with the scope wrapper for <pre> display. */
export const wrapCommandsForDisplay = (commands, scope, targetVdom) => {
    const wrapper = scopeWrapper(scope, targetVdom);
    if (!wrapper) return commands;
    return [...wrapper.open, ...commands.map((c) => (c ? `    ${c}` : c)), ...wrapper.close];
};
