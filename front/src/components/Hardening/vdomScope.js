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
