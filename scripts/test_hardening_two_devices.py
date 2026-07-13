#!/usr/bin/env python3
"""
Full FortiGate hardening + audit coverage test against TWO real devices — SSH
only, no DB. Every one of the 53 CIS controls is exercised on each device:
18 through the hardening flow, the other 35 through an audit-only sweep.

For every AUTO-FIXABLE CIS check (every control that has a remediation template
AND all of whose parameters have defaults — 18 checks, not just FG-BL-090), this
script, per device:

  1. Reads the control's live value using the SAME production SSH read + evaluator
     the audit uses (``FortiGateHardeningExecutor.verify_check`` -> the audit
     ``FortinetAuditService._evaluate_rule``).
  2. If the control is already COMPLIANT, forces it NON-COMPLIANT first (so the
     real fix path is always exercised); if it is already NON-COMPLIANT, hardens
     it directly.
  3. Hardens it through the EXACT production path used by ``execute_hardening`` /
     ``auto_harden_with_defaults`` (``executor.execute_commands`` with the
     template commands, then ``executor.verify_check``) — just without the DB
     read/write layer.
  4. Re-reads from the device to confirm the fix (PASS) or not (FAIL).
  5. Restores the ORIGINAL value in a finally block. Restores are registered
     BEFORE the device is touched and run LIFO even if the script crashes
     mid-check, so neither device is left weakened.

For the other 35 MANUAL / AUDIT-ONLY controls (everything not auto-fixable —
Manual recommendations plus templated checks that need operator-supplied
parameters) hardening can't be exercised, so a read-only sweep instead confirms
the audit itself is healthy on the device:

  1. the control's read command(s) actually RUN in the right scope,
  2. they return parseable output (not empty and not a device rejection like
     "command parse error" / "Command fail. Return code -N"),
  3. the production evaluator yields a clean PASS/NON-COMPLIANT verdict without
     raising.

Pass -> AUDIT-OK, any of the above failing -> AUDIT-ERROR. The device is never
mutated by this sweep; it runs first, on the pristine config.

Production-fidelity notes
-------------------------
* Exactly the SSH classes ``verify_hardening_e2e.py`` exercises:
  ``FortiGateHardeningExecutor`` (which owns a ``FortiGateSSHClient``). One SSH
  session per device is used for reads, the forced-break, the fix and the
  restore.
* NO database is imported or written — SSH only.
* Device 1 (172.16.200.20) has VDOMs enabled; Device 2 (172.16.200.40) does not.
  VDOM-scoped controls are routed to the management ("root") VDOM on the VDOM
  device and collapse to the flat context on the non-VDOM device — the SSH client
  handles this from each control's ``scope``.

A few auto-fixable controls are reported SKIP by design (never mutated), with the
reason printed inline — see ``UNTESTABLE`` below. These are honest limitations,
not passes.

Usage
-----
    FG_PASS=xxx  .venv/bin/python scripts/test_hardening_two_devices.py
    FG_PASS=xxx  .venv/bin/python scripts/test_hardening_two_devices.py --only FG-BL-090
    FG_PASS=xxx  .venv/bin/python scripts/test_hardening_two_devices.py --list

Credentials (username defaults to ``admin``):
    FG_USER / FG_PASS                      apply to BOTH devices
    FG_USER_20 / FG_PASS_20                override for 172.16.200.20
    FG_USER_40 / FG_PASS_40                override for 172.16.200.40
"""
import argparse
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# NB: intentionally NO app.core.database / models import — this test is SSH only.
from app.modules.fortinet.audit.rules import (  # noqa: E402
    FortiGateControl,
    get_fortinet_controls,
)
from app.modules.fortinet.audit.service import (  # noqa: E402
    FortinetAuditService,
    _entry_field_value,
    _get_field_value,
    _parse_table_entries,
)
from app.modules.fortinet.audit.ssh_client import (  # noqa: E402
    _BAD_OUTPUT_PATTERNS,
    FortiGateSSHClient,
)
from app.modules.fortinet.hardening.command_parser import (  # noqa: E402
    FortiGateRemediationParser,
    apply_fortigate_defaults,
)
from app.modules.fortinet.hardening.command_templates import (  # noqa: E402
    has_fortigate_template,
    IFACE_ALLOWACCESS_FORBIDDEN,
)
from app.modules.fortinet.hardening.parameter_metadata import (  # noqa: E402
    get_fortigate_check_defaults,
    is_fortigate_check_auto_fixable,
)
from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor  # noqa: E402

SEP = "=" * 78

# The two devices under test (overridable via CLI).
DEFAULT_DEVICES = [
    ("172.16.200.20", "VDOM enabled"),
    ("172.16.200.40", "no VDOM"),
]


# ---------------------------------------------------------------------------
# Breaker registry: how to force each auto-fixable control NON-COMPLIANT and how
# to snapshot/restore its ORIGINAL value. Command blocks are the INNER config
# only (``config <section>`` / ``set ...`` / ``end``) — the SSH client adds the
# scope wrapper (``config global`` or ``config vdom`` / ``edit root``) from the
# control's scope, exactly like the hardening executor.
# ---------------------------------------------------------------------------
@dataclass
class Breaker:
    """Declarative recipe to break + restore one control.

    kind:
      - "field"   : one or more ``key : value`` fields read from a ``get`` command;
                    snapshot is always available (``get`` prints resolved values).
      - "show_set": a ``set <key> <val>`` line from a ``show`` command; the field
                    is omitted when left at its default (snapshot -> None -> unset).
      - "profile" : a field on one entry of a profile table (``edit <profile>``).
      - "either"  : a control whose setting has >1 build-specific spelling — carries
                    ``variants`` (concrete field breakers, each with its own
                    ``read_cmd``); the first variant whose field exists on the
                    device is used, so the same control is exercised on every build.
    """
    section: str                       # inner config section, e.g. "system global"
    bad: Dict[str, str]                # field -> value that makes the control FAIL
    kind: str = "field"
    profile: Optional[str] = None      # entry name for kind == "profile"
    forceable: bool = True             # False -> the control has no valid non-compliant
    force_note: str = ""               # value on-device, so skip when already COMPLIANT
    read_cmd: Optional[str] = None     # override read cmd (default: control.rules[0].cmd)
    variants: Optional[List["Breaker"]] = None  # kind == "either": try each in order

    @property
    def fields(self) -> List[str]:
        return list(self.bad)


BREAKERS: Dict[str, Breaker] = {
    # ---- 2.1 General Settings (global) ----
    "FG-BL-092":  Breaker("system global", {"pre-login-banner": "disable"}),
    "FG-SYS-001": Breaker("system global", {"post-login-banner": "disable"}),
    "FG-SYS-005": Breaker("system auto-install",
                          {"auto-install-config": "enable", "auto-install-image": "enable"}),
    "FG-SYS-006": Breaker("system global", {"ssl-static-key-ciphers": "enable"}),
    "FG-BL-090":  Breaker("system global", {"strong-crypto": "disable"}),
    # ---- 2.2 Password Policy (global) ----
    "FG-BL-030":  Breaker("system password-policy", {"status": "disable"}),
    "FG-PW-001":  Breaker("system global", {"admin-lockout-threshold": "0"}, forceable=False,
                          force_note="control passes for threshold >= 1 and FortiOS rejects 0 "
                                     "(value parse error) — no valid non-compliant state to force"),
    # ---- 2.4 Administrators (global) ----
    "FG-BL-004":  Breaker("system global", {"admintimeout": "480"}),  # > 10 -> non-compliant
    # ---- 4.2 Antivirus ----
    # Build-aware: newer builds have machine-learning-detection under antivirus
    # settings; 60F/older builds use `config antivirus heuristic` (mode). Whichever
    # field the device actually exposes is the one snapshot/break/restore targets.
    "FG-AV-003":  Breaker("", {}, kind="either", variants=[
        Breaker("antivirus settings", {"machine-learning-detection": "disable"},
                read_cmd="get antivirus settings"),
        Breaker("antivirus heuristic", {"mode": "disable"},
                read_cmd="get antivirus heuristic"),
    ]),
    "FG-AV-004":  Breaker("antivirus settings", {"grayware": "disable"}),
    # ---- 4.3 / 4.4 profile tables (per-VDOM) ----
    "FG-DNS-001": Breaker("dnsfilter profile", {"block-botnet": "disable"},
                          kind="profile", profile="default"),
    # FG-APP-002 is intentionally review-only now (no template — the
    # enforce-default-app-port field is absent on some builds), so it is covered
    # by the manual audit sweep, not here.
    # ---- 7 Users / 8 Logs (per-VDOM + global) ----
    "FG-USER-001": Breaker("user setting", {"auth-lockout-threshold": "0"}, forceable=False,
                           force_note="control passes for threshold >= 1 and FortiOS rejects 0 "
                                      "(value parse error) — no valid non-compliant state to force"),
    "FG-LOG-001":  Breaker("log eventfilter", {"event": "disable"}),
    "FG-LOG-002":  Breaker("log fortianalyzer setting", {"enc-algorithm": "disable"}),
}

# Auto-fixable controls we deliberately DO NOT mutate. They are read + reported
# for context, but their result is SKIP with the reason below.
UNTESTABLE: Dict[str, str] = {
    "FG-BL-002": ("auto-fix is now correct (dynamic per-interface allowaccess strip via "
                  "build_iface_allowaccess_fix — removes only telnet/http, keeps other "
                  "services); NOT force-broken here because that would toggle real "
                  "management access on a live interface. Exercise via the UI 'Harden "
                  "Single' or a manual run"),
    "FG-BL-040": ("scope bug fixed (diagnose runs inside config global on VDOM devices, "
                  "top level on flat ones); still skipped because "
                  "the ntp_status_ok VERDICT depends on live NTP synchronisation, which "
                  "`set ntpsync enable` can't achieve synchronously — skipping avoids "
                  "desyncing the device and a timing-based FAIL"),
}


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class Result:
    check_id: str
    status: str            # auto: PASS|FAIL|SKIP|ERROR ; manual: AUDIT-OK|AUDIT-ERROR
    reason: str = ""
    initial: str = ""      # COMPLIANT / NON-COMPLIANT at start (for context)
    kind: str = "auto"     # "auto" (hardening) | "manual" (audit-only)
    suspect: bool = False  # manual AUDIT-OK whose verdict hinges on an absent field
    evidence: str = ""     # manual: full production evidence text (shown with --verbose)


@dataclass
class Restore:
    """A restore action registered before a control is touched."""
    check_id: str
    control: FortiGateControl
    cmds: List[str]
    vdom: Optional[str]


# ---------------------------------------------------------------------------
# Helpers built on the production SSH classes
# ---------------------------------------------------------------------------
def _control_map() -> Dict[str, FortiGateControl]:
    return {c.id: c for c in get_fortinet_controls()}


def auto_fixable_ids(controls: Dict[str, FortiGateControl]) -> List[str]:
    """Exactly the production 'auto-fixable' set, in catalog order."""
    return [cid for cid in controls
            if has_fortigate_template(cid) and is_fortigate_check_auto_fixable(cid)]


def manual_ids(controls: Dict[str, FortiGateControl], auto_ids: List[str]) -> List[str]:
    """Every control that is NOT auto-fixable — the manual / audit-only set, in
    catalog order. Includes Manual recommendations and templated checks that
    require operator-supplied parameters (no defaults to auto-apply)."""
    auto = set(auto_ids)
    return [cid for cid in controls if cid not in auto]


def build_fix_commands(control: FortiGateControl) -> List[str]:
    """Reproduce the production fix commands (template + defaults), identical to
    ``auto_harden_with_defaults`` / ``execute_hardening``."""
    parsed = FortiGateRemediationParser.parse_remediation(control.remediation, control.id)
    return FortiGateRemediationParser.substitute_parameters(
        parsed.commands, apply_fortigate_defaults({}, get_fortigate_check_defaults(control.id))
    )


def _block(section: str, assignments: List[str]) -> List[str]:
    return [f"config {section}", *assignments, "end"]


def _profile_block(section: str, profile: str, assignments: List[str]) -> List[str]:
    return [f"config {section}", f"edit {profile}", *assignments, "next", "end"]


def _resolve_and_snapshot(client, control: FortiGateControl, br: Breaker,
                          vdom: Optional[str]):
    """Return ``(effective_breaker, snapshot)``. For a build-aware ``either``
    breaker, pick the first variant whose field actually exists on this device
    (so the same control is exercised whatever spelling the build uses)."""
    if br.kind != "either":
        return br, snapshot_original(client, control, br, vdom)
    errors = []
    for variant in br.variants or []:
        try:
            return variant, snapshot_original(client, control, variant, vdom)
        except RuntimeError as e:
            errors.append(str(e))
    raise RuntimeError("no build variant applies (" + "; ".join(errors) + ")")


def snapshot_original(client, control: FortiGateControl, br: Breaker,
                      vdom: Optional[str]) -> Dict[str, Optional[str]]:
    """Read each field's ORIGINAL value so it can be restored exactly.

    Raises RuntimeError when the state needed to break/restore isn't present
    (e.g. the profile entry doesn't exist) so the caller can SKIP cleanly.
    """
    read_cmd = br.read_cmd or control.rules[0].cmd
    out = client.collect([read_cmd], scope=control.scope, vdom=vdom, use_cache=False)[read_cmd]

    snap: Dict[str, Optional[str]] = {}
    if br.kind == "profile":
        entries = {e["name"]: e["body"] for e in _parse_table_entries(out)}
        if br.profile not in entries:
            raise RuntimeError(f"profile '{br.profile}' not present in `{read_cmd}`")
        for f in br.fields:
            snap[f] = _entry_field_value(entries[br.profile], f)
    elif br.kind == "show_set":
        for f in br.fields:
            m = re.search(rf"set\s+{re.escape(f)}\s+(\S+)", out, re.IGNORECASE)
            snap[f] = m.group(1).strip('"') if m else None      # None -> field at default
    else:  # "field": get-style key : value (always resolved)
        for f in br.fields:
            v = _get_field_value(out, f)
            if v is None:
                raise RuntimeError(f"field '{f}' absent from `{read_cmd}` (cannot snapshot)")
            snap[f] = v
    return snap


def _assignments(mapping: Dict[str, Optional[str]]) -> List[str]:
    """``set k v`` for each field, or ``unset k`` when the restore value is None
    (field was at its FortiOS default originally)."""
    return [f"unset {k}" if v is None else f"set {k} {v}" for k, v in mapping.items()]


def break_commands(br: Breaker) -> List[str]:
    assigns = [f"set {k} {v}" for k, v in br.bad.items()]
    return (_profile_block(br.section, br.profile, assigns) if br.kind == "profile"
            else _block(br.section, assigns))


def restore_commands(br: Breaker, snap: Dict[str, Optional[str]]) -> List[str]:
    assigns = _assignments(snap)
    return (_profile_block(br.section, br.profile, assigns) if br.kind == "profile"
            else _block(br.section, assigns))


# ---------------------------------------------------------------------------
# Per-check runner
# ---------------------------------------------------------------------------
def _na_check(executor: FortiGateHardeningExecutor, control: FortiGateControl,
              vdom: Optional[str]) -> Optional[str]:
    """If the control's na_gate matches (feature off/absent on this build), return
    the reason so we skip hardening it; otherwise None. Reuses the production
    applicability logic so the test agrees with the audit."""
    gate = getattr(control, "na_gate", None)
    if gate is None:
        return None
    try:
        out = executor.ssh_client.collect([gate.cmd], scope=control.scope,
                                          vdom=vdom, use_cache=False).get(gate.cmd, "")
    except Exception:  # noqa: BLE001 - a read failure isn't an N/A determination
        return None
    applicable, reason = FortinetAuditService._applicability(control, {gate.cmd: out})
    return None if applicable else reason


def run_check(tag: str, executor: FortiGateHardeningExecutor,
              control: FortiGateControl, restores: List[Restore]) -> Result:
    cid = control.id
    client = executor.ssh_client
    # Route per-VDOM controls to the management VDOM; the client maps
    # SCOPE_VDOM + None -> root, and everything collapses on a flat device.
    vdom = None

    # Controls we never mutate — read current state for context, then SKIP.
    if cid in UNTESTABLE:
        try:
            compliant, _ = executor.verify_check(control, vdom=vdom)
            initial = "COMPLIANT" if compliant else "NON-COMPLIANT"
        except Exception as e:  # noqa: BLE001
            initial = f"read-error: {type(e).__name__}"
        return Result(cid, "SKIP", UNTESTABLE[cid], initial)

    # N/A gate (feature off/absent on this build) — don't try to harden it.
    na = _na_check(executor, control, vdom)
    if na:
        return Result(cid, "SKIP", f"N/A — {na}", "N/A")

    br = BREAKERS.get(cid)
    if br is None:
        return Result(cid, "SKIP", "no breaker defined for this auto-fixable check", "")

    # 1. initial state via the production verify path
    try:
        compliant0, _ = executor.verify_check(control, vdom=vdom)
    except Exception as e:  # noqa: BLE001
        return Result(cid, "ERROR", f"initial read failed: {type(e).__name__}: {e}", "")
    initial = "COMPLIANT" if compliant0 else "NON-COMPLIANT"

    # A control with no valid non-compliant value (e.g. a `>= 1` threshold the
    # device won't let us drop below 1) can't be exercised when already COMPLIANT;
    # skip cleanly without touching it. If it were somehow already NON-COMPLIANT we
    # still fall through and harden it.
    if compliant0 and not br.forceable:
        return Result(cid, "SKIP", br.force_note, initial)

    # 2. resolve the build-specific field variant, snapshot ORIGINAL, and register
    #    the restore BEFORE any mutation
    try:
        eff_br, snap = _resolve_and_snapshot(client, control, br, vdom)
    except RuntimeError as e:
        return Result(cid, "SKIP", str(e), initial)
    except Exception as e:  # noqa: BLE001
        return Result(cid, "ERROR", f"snapshot failed: {type(e).__name__}: {e}", initial)
    restores.append(Restore(cid, control, restore_commands(eff_br, snap), vdom))

    # 3. force NON-COMPLIANT if needed (always exercise the real fix path)
    if compliant0:
        res = client.run_config(break_commands(eff_br), scope=control.scope, vdom=vdom)
        if not res["success"]:
            return Result(cid, "SKIP", f"could not force non-compliant: {'; '.join(res['errors'])[:120]}", initial)
        broke, _ = executor.verify_check(control, vdom=vdom)
        if broke:  # still compliant -> break didn't take (e.g. another profile matches)
            return Result(cid, "SKIP", "break did not flip the control to NON-COMPLIANT", initial)

    # 4. harden through the production path (execute_commands + verify_check).
    #    Device-state-aware controls (e.g. FG-BL-002 per-interface allowaccess)
    #    compute their fix from the live config, exactly like execute_hardening.
    try:
        if cid in IFACE_ALLOWACCESS_FORBIDDEN:
            fix_cmds = executor.build_iface_allowaccess_fix(
                scope=control.scope, vdom=vdom,
                forbidden=IFACE_ALLOWACCESS_FORBIDDEN[cid])
        else:
            fix_cmds = build_fix_commands(control)
        exec_res = executor.execute_commands(fix_cmds, scope=control.scope, vdom=vdom)
        passed, evidence = executor.verify_check(control, vdom=vdom)
    except Exception as e:  # noqa: BLE001
        return Result(cid, "ERROR", f"harden failed: {type(e).__name__}: {e}", initial)

    if passed:
        return Result(cid, "PASS", "", initial)

    reason = ("; ".join(exec_res["errors"])[:160] if not exec_res["success"]
              else "verification failed after fix")
    # a compact line of evidence helps triage a real FAIL
    ev1 = (evidence or "").replace("\n", " ")[:160]
    return Result(cid, "FAIL", f"{reason} | evidence: {ev1}", initial)


def restore_all(tag: str, executor: FortiGateHardeningExecutor, restores: List[Restore]) -> None:
    """Run every registered restore LIFO; each is independent so one failure
    never blocks the rest. Re-verifies for an at-a-glance confirmation."""
    if not restores:
        return
    client = executor.ssh_client
    print(f"\n[{tag}] --- restoring {len(restores)} changed control(s) ---")
    for r in reversed(restores):
        try:
            res = client.run_config(r.cmds, scope=r.control.scope, vdom=r.vdom)
            ok, _ = executor.verify_check(r.control, vdom=r.vdom)
            state = "restored" if not res["errors"] else f"restore errors: {'; '.join(res['errors'])[:80]}"
            print(f"[{tag}] {r.check_id:12} -> {state} (now {'COMPLIANT' if ok else 'NON-COMPLIANT'})")
        except Exception as e:  # noqa: BLE001
            print(f"[{tag}] {r.check_id:12} -> WARNING restore raised: {type(e).__name__}: {e}")


# ---------------------------------------------------------------------------
# Manual / audit-only runner (read-only)
# ---------------------------------------------------------------------------
def _first_bad_line(output: str) -> str:
    """The first output line that shows a FortiOS rejection, for a concise reason."""
    for line in (output or "").splitlines():
        if any(p in line.lower() for p in _BAD_OUTPUT_PATTERNS):
            return line.strip()[:100]
    return "unparseable output"


# get-field rule types whose verdict is auto-NON-COMPLIANT when the key is absent
# (string comparisons). Int types are excluded — they legitimately fall back to
# the rule's numeric default when the line is omitted, so absence isn't suspect.
_SUSPECT_TYPES = frozenset({
    "get_field_eq", "get_field_ne", "get_field_in",
    "get_field_matches", "get_field_not_match", "get_field_excludes",
})


def _suspect_absent_fields(control: FortiGateControl, outputs: Dict[str, str]) -> List[str]:
    """Return the keys of string get-field rules whose field is ABSENT from a
    complete, non-error capture — the production 'may be a false NON-COMPLIANT'
    signal (usually a build-specific output-format mismatch). Such a verdict ran
    cleanly (so it's AUDIT-OK) but shouldn't be trusted without a look."""
    suspects: List[str] = []
    for r in control.rules:
        if r.type in _SUSPECT_TYPES and r.key:
            out = outputs.get(r.cmd, "")
            if out.strip() and FortiGateSSHClient._is_command_ok(out) \
                    and _get_field_value(out, r.key) is None:
                suspects.append(r.key)
    return suspects


def run_manual_audit(executor: FortiGateHardeningExecutor, control: FortiGateControl,
                     vdom: Optional[str]) -> Result:
    """Audit-only health check for a non-auto-fixable control: run its read
    command(s) through the production SSH path and confirm they execute, return
    parseable output, and yield a clean verdict via the production evaluator.
    Never mutates the device."""
    cid = control.id
    client = executor.ssh_client

    cmds: List[str] = []
    for r in control.rules:
        if r.cmd not in cmds:
            cmds.append(r.cmd)

    # 1. commands run (one scope entry; use_cache shares reads across controls)
    try:
        outputs = client.collect(cmds, scope=control.scope, vdom=vdom, use_cache=True)
    except Exception as e:  # noqa: BLE001
        return Result(cid, "AUDIT-ERROR", f"collect raised: {type(e).__name__}: {e}", kind="manual")

    # 2. output is present and not a device rejection
    for cmd in cmds:
        out = outputs.get(cmd, "")
        if not out.strip():
            return Result(cid, "AUDIT-ERROR", f"`{cmd}` returned empty output", kind="manual")
        if not FortiGateSSHClient._is_command_ok(out):
            return Result(cid, "AUDIT-ERROR", f"`{cmd}` -> {_first_bad_line(out)}", kind="manual")

    # 3. the production control evaluator produces a clean verdict — PASS,
    #    NON-COMPLIANT, or NOT_APPLICABLE (na_gate) — without raising.
    try:
        finding = FortinetAuditService._evaluate_control(control, outputs, None)
    except Exception as e:  # noqa: BLE001 - evaluator is meant to be exception-safe
        return Result(cid, "AUDIT-ERROR", f"evaluation crashed: {type(e).__name__}: {e}", kind="manual")

    evidence = finding.get("evidence", "")
    if not finding["applicable"]:
        return Result(cid, "AUDIT-OK", f"verdict: N/A ({finding['na_reason']})",
                      kind="manual", evidence=evidence)

    verdict = "COMPLIANT" if finding["passed"] else "NON-COMPLIANT"
    if control.needs_review:
        verdict += " [review]"
    suspects = _suspect_absent_fields(control, outputs)
    reason = f"verdict: {verdict}"
    if suspects:
        reason += (f"  SUSPECT: {', '.join(suspects)} absent from output "
                   f"— verdict may be a false NON-COMPLIANT (build format mismatch)")
    return Result(cid, "AUDIT-OK", reason, kind="manual", suspect=bool(suspects),
                  evidence=evidence)


# Set from --verbose in main(): print the full production evidence text under
# each manual check's result line, so the parsed values (worksheets, per-policy
# service lists, sensor names) are visible — not just the verdict.
SHOW_EVIDENCE = False


def _print_result_line(tag: str, res: Result) -> None:
    if res.kind == "manual":
        detail = ("command ran + parsed; " + res.reason if res.status == "AUDIT-OK"
                  else res.reason)
        suffix = f"(manual, {detail})"
    elif res.status == "PASS":
        suffix = f"(auto-fixable, hardened; was {res.initial})" if res.initial else "(auto-fixable, hardened)"
    else:
        detail = res.reason or (f"was {res.initial}" if res.initial else "")
        suffix = f"(auto-fixable, {detail})" if detail else "(auto-fixable)"
    print(f"[{tag}] {res.check_id:12} -> {res.status:11} {suffix}")
    if SHOW_EVIDENCE and res.kind == "manual" and res.evidence:
        for line in res.evidence.splitlines():
            print(f"[{tag}]      | {line}")


# ---------------------------------------------------------------------------
# Per-device driver
# ---------------------------------------------------------------------------
def run_device(host: str, label: str, user: str, password: str, port: int,
               auto_check_ids: List[str], manual_check_ids: List[str],
               controls: Dict[str, FortiGateControl],
               do_backup: bool, scratch: str) -> Dict[str, Result]:
    tag = host
    results: Dict[str, Result] = {}
    restores: List[Restore] = []
    all_ids = manual_check_ids + auto_check_ids
    vdom = None  # route by scope: SCOPE_VDOM -> root, SCOPE_GLOBAL -> global

    print(f"\n{SEP}\nDEVICE {host}  ({label})\n{SEP}")

    executor = FortiGateHardeningExecutor(ip=host, username=user, password=password, port=port)
    try:
        executor.__enter__()
    except Exception as e:  # noqa: BLE001
        print(f"[{tag}] CONNECT FAILED: {type(e).__name__}: {e}")
        for cid in all_ids:
            kind = "manual" if cid in manual_check_ids else "auto"
            status = "AUDIT-ERROR" if kind == "manual" else "ERROR"
            results[cid] = Result(cid, status, f"connect failed: {type(e).__name__}", kind=kind)
        return results

    try:
        executor.test_connectivity()
        vdom_on = executor.ssh_client.is_vdom_enabled()
        print(f"[{tag}] connected; VDOM mode {'ENABLED' if vdom_on else 'disabled'}")

        # One full-config safety backup to the scratchpad (SSH read only, no DB).
        if do_backup:
            try:
                backup = executor.backup_config()
                path = os.path.join(scratch, f"backup_{host.replace('.', '_')}.conf")
                with open(path, "w") as fh:
                    fh.write(backup)
                print(f"[{tag}] full-config backup saved: {path} ({len(backup)} bytes)")
            except Exception as e:  # noqa: BLE001
                print(f"[{tag}] WARNING backup failed (continuing): {type(e).__name__}: {e}")

        # --- manual / audit-only sweep first, on the pristine (read-only) config ---
        if manual_check_ids:
            print(f"\n[{tag}] --- manual audit sweep ({len(manual_check_ids)} checks, read-only) ---")
            for cid in manual_check_ids:
                res = run_manual_audit(executor, controls[cid], vdom)
                results[cid] = res
                _print_result_line(tag, res)

        # --- auto-fixable hardening (mutates + restores in the finally block) ---
        if auto_check_ids:
            print(f"\n[{tag}] --- auto-fixable hardening ({len(auto_check_ids)} checks) ---")
            for cid in auto_check_ids:
                res = run_check(tag, executor, controls[cid], restores)
                results[cid] = res
                _print_result_line(tag, res)

    finally:
        # Always restore, even on a mid-run crash, then close the SSH session.
        try:
            restore_all(tag, executor, restores)
        finally:
            executor.__exit__(None, None, None)

    return results


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
_ICONS = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "skip", "ERROR": "ERR ",
          "AUDIT-OK": "OK", "AUDIT-ERROR": "ERROR"}


def print_summary(devices: List, per_device: Dict[str, Dict[str, Result]],
                  auto_ids: List[str], manual_ids_: List[str]) -> None:
    hosts = [d[0] for d in devices]
    print(f"\n{SEP}\nSUMMARY (side by side)\n{SEP}")
    header = f"{'CHECK':<12} " + " ".join(f"{h:>17}" for h in hosts)

    def _rows(title: str, ids: List[str]) -> None:
        if not ids:
            return
        print(f"-- {title} --")
        for cid in ids:
            cells = []
            for h in hosts:
                r = per_device.get(h, {}).get(cid)
                icon = _ICONS.get(r.status, "-") if r else "-"
                if r and r.suspect:
                    icon += "*"          # AUDIT-OK but verdict hinges on an absent field
                cells.append(f"{icon:>17}")
            print(f"{cid:<12} " + " ".join(cells))

    print(header)
    print("-" * len(header))
    _rows("auto-fixable (hardening)", auto_ids)
    _rows("manual (audit-only)", manual_ids_)
    print("-" * len(header))

    for h in hosts:
        res = per_device.get(h, {})
        ap = sum(1 for cid in auto_ids if res.get(cid) and res[cid].status == "PASS")
        af = sum(1 for cid in auto_ids if res.get(cid) and res[cid].status == "FAIL")
        ask = sum(1 for cid in auto_ids if res.get(cid) and res[cid].status in ("SKIP", "ERROR"))
        mo = sum(1 for cid in manual_ids_ if res.get(cid) and res[cid].status == "AUDIT-OK")
        me = sum(1 for cid in manual_ids_ if res.get(cid) and res[cid].status == "AUDIT-ERROR")
        msus = sum(1 for cid in manual_ids_ if res.get(cid) and res[cid].suspect)
        total = len(auto_ids) + len(manual_ids_)
        print(f"\n[{h}]")
        if auto_ids:
            print(f"  Auto-fixable:  {ap}/{ap + af} PASS,  {af} FAIL   ({ask} skipped)")
        if manual_ids_:
            suspect_note = f"   ({msus} suspect* — verify)" if msus else ""
            print(f"  Manual audit:  {mo}/{mo + me} OK,    {me} ERROR{suspect_note}")
        print(f"  Total:         {ap + mo}/{total} OK")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _creds_for(host: str, args) -> tuple:
    octet = host.rsplit(".", 1)[-1]
    user = (os.environ.get(f"FG_USER_{octet}") or args.user
            or os.environ.get("FG_USER") or "admin")
    password = (os.environ.get(f"FG_PASS_{octet}") or os.environ.get("FG_PASS"))
    return user, password


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--devices", nargs="+", metavar="IP",
                    help="override the target device IPs (default: 172.16.200.20 172.16.200.40)")
    ap.add_argument("--user", help="SSH username for both devices (default: admin / $FG_USER)")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--only", nargs="+", metavar="CHECK_ID",
                    help="restrict to specific check IDs (auto or manual, e.g. FG-BL-090 FG-LIP-001)")
    ap.add_argument("--phase", choices=("both", "auto", "manual"), default="both",
                    help="run only the auto-fixable hardening phase, only the manual audit "
                         "sweep, or both (default: both)")
    ap.add_argument("--no-backup", action="store_true", help="skip the per-device full-config backup")
    ap.add_argument("--verbose", action="store_true",
                    help="keep the fortinet module's WARNING logs (absent-field / exec-error "
                         "details) AND print each manual check's full production evidence "
                         "text under its result line")
    ap.add_argument("--list", action="store_true",
                    help="print all 53 checks + their plan and exit (no device access)")
    args = ap.parse_args()

    # Quiet the interleaved module warnings by default — the per-check lines and
    # the SUSPECT annotations already carry the salient detail.
    logging.getLogger("app.modules.fortinet").setLevel(
        logging.WARNING if args.verbose else logging.ERROR)
    global SHOW_EVIDENCE
    SHOW_EVIDENCE = args.verbose

    controls = _control_map()
    auto_ids = auto_fixable_ids(controls) if args.phase in ("both", "auto") else []
    man_ids = manual_ids(controls, auto_fixable_ids(controls)) if args.phase in ("both", "manual") else []

    if args.only:
        wanted = {c.upper() for c in args.only}
        unknown = wanted - set(controls)
        if unknown:
            print(f"[warn] unknown check id(s), ignoring: {', '.join(sorted(unknown))}")
        auto_ids = [c for c in auto_ids if c in wanted]
        man_ids = [c for c in man_ids if c in wanted]
        if not auto_ids and not man_ids:
            print("[abort] no checks selected (check --only ids / --phase)")
            return 2

    if args.list:
        print(f"{len(auto_ids)} auto-fixable + {len(man_ids)} manual = "
              f"{len(auto_ids) + len(man_ids)} checks:\n")
        if auto_ids:
            print("AUTO-FIXABLE (hardened):")
            for cid in auto_ids:
                c = controls[cid]
                if cid in UNTESTABLE:
                    plan = f"SKIP — {UNTESTABLE[cid]}"
                else:
                    br = BREAKERS.get(cid)
                    if br is None:
                        plan = "no breaker defined"
                    elif br.kind == "either":
                        opts = " | ".join(f"`config {v.section}` -> {v.bad}" for v in br.variants or [])
                        plan = f"break via first available of: {opts}"
                    else:
                        plan = f"break via `config {br.section}` -> {br.bad}"
                print(f"  {cid:12} [{c.scope:10}] {c.title}\n               {plan}")
        if man_ids:
            print("\nMANUAL (audit-only — command runs + parses + verdict):")
            for cid in man_ids:
                c = controls[cid]
                cmds = ", ".join(dict.fromkeys(r.cmd for r in c.rules))
                print(f"  {cid:12} [{c.scope:10}] {c.title}\n               reads: {cmds}")
        return 0

    devices = [(ip, "") for ip in args.devices] if args.devices else list(DEFAULT_DEVICES)

    if not os.environ.get("FG_PASS") and not any(
        os.environ.get(f"FG_PASS_{ip.rsplit('.', 1)[-1]}") for ip, _ in devices
    ):
        print("[abort] no password provided. Set FG_PASS (and optionally FG_PASS_<octet>).")
        return 2

    scratch = os.environ.get("CLAUDE_SCRATCH", "/tmp")
    os.makedirs(scratch, exist_ok=True)

    all_ids = man_ids + auto_ids
    print(f"Testing {len(auto_ids)} auto-fixable + {len(man_ids)} manual = {len(all_ids)} checks "
          f"on {len(devices)} device(s): {', '.join(ip for ip, _ in devices)}")

    def _err_dict(status_reason: str) -> Dict[str, Result]:
        out = {}
        for cid in all_ids:
            kind = "manual" if cid in man_ids else "auto"
            out[cid] = Result(cid, "AUDIT-ERROR" if kind == "manual" else "ERROR",
                              status_reason, kind=kind)
        return out

    per_device: Dict[str, Dict[str, Result]] = {}
    for host, label in devices:
        user, password = _creds_for(host, args)
        if not password:
            per_device[host] = _err_dict("no password")
            print(f"\n[{host}] SKIPPED: no password (set FG_PASS or FG_PASS_{host.rsplit('.', 1)[-1]})")
            continue
        try:
            per_device[host] = run_device(host, label, user, password, args.port,
                                          auto_ids, man_ids, controls, not args.no_backup, scratch)
        except Exception as e:  # noqa: BLE001 - one device must not abort the other
            print(f"\n[{host}] DEVICE-LEVEL ERROR: {type(e).__name__}: {e}")
            per_device[host] = _err_dict(str(e))

    print_summary(devices, per_device, auto_ids, man_ids)

    # Non-zero exit if any hardening FAIL or audit AUDIT-ERROR occurred
    # (SKIP does not gate CI-style use).
    bad = {"FAIL", "AUDIT-ERROR"}
    any_bad = any(r.status in bad for d in per_device.values() for r in d.values())
    return 1 if any_bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
