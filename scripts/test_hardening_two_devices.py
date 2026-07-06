#!/usr/bin/env python3
"""
Full FortiGate hardening flow test against TWO real devices — SSH only, no DB.

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
    _entry_field_value,
    _get_field_value,
    _parse_table_entries,
)
from app.modules.fortinet.hardening.command_parser import (  # noqa: E402
    FortiGateRemediationParser,
    apply_fortigate_defaults,
)
from app.modules.fortinet.hardening.command_templates import has_fortigate_template  # noqa: E402
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
    """
    section: str                       # inner config section, e.g. "system global"
    bad: Dict[str, str]                # field -> value that makes the control FAIL
    kind: str = "field"
    profile: Optional[str] = None      # entry name for kind == "profile"

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
    "FG-PW-001":  Breaker("system global", {"admin-lockout-threshold": "0"}),
    # ---- 2.4 Administrators (global) ----
    "FG-BL-004":  Breaker("system global", {"admintimeout": "480"}),  # > 10 -> non-compliant
    # ---- 4.2 Antivirus ----
    "FG-AV-001":  Breaker("system autoupdate push-update", {"status": "disable"}, kind="show_set"),
    "FG-AV-003":  Breaker("antivirus settings", {"machine-learning-detection": "disable"}),
    "FG-AV-004":  Breaker("antivirus settings", {"grayware": "disable"}),
    # ---- 4.3 / 4.4 profile tables (per-VDOM) ----
    "FG-DNS-001": Breaker("dnsfilter profile", {"block-botnet": "disable"},
                          kind="profile", profile="default"),
    "FG-APP-002": Breaker("application list", {"enforce-default-app-port": "disable"},
                          kind="profile", profile="default"),
    # ---- 7 Users / 8 Logs (per-VDOM + global) ----
    "FG-USER-001": Breaker("user setting", {"auth-lockout-threshold": "0"}),
    "FG-LOG-001":  Breaker("log eventfilter", {"event": "disable"}),
    "FG-LOG-002":  Breaker("log fortianalyzer setting", {"enc-algorithm": "disable"}),
}

# Auto-fixable controls we deliberately DO NOT mutate. They are read + reported
# for context, but their result is SKIP with the reason below.
UNTESTABLE: Dict[str, str] = {
    "FG-BL-002": ("template sets GLOBAL admin-telnet/admin-http, but the audit measures "
                  "per-interface allowaccess — forcing/fixing would change global admin "
                  "access (lockout risk) and still can't satisfy this control"),
    "FG-BL-040": ("verification (ntp_status_ok) depends on live NTP synchronisation with a "
                  "custom server, which `set ntpsync enable` can't achieve synchronously — "
                  "not exercised to avoid desyncing the device"),
}


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------
@dataclass
class Result:
    check_id: str
    status: str            # PASS | FAIL | SKIP | ERROR
    reason: str = ""
    initial: str = ""      # COMPLIANT / NON-COMPLIANT at start (for context)


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


def snapshot_original(client, control: FortiGateControl, br: Breaker,
                      vdom: Optional[str]) -> Dict[str, Optional[str]]:
    """Read each field's ORIGINAL value so it can be restored exactly.

    Raises RuntimeError when the state needed to break/restore isn't present
    (e.g. the profile entry doesn't exist) so the caller can SKIP cleanly.
    """
    read_cmd = control.rules[0].cmd
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

    br = BREAKERS.get(cid)
    if br is None:
        return Result(cid, "SKIP", "no breaker defined for this auto-fixable check", "")

    # 1. initial state via the production verify path
    try:
        compliant0, _ = executor.verify_check(control, vdom=vdom)
    except Exception as e:  # noqa: BLE001
        return Result(cid, "ERROR", f"initial read failed: {type(e).__name__}: {e}", "")
    initial = "COMPLIANT" if compliant0 else "NON-COMPLIANT"

    # 2. snapshot ORIGINAL + register restore BEFORE any mutation
    try:
        snap = snapshot_original(client, control, br, vdom)
    except RuntimeError as e:
        return Result(cid, "SKIP", str(e), initial)
    except Exception as e:  # noqa: BLE001
        return Result(cid, "ERROR", f"snapshot failed: {type(e).__name__}: {e}", initial)
    restores.append(Restore(cid, control, restore_commands(br, snap), vdom))

    # 3. force NON-COMPLIANT if needed (always exercise the real fix path)
    if compliant0:
        res = client.run_config(break_commands(br), scope=control.scope, vdom=vdom)
        if not res["success"]:
            return Result(cid, "SKIP", f"could not force non-compliant: {'; '.join(res['errors'])[:120]}", initial)
        broke, _ = executor.verify_check(control, vdom=vdom)
        if broke:  # still compliant -> break didn't take (e.g. another profile matches)
            return Result(cid, "SKIP", "break did not flip the control to NON-COMPLIANT", initial)

    # 4. harden through the production path (execute_commands + verify_check)
    try:
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
# Per-device driver
# ---------------------------------------------------------------------------
def run_device(host: str, label: str, user: str, password: str, port: int,
               check_ids: List[str], controls: Dict[str, FortiGateControl],
               do_backup: bool, scratch: str) -> Dict[str, Result]:
    tag = host
    results: Dict[str, Result] = {}
    restores: List[Restore] = []

    print(f"\n{SEP}\nDEVICE {host}  ({label})\n{SEP}")

    executor = FortiGateHardeningExecutor(ip=host, username=user, password=password, port=port)
    try:
        executor.__enter__()
    except Exception as e:  # noqa: BLE001
        print(f"[{tag}] CONNECT FAILED: {type(e).__name__}: {e}")
        for cid in check_ids:
            results[cid] = Result(cid, "ERROR", f"connect failed: {type(e).__name__}", "")
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

        for cid in check_ids:
            control = controls[cid]
            res = run_check(tag, executor, control, restores)
            results[cid] = res
            line = f"[{tag}] {cid:12} -> {res.status}"
            if res.reason:
                line += f"  ({res.reason})"
            elif res.initial:
                line += f"  (was {res.initial})"
            print(line)

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
def _totals(results: Dict[str, Result]) -> str:
    p = sum(1 for r in results.values() if r.status == "PASS")
    f = sum(1 for r in results.values() if r.status == "FAIL")
    s = sum(1 for r in results.values() if r.status in ("SKIP", "ERROR"))
    return f"{p}/{p + f} PASS  ({s} skipped/error)"


def print_summary(devices: List, per_device: Dict[str, Dict[str, Result]], check_ids: List[str]) -> None:
    hosts = [d[0] for d in devices]
    print(f"\n{SEP}\nSUMMARY (side by side)\n{SEP}")
    header = f"{'CHECK':<12} " + " ".join(f"{h:>17}" for h in hosts)
    print(header)
    print("-" * len(header))
    icons = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "skip", "ERROR": "ERR "}
    for cid in check_ids:
        cells = []
        for h in hosts:
            r = per_device.get(h, {}).get(cid)
            cells.append(f"{(icons.get(r.status, '-') if r else '-'):>17}")
        print(f"{cid:<12} " + " ".join(cells))
    print("-" * len(header))
    for h in hosts:
        print(f"[{h}] DEVICE TOTAL: {_totals(per_device.get(h, {}))}")


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
                    help="restrict to specific check IDs (e.g. FG-BL-090 FG-AV-004)")
    ap.add_argument("--no-backup", action="store_true", help="skip the per-device full-config backup")
    ap.add_argument("--list", action="store_true",
                    help="print the auto-fixable checks + their plan and exit (no device access)")
    args = ap.parse_args()

    controls = _control_map()
    check_ids = auto_fixable_ids(controls)
    if args.only:
        wanted = {c.upper() for c in args.only}
        unknown = wanted - set(check_ids)
        if unknown:
            print(f"[warn] not auto-fixable / unknown, ignoring: {', '.join(sorted(unknown))}")
        check_ids = [c for c in check_ids if c in wanted]
        if not check_ids:
            print("[abort] no valid auto-fixable checks selected")
            return 2

    if args.list:
        print(f"{len(check_ids)} auto-fixable checks:\n")
        for cid in check_ids:
            c = controls[cid]
            if cid in UNTESTABLE:
                plan = f"SKIP — {UNTESTABLE[cid]}"
            else:
                br = BREAKERS.get(cid)
                plan = (f"break via `config {br.section}` -> {br.bad}" if br
                        else "no breaker defined")
            print(f"  {cid:12} [{c.scope:10}] {c.title}\n               {plan}")
        return 0

    devices = [(ip, "") for ip in args.devices] if args.devices else list(DEFAULT_DEVICES)

    if not os.environ.get("FG_PASS") and not any(
        os.environ.get(f"FG_PASS_{ip.rsplit('.', 1)[-1]}") for ip, _ in devices
    ):
        print("[abort] no password provided. Set FG_PASS (and optionally FG_PASS_<octet>).")
        return 2

    scratch = os.environ.get("CLAUDE_SCRATCH", "/tmp")
    os.makedirs(scratch, exist_ok=True)

    print(f"Testing {len(check_ids)} auto-fixable checks on {len(devices)} device(s): "
          f"{', '.join(ip for ip, _ in devices)}")

    per_device: Dict[str, Dict[str, Result]] = {}
    for host, label in devices:
        user, password = _creds_for(host, args)
        if not password:
            per_device[host] = {cid: Result(cid, "ERROR", "no password", "") for cid in check_ids}
            print(f"\n[{host}] SKIPPED: no password (set FG_PASS or FG_PASS_{host.rsplit('.', 1)[-1]})")
            continue
        try:
            per_device[host] = run_device(host, label, user, password, args.port,
                                          check_ids, controls, not args.no_backup, scratch)
        except Exception as e:  # noqa: BLE001 - one device must not abort the other
            print(f"\n[{host}] DEVICE-LEVEL ERROR: {type(e).__name__}: {e}")
            per_device[host] = {cid: Result(cid, "ERROR", str(e), "") for cid in check_ids}

    print_summary(devices, per_device, check_ids)

    # Non-zero exit if any real FAIL occurred (SKIP/ERROR do not gate CI-style use).
    any_fail = any(r.status == "FAIL" for d in per_device.values() for r in d.values())
    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
