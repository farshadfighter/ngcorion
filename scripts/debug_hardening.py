#!/usr/bin/env python3
"""
Standalone debugger for the FortiGate HARDENING flow (the "broken from the first
command" report).

It connects over SSH using the SAME client the audit uses
(``FortiGateSSHClient``), then reproduces — step by step — exactly what the
hardening executor does *up to and including the very first command it sends to
the device*, printing the raw FortiOS response at each step so the failing
command and the device's own error text are captured verbatim.

What it shows, in order (this mirrors ``FortiGateHardeningExecutor`` /
``FortiGateSSHClient.run_config``):

  1. connect()                 -> login + pager priming (``config system console``)
  2. get system status         -> FortiOS version + whether VDOM mode is ON
  3. scope entry               -> ``config global`` (or ``config vdom`` /
                                  ``edit <vdom>``) — the wrapper hardening adds
                                  automatically before your remediation block
  4. FIRST remediation command -> block[0] of the template (e.g.
                                  ``config system global``)

For each command it prints: the exact command string, the raw output (repr +
pretty), whether the output is prompt-terminated (a truncated read is a common
false-failure cause), and whether FortiOS rejected it (``command parse error``,
``Command fail``, ``unknown command`` ...).

By default it is NON-DESTRUCTIVE: it stops after the first *navigation* command
and never sends a ``set`` line, then cleanly unwinds the config context. Pass
``--apply`` to run the entire remediation block via the real production code
path (``run_config``) if you want to reproduce a mutation failure.

Usage:
    FG_PASS=xxx python3 scripts/debug_hardening.py <host> <user> [check_id]
    FG_PASS=xxx python3 scripts/debug_hardening.py 172.16.200.20 admin
    FG_PASS=xxx python3 scripts/debug_hardening.py 172.16.200.20 admin FG-BL-090 --apply

The password is read from FG_PASS (or prompted). ``check_id`` defaults to
FG-BL-090 (strong-crypto: global scope, no parameters — the simplest first fix).
"""
import argparse
import getpass
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.fortinet.audit.ssh_client import (  # noqa: E402
    FortiGateSSHClient,
    _ends_with_prompt,
    SCOPE_GLOBAL,
    SCOPE_VDOM,
    SCOPE_VDOM_ROOT,
    ROOT_VDOM,
)
from app.modules.fortinet.audit.rules import get_fortinet_controls  # noqa: E402
from app.modules.fortinet.hardening.command_parser import (  # noqa: E402
    FortiGateRemediationParser,
    apply_fortigate_defaults,
)
from app.modules.fortinet.hardening.command_templates import (  # noqa: E402
    has_fortigate_template,
    get_all_fortigate_templated_checks,
)

SEP = "=" * 72
DEFAULT_CHECK = "FG-BL-090"  # strong-crypto: global scope, no required params


def _control_by_id(check_id):
    for ctl in get_fortinet_controls():
        if ctl.id == check_id:
            return ctl
    return None


def _probe(client, command, step):
    """Send one command at the top-level via _raw_send and report the raw result."""
    print(f"\n{SEP}\n[{step}] SEND: {command!r}\n{SEP}")
    try:
        out = client._raw_send(command)
    except Exception as e:  # noqa: BLE001 - this is the diagnostic we want to see
        print(f"!! EXCEPTION while sending {command!r}: {type(e).__name__}: {e}")
        logging.getLogger("debug_hardening").error(
            "raw send failed for %r", command, exc_info=True
        )
        raise

    terminated = _ends_with_prompt(out)
    ok = FortiGateSSHClient._is_command_ok(out)
    print(f"raw output ({len(out)} chars):")
    print(out if out else "    <empty>")
    print(f"\n  prompt-terminated (looks complete): {terminated}")
    print(f"  accepted by FortiOS (no error tokens): {ok}")
    if not ok:
        print("  !! FortiOS REJECTED this command — see the error line(s) above.")
    if out and not terminated:
        print("  !! Output is NOT prompt-terminated — the read may be truncated,")
        print("     or the device is still streaming (timing/pager problem).")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Debug the FortiGate hardening flow's first command."
    )
    ap.add_argument("host")
    ap.add_argument("user")
    ap.add_argument("check_id", nargs="?", default=DEFAULT_CHECK,
                    help=f"CIS check to reproduce (default: {DEFAULT_CHECK})")
    ap.add_argument("--vdom", default=ROOT_VDOM,
                    help="Target VDOM for vdom-scoped checks (default: root)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("FG_PORT", "22")))
    ap.add_argument("--apply", action="store_true",
                    help="Actually run the FULL remediation block via run_config "
                         "(sends 'set' lines — MUTATES the device). Default: off.")
    args = ap.parse_args()

    # Surface the new exc_info logging from the SSH client / executor on stdout.
    logging.basicConfig(
        level=logging.DEBUG, stream=sys.stdout,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    check_id = args.check_id
    if not has_fortigate_template(check_id):
        print(f"'{check_id}' has no auto-remediation template. Templated checks:")
        print("  " + ", ".join(sorted(get_all_fortigate_templated_checks())))
        return 2

    control = _control_by_id(check_id)
    if control is None:
        print(f"No FortiGate control found for id '{check_id}'.")
        return 2

    # Build the remediation block EXACTLY like execute_hardening does.
    parsed = FortiGateRemediationParser.parse_remediation(remediation="", check_id=check_id)
    try:
        block = FortiGateRemediationParser.substitute_parameters(
            parsed.commands, apply_fortigate_defaults({}, parsed.defaults)
        )
    except ValueError as e:
        print(f"'{check_id}' needs parameters this debug tool doesn't supply: {e}")
        print("Pick a no-param check (e.g. FG-BL-090) or extend this script.")
        return 2

    scope = control.scope
    eff_vdom = FortiGateSSHClient.effective_vdom(scope, args.vdom)

    print(SEP)
    print(f"Target : {args.host}:{args.port} as {args.user}")
    print(f"Check  : {check_id} — {control.title}")
    print(f"Scope  : {scope}  (effective VDOM: {eff_vdom})")
    print(f"Block  : {block}")
    print(f"Mode   : {'APPLY (mutating, full block via run_config)' if args.apply else 'DRY (navigation only, non-destructive)'}")
    print(SEP)

    password = os.environ.get("FG_PASS") or getpass.getpass("FortiGate password: ")
    client = FortiGateSSHClient(args.host, args.user, password, port=args.port)

    # --- Step 1: connect (login + pager priming) -------------------------
    print(f"\n{SEP}\n[1] connect()  (login + '_prime_session' pager priming)\n{SEP}")
    try:
        client.connect()
    except Exception as e:  # noqa: BLE001
        print(f"!! CONNECT FAILED: {type(e).__name__}: {e}")
        logging.getLogger("debug_hardening").error("connect failed", exc_info=True)
        return 1
    print("connected OK")

    try:
        # --- Step 2: get system status / VDOM detection ------------------
        print(f"\n{SEP}\n[2] get system status  (version + VDOM mode)\n{SEP}")
        status = client.get_system_status()
        vdom_enabled = bool(status.get("vdom_enabled"))
        print(f"fortios_version : {status.get('fortios_version')}")
        print(f"version_line    : {status.get('version_line')}")
        print(f"vdom_enabled    : {vdom_enabled}")

        # Show precisely what production would send, in order, before your block.
        if vdom_enabled and scope == SCOPE_GLOBAL:
            entry = ["config global"]
        elif vdom_enabled:  # vdom / vdom_root
            entry = ["config vdom", f"edit {eff_vdom or ROOT_VDOM}"]
        else:
            entry = []  # flat device: single top-level context, no wrapper
        first_hardening_cmd = (entry + block)[0]
        print(f"\nScope-entry commands hardening will send first: {entry or '(none — flat device)'}")
        print(f">>> THE VERY FIRST HARDENING COMMAND SENT WILL BE: {first_hardening_cmd!r}")

        if args.apply:
            # --- Full production path: run the entire block via run_config ---
            print(f"\n{SEP}\n[3] run_config(...)  — FULL BLOCK via production code path\n{SEP}")
            result = client.run_config(block, scope=scope, vdom=args.vdom)
            print(f"success : {result['success']}")
            print(f"errors  : {result['errors']}")
            print(f"\noutput:\n{result['output']}")
            return 0 if result["success"] else 1

        # --- DRY path: navigate only, never send a 'set' -----------------
        step = 3
        for cmd in entry:
            out = _probe(client, cmd, step)
            step += 1
            if not FortiGateSSHClient._is_command_ok(out):
                print("\n>>> STOP: scope entry was rejected. This is where hardening "
                      "breaks on the first command. Capture the block above.")
                return 1

        # The first command of the remediation block is always a `config <section>`
        # navigator (not a mutation), so sending just this one is safe.
        nav = block[0]
        _probe(client, nav, step)
        print(f"\n{SEP}")
        print("DRY run stopped before any 'set' line (device NOT modified).")
        print("Re-run with --apply to execute the full block via run_config.")
        print(SEP)
        return 0

    finally:
        # Best-effort unwind of any config context we entered, then disconnect.
        try:
            for _ in range(3):
                client._raw_send("end")
        except Exception:  # noqa: BLE001
            pass
        client.disconnect()


if __name__ == "__main__":
    raise SystemExit(main())
