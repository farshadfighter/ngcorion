#!/usr/bin/env python3
"""
Standalone debugger for FG-NET-002 (Management services on a WAN interface).

Connects to a FortiGate, runs ``show system interface`` in the SAME scope the
audit uses (SCOPE_GLOBAL), and shows, step by step:

  1. the raw captured CLI output (length + whether it looks complete),
  2. whether the raw text even contains "role wan",
  3. how the parser splits it into interfaces (name / role / allowaccess),
  4. which interfaces are role=wan,
  5. which WAN interfaces expose a forbidden service, and the final verdict.

This isolates *collection* (does the WAN interface appear in the captured text
at all?) from *parsing* (did we split edit..next blocks and read role/allowaccess
correctly?) — the two things a "not detecting on the real device" report can mean.

Usage:
    python scripts/debug_fg_net_002.py <host> <user> [--port 22]

The password is read from the FG_PASS environment variable, or prompted for.
Example:
    FG_PASS=secret python scripts/debug_fg_net_002.py 172.16.200.20 admin
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient, SCOPE_GLOBAL  # noqa: E402
from app.modules.fortinet.audit.service import (  # noqa: E402
    _parse_interfaces, _wan_mgmt_violations, _looks_truncated,
)
from app.modules.fortinet.audit.rules import get_fortinet_controls  # noqa: E402

CMD = "show system interface"


def _forbidden_services():
    """The exact allowaccess services FG-NET-002 flags (read from the rule)."""
    for ctl in get_fortinet_controls():
        if ctl.id == "FG-NET-002":
            for rule in ctl.rules:
                if rule.type == "wan_mgmt_exposed":
                    return list(rule.expected or [])
    return ["http", "https", "ssh", "telnet"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Debug FG-NET-002 WAN mgmt-service detection.")
    ap.add_argument("host")
    ap.add_argument("user")
    ap.add_argument("--port", type=int, default=22)
    args = ap.parse_args()

    password = os.environ.get("FG_PASS") or getpass.getpass("FortiGate password: ")
    forbidden = _forbidden_services()

    with FortiGateSSHClient(args.host, args.user, password, port=args.port) as client:
        client.connect()
        vdom_enabled = client.is_vdom_enabled()
        # Exactly how the audit reads it: SCOPE_GLOBAL (enters `config global`
        # on VDOM devices, top-level on flat devices).
        output = client.collect([CMD], scope=SCOPE_GLOBAL)[CMD]

    sep = "=" * 72
    print(f"VDOM enabled: {vdom_enabled}")
    print(f"Forbidden services (FG-NET-002 flags any of these): {forbidden}")
    print(sep)
    print(f"RAW `{CMD}` OUTPUT ({len(output)} chars):")
    print(sep)
    print(output)
    print(sep)

    # --- Step 1: does the capture look complete? --------------------------
    truncated = _looks_truncated(output)
    complete = output.rstrip().endswith(("#", "$"))
    print(f"[1] Output prompt-terminated (looks complete): {complete}")
    if truncated:
        print("    !! Output looks TRUNCATED (does not end at a CLI prompt / 'end').")
        print("       A late WAN interface can be dropped from the read -> false PASS.")

    # --- Step 2: is 'role wan' even in the raw text? ----------------------
    role_wan_lines = [ln for ln in output.splitlines() if "role wan" in ln.lower()]
    print(f"\n[2] Lines containing 'role wan': "
          f"{role_wan_lines if role_wan_lines else 'NONE FOUND'}")
    if not role_wan_lines:
        print("    => The captured text has no `set role wan` at all. This is a")
        print("       COLLECTION/scope problem (or the interface's role is not")
        print("       actually 'wan' in the running config) — NOT a parser problem.")

    # --- Step 3: how does the parser see it? ------------------------------
    ifaces = _parse_interfaces(output)
    print(f"\n[3] Parser produced {len(ifaces)} interface(s):")
    for i in ifaces:
        print(f"      name={i['name']!r:16} role={i['role']!r:10} "
              f"allowaccess={i['allowaccess']}")

    # --- Step 4: which are WAN? -------------------------------------------
    wan = [i for i in ifaces if i["role"] == "wan"]
    print(f"\n[4] Interfaces parsed with role=wan: "
          f"{[i['name'] for i in wan] if wan else 'NONE'}")
    if role_wan_lines and not wan:
        print("    !! 'role wan' IS in the raw text but the parser did NOT tag any")
        print("       interface role=wan -> this WOULD be a parser bug. Capture the")
        print("       block above and report it.")

    # --- Step 5: violations + verdict -------------------------------------
    viols = _wan_mgmt_violations(output, forbidden)
    print(f"\n[5] WAN interfaces exposing a forbidden service: "
          f"{viols if viols else 'NONE'}")

    if viols:
        print("\nVERDICT: NON-COMPLIANT (correctly detected):")
        for v in viols:
            print(f"    - {v['name']} (role={v['role']}) exposes: {', '.join(v['exposed'])}")
    elif not ifaces:
        print("\nVERDICT: NON-COMPLIANT (fail-closed) — no interfaces parsed at all.")
        print("         => COLLECTION problem (empty/error/truncated read).")
    else:
        print("\nVERDICT: COMPLIANT — no WAN interface exposes a forbidden service.")
        if truncated or (role_wan_lines and not wan):
            print("         !! ...but the checks above are suspicious (see [1]/[2]/[4]).")
            print("            This COMPLIANT is likely a FALSE NEGATIVE.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
