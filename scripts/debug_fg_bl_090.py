#!/usr/bin/env python3
"""
Standalone debugger for FG-BL-090 (Global Strong Encryption / strong-crypto).

Connects to a FortiGate, runs `get system global` in the SAME scope the audit
uses, and shows:
  1. the raw captured CLI output (and its length / whether it looks complete),
  2. every line containing "strong-crypto",
  3. the value the audit parser extracts and the resulting verdict.

This isolates *parsing* (proven correct in tests) from *collection* (does the
field actually appear in the captured text?).

Usage:
    python scripts/debug_fg_bl_090.py <host> <user> [--port 22]

The password is read from the FG_PASS environment variable, or prompted for.
Example:
    FG_PASS=secret python scripts/debug_fg_bl_090.py 192.0.2.1 admin
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.fortinet.audit.ssh_client import FortiGateSSHClient, SCOPE_GLOBAL  # noqa: E402
from app.modules.fortinet.audit.service import _get_field_value, _norm_field        # noqa: E402

KEY = "strong-crypto"
CMD = "get system global"


def main() -> int:
    ap = argparse.ArgumentParser(description="Debug FG-BL-090 strong-crypto detection.")
    ap.add_argument("host")
    ap.add_argument("user")
    ap.add_argument("--port", type=int, default=22)
    args = ap.parse_args()

    password = os.environ.get("FG_PASS") or getpass.getpass("FortiGate password: ")

    with FortiGateSSHClient(args.host, args.user, password, port=args.port) as client:
        client.connect()
        vdom_enabled = client.is_vdom_enabled()
        # Exactly how the audit reads it: SCOPE_GLOBAL (enters `config global`
        # on VDOM devices, top-level on flat devices).
        output = client.collect([CMD], scope=SCOPE_GLOBAL)[CMD]

    sep = "=" * 72
    print(f"VDOM enabled: {vdom_enabled}")
    print(sep)
    print(f"RAW `{CMD}` OUTPUT ({len(output)} chars):")
    print(sep)
    print(output)
    print(sep)

    complete = output.rstrip().endswith(("#", "$"))
    print(f"Output prompt-terminated (looks complete): {complete}")
    if not complete:
        print("  !! Output does NOT end at a CLI prompt — it is likely TRUNCATED,")
        print("     which is the classic cause of trailing fields going missing.")

    hits = [ln for ln in output.splitlines() if KEY in ln.lower()]
    print(f"\nLines containing '{KEY}': {hits if hits else 'NONE FOUND'}")

    value = _get_field_value(output, KEY)
    print(f"Parser extracted value: {value!r}")

    if value is None:
        print(f"\nVERDICT: NON-COMPLIANT — but '{KEY}' is NOT in the captured text.")
        print("         => This is a COLLECTION problem (truncated/incomplete read),")
        print("            NOT a parsing problem. The verdict is a false negative.")
    else:
        ok = _norm_field(value) == _norm_field("enable")
        print(f"\nVERDICT: {'COMPLIANT' if ok else 'NON-COMPLIANT'} ({KEY} = {value})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
