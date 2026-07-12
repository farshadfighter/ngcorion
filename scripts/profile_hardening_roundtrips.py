#!/usr/bin/env python3
"""
Offline round-trip profiler for the FortiGate hardening SSH path.

Answers "where does the time go when hardening ONE check?" without a live
device: netmiko's connection object is replaced by a fake that returns canned
outputs instantly and RECORDS every send, tagged with the phase it happened in
and the read mode used:

  * "timing" — send_command_timing: returns only after CMD_LAST_READ (2.0s) of
    channel silence, so each send costs ~(device output time + 2.0s).
  * "prompt" — write_channel + read_until_pattern: returns as soon as the CLI
    prompt reappears, so each send costs ~1 network round-trip.

The wall-time estimate per phase is therefore:
    timing_sends * (CMD_LAST_READ + rtt) + prompt_sends * rtt
plus a fixed estimate for the TCP+KEX+auth+netmiko-session-prep connect (whose
internal commands are prompt-based and not simulated here).

Run BEFORE and AFTER a read-path change to see the exact round-trip census and
the modeled effect:

    .venv/bin/python scripts/profile_hardening_roundtrips.py [--rtt 0.15] [--connect 3.0]
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app.modules.fortinet.audit.ssh_client as ssh_client_mod
from app.modules.fortinet.audit.rules import get_fortinet_controls
from app.modules.fortinet.audit.ssh_client import SCOPE_GLOBAL, CMD_LAST_READ
from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor

HOST = "FGT-PROFILE"

STATUS_FLAT = (
    "Version: FortiGate-VM64 v7.4.3,build2573,240201 (GA.F)\n"
    "Serial-Number: FGVMPROFILE0000\n"
    "Hostname: FGT-PROFILE\n"
    "Virtual domain configuration: disable\n"
)
STATUS_VDOM = STATUS_FLAT.replace(
    "Virtual domain configuration: disable",
    "Virtual domain configuration: multiple",
)
SYSTEM_GLOBAL = (
    "admin-https-redirect : enable\n"
    "admintimeout        : 10\n"
    "strong-crypto       : enable\n"
)


class FakeFortiConnection:
    """Just enough of netmiko's surface for FortiGateSSHClient, with a context
    stack so prompts render realistically ("FGT #", "FGT (global) #", ...)."""

    def __init__(self, vdom_enabled: bool, recorder):
        self.vdom_enabled = vdom_enabled
        self.recorder = recorder
        self.base_prompt = HOST
        self._vdoms = vdom_enabled          # what netmiko's driver sets
        self._ctx = []                      # context stack for the prompt
        self._pending = None                # command awaiting a prompt read

    # ── prompt / context bookkeeping ────────────────────────────────
    def _prompt(self) -> str:
        return f"{HOST} ({self._ctx[-1]}) # " if self._ctx else f"{HOST} # "

    def _track_context(self, cmd: str) -> None:
        c = cmd.strip()
        if c == "config global":
            self._ctx.append("global")
        elif c == "config vdom":
            self._ctx.append("vdom")
        elif c.startswith("edit ") and self._ctx and self._ctx[-1] == "vdom":
            self._ctx[-1] = c.split(None, 1)[1]
        elif c.startswith("config "):
            self._ctx.append(c.split()[-1])
        elif c == "end" and self._ctx:
            self._ctx.pop()

    def _output_for(self, cmd: str) -> str:
        c = cmd.strip()
        if c.startswith("get system status"):
            body = STATUS_VDOM if self.vdom_enabled else STATUS_FLAT
        elif c.startswith("get system global"):
            body = SYSTEM_GLOBAL
        else:
            body = ""
        self._track_context(cmd)
        return f"{cmd}\n{body}{self._prompt()}"

    # ── netmiko surface ─────────────────────────────────────────────
    def send_command_timing(self, command_string, **kw):
        # Ignore the pager-continuation space sends (no --More-- in canned data).
        self.recorder.record(command_string, mode="timing")
        return self._output_for(command_string)

    def write_channel(self, data):
        self._pending = data.rstrip("\n")

    def read_until_pattern(self, pattern=None, read_timeout=None, **kw):
        cmd = self._pending or ""
        self._pending = None
        self.recorder.record(cmd, mode="prompt")
        return self._output_for(cmd)

    def read_channel_timing(self, **kw):
        return ""  # canned outputs are always prompt-terminated

    def find_prompt(self, **kw):
        return self._prompt().strip()

    def disconnect(self):
        pass


class Recorder:
    def __init__(self):
        self.phase = "connect+prime"
        self.events = []  # (phase, mode, command)

    def record(self, command, mode):
        self.events.append((self.phase, mode, command.strip()))


def profile(vdom_enabled: bool, rtt: float, connect_s: float):
    rec = Recorder()
    original = ssh_client_mod.ConnectHandler
    ssh_client_mod.ConnectHandler = lambda **kw: FakeFortiConnection(vdom_enabled, rec)
    try:
        control = next(c for c in get_fortinet_controls() if c.id == "FG-BL-004")
        with FortiGateHardeningExecutor(ip=HOST, username="x", password="x") as ex:
            rec.phase = "connectivity"
            ex.test_connectivity()
            rec.phase = "execute (3-line fix)"
            ex.execute_commands(
                ["config system global", "set admintimeout 10", "end"],
                scope=SCOPE_GLOBAL, vdom=None,
            )
            rec.phase = "verify"
            passed, _ = ex.verify_check(control)
            assert passed, "verify should PASS against the canned output"
            rec.phase = "disconnect"
    finally:
        ssh_client_mod.ConnectHandler = original

    # ── aggregate ───────────────────────────────────────────────────
    phases = ["connect+prime", "connectivity", "execute (3-line fix)", "verify"]
    counts = {p: defaultdict(int) for p in phases}
    cmds = defaultdict(list)
    for phase, mode, cmd in rec.events:
        if phase in counts:
            counts[phase][mode] += 1
            cmds[phase].append(f"{cmd} [{mode}]")

    def est(c):
        return c["timing"] * (CMD_LAST_READ + rtt) + c["prompt"] * rtt

    label = "VDOM-enabled" if vdom_enabled else "flat (no VDOMs)"
    print(f"\n=== Single-check execute (FG-BL-004), {label} device ===")
    print(f"{'phase':<24} {'timing':>7} {'prompt':>7} {'est time':>9}")
    print(f"{'ssh connect (netmiko)':<24} {'-':>7} {'-':>7} {connect_s:>8.1f}s")
    total = connect_s
    total_sends = 0
    for p in phases:
        c = counts[p]
        t = est(c)
        total += t
        total_sends += c["timing"] + c["prompt"]
        print(f"{p:<24} {c['timing']:>7} {c['prompt']:>7} {t:>8.1f}s")
    print(f"{'TOTAL':<24} {'':>7} {total_sends:>7} {total:>8.1f}s")
    for p in phases:
        print(f"  {p}: " + "; ".join(cmds[p]))
    return total


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rtt", type=float, default=0.15,
                    help="estimated network round-trip incl. device CLI latency (s)")
    ap.add_argument("--connect", type=float, default=3.0,
                    help="estimated TCP+KEX+auth+netmiko session-prep time (s)")
    args = ap.parse_args()

    print(f"CMD_LAST_READ (timing-read silence floor) = {CMD_LAST_READ}s; "
          f"assumed rtt = {args.rtt}s; assumed connect = {args.connect}s")
    print("NOTE: backup (show full-configuration) is skipped by default in the "
          "single-fix UI; when enabled it adds one long streaming read.")
    t_flat = profile(False, args.rtt, args.connect)
    t_vdom = profile(True, args.rtt, args.connect)
    print(f"\nModelled single-check totals: flat={t_flat:.1f}s vdom={t_vdom:.1f}s")


if __name__ == "__main__":
    main()
