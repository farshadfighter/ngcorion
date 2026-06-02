"""
Static validator for the Cisco CIS -> command-template mapping.

For every entry in CIS_SECTION_TO_IOS, synthesize a best-effort post-fix running
config from the mapped template's commands (defaults applied, required params filled
with dummy values), then run the corresponding CIS rule's check() against it.

A check that returns False means the mapped template's commands cannot satisfy that
check's verify function -> the fix would "execute successfully" yet always verify FAIL
(the Cause 2 mismatch, e.g. CIS-1.1.6 mapped to a 'transport input ssh' template while
its check requires 'login authentication').

This is a triage tool: a flagged check is *likely* a mapping/template bug, but the
synthesis is approximate, so each hit should be eyeballed. Run:

    .venv/bin/python -m scripts.validate_cisco_mappings
"""
import re

from app.modules.cisco.hardening.command_templates import CIS_SECTION_TO_IOS, get_template
from app.modules.cisco.hardening.command_parser import RemediationParser, apply_defaults
from app.modules.cisco.hardening.service import HardeningService

META = {"configure terminal", "config t", "conf t", "end", "exit",
        "write memory", "write mem", "wr", "copy running-config startup-config"}

# Dummy values for required (no-default) placeholders, chosen to satisfy the
# common regex/numeric expectations so we only flag genuine mapping mismatches.
DUMMY = {
    "MODULUS": "2048", "TIMEOUT_SEC": "60", "TIMEOUT_MIN": "5", "SIZE": "16384",
    "RETRIES": "3", "KEY_ID": "1", "AS_NUMBER": "65000", "OSPF_PROCESS": "1",
    "AREA": "0",
}


# Checks whose verify reads data that only appears in non-running-config show
# output (e.g. RSA key size from 'show crypto key mypubkey rsa', config register
# from 'show version'). Their templates are correct; they simply can't be validated
# from a synthesized running-config. verify_check now collects this via collect_turbo().
NEEDS_LIVE_SHOW_OUTPUT = {
    "CIS-2.1.1.1.3",  # _extract_ssh_key_bits -> 'show crypto key mypubkey rsa'
}


def _dummy_for(name: str) -> str:
    if name in DUMMY:
        return DUMMY[name]
    if any(tok in name for tok in ("TIMEOUT", "SIZE", "RETRIES", "MODULUS", "NUMBER",
                                   "PROCESS", "AREA", "KEY_ID", "BITS")):
        return "10"
    if "IP" in name or "SERVER" in name or "HOST" in name or "NET" in name:
        return "192.0.2.10"
    return "TESTVAL"


def synthesize_config(check_number: str) -> str:
    """Build approximate running-config text from a check's mapped template."""
    rule = HardeningService._get_rule_by_check_number(check_number)
    parsed = RemediationParser.parse_remediation(rule.remediation, check_number)
    params = apply_defaults({}, dict(parsed.defaults))
    for cmd in parsed.commands:
        for name in RemediationParser.extract_parameters(cmd):
            params.setdefault(name, _dummy_for(name))
    commands = RemediationParser.substitute_parameters(parsed.commands, params)
    lines = [c for c in commands if c.strip().lower() not in META]
    return "\n".join(lines) + "\n"


def main() -> int:
    mismatches = []
    needs_live = []
    errors = []
    for cis_id in sorted(CIS_SECTION_TO_IOS):
        try:
            rule = HardeningService._get_rule_by_check_number(cis_id)
        except ValueError:
            errors.append((cis_id, "no audit rule found"))
            continue
        try:
            config = synthesize_config(cis_id)
            ok = bool(rule.check(config))
        except Exception as e:  # noqa: BLE001 - triage tool
            errors.append((cis_id, f"{type(e).__name__}: {e}"))
            continue
        if not ok:
            if cis_id in NEEDS_LIVE_SHOW_OUTPUT:
                needs_live.append((cis_id, CIS_SECTION_TO_IOS[cis_id], rule.title))
            else:
                mismatches.append((cis_id, CIS_SECTION_TO_IOS[cis_id], rule.title))

    print(f"Checked {len(CIS_SECTION_TO_IOS)} CIS->template mappings\n")
    if mismatches:
        print(f"POTENTIAL MISMATCHES ({len(mismatches)}): template cannot satisfy check")
        for cis_id, ios_id, title in mismatches:
            print(f"  {cis_id:16} -> {ios_id:14}  {title}")
    else:
        print("No mapping mismatches detected.")
    if needs_live:
        print(f"\nNOT STATICALLY VERIFIABLE ({len(needs_live)}): check reads non-running-config "
              f"show output; template is correct, verify uses collect_turbo() live")
        for cis_id, ios_id, title in needs_live:
            print(f"  {cis_id:16} -> {ios_id:14}  {title}")
    if errors:
        print(f"\nUNVALIDATED ({len(errors)}): could not synthesize/evaluate")
        for cis_id, why in errors:
            print(f"  {cis_id:16}  {why}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
