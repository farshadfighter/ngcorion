"""
FortiGate Audit Service (VDOM-aware).

Orchestrates the audit:
1. Fetch asset, create session.
2. Connect over SSH (configurable port).
3. Detect VDOM mode; enumerate VDOMs when enabled.
4. Read every control in its correct scope:
     - global / vdom_root controls once,
     - per-VDOM controls once per target VDOM.
5. Evaluate, score (Manual excluded), and persist results tagged with their VDOM.
"""

import json
import logging
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import Asset, AuditResult, AuditSession
from app.models.audit import CheckStatus, DeviceType

from .rules import FortiGateControl, FortiGateRule, get_fortinet_controls
from .ssh_client import (
    SCOPE_GLOBAL,
    SCOPE_VDOM,
    SCOPE_VDOM_ROOT,
    FortiGateContextError,
    FortiGateSSHClient,
)

logger = logging.getLogger(__name__)


class FortinetAuditError(Exception):
    """Base exception for FortiGate audit errors."""


class FortinetEvaluationError(FortinetAuditError):
    """Raised when there are no controls to evaluate."""


# Label stored in AuditResult.vdom for the two non-per-VDOM scopes on VDOM devices.
_GLOBAL_LABEL = "global"
_ROOT_LABEL = "root"

# Management services that must not be reachable on a WAN-role interface
# (CIS 1.3 / FG-NET-002). Used by the "wan_mgmt_exposed" rule type. ping, snmp
# and radius-acct are intentionally excluded (only cleartext/interactive mgmt).
_WAN_FORBIDDEN_SERVICES = ("http", "https", "ssh", "telnet")

# Rule types whose evidence is a detailed, possibly multi-line per-entry report
# (one interface / Policy ID per line) that handles empty/error output itself —
# so its evidence is newline-joined and exempt from the short-snippet truncation.
_DETAILED_RULE_TYPES = frozenset({
    "wan_mgmt_exposed", "iface_allowaccess_excludes",
    "policy_field_eq", "policy_field_present", "policy_field_forbidden_token",
    "policy_unused", "isdb_deny_present",
})


def _parse_interfaces(output: str) -> List[Dict[str, Any]]:
    """
    Parse ``show system interface`` into a list of top-level interfaces:
    ``[{"name", "role", "allowaccess": [...], "ip"}]`` (``ip`` is the address
    without the netmask, '' when unset/DHCP).

    Handles both the wrapped form (``config system interface`` / ``edit`` / ``next``
    / ``end``) and a bare sequence of ``edit ... next`` blocks. Nested blocks
    (e.g. ``config secondaryip`` / ``config ipv6``) are ignored so their ``edit``
    entries and ``set`` lines are never mistaken for an interface.
    """
    interfaces: List[Dict[str, Any]] = []
    stack: List[str] = []          # open scopes: "config" or "edit"
    current: Optional[Dict[str, Any]] = None
    iface_level: Optional[int] = None  # stack depth of the interface's own edit

    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("config "):
            stack.append("config")
            continue

        m_edit = re.match(r'edit\s+"?([^"]*?)"?\s*$', line)
        if m_edit:
            is_interface = "edit" not in stack  # first-level edit == an interface
            stack.append("edit")
            if is_interface:
                current = {"name": m_edit.group(1), "role": "", "allowaccess": [], "ip": ""}
                iface_level = len(stack)
            continue

        if line == "end":
            if stack and stack[-1] == "config":
                stack.pop()
            continue

        if line == "next":
            if stack and stack[-1] == "edit":
                stack.pop()
            if current is not None and (iface_level is None or len(stack) < iface_level):
                interfaces.append(current)
                current = None
                iface_level = None
            continue

        # Settings are captured only at the interface's own level (not nested blocks).
        if current is not None and len(stack) == iface_level:
            m_role = re.match(r"set\s+role\s+(\S+)", line)
            if m_role:
                current["role"] = m_role.group(1).strip().strip('"').lower()
                continue
            m_aa = re.match(r"set\s+allowaccess\s+(.+?)\s*$", line)
            if m_aa:
                current["allowaccess"] = [s for s in m_aa.group(1).split() if s]
                continue
            m_ip = re.match(r"set\s+ip\s+(\S+)", line)
            if m_ip:
                current["ip"] = m_ip.group(1)

    if current is not None:  # output truncated before a closing 'next'
        interfaces.append(current)
    return interfaces


# Forbidden NTP server domain for CIS 2.1.4 / FG-BL-040 (default FortiGuard pool
# must be replaced by a custom server).
_NTP_FORBIDDEN_DOMAIN = "fortiguard.com"


def _parse_ntp_status(output: str) -> Dict[str, Any]:
    """
    Parse ``diagnose sys ntp status`` into
    ``{"synchronized", "ntpsync", "server_mode", "servers": [...]}``.

    The header line looks like::

        synchronized: yes, ntpsync: enabled, server-mode: enabled

    and each NTP server appears as ``ipv4 server(<host-or-ip>) <ip> -- ...``.
    Missing fields are ``None``; values are lowercased.
    """
    out = output or ""

    def field(name: str) -> Optional[str]:
        m = re.search(rf"{re.escape(name)}\s*:\s*(\w+)", out, re.IGNORECASE)
        return m.group(1).lower() if m else None

    servers = re.findall(r"server\(([^)]+)\)", out, re.IGNORECASE)
    return {
        "synchronized": field("synchronized"),
        "ntpsync": field("ntpsync"),
        "server_mode": field("server-mode"),
        "servers": [s.strip() for s in servers],
    }


def _ntp_status_failures(status: Dict[str, Any]) -> List[str]:
    """Return the list of failed NTP conditions (empty == compliant)."""
    failures: List[str] = []
    if status["synchronized"] != "yes":
        failures.append(f"synchronized={status['synchronized'] or 'unknown'} (expected yes)")
    if status["ntpsync"] != "enabled":
        failures.append(f"ntpsync={status['ntpsync'] or 'unknown'} (expected enabled)")
    if status["server_mode"] != "enabled":
        failures.append(f"server-mode={status['server_mode'] or 'unknown'} (expected enabled/custom)")
    fg = [s for s in status["servers"] if _NTP_FORBIDDEN_DOMAIN in s.lower()]
    if fg:
        failures.append(f"FortiGuard NTP server(s): {', '.join(fg)}")
    return failures


def _parse_snmp_users(output: str) -> List[str]:
    """
    Extract SNMPv3 user names from ``get system snmp user`` output.
    Entries appear as ``== [ <name> ]`` headers; falls back to ``edit "<name>"``
    or ``name: <name>`` lines for other output styles. Empty when no users.
    """
    out = output or ""
    names = re.findall(r"==\s*\[\s*([^\]]+?)\s*\]", out)
    if not names:
        names = re.findall(r'^\s*edit\s+"?([^"\n]+?)"?\s*$', out, re.MULTILINE)
    if not names:
        names = re.findall(r"^\s*name\s*:\s*(\S+)", out, re.MULTILINE | re.IGNORECASE)
    return [n.strip() for n in names if n.strip()]


# Interactive SNMPv3 remediation guide (shown in the FG-BL-050 report only when
# NON-COMPLIANT). Placeholders are <username> <ip> <password>; choose ONE option.
_SNMPV3_REMEDIATION_GUIDE = """
--- Remediation: configure an SNMPv3 user (choose ONE security level) ---
Placeholders: <username> = SNMP user name, <ip> = trap/notify host, <password> = a strong secret.

OPTION 1 - no-auth-no-priv (least secure):
  config system snmp user
    edit <username>
      set notify-hosts <ip>
      set security-level no-auth-no-priv
    next
  end

OPTION 2 - auth-no-priv:
  config system snmp user
    edit <username>
      set notify-hosts <ip>
      set security-level auth-no-priv
      set auth-proto <md5|sha>
      set auth-pwd <password>
    next
  end

OPTION 3 - auth-priv (MOST SECURE, RECOMMENDED; best practice: sha512 + aes256):
  config system snmp user
    edit <username>
      set notify-hosts <ip>
      set security-level auth-priv
      set auth-proto <md5|sha|sha224|sha256|sha384|sha512>
      set auth-pwd <password>
      set priv-proto <aes|des|aes256|aes256cisco>
      set priv-pwd <password>
    next
  end

Note: the correct keyword is "security-level" (FortiOS docs sometimes mis-spell it "secuity-level").
""".strip()


def _snmp_evidence(control, outputs: Dict[str, str]) -> str:
    """
    Combined two-step SNMPv3 report (FG-BL-050): SNMP master status, the SNMPv3
    users found, which step failed, and the overall verdict. When NON-COMPLIANT
    the interactive 3-option remediation guide is appended to the report.
    """
    sysinfo = users_out = ""
    for r in control.rules:
        if r.type == "snmp_status_enabled":
            sysinfo = outputs.get(r.cmd, "")
        elif r.type == "snmp_user_exists":
            users_out = outputs.get(r.cmd, "")

    status = (_get_field_value(sysinfo, "status") or "unknown").lower()
    parts = [f"SNMP status={status}"]
    non_compliant = True

    if status != "enable":
        parts.append("FAILED step 1: SNMP status is disabled (SNMP not configured)")
    else:
        users = _parse_snmp_users(users_out)
        parts.append(f"SNMPv3 users=[{', '.join(users) if users else 'none'}]")
        if users:
            non_compliant = False
        else:
            parts.append("FAILED step 2: SNMP enabled but no SNMPv3 user configured")

    parts.append("NON-COMPLIANT" if non_compliant else "COMPLIANT")
    report = " | ".join(parts)
    if non_compliant:
        report += "\n\n" + _SNMPV3_REMEDIATION_GUIDE
    return report


def _get_field_value(output: str, key: str) -> Optional[str]:
    """
    Return the value of a ``get``-style ``key : value`` field (e.g. from
    ``get system global``), or ``None`` when the field is absent.
    Example line: ``timezone            : (GMT+3:30) Tehran``.
    """
    m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$",
                  output or "", re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def _norm_field(value: str) -> str:
    """Normalize a field value for tolerant comparison: drop whitespace, lowercase.
    Lets ``(GMT+3:30) Tehran`` match ``(GMT+3:30)Tehran`` across FortiOS spacing."""
    return re.sub(r"\s+", "", value or "").lower()


def _field_forbidden_tokens(output: str, key: str, forbidden) -> tuple:
    """
    For a space-separated ``get``-style field, return
    ``(value_or_None, [forbidden tokens present])``. ``value`` is ``None`` when
    the field is absent (e.g. left at default). Token match is whole-word and
    case-insensitive.
    """
    value = _get_field_value(output, key)
    if value is None:
        return None, []
    tokens = {t.lower() for t in value.split()}
    active = [f for f in (forbidden or []) if f.lower() in tokens]
    return value, active


def _iface_allowaccess_violations(output: str, forbidden, role: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Return interfaces whose ``allowaccess`` exposes a forbidden service. When
    ``role`` is given, only interfaces with that role are considered; otherwise
    every interface is checked. Each entry: ``{"name", "role", "exposed": [...]}``.
    """
    forbidden_set = {s.lower() for s in (forbidden or [])}
    violations: List[Dict[str, Any]] = []
    for itf in _parse_interfaces(output):
        if role and itf["role"] != role:
            continue
        exposed = [s for s in itf["allowaccess"] if s.lower() in forbidden_set]
        if exposed:
            violations.append({"name": itf["name"], "role": itf["role"] or "-", "exposed": exposed})
    return violations


def _wan_mgmt_violations(output: str, forbidden=None) -> List[Dict[str, Any]]:
    """WAN-role interfaces that expose a management service (CIS 1.3 / FG-NET-002)."""
    return _iface_allowaccess_violations(output, forbidden or _WAN_FORBIDDEN_SERVICES, role="wan")


def _interfaces_or_error(output: str) -> tuple:
    """
    Parse interfaces, returning ``(interfaces, error_message)``. ``error_message``
    is set when the output is empty/an error marker or no interface could be
    parsed at all — so an interface check fails closed (surfaced as unverifiable)
    instead of silently PASSING on missing data.
    """
    if (output or "").lstrip().lower().startswith("__error__"):
        return [], "could not read interfaces (collection error)"
    if not (output or "").strip():
        return [], "no interface output returned"
    ifaces = _parse_interfaces(output)
    if not ifaces:
        return [], "no interfaces could be parsed from output"
    return ifaces, None


def _looks_truncated(output: str) -> bool:
    """
    Heuristic: a non-empty capture that does not end at a CLI prompt (``…#``/``$``)
    nor at the config terminator ``end`` was very likely cut off mid-stream. A
    truncated ``show system interface`` can drop trailing interface blocks (so a
    late WAN interface goes unseen) while earlier ones still parse — which would
    turn a real violation into a false COMPLIANT. Used for logging only.
    """
    tail = (output or "").rstrip()
    if not tail:
        return False
    last = tail.splitlines()[-1].strip()
    return not (last.endswith("#") or last.endswith("$") or last == "end")


def _wan_mgmt_evidence(output: str, forbidden=None) -> str:
    """Per-interface report for FG-NET-002 (management services exposed on WAN)."""
    forbidden = forbidden or _WAN_FORBIDDEN_SERVICES
    ifaces, error = _interfaces_or_error(output)
    if error:
        return f"{error} - unable to verify WAN exposure (NON-COMPLIANT)"
    viols = _iface_allowaccess_violations(output, forbidden, role="wan")
    if viols:
        return "\n".join(
            f"Interface {v['name']} (role={v['role']}) exposes: "
            f"{', '.join(v['exposed'])} (NON-COMPLIANT)"
            for v in viols
        )
    wan_ifaces = [i["name"] for i in ifaces if i["role"] == "wan"]
    if wan_ifaces:
        return (f"{len(ifaces)} interfaces; WAN-role interface(s) "
                f"{', '.join(wan_ifaces)} expose no management services (COMPLIANT)")
    return (f"{len(ifaces)} interfaces checked; none has role=wan "
            f"(no WAN-role interface to expose management services) (COMPLIANT)")


def _iface_excludes_evidence(output: str, forbidden, role) -> str:
    """Per-interface report for FG-BL-002 (no cleartext mgmt on any interface)."""
    ifaces, error = _interfaces_or_error(output)
    if error:
        return f"{error} - unable to verify (NON-COMPLIANT)"
    viols = _iface_allowaccess_violations(output, forbidden, role=(role or None))
    if viols:
        return "\n".join(
            f"Interface {v['name']} (role={v['role']}) exposes: "
            f"{', '.join(v['exposed'])} (NON-COMPLIANT)"
            for v in viols
        )
    return f"{len(ifaces)} interfaces; none exposes the forbidden services (COMPLIANT)"


# ---------------------------------------------------------------------------
# Generic `get`-style field rules (parse the live value of `key : value`)
# ---------------------------------------------------------------------------
_GET_FIELD_TYPES = frozenset({
    "get_field_eq", "get_field_ne", "get_field_in", "get_field_matches",
    "get_field_not_match", "get_field_int_le", "get_field_int_ge",
})


def _eval_get_field(rule, output: str) -> bool:
    """Evaluate any generic `get`-style field rule. Absent field == non-compliant
    (a `get` command always prints the resolved value, so absence means error)."""
    t = rule.type
    val = _get_field_value(output, rule.key)

    if t in ("get_field_int_le", "get_field_int_ge"):
        m = re.search(r"-?\d+", val) if val else None
        actual = int(m.group()) if m else rule.default
        if actual is None:
            return False
        return actual <= rule.expected if t.endswith("le") else actual >= rule.expected

    if val is None:
        return False
    if t == "get_field_eq":
        return _norm_field(val) == _norm_field(str(rule.expected))
    if t == "get_field_ne":
        return _norm_field(val) != _norm_field(str(rule.expected))
    if t == "get_field_in":
        return _norm_field(val) in {_norm_field(str(x)) for x in (rule.expected or [])}
    if t == "get_field_matches":
        return bool(re.search(rule.pattern, val, re.IGNORECASE))
    if t == "get_field_not_match":
        return not re.search(rule.pattern, val, re.IGNORECASE)
    return False


# TLS versions that satisfy "SSL-VPN min proto >= 1.2" in the single-field format.
_SSLVPN_OK_MIN = frozenset({"tls1-2", "tls1-3", "tlsv1-2", "tlsv1-3"})
# Per-version boolean fields for the weak protocols that must NOT be enabled.
_SSLVPN_WEAK_FIELDS = ("tlsv1-0", "tlsv1-1")


def _sslvpn_min_tls_ok(output: str) -> bool:
    """SSL-VPN must allow only TLS >= 1.2. Handles BOTH build output formats:

    * single resolved field ``ssl-min-proto-ver : tls1-2`` -> value must be 1.2/1.3;
    * per-version booleans ``tlsv1-0/1/2/3 : enable/disable`` (some 60F builds have
      no ``ssl-min-proto-ver`` at all) -> compliant only when no weak version
      (TLS 1.0/1.1) is enabled.
    """
    v = _get_field_value(output, "ssl-min-proto-ver")
    if v is not None:
        return _norm_field(v) in {_norm_field(x) for x in _SSLVPN_OK_MIN}
    saw_bool = False
    for weak in _SSLVPN_WEAK_FIELDS:
        b = _get_field_value(output, weak)
        if b is not None:
            saw_bool = True
            if b.strip().lower() == "enable":
                return False  # a weak TLS version is enabled -> NON-COMPLIANT
    # Compliant only if we actually parsed the booleans and none weak was enabled;
    # neither format present -> can't confirm -> fail closed.
    return saw_bool


def _field_expectation(rule) -> str:
    """
    Human-readable expectation for a NON-COMPLIANT generic field rule.

    Computed per-type (NOT as an eager dict) so a scalar ``expected`` on an
    int/eq rule is never fed to the list-formatting branch meant for
    ``get_field_in`` — the eager dict previously ran ``map(str, rule.expected)``
    for *every* type, which raised ``'int' object is not iterable`` on an
    ``expected=10`` int rule (FG-BL-004).
    """
    t, exp, pat = rule.type, rule.expected, rule.pattern
    if t == "get_field_eq":
        return f"expected {exp}"
    if t == "get_field_ne":
        return f"must not be {exp}"
    if t == "get_field_in":
        allowed = exp if isinstance(exp, (list, tuple, set)) else [exp]
        return f"allowed: {', '.join(map(str, allowed))}"
    if t == "get_field_matches":
        return f"must match /{pat}/"
    if t == "get_field_not_match":
        return f"must not match /{pat}/"
    if t == "get_field_int_le":
        return f"must be <= {exp}"
    if t == "get_field_int_ge":
        return f"must be >= {exp}"
    return ""


def _field_evidence_line(rule, output: str) -> str:
    """One-line report for a generic field rule: current value + verdict + expectation."""
    val = _get_field_value(output, rule.key)
    ok = _eval_get_field(rule, output)
    shown = val if val is not None else "<not found>"
    if ok:
        return f"{rule.key}: {shown} (compliant)"
    return f"{rule.key}: {shown} (NON-COMPLIANT, {_field_expectation(rule)})"


# ---------------------------------------------------------------------------
# Generic config-table rules (parse `edit ... next` entries, evaluate each)
# ---------------------------------------------------------------------------
def _parse_table_entries(output: str) -> List[Dict[str, str]]:
    """
    Parse a `show`/`get` table into top-level entries: ``[{"name", "body"}]`` where
    ``body`` is the raw text of that entry (nested config blocks included). Used to
    evaluate a per-entry condition across ALL entries instead of mere presence.
    """
    entries: List[Dict[str, str]] = []
    name: Optional[str] = None
    body: List[str] = []
    cfg = 0   # open `config` blocks
    ed = 0    # open `edit` blocks
    for raw in (output or "").splitlines():
        s = raw.strip()
        if s.startswith("config "):
            if name is not None:
                body.append(raw)
            cfg += 1
            continue
        m = re.match(r'edit\s+"?([^"]*?)"?\s*$', s)
        if m:
            if ed == 0:
                name, body = m.group(1), []
            elif name is not None:
                body.append(raw)
            ed += 1
            continue
        if s == "next":
            ed = max(0, ed - 1)
            if ed == 0 and name is not None:
                entries.append({"name": name, "body": "\n".join(body)})
                name, body = None, []
            elif name is not None:
                body.append(raw)
            continue
        if s == "end":
            cfg = max(0, cfg - 1)
            if name is not None:
                body.append(raw)
            continue
        if name is not None:
            body.append(raw)
    if name is not None:
        entries.append({"name": name, "body": "\n".join(body)})
    return entries


def _eval_table(rule, output: str) -> bool:
    entries = _parse_table_entries(output)
    pat = rule.pattern

    def hit(e):
        return bool(re.search(pat, e["body"], re.IGNORECASE | re.MULTILINE))

    if rule.type == "table_none_match":
        return not any(hit(e) for e in entries)
    if rule.type == "table_all_match":
        return all(hit(e) for e in entries)            # vacuously True when empty
    if rule.type == "table_any_match":
        return any(hit(e) for e in entries)            # best-effort: needs >=1
    return False


def _table_evidence_line(rule, output: str) -> str:
    entries = _parse_table_entries(output)
    n = len(entries)
    label = rule.key or "condition"

    def hit(e):
        return bool(re.search(rule.pattern, e["body"], re.IGNORECASE | re.MULTILINE))

    if rule.type == "table_none_match":
        off = [e["name"] for e in entries if hit(e)]
        return (f"{n} entries; '{label}' violated by: {', '.join(off)} (NON-COMPLIANT)"
                if off else f"{n} entries; none violate '{label}' (compliant)")
    if rule.type == "table_all_match":
        off = [e["name"] for e in entries if not hit(e)]
        return (f"{n} entries; missing '{label}': {', '.join(off)} (NON-COMPLIANT)"
                if off else f"{n} entries; all satisfy '{label}' (compliant)")
    if rule.type == "table_any_match":
        hits = [e["name"] for e in entries if hit(e)]
        if hits:
            return f"{n} entries; '{label}' present in: {', '.join(hits)} (best-effort PASS)"
        # Name what WAS parsed so a FAIL is verifiable (e.g. which IPS sensors
        # exist and simply lack the setting) — capped so huge tables stay readable.
        checked = ", ".join(e["name"] for e in entries[:20])
        more = f" (+{n - 20} more)" if n > 20 else ""
        suffix = f" — entries checked: {checked}{more}" if checked else ""
        return f"{n} entries; '{label}' found in none (best-effort FAIL){suffix}"
    return f"{n} entries"


# ---------------------------------------------------------------------------
# Per-policy field rules (parse `edit <id> ... next`, evaluate a field per entry
# and report each failing Policy ID individually).
# ---------------------------------------------------------------------------
def _entry_field_value(body: str, key: str) -> Optional[str]:
    """Return the value of ``set <key> <value>`` inside one table entry body,
    or ``None`` when the line is absent (left at its FortiOS default)."""
    m = re.search(rf"^\s*set\s+{re.escape(key)}\s+(.+?)\s*$",
                  body or "", re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip().strip('"') if m else None


def _policy_in_scope(entry: Dict[str, str], scope_pattern: Optional[str]) -> bool:
    """Whether a policy entry is in scope for a per-policy rule. With no
    ``scope_pattern`` every entry counts; otherwise only those whose body matches
    (e.g. only ``set action accept`` policies for profile checks)."""
    if not scope_pattern:
        return True
    return bool(re.search(scope_pattern, entry["body"], re.IGNORECASE | re.MULTILINE))


def _entry_field_raw(body: str, key: str) -> Optional[str]:
    """Like :func:`_entry_field_value` but returns the value UNSTRIPPED — for
    multi-object fields (``set service "HTTP" "ALL"``) where stripping the outer
    quotes would corrupt the token boundaries."""
    m = re.search(rf"^\s*set\s+{re.escape(key)}\s+(.+?)\s*$",
                  body or "", re.IGNORECASE | re.MULTILINE)
    return m.group(1) if m else None


def _field_value_tokens(value: Optional[str]) -> List[str]:
    """Split a multi-object field value (``"ALL" "HTTP"`` or bare ``ALL``) into
    its object-name tokens, quotes stripped."""
    if not value:
        return []
    return [q or b for q, b in re.findall(r'"([^"]*)"|(\S+)', value)]


def _policy_label(entry: Dict[str, str]) -> str:
    """Human-readable policy reference for evidence lines: ``"13 (Allow-Web)"``
    (or bare ``"13"`` for unnamed policies). The leading ID is what the
    hardening UI extracts back out (see manual_remediation._POLICY_ID_RE /
    selection_object_name), so it must always come first."""
    name = _entry_field_value(entry["body"], "name")
    return f"{entry['name']} ({name})" if name else str(entry["name"])


def _policy_field_failures(rule, output: str) -> tuple:
    """
    Evaluate a ``policy_field_eq`` / ``policy_field_present`` /
    ``policy_field_forbidden_token`` rule per policy.

    Returns ``(failures, in_scope_count, error)`` where ``failures`` is a list of
    ``{"name", "label", "value"}`` for each in-scope policy that violates the
    rule and ``error`` is a message when the policy output could not be read at
    all (so the verdict can fail closed rather than silently pass).
    """
    if (output or "").lstrip().lower().startswith("__error__"):
        return [], 0, "could not read firewall policies (collection error)"
    entries = _parse_table_entries(output)
    in_scope = [e for e in entries if _policy_in_scope(e, rule.scope_pattern)]
    failures: List[Dict[str, Any]] = []
    for e in in_scope:
        val = _entry_field_value(e["body"], rule.key)
        if rule.type == "policy_field_eq":
            if val is None or _norm_field(val) != _norm_field(str(rule.expected)):
                failures.append({"name": e["name"], "label": _policy_label(e), "value": val})
        elif rule.type == "policy_field_forbidden_token":
            # The field's object LIST must not contain the forbidden object as an
            # exact token in ANY position ("ALL" matches; "ALL_TCP" does not).
            # Token-split the RAW value: _entry_field_value strips outer quotes,
            # which corrupts multi-object lists like `"HTTP" "ALL"`.
            raw = _entry_field_raw(e["body"], rule.key)
            tokens = _field_value_tokens(raw)
            if any(t.upper() == str(rule.expected).upper() for t in tokens):
                failures.append({"name": e["name"], "label": _policy_label(e), "value": raw})
        else:  # policy_field_present
            if not val:
                failures.append({"name": e["name"], "label": _policy_label(e), "value": val})
    return failures, len(in_scope), None


def _policy_field_evidence(rule, output: str) -> str:
    """Per-policy report listing each failing Policy ID individually."""
    failures, scope_n, error = _policy_field_failures(rule, output)
    if error:
        return f"{error} - unable to verify (NON-COMPLIANT)"

    if rule.type == "policy_field_eq":
        if not failures:
            return f"{scope_n} policies; all have {rule.key} = {rule.expected} (COMPLIANT)"
        lines = [
            f"Policy ID {f['label']}: {rule.key} = "
            f"{f['value'] if f['value'] is not None else '<not set>'} (NON-COMPLIANT)"
            for f in failures
        ]
        return f"{len(failures)}/{scope_n} policies NON-COMPLIANT:\n" + "\n".join(lines)

    if rule.type == "policy_field_forbidden_token":
        if not failures:
            # Show WHAT was parsed, not just the verdict — a COMPLIANT here is
            # only trustworthy if the per-policy object lists are visible (e.g.
            # "ALL_ICMP" must appear as parsed-and-accepted, not silently skipped).
            entries = _parse_table_entries(output)
            lines = [
                f"Policy ID {_policy_label(e)}: {rule.key} = "
                f"{_entry_field_raw(e['body'], rule.key) or '<not set>'} (ok)"
                for e in entries
            ]
            return (f"{scope_n} policies; none use '{rule.expected}' as {rule.key} "
                    f"(COMPLIANT):\n" + "\n".join(lines)) if lines else \
                   f"0 policies configured (COMPLIANT)"
        lines = [
            f"Policy ID {f['label']}: {rule.key} = {f['value']} (NON-COMPLIANT)"
            for f in failures
        ]
        return (f"{len(failures)}/{scope_n} policies use '{rule.expected}' as "
                f"{rule.key}:\n" + "\n".join(lines))

    # policy_field_present
    if not failures:
        return f"{scope_n} accept policies; all have {rule.key} (COMPLIANT)"
    lines = [f"Policy ID {f['label']}: missing {rule.key} (NON-COMPLIANT)" for f in failures]
    return (f"{len(failures)}/{scope_n} accept policies missing {rule.key}:\n"
            + "\n".join(lines))


# ---------------------------------------------------------------------------
# 3.1 unused-policy detection & 3.3 ISDB deny detection
# ---------------------------------------------------------------------------
# One kernel policy block in `diagnose firewall iprope list 100004` starts with
# "policy index=<policy ID>" and carries its traffic counters in a
# "pol_stats: bytes=N(all) packets=N(all), ..." line.
_IPROPE_POLICY_ID_RE = re.compile(r"policy\s+index\s*=\s*(\d+)", re.IGNORECASE)
_IPROPE_BYTES_RE = re.compile(r"\bbytes\s*[=:]\s*(\d+)", re.IGNORECASE)


def _parse_policy_bytes(stats_output: str) -> Optional[Dict[str, int]]:
    """
    Parse ``diagnose firewall iprope list 100004`` into ``{policy_id: bytes}``.

    Returns ``None`` when the output is missing/rejected/unparseable — the
    caller then treats byte counters as unavailable (0) rather than trusting a
    bad read.
    """
    out = (stats_output or "").strip()
    if not out or out.lower().startswith("__error__"):
        return None
    counters: Dict[str, int] = {}
    current_id: Optional[str] = None
    for line in out.splitlines():
        m_id = _IPROPE_POLICY_ID_RE.search(line)
        if m_id:
            current_id = m_id.group(1)
            counters.setdefault(current_id, 0)
            continue
        if current_id is not None:
            m_bytes = _IPROPE_BYTES_RE.search(line)
            if m_bytes:
                counters[current_id] = max(counters[current_id], int(m_bytes.group(1)))
    return counters if counters else None


def _policy_unused_report(rule, outputs: Dict[str, str]) -> Tuple[bool, str]:
    """
    FG-POL-001 (CIS 3.1): a policy that is DISABLED (``set status disable``) and
    has 0 traffic bytes (per the kernel counters, ``rule.aux_cmd``) was never
    used — it is an unused policy and the check FAILS, listing each one as a
    deletion candidate. Disabled policies are unloaded from the kernel table, so
    a policy absent from the counters counts as 0 bytes; an unreadable counter
    read degrades the same way (noted in the evidence) instead of passing.

    Only failing policies get the ``Policy ID <id> (<name>):`` line prefix —
    that is what the hardening UI parses into the delete multi-select — the
    review worksheet for the remaining policies uses a different shape.

    Returns ``(passed, evidence)``; fails closed when the policy table couldn't
    be read. An empty policy table is compliant (nothing to review).
    """
    output = outputs.get(rule.cmd, "")
    if not (output or "").strip() or output.lstrip().lower().startswith("__error__"):
        return False, "could not read firewall policies - unable to verify (NON-COMPLIANT)"
    entries = _parse_table_entries(output)
    if not entries:
        return True, "0 firewall policies configured - nothing to review (COMPLIANT)"

    counters = _parse_policy_bytes(outputs.get(rule.aux_cmd, "") if rule.aux_cmd else "")
    counters_note = ""
    if counters is None:
        counters_note = ("byte counters could not be read from the device "
                         "(diagnose firewall iprope list 100004) — disabled "
                         "policies are treated as 0 bytes")

    unused: List[str] = []      # "Policy ID <label>: ..." lines (parseable)
    worksheet: List[str] = []   # non-parseable review lines for the rest
    for e in entries:
        label = _policy_label(e)
        status = (_entry_field_value(e["body"], "status") or "enable").lower()
        pbytes = (counters or {}).get(str(e["name"]), 0)
        shown_bytes = pbytes if counters is not None else "unknown"
        if status == "disable" and pbytes == 0:
            unused.append(f"Policy ID {label}: status=disable, bytes=0 "
                          f"(NON-COMPLIANT — unused, candidate for deletion)")
        elif status == "disable":
            worksheet.append(f"  #{label} - disabled, bytes={shown_bytes} (has past traffic; review)")
        else:
            worksheet.append(f"  #{label} - enabled, bytes={shown_bytes}")

    if unused:
        header = (f"{len(unused)}/{len(entries)} policies are disabled with 0 traffic "
                  f"bytes — unused, delete them:")
        parts = [header] + unused
        if counters_note:
            parts.append(f"NOTE: {counters_note}.")
        parts.append(f"Remaining {len(entries) - len(unused)} policies "
                     f"(review usage / hit counts in the GUI):")
        parts.extend(worksheet)
        return False, "\n".join(parts)

    header = (f"{len(entries)} firewall policies; none is disabled with 0 traffic bytes "
              f"(COMPLIANT). Review usage and remove or disable unused ones:")
    parts = [header] + worksheet
    if counters_note:
        parts.append(f"NOTE: {counters_note}.")
    return True, "\n".join(parts)


# 7.0.x ISDB reference fields on a firewall policy (destination and source
# directions, name- and id-based spellings).
_ISDB_FIELD_RE = re.compile(
    r"^\s*set\s+internet-service(?:-src)?-(?:name|id)\s+(.+?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_ACTION_ACCEPT_RE = re.compile(r"^\s*set\s+action\s+accept\b", re.IGNORECASE | re.MULTILINE)


def _isdb_deny_matches(rule, output: str) -> List[Dict[str, Any]]:
    """
    FG-POL-002 (CIS 3.3): qualifying entries are DENY policies (deny is the
    action default, so ``show`` prints no ``set action`` line for them) whose
    ISDB object references match ``rule.pattern`` (Tor/Malicious/Scanner/Botnet).
    ``set internet-service enable`` alone — common on accept policies for
    SD-WAN steering / ISDB allow rules — does NOT qualify.

    Returns ``[{"name", "objects"}]`` for each qualifying deny policy.
    """
    matches: List[Dict[str, Any]] = []
    for e in _parse_table_entries(output):
        if _ACTION_ACCEPT_RE.search(e["body"]):
            continue  # accept policy — not a deny rule, whatever it references
        objects: List[str] = []
        for value in _ISDB_FIELD_RE.findall(e["body"]):
            objects.extend(
                t for t in _field_value_tokens(value)
                if re.search(rule.pattern, t, re.IGNORECASE)
            )
        if objects:
            matches.append({"name": e["name"], "objects": objects})
    return matches


def _isdb_deny_evidence(rule, output: str) -> str:
    if not (output or "").strip() or output.lstrip().lower().startswith("__error__"):
        return "could not read firewall policies - unable to verify (NON-COMPLIANT)"
    matches = _isdb_deny_matches(rule, output)
    n = len(_parse_table_entries(output))
    if not matches:
        return (f"{n} policies; no DENY policy references Tor/Malicious/Scanner/"
                f"Botnet ISDB objects (best-effort FAIL)")
    lines = [f"Policy ID {m['name']}: deny via {', '.join(m['objects'])}"
             for m in matches]
    return (f"{n} policies; ISDB deny policies found (best-effort PASS):\n"
            + "\n".join(lines))


# Prepended to the evidence of ambiguous (heuristic) checks so the report itself
# documents that the PASS/FAIL is indicative only. Kept ASCII for clean exports;
# the UI also renders a "Manual review" badge from the API's needs_review flag.
_REVIEW_NOTICE = ("[MANUAL REVIEW REQUIRED] Heuristic check: the PASS/FAIL below is "
                  "indicative only (based on presence/absence of config) and must be "
                  "verified manually.")

_NA_NOTICE = "[NOT APPLICABLE]"


# Secrets to redact from captured command output before persisting.
_REDACTION_PATTERNS = [
    (re.compile(r"(set\s+(?:password|passwd|key|community|secret|auth-pwd|auth-password|"
                r"enc-password|private-key|psksecret|ppk-secret)\s+)\S+", re.IGNORECASE), r"\1<REDACTED>"),
    (re.compile(r"ENC\s+[A-Za-z0-9+/=]+"), "ENC <REDACTED>"),
]


class FortinetAuditService:
    """Service for executing and managing FortiGate security audits."""

    BATCH_SIZE = 100

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------
    @staticmethod
    @contextmanager
    def _timed_operation(operation_name: str):
        start = time.time()
        logger.info("Starting: %s", operation_name)
        try:
            yield
        finally:
            logger.info("Completed: %s (%.2fs)", operation_name, time.time() - start)

    @staticmethod
    def _get_controls(profile: str) -> List[FortiGateControl]:
        """Filter controls by profile. All CIS controls are L1, so every profile
        currently returns the full catalogue; the filter is kept for forward-compat."""
        controls = get_fortinet_controls()
        if profile == "L1":
            return [c for c in controls if c.level == "L1"]
        if profile == "L2":
            return [c for c in controls if c.level in ("L1", "L2")]
        return controls  # FULL

    @staticmethod
    def _redact(text: str) -> str:
        out = text or ""
        for pattern, repl in _REDACTION_PATTERNS:
            out = pattern.sub(repl, out)
        return out

    # ------------------------------------------------------------------
    # Rule / control evaluation
    # ------------------------------------------------------------------
    @staticmethod
    def _evaluate_rule(rule: FortiGateRule, output: str) -> bool:
        output = output or ""
        try:
            if rule.type == "set_bool":
                # Pass if the opposite state is absent (handles show-omits-defaults).
                opposite = "disable" if rule.expected else "enable"
                pattern = rf"set\s+{re.escape(rule.key)}\s+{opposite}"
                return not bool(re.search(pattern, output, re.IGNORECASE | re.MULTILINE))

            if rule.type in ("set_int_le", "set_int_ge"):
                match = re.search(rf"set\s+{re.escape(rule.key)}\s+(\d+)", output, re.IGNORECASE)
                actual = int(match.group(1)) if match else rule.default
                if actual is None:
                    return False  # not configured and no known default
                return actual <= rule.expected if rule.type == "set_int_le" else actual >= rule.expected

            if rule.type == "set_eq":
                match = re.search(rf"set\s+{re.escape(rule.key)}\s+(\S+)", output, re.IGNORECASE)
                return bool(match) and match.group(1).strip('"') == str(rule.expected)

            if rule.type == "wan_mgmt_exposed":
                # Compliant (pass) only when NO WAN-role interface exposes a
                # management service in its allowaccess. Fail closed when the
                # interface output is empty/error or yields no parseable
                # interface — otherwise a collection failure would silently PASS.
                ifaces = _parse_interfaces(output)
                if not ifaces:
                    return False
                viols = _wan_mgmt_violations(output, rule.expected)
                if not viols:
                    # A PASS here is only trustworthy if we actually saw the WAN
                    # interfaces. If none parsed AND the capture looks truncated,
                    # the real WAN interface was probably dropped from the read —
                    # surface it so it isn't a silent false negative.
                    wan = [i["name"] for i in ifaces if i["role"] == "wan"]
                    if not wan and _looks_truncated(output):
                        logger.warning(
                            "FG-NET-002 PASS is suspect: %d interfaces parsed but "
                            "NONE has role=wan, and `show system interface` output "
                            "looks truncated (%d chars, no trailing prompt). The WAN "
                            "interface may have been dropped from the capture — "
                            "verdict COMPLIANT may be a false negative.",
                            len(ifaces), len(output or ""),
                        )
                    else:
                        logger.debug(
                            "FG-NET-002: %d interfaces parsed, WAN-role=%s, none "
                            "exposes %s", len(ifaces), wan or "(none)", list(rule.expected or []),
                        )
                return not viols

            if rule.type == "iface_allowaccess_excludes":
                # No interface (optionally filtered to rule.key role) exposes a
                # forbidden service (rule.expected) in its allowaccess. Fail
                # closed when no interface could be parsed (empty/error output).
                if not _parse_interfaces(output):
                    return False
                return not _iface_allowaccess_violations(output, rule.expected, role=(rule.key or None))

            if rule.type in ("policy_field_eq", "policy_field_present",
                             "policy_field_forbidden_token"):
                # Per-policy field check: PASS only when no in-scope policy fails
                # and the policy output was readable (errors fail closed).
                failures, _scope_n, error = _policy_field_failures(rule, output)
                return not error and not failures

            # "policy_unused" (3.1) correlates TWO command outputs and is
            # evaluated at the control level in _evaluate_control, not here.

            if rule.type == "isdb_deny_present":
                # 3.3: at least one DENY policy referencing Tor/Malicious/Scanner/
                # Botnet ISDB objects. Fails closed on unreadable output.
                if not output.strip() or output.lstrip().lower().startswith("__error__"):
                    return False
                return bool(_isdb_deny_matches(rule, output))

            if rule.type in _GET_FIELD_TYPES:
                # Parse the live value of a `get`-style `key : value` field and
                # compare it (eq/ne/in/matches/not_match/int_le/int_ge).
                if (output and not output.lstrip().lower().startswith("__error__")
                        and _get_field_value(output, rule.key) is None):
                    # The field is missing from a non-empty capture. Distinguish
                    # the (very different) reasons so a false NON-COMPLIANT is
                    # diagnosable instead of always blaming truncation.
                    low = output.lower()
                    if ("command parse error" in low or "command fail" in low
                            or "unknown action" in low):
                        reason = ("device REJECTED the command (parse error) — the "
                                  "command/scope is wrong for this FortiOS build")
                    elif _looks_truncated(output):
                        reason = ("capture looks TRUNCATED (no trailing prompt) — "
                                  "the read was cut off")
                    else:
                        reason = ("field absent from a COMPLETE capture — it may be "
                                  "unset/default, the feature may be disabled, or the "
                                  "rule key may not match this build's field name")
                    logger.warning(
                        "get-field %r NOT FOUND in `%s` output (%d chars): %s. "
                        "Verdict may be a false NON-COMPLIANT. First 160 chars: %r",
                        rule.key, rule.cmd, len(output), reason, output[:160],
                    )
                return _eval_get_field(rule, output)

            if rule.type in ("table_none_match", "table_all_match", "table_any_match"):
                # Parse every `edit ... next` entry and evaluate the per-entry
                # condition across all of them (not mere presence).
                return _eval_table(rule, output)

            if rule.type == "get_field_excludes":
                # Compliant only when the field is present AND contains none of
                # the forbidden tokens. Absent/default field == non-compliant.
                value, active = _field_forbidden_tokens(output, rule.key, rule.expected)
                return value is not None and not active

            if rule.type == "sslvpn_min_tls":
                # SSL-VPN min TLS >= 1.2, tolerant of the ssl-min-proto-ver field
                # OR the per-version tlsv1-N booleans some builds use instead.
                return _sslvpn_min_tls_ok(output)

            if rule.type == "snmp_status_enabled":
                # Step 1: SNMP master switch must be enabled.
                return (_get_field_value(output, "status") or "").lower() == "enable"

            if rule.type == "snmp_user_exists":
                # Step 2: at least one SNMPv3 user must be configured.
                return len(_parse_snmp_users(output)) > 0

            if rule.type == "ntp_status_ok":
                # Compliant only when synchronized + ntpsync + server-mode are
                # all good and no forbidden (FortiGuard) NTP server is in use.
                return not _ntp_status_failures(_parse_ntp_status(output))

            if rule.type == "regex_present":
                return bool(re.search(rule.pattern, output, re.IGNORECASE | re.MULTILINE))

            if rule.type == "regex_absent":
                return not bool(re.search(rule.pattern, output, re.IGNORECASE | re.MULTILINE))

            logger.warning("Unknown rule type: %s", rule.type)
            return False
        except Exception as e:  # noqa: BLE001
            logger.error("Error evaluating rule %s: %s", rule.type, e)
            return False

    @staticmethod
    def _extract_evidence(control: FortiGateControl, outputs: Dict[str, str]) -> str:
        # Multi-command SNMPv3 check produces a single combined report (and must
        # run before the per-rule loop, which skips empty command outputs).
        # Returned in full — the NON-COMPLIANT case embeds the multi-line
        # remediation guide, which must not be truncated to 500 chars.
        if any(r.type == "snmp_status_enabled" for r in control.rules):
            return _snmp_evidence(control, outputs)

        # Detailed per-interface / per-policy reports do their own empty/error
        # handling (so a collection failure is surfaced, never silently passed)
        # and can be multi-line (one Policy ID per line) — so they bypass the
        # short-snippet truncation below.
        detailed = any(r.type in _DETAILED_RULE_TYPES for r in control.rules)

        lines: List[str] = []
        for rule in control.rules:
            out = outputs.get(rule.cmd, "")

            if rule.type == "wan_mgmt_exposed":
                lines.append(_wan_mgmt_evidence(out, rule.expected))
                continue
            if rule.type == "iface_allowaccess_excludes":
                lines.append(_iface_excludes_evidence(out, rule.expected, rule.key))
                continue
            if rule.type in ("policy_field_eq", "policy_field_present",
                             "policy_field_forbidden_token"):
                lines.append(_policy_field_evidence(rule, out))
                continue
            if rule.type == "policy_unused":
                lines.append(_policy_unused_report(rule, outputs)[1])
                continue
            if rule.type == "isdb_deny_present":
                lines.append(_isdb_deny_evidence(rule, out))
                continue

            if not out:
                continue
            if rule.type in _GET_FIELD_TYPES:
                lines.append(_field_evidence_line(rule, out))
                continue
            if rule.type in ("table_none_match", "table_all_match", "table_any_match"):
                lines.append(_table_evidence_line(rule, out))
                continue
            if rule.type == "get_field_excludes":
                value, active = _field_forbidden_tokens(out, rule.key, rule.expected)
                if value is None:
                    lines.append(f"{rule.key}: <not set / default> (NON-COMPLIANT)")
                elif active:
                    lines.append(f"{rule.key}: {value} (NON-COMPLIANT — insecure: {', '.join(active)})")
                else:
                    lines.append(f"{rule.key}: {value} (compliant)")
                continue
            if rule.type == "sslvpn_min_tls":
                v = _get_field_value(out, "ssl-min-proto-ver")
                if v is not None:
                    ok = _norm_field(v) in {_norm_field(x) for x in _SSLVPN_OK_MIN}
                    lines.append(f"ssl-min-proto-ver: {v} "
                                 f"({'compliant' if ok else 'NON-COMPLIANT — must be tls1-2+'})")
                else:
                    states = {k: _get_field_value(out, k)
                              for k in ("tlsv1-0", "tlsv1-1", "tlsv1-2", "tlsv1-3")}
                    present = {k: val for k, val in states.items() if val is not None}
                    weak_on = [k for k in _SSLVPN_WEAK_FIELDS
                               if (present.get(k) or "").lower() == "enable"]
                    shown = ", ".join(f"{k}={val}" for k, val in present.items())
                    if not present:
                        lines.append("no ssl-min-proto-ver / tlsv1-N fields found (NON-COMPLIANT)")
                    elif weak_on:
                        lines.append(f"weak TLS enabled: {', '.join(weak_on)} [{shown}] (NON-COMPLIANT)")
                    else:
                        lines.append(f"only TLS 1.2+ enabled [{shown}] (compliant)")
                continue
            if rule.type == "ntp_status_ok":
                st = _parse_ntp_status(out)
                servers = ", ".join(st["servers"]) if st["servers"] else "none"
                report = (
                    f"synchronized={st['synchronized'] or 'unknown'} | "
                    f"ntpsync={st['ntpsync'] or 'unknown'} | "
                    f"server-mode={st['server_mode'] or 'unknown'} | "
                    f"servers=[{servers}]"
                )
                fails = _ntp_status_failures(st)
                report += " | FAILED: " + "; ".join(fails) if fails else " | COMPLIANT"
                # NTP is a single global service even with VDOMs enabled; the
                # finding's vdom label records the scope it was read in.
                report += " | (NTP is global; read at device top-level)"
                lines.append(report)
                continue
            if rule.key:
                lines.extend(re.findall(rf".*{re.escape(rule.key)}.*", out, re.IGNORECASE | re.MULTILINE)[:3])
            elif rule.pattern:
                m = re.findall(rule.pattern, out, re.IGNORECASE | re.MULTILINE)
                if m:
                    sample = m[0] if isinstance(m[0], str) else " ".join(x for x in m[0] if x)
                    lines.append(f"match: {sample}")
        # "any"-combined controls (one setting, several build spellings) read as an
        # OR so a PASS via one form isn't confused by the other form's absence.
        sep = "\n" if detailed else (" OR " if control.rule_combine == "any" else " | ")
        evidence = sep.join(x.strip() for x in lines if x and x.strip())
        if not evidence:
            evidence = "No matching configuration found"
        # Detailed reports must NEVER drop entries: the hardening UI parses the
        # failing Policy IDs out of this evidence, so truncating it silently
        # hides policies from the fix multi-select (a device with 133 failing
        # policies used to lose everything past ~70). The column is TEXT, so the
        # cap is only a runaway guard, not a budget.
        cap = 60_000 if detailed else 500
        return evidence[:cap - 3] + "..." if len(evidence) > cap else evidence

    @staticmethod
    def _applicability(control: FortiGateControl, outputs: Dict[str, str]) -> Tuple[bool, str]:
        """Return (applicable, reason). A control is NOT_APPLICABLE when its
        ``na_gate`` matches — the feature is switched off (gate field == an
        off value) or not present on this build (gate command was rejected)."""
        gate = getattr(control, "na_gate", None)
        if gate is None:
            return True, ""
        out = outputs.get(gate.cmd, "")
        if gate.na_if_cmd_error and out and not FortiGateSSHClient._is_command_ok(out):
            return False, gate.note or "feature not present on this build (command rejected)"
        if gate.key:
            val = _get_field_value(out, gate.key)
            if val is not None and _norm_field(val) in {_norm_field(v) for v in gate.off_values}:
                return False, gate.note or f"{gate.key}={val}"
        return True, ""

    @classmethod
    def _evaluate_control(cls, control: FortiGateControl, outputs: Dict[str, str], vdom_label: Optional[str]) -> Dict[str, Any]:
        # Applicability gate: score NOT_APPLICABLE (not NON-COMPLIANT) when the
        # underlying feature is switched off or absent from this build, so a
        # legitimately-absent sub-field isn't reported as a false finding.
        applicable, na_reason = cls._applicability(control, outputs)

        if not applicable:
            # Feature is off — skip the sub-rules entirely (their fields are
            # legitimately absent, so evaluating them only yields a misleading
            # NON-COMPLIANT + "field NOT FOUND" noise) and record just why.
            passed, evidence = False, f"{_NA_NOTICE} {na_reason}"
        else:
            # "any" for controls whose setting has >1 build-specific spelling
            # (compliant if EITHER form is enabled); "all" (AND) otherwise.
            # "policy_unused" correlates two command outputs (policy table +
            # kernel byte counters), so it is evaluated here with the full
            # outputs dict instead of inside the single-output _evaluate_rule.
            def _rule_passed(r: FortiGateRule) -> bool:
                if r.type == "policy_unused":
                    return _policy_unused_report(r, outputs)[0]
                return cls._evaluate_rule(r, outputs.get(r.cmd, ""))

            combiner = any if control.rule_combine == "any" else all
            passed = combiner(_rule_passed(r) for r in control.rules)
            # Evidence formatting must never fail the whole audit: a single
            # control's edge case (unexpected real-device output shape) should
            # degrade to a placeholder, not raise a 500. The PASS/FAIL above is
            # already computed by the exception-safe _evaluate_rule, so the finding
            # stays meaningful.
            try:
                evidence = cls._extract_evidence(control, outputs)
            except Exception as e:  # noqa: BLE001
                logger.error(
                    "Evidence extraction failed for control %s (%s) — recording a "
                    "placeholder so the audit can complete. Full traceback follows.",
                    control.id, type(e).__name__, exc_info=True,
                )
                evidence = f"(evidence unavailable — {type(e).__name__}: {e})"
            # Ambiguous (heuristic) checks: document the uncertainty in the report
            # itself so a PASS/FAIL is never mistaken for a definitive result.
            if control.needs_review:
                evidence = f"{_REVIEW_NOTICE}\n{evidence}"
        return {
            "control_id": control.id,
            "title": control.title,
            "passed": passed,
            "applicable": applicable,
            "na_reason": na_reason,
            "manual": control.is_manual,
            "needs_review": control.needs_review,
            "evidence": evidence,
            "severity": control.severity,
            "level": control.level,
            "vdom": vdom_label,
        }

    # ------------------------------------------------------------------
    # Output collection (scope-aware)
    # ------------------------------------------------------------------
    @staticmethod
    def _commands_for(controls: List[FortiGateControl]) -> List[str]:
        seen, cmds = set(), []
        for c in controls:
            for r in c.rules:
                for cmd in (r.cmd, r.aux_cmd):
                    if cmd and cmd not in seen:
                        seen.add(cmd)
                        cmds.append(cmd)
        return cmds

    @staticmethod
    def _safe_collect(client: FortiGateSSHClient, commands: List[str], scope: str,
                      vdom: Optional[str]) -> Dict[str, str]:
        """collect() but never raises: a bad VDOM/context yields error evidence."""
        if not commands:
            return {}
        try:
            return client.collect(commands, scope=scope, vdom=vdom)
        except FortiGateContextError as e:
            logger.warning("Context error (scope=%s vdom=%s): %s", scope, vdom, e)
            return {cmd: f"__ERROR__: {e}" for cmd in commands}
        except Exception as e:  # noqa: BLE001
            logger.warning("Collect failed (scope=%s vdom=%s): %s", scope, vdom, e)
            return {cmd: f"__ERROR__: {type(e).__name__}: {e}" for cmd in commands}

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    @classmethod
    def execute_fortinet_audit(
        cls,
        db: Session,
        asset_id: int,
        user_id: int,
        ssh_username: str,
        ssh_password: str,
        vdom: Optional[str] = None,
        profile: str = "L1",
        job_name: Optional[str] = None,
        ssh_port: int = 22,
    ) -> AuditSession:
        """
        Execute a CIS audit across every VDOM (or a single VDOM if ``vdom`` is given).

        Returns the completed :class:`AuditSession`.
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")
        target_ip = asset.ip_address

        session = AuditSession(
            template_id=None,
            user_id=user_id,
            asset_id=asset_id,
            target_ip=target_ip,
            device_type=DeviceType.FORTINET,
            job_name=job_name,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        try:
            controls = cls._get_controls(profile)
            if not controls:
                raise FortinetEvaluationError(f"No controls found for profile {profile}")

            global_controls = [c for c in controls if c.scope == SCOPE_GLOBAL]
            root_controls = [c for c in controls if c.scope == SCOPE_VDOM_ROOT]
            vdom_controls = [c for c in controls if c.scope == SCOPE_VDOM]

            findings: List[Dict[str, Any]] = []
            raw_dump: Dict[str, str] = {}

            with cls._timed_operation("SSH collection + evaluation"):
                with FortiGateSSHClient(target_ip, ssh_username, ssh_password, port=ssh_port) as client:
                    client.connect()
                    vdom_enabled = client.is_vdom_enabled()

                    # Resolve the VDOMs whose per-VDOM controls we evaluate.
                    if not vdom_enabled:
                        target_vdoms: List[Optional[str]] = [None]
                    elif vdom:
                        target_vdoms = [vdom]
                    else:
                        target_vdoms = client.enumerate_vdoms() or ["root"]

                    logger.info(
                        "FortiGate %s: vdom_mode=%s target_vdoms=%s",
                        target_ip, vdom_enabled, target_vdoms,
                    )

                    # --- global scope (once) ---
                    g_out = cls._safe_collect(client, cls._commands_for(global_controls), SCOPE_GLOBAL, None)
                    g_label = _GLOBAL_LABEL if vdom_enabled else None
                    for c in global_controls:
                        findings.append(cls._evaluate_control(c, g_out, g_label))
                    cls._merge_dump(raw_dump, g_out, SCOPE_GLOBAL, g_label)

                    # --- root VDOM scope (once) ---
                    r_out = cls._safe_collect(client, cls._commands_for(root_controls), SCOPE_VDOM_ROOT, None)
                    r_label = _ROOT_LABEL if vdom_enabled else None
                    for c in root_controls:
                        findings.append(cls._evaluate_control(c, r_out, r_label))
                    cls._merge_dump(raw_dump, r_out, SCOPE_VDOM_ROOT, r_label)

                    # --- per-VDOM scope (once per target VDOM) ---
                    v_cmds = cls._commands_for(vdom_controls)
                    for tv in target_vdoms:
                        v_out = cls._safe_collect(client, v_cmds, SCOPE_VDOM, tv)
                        v_label = tv if vdom_enabled else None
                        for c in vdom_controls:
                            findings.append(cls._evaluate_control(c, v_out, v_label))
                        cls._merge_dump(raw_dump, v_out, SCOPE_VDOM, v_label)

            # Compliance metrics — Manual controls are scored like Automated ones,
            # but NOT_APPLICABLE controls (na_gate matched: feature off/absent) are
            # excluded from the score entirely, so an off feature neither passes nor
            # drags the percentage down. total_checks still counts every result row.
            na = sum(1 for f in findings if not f.get("applicable", True))
            passed = sum(1 for f in findings if f.get("applicable", True) and f["passed"])
            total = len(findings)
            failed = total - passed - na
            scored = passed + failed
            compliance_pct = round(100.0 * passed / scored, 2) if scored else 0.0

            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = total
            session.passed_checks = passed
            session.failed_checks = failed
            session.error_checks = 0
            session.compliance_pct = compliance_pct
            session.turbo_dump = json.dumps(raw_dump, indent=2, default=str)[:1_000_000]
            db.commit()

            with cls._timed_operation("Insert audit results"):
                cls._bulk_insert_results(db, session.id, findings)

            db.refresh(session)
            logger.info(
                "Audit done for asset %s (%s): %s%% (%s/%s) across %s vdom target(s)",
                asset_id, target_ip, compliance_pct, passed, total, len(target_vdoms),
            )
            return session

        except Exception as e:
            session.status = "failed"
            session.completed_at = datetime.now(timezone.utc)
            msg = str(e)
            if "password" in msg.lower() or "secret" in msg.lower():
                msg = f"{type(e).__name__}: Authentication or connection error"
            else:
                msg = f"{type(e).__name__}: {msg}"
            session.connection_error = msg[:500]
            db.commit()
            db.refresh(session)
            # Log the FULL traceback (type + message + file:line), not just the
            # exception class name — a bare "TypeError" is undiagnosable.
            logger.error("Audit failed for asset %s (%s): %s: %s",
                         asset_id, target_ip, type(e).__name__, e, exc_info=True)
            raise

    @classmethod
    def _merge_dump(cls, dump: Dict[str, str], outputs: Dict[str, str], scope: str, label: Optional[str]) -> None:
        for cmd, out in outputs.items():
            dump[f"{scope}:{label or '-'}:{cmd}"] = cls._redact(out)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    @classmethod
    def _bulk_insert_results(cls, db: Session, session_id: int, findings: List[Dict[str, Any]]) -> None:
        results: List[AuditResult] = []
        for f in findings:
            # Every control is scored — Manual controls get a PASS/FAIL like the
            # Automated ones. The only NOT_APPLICABLE cases are controls whose
            # na_gate matched (the underlying feature is switched off).
            if not f.get("applicable", True):
                status = CheckStatus.NOT_APPLICABLE
            else:
                status = CheckStatus.PASS if f["passed"] else CheckStatus.FAIL
            results.append(AuditResult(
                session_id=session_id,
                check_number=f["control_id"],
                check_title=f["title"],
                severity=f["severity"],
                level=f["level"],
                vdom=f["vdom"],
                status=status,
                # Column is TEXT; the slice is only a runaway guard. Must stay
                # above the per-policy evidence cap (60k) — the hardening UI
                # parses failing Policy IDs from this field, so truncation here
                # silently hides policies from the fix multi-select.
                evidence_snippet=(f["evidence"][:65_000] if f["evidence"] else None),
                checked_at=datetime.now(timezone.utc),
            ))
            if len(results) >= cls.BATCH_SIZE:
                db.bulk_save_objects(results)
                db.commit()
                results = []
        if results:
            db.bulk_save_objects(results)
            db.commit()

    # ------------------------------------------------------------------
    # VDOM discovery (for the UI before an audit/hardening run)
    # ------------------------------------------------------------------
    @staticmethod
    def discover_vdoms(db: Session, asset_id: int, ssh_username: str, ssh_password: str,
                       ssh_port: int = 22) -> List[str]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")
        with FortiGateSSHClient(asset.ip_address, ssh_username, ssh_password, port=ssh_port) as client:
            vdoms = client.enumerate_vdoms()
        logger.info("Discovered %s VDOMs on %s: %s", len(vdoms), asset.ip_address, vdoms)
        return vdoms

    # ------------------------------------------------------------------
    # Session / result accessors (unchanged surface)
    # ------------------------------------------------------------------
    @staticmethod
    def get_audit_session(db: Session, session_id: int) -> Optional[AuditSession]:
        return db.query(AuditSession).filter(AuditSession.id == session_id).first()

    @staticmethod
    def get_audit_results(db: Session, session_id: int) -> List[AuditResult]:
        return db.query(AuditResult).filter(AuditResult.session_id == session_id).all()

    @staticmethod
    def get_all_sessions(db: Session, device_type: Optional[DeviceType] = None,
                         limit: int = 50, offset: int = 0) -> List[AuditSession]:
        query = db.query(AuditSession)
        if device_type:
            query = query.filter(AuditSession.device_type == device_type)
        return query.order_by(AuditSession.started_at.desc()).offset(offset).limit(limit).all()

    @staticmethod
    def get_sessions_count(db: Session, device_type: DeviceType = DeviceType.FORTINET) -> int:
        return db.query(AuditSession).filter(AuditSession.device_type == device_type).count()

    @staticmethod
    def get_session_summary(db: Session, session_id: int) -> Optional[Dict[str, Any]]:
        session = FortinetAuditService.get_audit_session(db, session_id)
        if not session:
            return None
        asset = db.query(Asset).filter(Asset.id == session.asset_id).first() if session.asset_id else None
        duration_seconds = None
        if session.started_at and session.completed_at:
            duration_seconds = (session.completed_at - session.started_at).total_seconds()
        return {
            "session_id": session.id,
            "job_name": session.job_name,
            "asset_id": session.asset_id,
            "asset_name": asset.asset_name if asset else None,
            "target_ip": session.target_ip,
            "device_type": session.device_type.value,
            "status": session.status,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "duration_seconds": duration_seconds,
            "compliance": {
                "total_checks": session.total_checks or 0,
                "passed": session.passed_checks or 0,
                "failed": session.failed_checks or 0,
                "compliance_pct": session.compliance_pct or 0.0,
            },
            "connection_error": session.connection_error,
        }

    @staticmethod
    def delete_audit_session(db: Session, session_id: int) -> bool:
        session = FortinetAuditService.get_audit_session(db, session_id)
        if not session:
            return False
        db.query(AuditResult).filter(AuditResult.session_id == session_id).delete()
        db.delete(session)
        db.commit()
        logger.info("Deleted audit session %s", session_id)
        return True
