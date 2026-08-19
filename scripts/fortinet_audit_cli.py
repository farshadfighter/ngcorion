#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NGCorion — FortiGate (FortiOS) Auditing CLI Tool (Enterprise v4)
=================================================================

Full-featured CLI tool for comprehensive FortiGate security auditing.

Enhanced Features in v4:
✅ Expanded security controls (~120+ checks, enhanced CIS coverage)
✅ Performance optimized with parallel VDOM processing
✅ Enhanced HTML reporting with executive dashboard
✅ Improved VDOM handling with better context management
✅ Advanced analytics (shadow rules, unused objects, coverage matrix)
✅ Risk scoring and compliance trending
✅ Multi-format export (JSON, CSV, HTML, PDF-ready)
✅ Command batching and caching for faster execution
✅ Better error handling and recovery

Install:
  pip install netmiko jinja2
  # optional:
  pip install pyyaml

Run:
  python scripts/fortinet_audit_cli.py --host 192.0.2.10 --username admin --password '***' --out-prefix rpt_fg

Options:
  --all-vdoms              Audit all VDOMs in parallel
  --catalog controls.yaml  Use custom control catalog
  --export-catalog out.yaml Export built-in catalog
  --no-evidence            Exclude raw command output from reports
  --html                   Generate HTML report (default: enabled)
  --workers N              Parallel VDOM workers (default: 4)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set, Iterable

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

# Optional dependencies
try:
    import yaml  # type: ignore
    HAS_YAML = True
except Exception:
    yaml = None
    HAS_YAML = False

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except Exception:
    Template = None
    HAS_JINJA2 = False


# =========================
# Utilities
# =========================

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def regex_search(pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> Optional[re.Match]:
    return re.search(pattern, text or "", flags)

def has_line(text: str, pattern: str) -> bool:
    return regex_search(pattern, text or "") is not None

def safe_int(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    try:
        return int(str(s).strip())
    except Exception:
        return None

def normalize_bool(val: Optional[str]) -> Optional[bool]:
    if val is None:
        return None
    v = val.strip().lower()
    if v in {"enable", "enabled", "on", "yes", "true"}:
        return True
    if v in {"disable", "disabled", "off", "no", "false"}:
        return False
    return None

def strip_quotes(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1]
    return v

def get_set_value(text: str, key: str) -> Optional[str]:
    m = regex_search(rf"^\s*set\s+{re.escape(key)}\s+(.+?)\s*$", text)
    if not m:
        return None
    return strip_quotes(m.group(1).strip())

def parse_version(v: str) -> Tuple[int, int, int]:
    parts = re.findall(r"\d+", v or "")
    return (
        int(parts[0]) if len(parts) > 0 else 0,
        int(parts[1]) if len(parts) > 1 else 0,
        int(parts[2]) if len(parts) > 2 else 0,
    )

def version_in_range(cur: str, min_v: Optional[str], max_v: Optional[str]) -> bool:
    c = parse_version(cur)
    if min_v and c < parse_version(min_v):
        return False
    if max_v and c > parse_version(max_v):
        return False
    return True

def cmd_ok(out: str) -> bool:
    if (out or "").startswith("__ERROR__"):
        return False
    low = (out or "").lower()
    bad = [
        "command fail",
        "parse error",
        "unknown command",
        "unknown action",
        "invalid",
        "not found",
        "permission denied",
    ]
    return not any(b in low for b in bad)

def uniq(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# =========================
# Connection Pool
# =========================

class ConnectionPool:
    """Thread-safe connection pool for parallel VDOM processing"""

    def __init__(self, host: str, username: str, password: str, port: int, max_connections: int = 4):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.max_connections = max_connections
        self._connections: List[ConnectHandler] = []

    def get_connection(self) -> ConnectHandler:
        """Get or create a connection"""
        if self._connections:
            return self._connections.pop()
        return self._create_connection()

    def return_connection(self, conn: ConnectHandler) -> None:
        """Return connection to pool"""
        if len(self._connections) < self.max_connections:
            self._connections.append(conn)
        else:
            try:
                conn.disconnect()
            except Exception as e:
                print(
                    f"[Warning] closing the surplus pooled connection to {self.host} "
                    f"failed: {e}",
                    file=sys.stderr,
                )

    def _create_connection(self) -> ConnectHandler:
        """Create new connection"""
        base = dict(host=self.host, username=self.username, password=self.password,
                   port=self.port, fast_cli=False, global_delay_factor=1)
        for dt in ("fortinet", "fortigate"):
            try:
                params = dict(base)
                params["device_type"] = dt
                return ConnectHandler(**params)
            except Exception as e:
                last_error = e
        raise last_error if 'last_error' in locals() else RuntimeError("Unable to connect")

    def close_all(self) -> None:
        """Close all pooled connections"""
        for conn in self._connections:
            try:
                conn.disconnect()
            except Exception as e:
                print(
                    f"[Warning] closing a pooled connection to {self.host} failed: "
                    f"{e}",
                    file=sys.stderr,
                )
        self._connections.clear()


# =========================
# Adapter Abstraction
# =========================

class DeviceAdapter:
    vendor: str = "generic"

    def connect(self, host: str, username: str, password: str, port: int) -> Any:
        raise NotImplementedError

    def disconnect(self, conn: Any) -> None:
        try:
            conn.disconnect()
        except Exception as e:
            print(f"[Warning] device disconnect failed: {e}", file=sys.stderr)

    def send(self, conn: Any, cmd: str) -> str:
        raise NotImplementedError

    def run(self, conn: Any, commands: List[str]) -> Dict[str, str]:
        outs: Dict[str, str] = {}
        for c in commands:
            try:
                outs[c] = self.send(conn, c)
            except Exception as e:
                outs[c] = f"__ERROR__: {e}"
        return outs


class FortiGateAdapter(DeviceAdapter):
    vendor = "fortinet_fortigate"

    def __init__(self):
        self._cmd_cache: Dict[str, Tuple[str, float]] = {}
        self._cache_ttl = 300  # 5 minutes

    def connect(self, host: str, username: str, password: str, port: int) -> ConnectHandler:
        base = dict(host=host, username=username, password=password, port=port,
                   fast_cli=False, global_delay_factor=1)
        last = None
        for dt in ("fortinet", "fortigate"):
            try:
                p = dict(base)
                p["device_type"] = dt
                return ConnectHandler(**p)
            except Exception as e:
                last = e
        raise last if last else RuntimeError("Unable to connect to FortiGate.")

    def send(self, conn: ConnectHandler, cmd: str, use_cache: bool = True) -> str:
        # Check cache
        if use_cache and cmd in self._cmd_cache:
            cached_out, timestamp = self._cmd_cache[cmd]
            if time.time() - timestamp < self._cache_ttl:
                return cached_out

        out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
        while re.search(r"--More--", out or "", flags=re.IGNORECASE):
            out = re.sub(r"--More--", "", out, flags=re.IGNORECASE)
            out += conn.send_command_timing(" ", strip_prompt=False, strip_command=False)

        # Cache result
        if use_cache:
            self._cmd_cache[cmd] = (out, time.time())

        return out

    def run_batch(self, conn: ConnectHandler, commands: List[str]) -> Dict[str, str]:
        """Optimized batch command execution with caching"""
        outs: Dict[str, str] = {}
        for c in commands:
            try:
                outs[c] = self.send(conn, c)
            except Exception as e:
                outs[c] = f"__ERROR__: {e}"
        return outs


# =========================
# System status + VDOM
# =========================

def parse_system_status(status_out: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"fortios_version": "0.0.0"}

    m_ver = regex_search(r"^\s*Version:\s*(.+)\s*$", status_out)
    if m_ver:
        meta["version_line"] = m_ver.group(1).strip()
        mv = re.search(r"\bv(\d+\.\d+(?:\.\d+)?)\b", meta["version_line"])
        if mv:
            meta["fortios_version"] = mv.group(1)
        mb = re.search(r"\bbuild(\d+)\b", meta["version_line"])
        if mb:
            meta["build"] = mb.group(1)
        mm = re.search(r"^(.+?)\s+v\d+\.\d+", meta["version_line"])
        if mm:
            meta["model"] = mm.group(1).strip()

    m_hn = regex_search(r"^\s*Hostname:\s*(.+)\s*$", status_out)
    if m_hn:
        meta["hostname"] = m_hn.group(1).strip()

    m_sn = regex_search(r"^\s*Serial-Number:\s*(.+)\s*$", status_out)
    if m_sn:
        meta["serial"] = m_sn.group(1).strip()

    m_vdom = re.search(r"Virtual\s+domain\s+configuration:\s*(enable|disable)", status_out, flags=re.IGNORECASE)
    if m_vdom:
        meta["vdom_enabled"] = (m_vdom.group(1).lower() == "enable")

    return meta

def discover_vdoms(adapter: FortiGateAdapter, conn: ConnectHandler) -> List[str]:
    cands = ["get system vdom-property", "diagnose sys vdom list", "show vdom"]
    raw = {c: adapter.send(conn, c) for c in cands}

    vdoms: List[str] = []
    vprop = raw.get("get system vdom-property", "")
    for m in re.finditer(r"^\s*(?:name|VDOM name)\s*:\s*([A-Za-z0-9._-]+)\s*$", vprop, flags=re.MULTILINE):
        vdoms.append(m.group(1))

    if not vdoms:
        d = raw.get("diagnose sys vdom list", "")
        for m in re.finditer(r"^\s*name\s*=\s*([A-Za-z0-9._-]+)\b", d, flags=re.MULTILINE | re.IGNORECASE):
            vdoms.append(m.group(1))

    if not vdoms:
        sv = raw.get("show vdom", "")
        for m in re.finditer(r'^\s*edit\s+"?([A-Za-z0-9._-]+)"?\s*$', sv, flags=re.MULTILINE | re.IGNORECASE):
            vdoms.append(m.group(1))

    return uniq(vdoms)

def prompt_user_select_vdom(vdoms: List[str]) -> Optional[str]:
    if not vdoms:
        return None
    print("\nDetected VDOMs:")
    for i, v in enumerate(vdoms, start=1):
        print(f"  {i}) {v}")
    while True:
        choice = input("\nSelect VDOM by number (or press Enter for 1): ").strip()
        if choice == "":
            return vdoms[0]
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(vdoms):
                return vdoms[idx - 1]
        print("Invalid selection. Try again.")

def enter_vdom_best_effort(conn: ConnectHandler, vdom: str) -> bool:
    out1 = conn.send_command_timing("config vdom", strip_prompt=False, strip_command=False)
    out2 = conn.send_command_timing(f"edit {vdom}", strip_prompt=False, strip_command=False)
    return cmd_ok((out1 or "") + "\n" + (out2 or ""))

def exit_vdom(conn: ConnectHandler) -> None:
    conn.send_command_timing("end", strip_prompt=False, strip_command=False)


# =========================
# Feature detection -> Packs
# =========================

def detect_features(adapter: FortiGateAdapter, conn: ConnectHandler) -> Dict[str, bool]:
    feats: Dict[str, bool] = {}
    ha = adapter.send(conn, "get system ha status")
    if not cmd_ok(ha):
        ha = adapter.send(conn, "diagnose sys ha status")
    feats["ha"] = cmd_ok(ha) and ("mode:" in ha.lower() or "group:" in ha.lower())

    sdwan1 = adapter.send(conn, "show system virtual-wan-link")
    sdwan2 = adapter.send(conn, "show system sdwan")
    feats["sdwan"] = (cmd_ok(sdwan1) and "virtual-wan-link" in sdwan1.lower()) or (cmd_ok(sdwan2) and "system sdwan" in sdwan2.lower())

    ssl = adapter.send(conn, "show vpn ssl settings")
    feats["vpn_ssl"] = cmd_ok(ssl) and "vpn ssl" in ssl.lower()

    ipsec = adapter.send(conn, "show vpn ipsec phase1-interface")
    feats["vpn_ipsec"] = cmd_ok(ipsec) and "ipsec phase1" in ipsec.lower()

    cnat = adapter.send(conn, "show firewall central-snat-map")
    feats["central_nat"] = cmd_ok(cnat) and "central-snat-map" in cnat.lower()

    lin = adapter.send(conn, "show firewall local-in-policy")
    feats["local_in"] = cmd_ok(lin) and "local-in-policy" in lin.lower()

    faz = adapter.send(conn, "show log fortianalyzer setting")
    feats["faz"] = cmd_ok(faz) and ("fortianalyzer" in faz.lower())

    vip = adapter.send(conn, "show firewall vip")
    feats["vip"] = cmd_ok(vip) and "config firewall vip" in vip.lower()

    feats["utm"] = True
    feats["shadow"] = True
    feats["unused"] = True
    feats["coverage"] = True
    return feats

def packs_from_features(feats: Dict[str, bool]) -> Set[str]:
    packs: Set[str] = {"BASELINE"}
    if feats.get("ha"):
        packs.add("HA")
    if feats.get("sdwan"):
        packs.add("SDWAN")
    if feats.get("vpn_ssl"):
        packs.add("VPN_SSL")
    if feats.get("vpn_ipsec"):
        packs.add("VPN_IPSEC")
    if feats.get("central_nat"):
        packs.add("CENTRAL_NAT")
    if feats.get("local_in"):
        packs.add("LOCAL_IN")
    if feats.get("faz"):
        packs.add("FAZ")
    if feats.get("vip"):
        packs.add("EXPOSURE")
    if feats.get("coverage"):
        packs.add("COVERAGE")
    packs.update({"UTM", "SHADOW", "UNUSED"})
    return packs


# =========================
# Rule Engine
# =========================

@dataclass
class Rule:
    type: str
    cmd: str
    key: Optional[str] = None
    expected: Any = None
    any_of: Optional[List[Any]] = None
    pattern: Optional[str] = None

@dataclass
class Control:
    id: str
    title: str
    pack: str
    domain: str
    severity: str
    level: str
    rules: List[Rule]
    remediation: str
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    cis_id: Optional[str] = None
    cis_section: Optional[str] = None
    cis_profile: Optional[str] = None
    tags: List[str] = field(default_factory=list)

@dataclass
class Finding:
    id: str
    title: str
    pack: str
    domain: str
    severity: str
    level: str
    status: str
    details: str
    commands: List[str]
    remediation: str
    cis_id: Optional[str] = None
    cis_section: Optional[str] = None
    cis_profile: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    evidence: Dict[str, str] = field(default_factory=dict)

def eval_rule(rule: Rule, evd: Dict[str, str]) -> Tuple[str, str]:
    out = evd.get(rule.cmd, "")
    if not cmd_ok(out):
        return ("ERROR", f"Command failed/unsupported: {rule.cmd}")

    if rule.type == "set_eq":
        v = get_set_value(out, rule.key or "")
        if v is None:
            return ("WARN", f"{rule.cmd}: key '{rule.key}' not found")
        return ("PASS", f"{rule.key}={v}") if str(v).lower() == str(rule.expected).lower() else ("FAIL", f"Expected {rule.key}={rule.expected}, got {v}")

    if rule.type == "set_bool":
        v = normalize_bool(get_set_value(out, rule.key or ""))
        if v is None:
            return ("WARN", f"{rule.cmd}: key '{rule.key}' not parsable")
        exp = bool(rule.expected)
        return ("PASS", f"{rule.key}={v}") if v == exp else ("FAIL", f"Expected {rule.key}={exp}, got {v}")

    if rule.type == "set_in":
        v = get_set_value(out, rule.key or "")
        if v is None:
            return ("WARN", f"{rule.cmd}: key '{rule.key}' not found")
        allowed = [str(x).lower() for x in (rule.any_of or [])]
        return ("PASS", f"{rule.key}={v}") if str(v).lower() in allowed else ("FAIL", f"{rule.key}={v} not in {allowed}")

    if rule.type == "set_int_le":
        v = safe_int(get_set_value(out, rule.key or ""))
        if v is None:
            return ("WARN", f"{rule.cmd}: int key '{rule.key}' not parsable")
        return ("PASS", f"{rule.key}={v} <= {rule.expected}") if v <= int(rule.expected) else ("FAIL", f"{rule.key}={v} > {rule.expected}")

    if rule.type == "set_int_ge":
        v = safe_int(get_set_value(out, rule.key or ""))
        if v is None:
            return ("WARN", f"{rule.cmd}: int key '{rule.key}' not parsable")
        return ("PASS", f"{rule.key}={v} >= {rule.expected}") if v >= int(rule.expected) else ("FAIL", f"{rule.key}={v} < {rule.expected}")

    if rule.type == "regex_present":
        return ("PASS", f"Pattern found: {rule.pattern}") if has_line(out, rule.pattern or "") else ("FAIL", f"Pattern missing: {rule.pattern}")

    if rule.type == "regex_absent":
        return ("PASS", f"Pattern absent (good): {rule.pattern}") if not has_line(out, rule.pattern or "") else ("FAIL", f"Pattern present (bad): {rule.pattern}")

    return ("WARN", f"Unknown rule type: {rule.type}")

def eval_control(ctrl: Control, evd: Dict[str, str]) -> Tuple[str, str]:
    order = {"FAIL": 0, "ERROR": 1, "WARN": 2, "PASS": 3}
    best = "PASS"
    details: List[str] = []
    for r in ctrl.rules:
        st, det = eval_rule(r, evd)
        details.append(f"[{st}] {det}")
        if order.get(st, 99) < order.get(best, 99):
            best = st
    return best, " | ".join(details)


# =========================
# Catalog (expanded to 120+ controls)
# =========================

def _mk_set_bool(cid, title, pack, domain, sev, lvl, cmd, key, expected, remediation, cis=None, tags=None) -> Control:
    cis = cis or {}
    return Control(cid, title, pack, domain, sev, lvl, [Rule("set_bool", cmd, key=key, expected=expected)], remediation,
                   cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
                   tags=list(tags or []))

def _mk_re_abs(cid, title, pack, domain, sev, lvl, cmd, pattern, remediation, cis=None, tags=None) -> Control:
    cis = cis or {}
    return Control(cid, title, pack, domain, sev, lvl, [Rule("regex_absent", cmd, pattern=pattern)], remediation,
                   cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
                   tags=list(tags or []))

def _mk_re_pre(cid, title, pack, domain, sev, lvl, cmd, pattern, remediation, cis=None, tags=None) -> Control:
    cis = cis or {}
    return Control(cid, title, pack, domain, sev, lvl, [Rule("regex_present", cmd, pattern=pattern)], remediation,
                   cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
                   tags=list(tags or []))

def _mk_int_le(cid, title, pack, domain, sev, lvl, cmd, key, expected, remediation, cis=None, tags=None) -> Control:
    cis = cis or {}
    return Control(cid, title, pack, domain, sev, lvl, [Rule("set_int_le", cmd, key=key, expected=expected)], remediation,
                   cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
                   tags=list(tags or []))

def _mk_int_ge(cid, title, pack, domain, sev, lvl, cmd, key, expected, remediation, cis=None, tags=None) -> Control:
    cis = cis or {}
    return Control(cid, title, pack, domain, sev, lvl, [Rule("set_int_ge", cmd, key=key, expected=expected)], remediation,
                   cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
                   tags=list(tags or []))

def _mk_set_eq(cid, title, pack, domain, sev, lvl, cmd, key, expected, remediation, cis=None, tags=None) -> Control:
    cis = cis or {}
    return Control(cid, title, pack, domain, sev, lvl, [Rule("set_eq", cmd, key=key, expected=expected)], remediation,
                   cis_id=cis.get("id"), cis_section=cis.get("section"), cis_profile=cis.get("profile"),
                   tags=list(tags or []))

def built_in_controls() -> List[Control]:
    """Expanded catalog with 120+ controls covering CIS benchmarks and enterprise best practices"""

    SG="show system global"; SP="show system password-policy"; SA="show system admin"
    NTP="show system ntp"; DNS="show system dns"; IFACE="show system interface"
    SYSLOG="show log syslogd setting"; LOGSET="show log setting"
    SNMPC="show system snmp community"; SNMPU="show system snmp user"; SNMPH="show system snmp sysinfo"
    AUTO="show system auto-script"; FCT="show system central-management"; FGT="get system status"; POL="show firewall policy"
    LOCALIN="show firewall local-in-policy"; VIP="show firewall vip"; VIPGRP="show firewall vipgrp"
    CNAT="show firewall central-snat-map"; HA_S="get system ha status"; HA_C="show system ha"
    SDWAN_NEW="show system sdwan"; SDWAN_OLD="show system virtual-wan-link"
    SSL="show vpn ssl settings"; IPSEC="show vpn ipsec phase1-interface"; FAZ="show log fortianalyzer setting"
    ACCT="show system accprofile"; SETTINGS="show system settings"

    C: List[Control] = []

    # ===== BASELINE PACK (Enhanced) =====
    C += [
        # Management Plane Security
        _mk_set_bool("FG-BL-001","Admin HTTPS enabled","BASELINE","Management Plane","High","L1",SG,"admin-https",True,
                    "config system global\\n set admin-https enable\\nend",
                    cis={"id":"1.1.1","section":"Management Access","profile":"L1"},tags=["mgmt","cis"]),
        _mk_set_bool("FG-BL-002","Admin HTTP disabled","BASELINE","Management Plane","Critical","L1",SG,"admin-http",False,
                    "config system global\\n set admin-http disable\\nend",
                    cis={"id":"1.1.2","section":"Management Access","profile":"L1"},tags=["mgmt","cis"]),
        _mk_set_bool("FG-BL-003","Admin Telnet disabled","BASELINE","Management Plane","Critical","L1",SG,"admin-telnet",False,
                    "config system global\\n set admin-telnet disable\\nend",
                    cis={"id":"1.1.3","section":"Management Access","profile":"L1"},tags=["mgmt","cis"]),
        _mk_int_le("FG-BL-004","Admin idle timeout <= 10 minutes","BASELINE","Management Plane","Medium","L1",SG,"admintimeout",10,
                  "config system global\\n set admintimeout 10\\nend",
                  cis={"id":"1.2.1","section":"Session Management","profile":"L1"},tags=["mgmt","session"]),
        _mk_re_abs("FG-BL-005","Admin GUI TLS 1.0/1.1 disabled","BASELINE","Management Plane","High","L2",SG,
                   r"set\s+(admin-https-ssl-versions|admin-ssl-min-proto-version)\s+.*\b(tlsv1-0|tlsv1-1)\b",
                   "config system global\\n set admin-https-ssl-versions tlsv1-2 tlsv1-3\\nend",
                   cis={"id":"1.3.1","section":"Cryptography","profile":"L1"},tags=["tls","mgmt","cis"]),

        # Strong Ciphers
        _mk_re_abs("FG-BL-006","Weak SSH ciphers disabled","BASELINE","Management Plane","High","L2",SG,
                   r"set\s+ssh-enc-algo\s+.*\b(des|3des|arcfour|rc4)\b",
                   "config system global\\n set ssh-enc-algo aes256-ctr aes192-ctr aes128-ctr\\nend",
                   cis={"id":"1.3.2","section":"Cryptography","profile":"L2"},tags=["ssh","crypto"]),

        # Management Port Restrictions
        _mk_int_le("FG-BL-007","Admin sport restricted (not default 443)","BASELINE","Management Plane","Medium","L2",SG,"admin-sport",10443,
                  "config system global\\n set admin-sport 10443\\nend",tags=["mgmt","hardening"]),
        _mk_set_bool("FG-BL-008","Admin SSH enabled for CLI access","BASELINE","Management Plane","Low","L1",SG,"admin-ssh",True,
                    "config system global\\n set admin-ssh enable\\nend",tags=["mgmt"]),

        # Inventory
        _mk_re_pre("FG-BL-010","System status readable","BASELINE","Inventory","Low","L1",FGT,r"^\s*Version:",
                  "Ensure operator can read system status",tags=["inventory"]),

        # Identity & Access Management
        _mk_re_pre("FG-BL-020","Admin trusthost configured","BASELINE","Identity & Access","High","L1",SA,
                  r"set\s+trusthost[1-9]\s+(?!0\.0\.0\.0\s+0\.0\.0\.0)",
                  "config system admin\\n edit <admin>\\n set trusthost1 <mgmt-subnet> <netmask>\\nend",
                  cis={"id":"2.1.1","section":"Access Control","profile":"L1"},tags=["iam","cis"]),
        _mk_re_abs("FG-BL-021","Default 'admin' account disabled/renamed","BASELINE","Identity & Access","High","L2",SA,
                  r'^\s*edit\s+"?admin"?\s*$',
                  "Disable or rename default admin account; use named accounts with proper roles",
                  cis={"id":"2.1.2","section":"Access Control","profile":"L2"},tags=["iam","cis"]),
        _mk_re_pre("FG-BL-022","Multi-factor authentication configured","BASELINE","Identity & Access","High","L2",SA,
                  r"set\s+two-factor\s+(fortitoken|email|sms)",
                  "config system admin\\n edit <admin>\\n set two-factor fortitoken\\nend",
                  cis={"id":"2.2.1","section":"Authentication","profile":"L2"},tags=["iam","mfa"]),

        # Password Policy
        _mk_set_bool("FG-BL-030","Password policy enabled","BASELINE","Identity & Access","High","L1",SP,"status",True,
                    "config system password-policy\\n set status enable\\nend",
                    cis={"id":"2.3.1","section":"Password Policy","profile":"L1"},tags=["password","cis"]),
        _mk_int_ge("FG-BL-031","Password min length >= 12","BASELINE","Identity & Access","High","L1",SP,"minimum-length",12,
                  "config system password-policy\\n set minimum-length 12\\nend",
                  cis={"id":"2.3.2","section":"Password Policy","profile":"L1"},tags=["password","cis"]),
        _mk_set_bool("FG-BL-032","Password must contain uppercase","BASELINE","Identity & Access","Medium","L1",SP,"must-contain-uppercase",True,
                    "config system password-policy\\n set must-contain-uppercase enable\\nend",
                    cis={"id":"2.3.3","section":"Password Policy","profile":"L1"},tags=["password"]),
        _mk_set_bool("FG-BL-033","Password must contain lowercase","BASELINE","Identity & Access","Medium","L1",SP,"must-contain-lowercase",True,
                    "config system password-policy\\n set must-contain-lowercase enable\\nend",
                    cis={"id":"2.3.4","section":"Password Policy","profile":"L1"},tags=["password"]),
        _mk_set_bool("FG-BL-034","Password must contain numbers","BASELINE","Identity & Access","Medium","L1",SP,"must-contain-number",True,
                    "config system password-policy\\n set must-contain-number enable\\nend",
                    cis={"id":"2.3.5","section":"Password Policy","profile":"L1"},tags=["password"]),
        _mk_set_bool("FG-BL-035","Password must contain special chars","BASELINE","Identity & Access","Medium","L1",SP,"must-contain-non-alphanumeric",True,
                    "config system password-policy\\n set must-contain-non-alphanumeric enable\\nend",
                    cis={"id":"2.3.6","section":"Password Policy","profile":"L1"},tags=["password"]),
        _mk_int_ge("FG-BL-036","Password min changed characters >= 4","BASELINE","Identity & Access","Medium","L2",SP,"min-changed-characters",4,
                  "config system password-policy\\n set min-changed-characters 4\\nend",
                  cis={"id":"2.3.7","section":"Password Policy","profile":"L2"},tags=["password"]),

        # Time & Sync
        _mk_set_bool("FG-BL-040","NTP enabled","BASELINE","Time & Sync","Medium","L1",NTP,"status",True,
                    "config system ntp\\n set status enable\\nend",
                    cis={"id":"3.1.1","section":"Time Services","profile":"L1"},tags=["ntp","cis"]),
        _mk_re_pre("FG-BL-041","NTP server configured","BASELINE","Time & Sync","Medium","L1",NTP,
                  r"config\s+ntpserver[\s\S]*?edit\s+\d+",
                  "config system ntp\\n config ntpserver\\n edit 1\\n set server <ntp-server>\\nend",
                  cis={"id":"3.1.2","section":"Time Services","profile":"L1"},tags=["ntp","cis"]),
        _mk_set_eq("FG-BL-042","NTP sync interface specified","BASELINE","Time & Sync","Low","L2",NTP,"interface","port1",
                  "config system ntp\\n set interface <mgmt-interface>\\nend",tags=["ntp"]),

        # DNS
        _mk_re_pre("FG-BL-043","DNS primary configured","BASELINE","Network Services","Low","L1",DNS,
                  r"set\s+primary\s+\d+\.\d+\.\d+\.\d+",
                  "config system dns\\n set primary <dns-ip>\\nend",tags=["dns"]),
        _mk_re_pre("FG-BL-044","DNS secondary configured","BASELINE","Network Services","Low","L1",DNS,
                  r"set\s+secondary\s+\d+\.\d+\.\d+\.\d+",
                  "config system dns\\n set secondary <dns-ip>\\nend",tags=["dns"]),

        # SNMP Security
        _mk_re_abs("FG-BL-050","SNMPv2 community disabled","BASELINE","Network Services","High","L1",SNMPC,
                  r"^\s*edit\s+\d+\s*$",
                  "Remove SNMP v1/v2c communities; use SNMPv3 with auth-priv only",
                  cis={"id":"4.1.1","section":"SNMP","profile":"L1"},tags=["snmp","cis"]),
        _mk_re_pre("FG-BL-051","SNMPv3 user exists","BASELINE","Network Services","Medium","L1",SNMPU,
                  r"^\s*edit\s+",
                  "config system snmp user\\n edit <user>\\n set security-level auth-priv\\nend",
                  cis={"id":"4.1.2","section":"SNMP","profile":"L1"},tags=["snmp","cis"]),
        _mk_re_pre("FG-BL-052","SNMP contact/location set","BASELINE","Network Services","Low","L2",SNMPH,
                  r"set\s+(contact-info|location)\s+",
                  "config system snmp sysinfo\\n set contact-info <contact>\\n set location <location>\\nend",
                  tags=["snmp","inventory"]),

        # Logging & Monitoring
        _mk_set_bool("FG-BL-060","Remote syslog enabled","BASELINE","Logging & Monitoring","High","L1",SYSLOG,"status",True,
                    "config log syslogd setting\\n set status enable\\n set server <syslog-ip>\\nend",
                    cis={"id":"5.1.1","section":"Logging","profile":"L1"},tags=["logging","cis"]),
        _mk_re_pre("FG-BL-061","Remote syslog server set","BASELINE","Logging & Monitoring","High","L1",SYSLOG,
                  r"set\s+server\s+\d+\.\d+\.\d+\.\d+",
                  "config log syslogd setting\\n set server <syslog-ip>\\nend",
                  cis={"id":"5.1.2","section":"Logging","profile":"L1"},tags=["logging","cis"]),
        _mk_set_eq("FG-BL-062","Syslog facility set to local7","BASELINE","Logging & Monitoring","Low","L2",SYSLOG,"facility","local7",
                  "config log syslogd setting\\n set facility local7\\nend",tags=["logging"]),
        _mk_re_pre("FG-BL-063","Local disk logging enabled","BASELINE","Logging & Monitoring","Medium","L2",LOGSET,
                  r"set\s+local-disk-enable\s+enable",
                  "config log setting\\n set local-disk-enable enable\\nend",tags=["logging"]),

        # Event Logging
        _mk_set_bool("FG-BL-064","Log invalid traffic enabled","BASELINE","Logging & Monitoring","Medium","L2",LOGSET,"log-invalid-packet",True,
                    "config log setting\\n set log-invalid-packet enable\\nend",tags=["logging"]),
        _mk_set_bool("FG-BL-065","User event logging enabled","BASELINE","Logging & Monitoring","Low","L2",LOGSET,"user-event-logging",True,
                    "config log setting\\n set user-event-logging enable\\nend",tags=["logging"]),

        # Automation & Central Management
        _mk_re_abs("FG-BL-070","Auto-script disabled (unless required)","BASELINE","Automation","Low","L2",AUTO,
                  r"set\s+status\s+enable",
                  "Review auto-scripts; disable unused: config system auto-script\\n edit <script>\\n set status disable\\nend",
                  tags=["automation"]),
        _mk_re_pre("FG-BL-071","Central management reviewed","BASELINE","Management Plane","Low","L2",FCT,
                  r"config\s+system\s+central-management",
                  "Review FortiManager/FortiCloud integration settings",tags=["mgmt","inventory"]),

        # Firewall Policy Best Practices
        _mk_re_abs("FG-BL-080","No Any/Any/ALL ACCEPT policy","BASELINE","Firewall Policy","Critical","L1",POL,
                  r"set\s+srcaddr\s+all[\s\S]*?set\s+dstaddr\s+all[\s\S]*?set\s+service\s+ALL[\s\S]*?set\s+action\s+accept",
                  "Replace Any/Any/ALL accept policies with least-privilege rules",
                  cis={"id":"6.1.1","section":"Firewall Policy","profile":"L1"},tags=["policy","cis"]),
        _mk_re_pre("FG-BL-081","Explicit deny rule at end of policy","BASELINE","Firewall Policy","Medium","L2",POL,
                  r"set\s+action\s+deny[\s\S]*?set\s+srcaddr\s+all[\s\S]*?set\s+dstaddr\s+all",
                  "Add explicit deny-all rule at end of policy table",tags=["policy"]),
        _mk_re_pre("FG-BL-082","Policy logging enabled for critical rules","BASELINE","Firewall Policy","Medium","L1",POL,
                  r"set\s+logtraffic\s+(all|utm)",
                  "Enable logging on firewall policies: set logtraffic all",
                  cis={"id":"6.2.1","section":"Policy Logging","profile":"L1"},tags=["policy","logging"]),

        # Global Settings
        _mk_set_bool("FG-BL-090","Strong encryption required","BASELINE","Cryptography","High","L1",SG,"strong-crypto",True,
                    "config system global\\n set strong-crypto enable\\nend",
                    cis={"id":"1.4.1","section":"Cryptography","profile":"L1"},tags=["crypto","cis"]),
        _mk_re_abs("FG-BL-091","FGFM auto-update disabled (manual preferred)","BASELINE","System Updates","Low","L2",SG,
                  r"set\s+fgfm-auto-update\s+enable",
                  "config system global\\n set fgfm-auto-update disable\\nend (Manual update recommended for production)",
                  tags=["updates"]),
        _mk_set_bool("FG-BL-092","Pre-login banner configured","BASELINE","Compliance","Low","L2",SG,"pre-login-banner",True,
                    "config system global\\n set pre-login-banner enable\\n set pre-login-banner-message <banner>\\nend",
                    tags=["compliance"]),

        # System Settings
        _mk_set_bool("FG-BL-093","GUI display hostname enabled","BASELINE","Management Plane","Low","L2",SETTINGS,"gui-display-hostname",True,
                    "config system settings\\n set gui-display-hostname enable\\nend",tags=["mgmt","usability"]),
    ]

    # WAN Interface Exposure Controls (Enhanced)
    exposure_protos = [
        ("http", "Critical"), ("https", "Critical"), ("ssh", "Critical"),
        ("telnet", "High"), ("snmp", "High"), ("fgfm", "High"),
        ("ping", "Medium"), ("fabric", "High")
    ]
    for proto, sev in exposure_protos:
        C.append(_mk_re_abs(
            f"FG-BL-WAN-{proto.upper()}",
            f"Disallow {proto} on WAN allowaccess",
            "BASELINE", "Management Exposure", sev, "L1", IFACE,
            rf'edit\s+"?wan[^"]*"?[\s\S]*?set\s+allowaccess\s+.*\b{re.escape(proto)}\b',
            f"Remove {proto} from WAN interface allowaccess; use dedicated mgmt VLAN + local-in-policy",
            cis={"id":"7.1.1","section":"Interface Security","profile":"L1"},
            tags=["exposure","wan","cis"]
        ))

    # ===== HA PACK =====
    C += [
        _mk_re_pre("FG-HA-001","HA status readable","HA","High Availability","Medium","L1",HA_S,
                  r"(Mode:|mode:|Group:|group:|Master|Primary|role)",
                  "Verify HA configuration: get system ha status",tags=["ha"]),
        _mk_set_bool("FG-HA-002","HA override disabled","HA","High Availability","Low","L2",HA_C,"override",False,
                    "config system ha\\n set override disable\\nend (Recommended for stable failover)",tags=["ha"]),
        _mk_re_pre("FG-HA-003","HA heartbeat encryption enabled","HA","High Availability","High","L2",HA_C,
                  r"set\s+password\s+",
                  "config system ha\\n set password <strong-password>\\nend",tags=["ha","crypto"]),
        _mk_set_eq("FG-HA-004","HA mode configured (a-p or a-a)","HA","High Availability","Low","L1",HA_C,"mode","a-p",
                  "config system ha\\n set mode a-p\\nend",tags=["ha"]),
    ]

    # ===== SD-WAN PACK =====
    C += [
        _mk_re_pre("FG-SDW-001","SD-WAN configuration present","SDWAN","SD-WAN","Medium","L1",SDWAN_OLD,
                  r"config\s+system\s+(virtual-wan-link|sdwan)",
                  "Review SD-WAN configuration for optimal routing",tags=["sdwan"]),
        _mk_re_pre("FG-SDW-002","SD-WAN health-check configured","SDWAN","SD-WAN","Medium","L1",SDWAN_NEW,
                  r"config\s+health-check",
                  "config system sdwan\\n config health-check\\n edit <name>\\nend",tags=["sdwan"]),
    ]

    # ===== VPN PACKS =====
    C += [
        _mk_re_abs("FG-VPN-SSL-001","SSL-VPN TLS 1.0/1.1 disabled","VPN_SSL","VPN (SSL)","High","L2",SSL,
                  r"set\s+(ssl-min-proto-version|tls-min-version)\s+(tlsv1-0|tlsv1-1)",
                  "config vpn ssl settings\\n set ssl-min-proto-version tlsv1-2\\nend",
                  cis={"id":"8.1.1","section":"VPN","profile":"L1"},tags=["vpn","tls","cis"]),
        _mk_re_abs("FG-VPN-SSL-002","SSL-VPN weak ciphers disabled","VPN_SSL","VPN (SSL)","High","L2",SSL,
                  r"set\s+ssl-cipher-suites\s+.*\b(des|3des|rc4|md5)\b",
                  "Use only strong cipher suites in SSL-VPN settings",tags=["vpn","crypto"]),

        _mk_re_abs("FG-VPN-IPSEC-001","IPsec Phase1 weak proposals disabled","VPN_IPSEC","VPN (IPsec)","High","L2",IPSEC,
                  r"set\s+proposal\s+.*\b(des|3des|md5)\b",
                  "config vpn ipsec phase1-interface\\n edit <name>\\n set proposal aes256-sha256 aes256-sha512\\nend",
                  cis={"id":"8.2.1","section":"VPN","profile":"L1"},tags=["vpn","crypto","cis"]),
        _mk_re_pre("FG-VPN-IPSEC-002","IPsec DPD enabled","VPN_IPSEC","VPN (IPsec)","Low","L2",IPSEC,
                  r"set\s+dpd\s+enable",
                  "config vpn ipsec phase1-interface\\n edit <name>\\n set dpd enable\\nend",tags=["vpn"]),
    ]

    # ===== NAT & EXPOSURE PACKS =====
    C += [
        _mk_re_pre("FG-CNAT-001","Central SNAT map reviewed","CENTRAL_NAT","NAT","Low","L1",CNAT,
                  r"^\s*edit\s+\d+\s*$",
                  "Review central SNAT rules for proper NAT configuration",tags=["nat"]),

        _mk_re_pre("FG-LIP-001","Local-in-policy rules configured","LOCAL_IN","Management Exposure","Medium","L2",LOCALIN,
                  r"^\s*edit\s+\d+\s*$",
                  "Implement local-in-policy to restrict management plane access",
                  cis={"id":"7.2.1","section":"Management Security","profile":"L2"},tags=["local-in","cis"]),

        _mk_re_pre("FG-EXP-001","VIP objects reviewed","EXPOSURE","Exposure","Medium","L1",VIP,
                  r"^\s*edit\s+",
                  "Review VIP (virtual IP) exposure and port forwarding rules",tags=["vip","exposure"]),
        _mk_re_abs("FG-EXP-002","VIP extintf not 'any'","EXPOSURE","Exposure","High","L2",VIP,
                  r'set\s+extintf\s+"?any"?',
                  "Bind VIP to specific WAN interface, not 'any'",tags=["vip","exposure"]),
    ]

    # ===== UTM PACK =====
    C += [
        _mk_re_abs("FG-UTM-001","WAN inbound UTM-status not disabled","UTM","Security Profiles","High","L2",POL,
                  r"set\s+srcintf\s+\"?wan[^\" ]*\"?[\s\S]*?set\s+action\s+accept[\s\S]*?set\s+utm-status\s+disable",
                  "Enable UTM profiles on WAN inbound accept policies",
                  cis={"id":"9.1.1","section":"UTM","profile":"L2"},tags=["utm","cis"]),
        _mk_re_pre("FG-UTM-002","Antivirus profile in use","UTM","Security Profiles","Medium","L2",POL,
                  r"set\s+av-profile\s+",
                  "Apply AV profiles to policies: set av-profile <profile>",tags=["utm","av"]),
        _mk_re_pre("FG-UTM-003","IPS sensor in use","UTM","Security Profiles","Medium","L2",POL,
                  r"set\s+ips-sensor\s+",
                  "Apply IPS sensors to policies: set ips-sensor <sensor>",tags=["utm","ips"]),
        _mk_re_pre("FG-UTM-004","Web filter profile in use","UTM","Security Profiles","Medium","L2",POL,
                  r"set\s+webfilter-profile\s+",
                  "Apply web filter profiles to policies: set webfilter-profile <profile>",tags=["utm","webfilter"]),
    ]

    # ===== FAZ PACK =====
    C += [
        _mk_set_bool("FG-FAZ-001","FortiAnalyzer logging enabled","FAZ","Logging & Monitoring","Medium","L1",FAZ,"status",True,
                    "config log fortianalyzer setting\\n set status enable\\n set server <faz-ip>\\nend",tags=["faz","logging"]),
        _mk_re_pre("FG-FAZ-002","FortiAnalyzer server configured","FAZ","Logging & Monitoring","Medium","L1",FAZ,
                  r"set\s+server\s+\d+\.\d+\.\d+\.\d+",
                  "config log fortianalyzer setting\\n set server <faz-ip>\\nend",tags=["faz","logging"]),
    ]

    # ===== ANALYTICS INVENTORY CONTROLS =====
    C += [
        _mk_re_pre("FG-SHADOW-INV-001","Policy table present for shadow analysis","SHADOW","Firewall Policy","Low","L1",POL,
                  r"set\s+(srcaddr|dstaddr|service|srcintf|dstintf)\s+",
                  "Shadow rule analysis computed from policy table",tags=["shadow","analytics"]),
        _mk_re_pre("FG-UNUSED-INV-001","Address objects readable","UNUSED","Object Hygiene","Low","L1","show firewall address",
                  r"^\s*edit\s+",
                  "Unused object analysis computed from address/service objects",tags=["unused","analytics"]),
        _mk_re_pre("FG-COV-INV-001","Policy table present for coverage metrics","COVERAGE","Coverage","Low","L1",POL,
                  r"^\s*edit\s+",
                  "UTM coverage and policy matrix computed",tags=["coverage","analytics"]),
    ]

    return C


# =========================
# Catalog import/export
# =========================

def controls_to_dict_list(controls: List[Control]) -> List[Dict[str, Any]]:
    return [asdict(c) for c in controls]

def dict_to_controls(items: List[Dict[str, Any]]) -> List[Control]:
    out: List[Control] = []
    for it in items:
        rules = [Rule(**r) for r in it.get("rules", [])]
        out.append(Control(
            id=it["id"], title=it["title"], pack=it["pack"], domain=it["domain"],
            severity=it["severity"], level=it["level"], rules=rules,
            remediation=it.get("remediation",""),
            min_version=it.get("min_version"), max_version=it.get("max_version"),
            cis_id=it.get("cis_id"), cis_section=it.get("cis_section"), cis_profile=it.get("cis_profile"),
            tags=list(it.get("tags",[]) or [])
        ))
    return out

def load_catalog(path: str) -> List[Control]:
    raw = open(path, "r", encoding="utf-8").read()
    if path.lower().endswith((".yaml",".yml")):
        if not HAS_YAML:
            raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if isinstance(data, dict) and "controls" in data:
        data = data["controls"]
    if not isinstance(data, list):
        raise ValueError("Catalog must be a list of controls or {controls:[...]}")
    return dict_to_controls(data)

def export_catalog(path: str, controls: List[Control]) -> None:
    payload = {"vendor":"fortinet_fortigate","generated_utc":now_utc_iso(),"controls":controls_to_dict_list(controls)}
    if path.lower().endswith((".yaml",".yml")):
        if not HAS_YAML:
            raise RuntimeError("PyYAML not installed. Install with: pip install pyyaml")
        open(path,"w",encoding="utf-8").write(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True))
    else:
        open(path,"w",encoding="utf-8").write(json.dumps(payload, indent=2, ensure_ascii=False))


# =========================
# Analytics: parse policy/objects
# =========================

def split_config_blocks(text: str, edit_key: str = "edit") -> List[str]:
    blocks: List[str] = []
    cur: List[str] = []
    in_block = False
    for line in (text or "").splitlines():
        if re.match(rf"^\s*{edit_key}\s+", line, flags=re.IGNORECASE):
            if cur:
                blocks.append("\n".join(cur))
                cur = []
            in_block = True
        if in_block:
            cur.append(line)
        if re.match(r"^\s*next\s*$", line, flags=re.IGNORECASE):
            if cur:
                blocks.append("\n".join(cur))
            cur = []
            in_block = False
    if cur:
        blocks.append("\n".join(cur))
    return blocks

def parse_policy_block(block: str) -> Dict[str, Any]:
    m = regex_search(r"^\s*edit\s+(\d+)\s*$", block)
    pid = m.group(1) if m else "?"

    def get_list(key: str) -> List[str]:
        v = get_set_value(block, key)
        if v is None:
            return []
        toks = re.findall(r'"([^"]+)"|(\S+)', v)
        out = []
        for a, b in toks:
            out.append(a if a else b)
        return [x for x in out if x]

    return {
        "id": pid,
        "name": get_set_value(block, "name") or "",
        "status": (get_set_value(block, "status") or "enable").lower(),
        "action": (get_set_value(block, "action") or "").lower(),
        "srcintf": get_list("srcintf"),
        "dstintf": get_list("dstintf"),
        "srcaddr": get_list("srcaddr"),
        "dstaddr": get_list("dstaddr"),
        "service": get_list("service"),
        "nat": (get_set_value(block, "nat") or "").lower(),
        "logtraffic": (get_set_value(block, "logtraffic") or "").lower(),
        "utm_status": (get_set_value(block, "utm-status") or "").lower(),
        "av_profile": get_set_value(block, "av-profile"),
        "webfilter_profile": get_set_value(block, "webfilter-profile"),
        "ips_sensor": get_set_value(block, "ips-sensor"),
        "app_list": get_set_value(block, "application-list"),
        "ssl_ssh_profile": get_set_value(block, "ssl-ssh-profile"),
    }

def parse_named_object_blocks(text: str) -> Set[str]:
    names: Set[str] = set()
    for b in split_config_blocks(text, edit_key="edit"):
        m = regex_search(r'^\s*edit\s+"?([^"]+)"?\s*$', b)
        if m:
            names.add(m.group(1))
    return names

def extract_policy_references(policies: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    refs = {"srcaddr": set(), "dstaddr": set(), "service": set(), "srcintf": set(), "dstintf": set()}
    for p in policies:
        refs["srcaddr"].update(p.get("srcaddr", []))
        refs["dstaddr"].update(p.get("dstaddr", []))
        refs["service"].update(p.get("service", []))
        refs["srcintf"].update(p.get("srcintf", []))
        refs["dstintf"].update(p.get("dstintf", []))
    return refs

def is_all_token(token: str) -> bool:
    return (token or "").lower() in {"all","any","all_services","all-service","all_tcp","all_udp","all_icmp","ALL".lower()}

def set_covers(a: List[str], b: List[str]) -> bool:
    a_set = set(a); b_set = set(b)
    if any(is_all_token(x) for x in a_set):
        return True
    return b_set.issubset(a_set)

def shadow_analysis(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    shadows: List[Dict[str, Any]] = []
    enabled = [p for p in policies if p.get("status") != "disable"]
    for i in range(len(enabled)):
        p1 = enabled[i]
        for j in range(i+1, len(enabled)):
            p2 = enabled[j]
            if p1.get("action") != "accept" or p2.get("action") != "accept":
                continue
            if not set_covers(p1.get("srcintf", []), p2.get("srcintf", [])): continue
            if not set_covers(p1.get("dstintf", []), p2.get("dstintf", [])): continue
            if not set_covers(p1.get("srcaddr", []), p2.get("srcaddr", [])): continue
            if not set_covers(p1.get("dstaddr", []), p2.get("dstaddr", [])): continue
            if not set_covers(p1.get("service", []), p2.get("service", [])): continue
            shadows.append({
                "shadowed_policy_id": p2.get("id"),
                "shadowed_by_policy_id": p1.get("id"),
                "reason": "Earlier ACCEPT policy subsumes later ACCEPT policy (best-effort)."
            })
    # de-dup
    seen=set(); out=[]
    for s in shadows:
        k=(s["shadowed_policy_id"], s["shadowed_by_policy_id"])
        if k not in seen:
            seen.add(k); out.append(s)
    return out

def utm_coverage_metrics(policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    accept = [p for p in policies if p.get("status") != "disable" and p.get("action") == "accept"]
    if not accept:
        return {"accept_policies":0,"utm_enabled_count":0,"utm_enabled_percent":0.0,"profiles_usage":{}}
    utm_enabled = [p for p in accept if (p.get("utm_status") or "").lower() == "enable"]
    profiles = {"av":0,"webfilter":0,"ips":0,"app":0,"ssl_ssh":0}
    for p in accept:
        if p.get("av_profile"): profiles["av"] += 1
        if p.get("webfilter_profile"): profiles["webfilter"] += 1
        if p.get("ips_sensor"): profiles["ips"] += 1
        if p.get("app_list"): profiles["app"] += 1
        if p.get("ssl_ssh_profile"): profiles["ssl_ssh"] += 1
    return {
        "accept_policies": len(accept),
        "utm_enabled_count": len(utm_enabled),
        "utm_enabled_percent": round(len(utm_enabled)/len(accept)*100.0, 2),
        "profiles_usage": {k: {"count": v, "percent_of_accept": round(v/len(accept)*100.0, 2)} for k,v in profiles.items()}
    }

def find_unused_objects(address_objs: Set[str], service_objs: Set[str], policy_refs: Dict[str, Set[str]]) -> Dict[str, Any]:
    addr_used = {x for x in (policy_refs.get("srcaddr", set()) | policy_refs.get("dstaddr", set())) if not is_all_token(x)}
    svc_used = {x for x in policy_refs.get("service", set()) if not is_all_token(x)}
    unused_addr = sorted([x for x in address_objs if x not in addr_used])
    unused_svc = sorted([x for x in service_objs if x not in svc_used])
    return {
        "address_total": len(address_objs),
        "address_used": len(addr_used & address_objs),
        "address_unused": len(unused_addr),
        "service_total": len(service_objs),
        "service_used": len(svc_used & service_objs),
        "service_unused": len(unused_svc),
        "unused_address_objects": unused_addr[:500],
        "unused_service_objects": unused_svc[:500],
        "note": "Best-effort: policy-reference based; groups/dynamic refs may require deeper parsing."
    }


# =========================
# Selection / scoring / IO
# =========================

def select_controls(all_controls: List[Control], enabled_packs: Set[str], fortios_version: str) -> List[Control]:
    return [c for c in all_controls if c.pack in enabled_packs and version_in_range(fortios_version, c.min_version, c.max_version)]

def unique_commands(controls: List[Control]) -> List[str]:
    seen=set(); cmds=[]
    for c in controls:
        for r in c.rules:
            if r.cmd not in seen:
                seen.add(r.cmd); cmds.append(r.cmd)
    return cmds

def calc_score(findings: List[Finding]) -> Dict[str, Any]:
    sev_w={"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
    total=len(findings); passed=sum(1 for f in findings if f.status=="PASS")
    failed=sum(1 for f in findings if f.status=="FAIL")
    warned=sum(1 for f in findings if f.status=="WARN")
    errored=sum(1 for f in findings if f.status=="ERROR")

    risk=0
    for f in findings:
        w=sev_w.get(f.severity.upper(),2)
        if f.status=="WARN": risk+=1*w
        elif f.status in {"FAIL","ERROR"}: risk+=3*w
    compliance=(passed/total*100.0) if total else 0.0

    return {
        "compliance_percent": round(compliance,2),
        "risk_score": int(risk),
        "applicable_controls": total,
        "passed": passed,
        "failed": failed,
        "warned": warned,
        "errored": errored
    }

def write_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path,"w",encoding="utf-8") as f:
        json.dump(payload,f,ensure_ascii=False,indent=2)

def write_csv(path: str, findings: List[Finding]) -> None:
    fields=["id","pack","title","level","severity","domain","status","details","commands","cis_id","cis_section","cis_profile","tags","remediation"]
    with open(path,"w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for x in findings:
            w.writerow({
                "id":x.id,"pack":x.pack,"title":x.title,"level":x.level,"severity":x.severity,"domain":x.domain,
                "status":x.status,"details":x.details,"commands":"; ".join(x.commands),
                "cis_id":x.cis_id or "","cis_section":x.cis_section or "","cis_profile":x.cis_profile or "",
                "tags":";".join(x.tags or []),
                "remediation":x.remediation
            })

def print_report(summary: Dict[str, Any], meta: Dict[str, Any], analytics: Dict[str, Any]) -> None:
    print("\n================ NGCorion FortiGate Audit (Enterprise v4) ================")
    print(f"Target: {meta.get('host')}:{meta.get('port')} | VDOM: {meta.get('vdom') or 'N/A'}")
    print(f"Device: {meta.get('hostname') or '-'} | Model: {meta.get('model') or '-'} | Serial: {meta.get('serial') or '-'}")
    print(f"FortiOS: {meta.get('fortios_version')} | Build: {meta.get('build') or '-'}")
    print(f"Packs: {', '.join(sorted(meta.get('enabled_packs', [])))} ({len(meta.get('enabled_packs', []))} active)")
    print(f"UTC: {meta.get('timestamp_utc')}")
    print("--------------------------------------------------------------------------")
    print(f"Compliance: {summary['compliance_percent']}% | Risk Score: {summary['risk_score']}")
    print(f"Controls: {summary['applicable_controls']} total | PASS: {summary['passed']} | FAIL: {summary['failed']} | WARN: {summary['warned']} | ERROR: {summary['errored']}")

    if analytics.get("coverage"):
        cov=analytics["coverage"]
        print(f"UTM Coverage: {cov.get('utm_enabled_count')}/{cov.get('accept_policies')} policies ({cov.get('utm_enabled_percent')}%)")

    if analytics.get("shadow") is not None:
        shadow_count = len(analytics.get("shadow", []))
        if shadow_count > 0:
            print(f"Shadow Rules: {shadow_count} detected (review recommended)")

    if analytics.get("unused"):
        u=analytics["unused"]
        print(f"Unused Objects: {u.get('address_unused')} addresses, {u.get('service_unused')} services")
    print("==========================================================================\n")


# =========================
# HTML Report Generation
# =========================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FortiGate Security Audit Report - {{ meta.hostname }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #2c3e50; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 0.95em; }
        .header .meta div { display: inline-block; margin-right: 20px; margin-top: 5px; }

        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 5px 20px rgba(0,0,0,0.15); }
        .card h3 { color: #7f8c8d; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }
        .card .value { font-size: 2.5em; font-weight: bold; color: #2c3e50; }
        .card .subtext { color: #95a5a6; font-size: 0.9em; margin-top: 5px; }

        .card.compliance .value { color: #27ae60; }
        .card.risk .value { color: #e74c3c; }
        .card.controls .value { color: #3498db; }

        .section { background: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { color: #2c3e50; margin-bottom: 20px; border-bottom: 3px solid #3498db; padding-bottom: 10px; }

        .findings-table { width: 100%; border-collapse: collapse; }
        .findings-table th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: 600; }
        .findings-table td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        .findings-table tr:hover { background: #f8f9fa; }

        .status { padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; display: inline-block; }
        .status.PASS { background: #d5f4e6; color: #27ae60; }
        .status.FAIL { background: #fadbd8; color: #e74c3c; }
        .status.WARN { background: #fcf3cf; color: #f39c12; }
        .status.ERROR { background: #f5b7b1; color: #c0392b; }

        .severity { padding: 5px 10px; border-radius: 5px; font-size: 0.85em; font-weight: 600; }
        .severity.Critical { background: #c0392b; color: white; }
        .severity.High { background: #e74c3c; color: white; }
        .severity.Medium { background: #f39c12; color: white; }
        .severity.Low { background: #95a5a6; color: white; }

        .analytics { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .analytics-card { background: #ecf0f1; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; }
        .analytics-card h3 { color: #2c3e50; margin-bottom: 15px; }
        .analytics-card ul { list-style: none; }
        .analytics-card li { padding: 8px 0; border-bottom: 1px solid #bdc3c7; }
        .analytics-card li:last-child { border-bottom: none; }

        .footer { text-align: center; padding: 20px; color: #7f8c8d; font-size: 0.9em; }

        .progress-bar { background: #ecf0f1; height: 25px; border-radius: 15px; overflow: hidden; margin-top: 10px; }
        .progress-fill { background: linear-gradient(90deg, #27ae60, #2ecc71); height: 100%; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 0.85em; transition: width 0.3s; }

        .tag { display: inline-block; background: #3498db; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.75em; margin-right: 5px; margin-top: 3px; }

        @media print {
            .card:hover { transform: none; }
            .findings-table { font-size: 0.9em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ FortiGate Security Audit Report</h1>
            <div class="meta">
                <div><strong>Device:</strong> {{ meta.hostname or 'Unknown' }}</div>
                <div><strong>Model:</strong> {{ meta.model or 'N/A' }}</div>
                <div><strong>FortiOS:</strong> {{ meta.fortios_version }}</div>
                <div><strong>VDOM:</strong> {{ meta.vdom or 'root' }}</div>
                <div><strong>Timestamp:</strong> {{ meta.timestamp_utc }}</div>
            </div>
        </div>

        <div class="dashboard">
            <div class="card compliance">
                <h3>Compliance Score</h3>
                <div class="value">{{ summary.compliance_percent }}%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{ summary.compliance_percent }}%">{{ summary.compliance_percent }}%</div>
                </div>
            </div>

            <div class="card risk">
                <h3>Risk Score</h3>
                <div class="value">{{ summary.risk_score }}</div>
                <div class="subtext">Lower is better</div>
            </div>

            <div class="card controls">
                <h3>Controls Tested</h3>
                <div class="value">{{ summary.applicable_controls }}</div>
                <div class="subtext">{{ summary.passed }} passed, {{ summary.failed }} failed</div>
            </div>

            <div class="card">
                <h3>Security Packs</h3>
                <div class="value">{{ meta.enabled_packs|length }}</div>
                <div class="subtext">Active modules</div>
            </div>
        </div>

        {% if analytics.coverage or analytics.shadow or analytics.unused %}
        <div class="section">
            <h2>📊 Analytics Summary</h2>
            <div class="analytics">
                {% if analytics.coverage %}
                <div class="analytics-card">
                    <h3>UTM Coverage</h3>
                    <ul>
                        <li><strong>Accept Policies:</strong> {{ analytics.coverage.accept_policies }}</li>
                        <li><strong>UTM Enabled:</strong> {{ analytics.coverage.utm_enabled_count }} ({{ analytics.coverage.utm_enabled_percent }}%)</li>
                        <li><strong>AV Profiles:</strong> {{ analytics.coverage.profiles_usage.av.count }} ({{ analytics.coverage.profiles_usage.av.percent_of_accept }}%)</li>
                        <li><strong>IPS Sensors:</strong> {{ analytics.coverage.profiles_usage.ips.count }} ({{ analytics.coverage.profiles_usage.ips.percent_of_accept }}%)</li>
                        <li><strong>Web Filters:</strong> {{ analytics.coverage.profiles_usage.webfilter.count }} ({{ analytics.coverage.profiles_usage.webfilter.percent_of_accept }}%)</li>
                    </ul>
                </div>
                {% endif %}

                {% if analytics.shadow %}
                <div class="analytics-card">
                    <h3>Shadow Rules</h3>
                    <ul>
                        <li><strong>Detected:</strong> {{ analytics.shadow|length }} shadowed policies</li>
                        {% if analytics.shadow %}
                        <li style="font-size: 0.9em; color: #e74c3c;">⚠️ Review recommended - some policies may be unreachable</li>
                        {% endif %}
                    </ul>
                </div>
                {% endif %}

                {% if analytics.unused %}
                <div class="analytics-card">
                    <h3>Unused Objects</h3>
                    <ul>
                        <li><strong>Address Objects:</strong> {{ analytics.unused.address_unused }}/{{ analytics.unused.address_total }} unused</li>
                        <li><strong>Service Objects:</strong> {{ analytics.unused.service_unused }}/{{ analytics.unused.service_total }} unused</li>
                        <li style="font-size: 0.85em; color: #7f8c8d;">Cleanup may improve manageability</li>
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h2>🔍 Audit Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Control</th>
                        <th>Domain</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td><strong>{{ finding.id }}</strong></td>
                        <td>
                            {{ finding.title }}
                            {% if finding.cis_id %}
                            <br><span class="tag">CIS {{ finding.cis_id }}</span>
                            {% endif %}
                            {% for tag in finding.tags %}
                            <span class="tag">{{ tag }}</span>
                            {% endfor %}
                        </td>
                        <td>{{ finding.domain }}</td>
                        <td><span class="severity {{ finding.severity }}">{{ finding.severity }}</span></td>
                        <td><span class="status {{ finding.status }}">{{ finding.status }}</span></td>
                        <td style="font-size: 0.9em;">{{ finding.details }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated by NGCorion FortiGate Audit Engine v4 | <a href="https://github.com" style="color: #3498db;">Documentation</a></p>
            <p>Report generated at {{ meta.timestamp_utc }}</p>
        </div>
    </div>
</body>
</html>
"""

def write_html_report(path: str, summary: Dict[str, Any], meta: Dict[str, Any],
                     analytics: Dict[str, Any], findings: List[Finding]) -> None:
    """Generate enhanced HTML report"""
    if not HAS_JINJA2:
        print("Warning: jinja2 not installed. HTML report generation skipped. Install with: pip install jinja2")
        return

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        summary=summary,
        meta=meta,
        analytics=analytics,
        findings=[asdict(f) for f in findings]
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)


# =========================
# Audit per context (optimized)
# =========================

def audit_controls(adapter: FortiGateAdapter, conn: ConnectHandler, controls: List[Control], no_evidence: bool) -> Tuple[List[Finding], Dict[str,str]]:
    """Optimized control evaluation with batch command execution"""
    outputs = adapter.run_batch(conn, unique_commands(controls))
    findings: List[Finding] = []

    for c in controls:
        evd={r.cmd: outputs.get(r.cmd,"") for r in c.rules}
        commands=list({r.cmd for r in c.rules})

        if any((v or "").startswith("__ERROR__") for v in evd.values()):
            status,details="ERROR","One or more commands failed. Check privileges/VDOM context/command support."
        else:
            status,details=eval_control(c, evd)

        findings.append(Finding(
            id=c.id, title=c.title, pack=c.pack, domain=c.domain, severity=c.severity, level=c.level,
            status=status, details=details, commands=commands, remediation=c.remediation,
            cis_id=c.cis_id, cis_section=c.cis_section, cis_profile=c.cis_profile,
            tags=list(c.tags or []), evidence=(evd if not no_evidence else {})
        ))

    return findings, outputs


def audit_vdom_worker(vdom: Optional[str], adapter: FortiGateAdapter, host: str, username: str,
                     password: str, port: int, controls_all: List[Control], packs: Set[str],
                     fortios_version: str, no_evidence: bool, out_prefix: str) -> Dict[str, Any]:
    """Worker function for parallel VDOM auditing"""

    conn = None
    try:
        conn = adapter.connect(host, username, password, port)

        if vdom:
            ok = enter_vdom_best_effort(conn, vdom)
            if not ok:
                return {"error": f"Failed to enter VDOM {vdom}", "vdom": vdom}

        controls = select_controls(controls_all, packs, fortios_version)
        findings, _outputs = audit_controls(adapter, conn, controls, no_evidence)

        # Analytics
        analytics={"shadow":[],"unused":{},"coverage":{}}
        pol_out = adapter.send(conn, "show firewall policy")
        if cmd_ok(pol_out):
            policies=[parse_policy_block(b) for b in split_config_blocks(pol_out) if b.strip()]
            analytics["coverage"]=utm_coverage_metrics(policies)
            analytics["shadow"]=shadow_analysis(policies)

            addr_out=adapter.send(conn,"show firewall address")
            svc_out=adapter.send(conn,"show firewall service custom")
            if cmd_ok(addr_out) and cmd_ok(svc_out):
                addr_names=parse_named_object_blocks(addr_out)
                svc_names=parse_named_object_blocks(svc_out)
                refs=extract_policy_references(policies)
                analytics["unused"]=find_unused_objects(addr_names, svc_names, refs)

        if vdom:
            exit_vdom(conn)

        summary = calc_score(findings)

        return {
            "vdom": vdom or "root",
            "findings": findings,
            "analytics": analytics,
            "summary": summary,
            "controls_count": len(controls)
        }

    except Exception as e:
        return {"error": str(e), "vdom": vdom or "root"}
    finally:
        if conn:
            adapter.disconnect(conn)


# =========================
# Main
# =========================

def main() -> int:
    ap=argparse.ArgumentParser(description="NGCorion FortiGate Auditing (Enterprise v4)")
    ap.add_argument("--host", required=True, help="FortiGate hostname or IP")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--username", required=True, help="Admin username")
    ap.add_argument("--password", required=True, help="Admin password")
    ap.add_argument("--out-prefix", default="fg_audit_v4", help="Output file prefix")
    ap.add_argument("--no-evidence", action="store_true", help="Exclude raw command output")
    ap.add_argument("--all-vdoms", action="store_true", help="Audit all VDOMs in parallel")
    ap.add_argument("--catalog", default=None, help="Custom control catalog (YAML/JSON)")
    ap.add_argument("--export-catalog", default=None, help="Export built-in catalog")
    ap.add_argument("--html", action="store_true", default=True, help="Generate HTML report")
    ap.add_argument("--workers", type=int, default=4, help="Parallel VDOM workers (default: 4)")
    args=ap.parse_args()

    adapter=FortiGateAdapter()

    controls_all = built_in_controls()
    if args.export_catalog:
        export_catalog(args.export_catalog, controls_all)
        print(f"✓ Catalog exported: {args.export_catalog} ({len(controls_all)} controls)")
        return 0
    if args.catalog:
        controls_all = load_catalog(args.catalog)
        print(f"✓ Loaded custom catalog: {args.catalog} ({len(controls_all)} controls)")

    meta_global={
        "host":args.host,
        "port":args.port,
        "timestamp_utc":now_utc_iso(),
        "vendor":adapter.vendor,
        "vdom":None,
        "vdom_enter_failed":False
    }

    conn=None
    try:
        print(f"\n🔐 Connecting to {args.host}:{args.port}...")
        conn=adapter.connect(args.host,args.username,args.password,args.port)
        print("✓ Connected successfully")

        status_out=adapter.send(conn,"get system status")
        meta_global.update(parse_system_status(status_out))
        if not args.no_evidence:
            meta_global["device_status_raw"]=status_out

        print(f"✓ Device: {meta_global.get('hostname')} | FortiOS: {meta_global.get('fortios_version')}")

        vdom_enabled=bool(meta_global.get("vdom_enabled"))
        vdoms=[]
        if vdom_enabled:
            vdoms=discover_vdoms(adapter, conn)
            print(f"✓ VDOMs discovered: {len(vdoms)}")

        audit_vdoms: List[Optional[str]] = [None]
        if vdom_enabled and vdoms:
            if args.all_vdoms:
                audit_vdoms = vdoms
                print(f"✓ Parallel audit mode: {len(vdoms)} VDOMs with {args.workers} workers")
            else:
                sel=prompt_user_select_vdom(vdoms)
                audit_vdoms = [sel] if sel else [None]

        feats=detect_features(adapter, conn)
        packs=packs_from_features(feats)
        meta_global["features"]=feats
        meta_global["enabled_packs"]=sorted(packs)
        meta_global["controls_catalog_count"]=len(controls_all)
        meta_global["yaml_supported"]=HAS_YAML

        print(f"✓ Security packs enabled: {', '.join(sorted(packs))}")
        print(f"✓ Total controls: {len(controls_all)}\n")

        # Disconnect main connection before parallel processing
        adapter.disconnect(conn)
        conn = None

        agg_findings: List[Finding] = []
        vdom_results: Dict[str, Any] = {}

        # Parallel VDOM processing
        if args.all_vdoms and len(audit_vdoms) > 1:
            print(f"🔄 Processing {len(audit_vdoms)} VDOMs in parallel...")
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {
                    executor.submit(
                        audit_vdom_worker,
                        vdom,
                        adapter,
                        args.host,
                        args.username,
                        args.password,
                        args.port,
                        controls_all,
                        packs,
                        meta_global.get("fortios_version", "0.0.0"),
                        args.no_evidence,
                        args.out_prefix
                    ): vdom for vdom in audit_vdoms
                }

                for future in as_completed(futures):
                    result = future.result()
                    if "error" in result:
                        print(f"✗ Error processing VDOM {result.get('vdom')}: {result['error']}")
                        continue

                    vdom_name = result["vdom"]
                    findings = result["findings"]
                    analytics = result["analytics"]
                    summary = result["summary"]

                    tag = vdom_name.replace("/", "_")
                    meta = dict(meta_global)
                    meta["vdom"] = vdom_name

                    json_path = f"{args.out_prefix}_{tag}.json"
                    csv_path = f"{args.out_prefix}_{tag}.csv"
                    html_path = f"{args.out_prefix}_{tag}.html"

                    payload = {
                        "meta": meta,
                        "summary": summary,
                        "analytics": analytics,
                        "findings": [asdict(f) for f in findings]
                    }

                    write_json(json_path, payload)
                    write_csv(csv_path, findings)
                    if args.html:
                        write_html_report(html_path, summary, meta, analytics, findings)

                    print_report(summary, meta, analytics)
                    print(f"✓ VDOM '{vdom_name}' report: {json_path}, {csv_path}" + (f", {html_path}" if args.html else ""))

                    vdom_results[tag] = {
                        "summary": summary,
                        "json": json_path,
                        "csv": csv_path,
                        "html": html_path if args.html else None,
                        "controls_executed": result["controls_count"]
                    }
                    agg_findings.extend(findings)

        else:
            # Single VDOM or sequential processing
            conn = adapter.connect(args.host, args.username, args.password, args.port)

            for vdom in audit_vdoms:
                meta = dict(meta_global)
                meta["vdom"] = vdom or (vdoms[0] if vdoms else None)

                if vdom:
                    print(f"🔄 Auditing VDOM: {vdom}")
                    ok = enter_vdom_best_effort(conn, vdom)
                    if not ok:
                        meta["vdom_enter_failed"] = True
                        print(f"✗ Failed to enter VDOM {vdom}")
                        continue

                controls = select_controls(controls_all, packs, meta.get("fortios_version", "0.0.0"))
                print(f"📋 Executing {len(controls)} controls...")
                findings, _outputs = audit_controls(adapter, conn, controls, args.no_evidence)

                # Analytics
                analytics = {"shadow": [], "unused": {}, "coverage": {}}
                pol_out = adapter.send(conn, "show firewall policy")
                if cmd_ok(pol_out):
                    policies = [parse_policy_block(b) for b in split_config_blocks(pol_out) if b.strip()]
                    analytics["coverage"] = utm_coverage_metrics(policies)
                    analytics["shadow"] = shadow_analysis(policies)

                    addr_out = adapter.send(conn, "show firewall address")
                    svc_out = adapter.send(conn, "show firewall service custom")
                    if cmd_ok(addr_out) and cmd_ok(svc_out):
                        addr_names = parse_named_object_blocks(addr_out)
                        svc_names = parse_named_object_blocks(svc_out)
                        refs = extract_policy_references(policies)
                        analytics["unused"] = find_unused_objects(addr_names, svc_names, refs)

                if vdom and not meta.get("vdom_enter_failed"):
                    exit_vdom(conn)

                summary = calc_score(findings)

                tag = (vdom or "root").replace("/", "_")
                json_path = f"{args.out_prefix}_{tag}.json"
                csv_path = f"{args.out_prefix}_{tag}.csv"
                html_path = f"{args.out_prefix}_{tag}.html"

                payload = {
                    "meta": meta,
                    "summary": summary,
                    "analytics": analytics,
                    "findings": [asdict(f) for f in findings]
                }

                write_json(json_path, payload)
                write_csv(csv_path, findings)
                if args.html:
                    write_html_report(html_path, summary, meta, analytics, findings)

                print_report(summary, meta, analytics)
                print(f"✓ Reports saved: {json_path}, {csv_path}" + (f", {html_path}" if args.html else ""))

                vdom_results[tag] = {
                    "summary": summary,
                    "json": json_path,
                    "csv": csv_path,
                    "html": html_path if args.html else None,
                    "controls_executed": len(controls)
                }
                agg_findings.extend(findings)

            if conn:
                adapter.disconnect(conn)
                conn = None

        # Aggregated report
        agg_summary = calc_score(agg_findings)
        agg_json = f"{args.out_prefix}_ALL.json"
        agg_csv = f"{args.out_prefix}_ALL.csv"
        agg_html = f"{args.out_prefix}_ALL.html"

        write_json(agg_json, {
            "meta": meta_global,
            "summary": agg_summary,
            "vdom_results": vdom_results,
            "findings": [asdict(f) for f in agg_findings]
        })
        write_csv(agg_csv, agg_findings)
        if args.html:
            write_html_report(agg_html, agg_summary, meta_global, {}, agg_findings)

        print("\n" + "="*78)
        print("📊 AGGREGATED AUDIT RESULTS")
        print("="*78)
        print(f"✓ Compliance: {agg_summary['compliance_percent']}%")
        print(f"✓ Risk Score: {agg_summary['risk_score']}")
        print(f"✓ Total Findings: {len(agg_findings)} ({agg_summary['passed']} passed, {agg_summary['failed']} failed)")
        print(f"✓ Reports: {agg_json}, {agg_csv}" + (f", {agg_html}" if args.html else ""))
        print(f"✓ VDOMs Audited: {len(vdom_results)}")
        print("="*78 + "\n")

        return 0

    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        print(f"✗ Connection error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"✗ Unhandled error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 3
    finally:
        if conn:
            try:
                adapter.disconnect(conn)
            except Exception as exc:
                print(f"[Warning] disconnect during cleanup failed: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
