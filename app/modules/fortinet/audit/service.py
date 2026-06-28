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
from typing import Any, Dict, List, Optional

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
# (CIS 1.3 / FG-NET-002). Used by the "wan_mgmt_exposed" rule type.
_WAN_FORBIDDEN_SERVICES = ("ping", "http", "https", "ssh", "telnet", "snmp", "radius-acct")


def _parse_interfaces(output: str) -> List[Dict[str, Any]]:
    """
    Parse ``show system interface`` into a list of top-level interfaces:
    ``[{"name", "role", "allowaccess": [...]}]``.

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
                current = {"name": m_edit.group(1), "role": "", "allowaccess": []}
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


def _wan_mgmt_violations(output: str, forbidden=None) -> List[Dict[str, Any]]:
    """
    Return WAN-role interfaces that expose management services.

    An interface is a violation when ``role == wan`` AND its ``allowaccess`` set
    contains at least one forbidden service. Each entry:
    ``{"name", "role", "exposed": [services...]}``.
    """
    forbidden_set = {s.lower() for s in (forbidden or _WAN_FORBIDDEN_SERVICES)}
    violations: List[Dict[str, Any]] = []
    for itf in _parse_interfaces(output):
        if itf["role"] != "wan":
            continue
        exposed = [s for s in itf["allowaccess"] if s.lower() in forbidden_set]
        if exposed:
            violations.append({"name": itf["name"], "role": itf["role"], "exposed": exposed})
    return violations


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
                # management service in its allowaccess.
                return not _wan_mgmt_violations(output, rule.expected)

            if rule.type == "get_field_eq":
                # Compliant (pass) only when the parsed `key : value` field
                # equals the expected value (whitespace-insensitive).
                actual = _get_field_value(output, rule.key)
                if actual is None:
                    return False
                return _norm_field(actual) == _norm_field(str(rule.expected))

            if rule.type == "get_field_not_match":
                # Compliant (pass) only when the parsed `key : value` field does
                # NOT match the pattern (e.g. a default FGT<serial> hostname).
                actual = _get_field_value(output, rule.key)
                if actual is None:
                    return False
                return not bool(re.search(rule.pattern, actual))

            if rule.type == "get_field_excludes":
                # Compliant only when the field is present AND contains none of
                # the forbidden tokens. Absent/default field == non-compliant.
                value, active = _field_forbidden_tokens(output, rule.key, rule.expected)
                return value is not None and not active

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
        lines: List[str] = []
        for rule in control.rules:
            out = outputs.get(rule.cmd, "")
            if not out:
                continue
            if rule.type == "wan_mgmt_exposed":
                viols = _wan_mgmt_violations(out, rule.expected)
                if viols:
                    lines.extend(
                        f"{v['name']} (role={v['role']}) exposes: {', '.join(v['exposed'])}"
                        for v in viols
                    )
                else:
                    lines.append("No WAN-role interface exposes management services")
                continue
            if rule.type == "get_field_eq":
                actual = _get_field_value(out, rule.key)
                if actual is None:
                    lines.append(f"{rule.key}: <not found> (NON-COMPLIANT, expected {rule.expected})")
                elif _norm_field(actual) == _norm_field(str(rule.expected)):
                    lines.append(f"{rule.key}: {actual} (compliant)")
                else:
                    lines.append(f"{rule.key}: {actual} (NON-COMPLIANT, expected {rule.expected})")
                continue
            if rule.type == "get_field_not_match":
                actual = _get_field_value(out, rule.key)
                if actual is None:
                    lines.append(f"{rule.key}: <not found> (NON-COMPLIANT)")
                elif re.search(rule.pattern, actual):
                    lines.append(f"{rule.key}: {actual} (NON-COMPLIANT — hostname matches default FGT serial pattern)")
                else:
                    lines.append(f"{rule.key}: {actual} (compliant)")
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
                lines.append(report)
                continue
            if rule.key:
                lines.extend(re.findall(rf".*{re.escape(rule.key)}.*", out, re.IGNORECASE | re.MULTILINE)[:3])
            elif rule.pattern:
                m = re.findall(rule.pattern, out, re.IGNORECASE | re.MULTILINE)
                if m:
                    sample = m[0] if isinstance(m[0], str) else " ".join(x for x in m[0] if x)
                    lines.append(f"match: {sample}")
        evidence = " | ".join(x.strip() for x in lines if x and x.strip())
        if not evidence:
            evidence = "No matching configuration found"
        return evidence[:497] + "..." if len(evidence) > 500 else evidence

    @classmethod
    def _evaluate_control(cls, control: FortiGateControl, outputs: Dict[str, str], vdom_label: Optional[str]) -> Dict[str, Any]:
        passed = all(cls._evaluate_rule(r, outputs.get(r.cmd, "")) for r in control.rules)
        return {
            "control_id": control.id,
            "title": control.title,
            "passed": passed,
            "manual": control.is_manual,
            "evidence": cls._extract_evidence(control, outputs),
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
                if r.cmd not in seen:
                    seen.add(r.cmd)
                    cmds.append(r.cmd)
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

            # Compliance metrics — the entire CIS checklist is scored (Manual
            # controls included; every control yields a PASS/FAIL).
            passed = sum(1 for f in findings if f["passed"])
            total = len(findings)
            failed = total - passed
            compliance_pct = round(100.0 * passed / total, 2) if total else 0.0

            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            session.total_checks = total
            session.passed_checks = passed
            session.failed_checks = failed
            session.error_checks = 0
            session.compliance_pct = compliance_pct
            session.turbo_dump = json.dumps(raw_dump, indent=2)[:1_000_000]
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
            logger.error("Audit failed for asset %s (%s): %s", asset_id, target_ip, type(e).__name__)
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
            # Every control is scored — Manual controls are no longer marked
            # NOT_APPLICABLE; they get a PASS/FAIL like the Automated ones.
            status = CheckStatus.PASS if f["passed"] else CheckStatus.FAIL
            results.append(AuditResult(
                session_id=session_id,
                check_number=f["control_id"],
                check_title=f["title"],
                severity=f["severity"],
                level=f["level"],
                vdom=f["vdom"],
                status=status,
                evidence_snippet=(f["evidence"][:1000] if f["evidence"] else None),
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
