"""
FortiGate hardening SSH executor.

Thin wrapper over the scope-aware ``FortiGateSSHClient`` that:
  - backs up the full configuration,
  - applies a remediation command block in the correct scope/VDOM,
  - re-verifies the control afterwards.

All global/VDOM context switching is delegated to the SSH client; this class only
forwards the control's ``scope`` and the target ``vdom``.
"""

import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.modules.fortinet.audit.rules import FortiGateControl, IFACE
from app.modules.fortinet.audit.service import (
    FortinetAuditService,
    _ntp_status_failures,
    _parse_interfaces,
    _parse_ntp_status,
)
from app.modules.fortinet.audit.ssh_client import SCOPE_GLOBAL, FortiGateSSHClient
from .command_templates import build_iface_allowaccess_commands
from .manual_remediation import selection_object_name

logger = logging.getLogger(__name__)

# Management services stripped from WAN-role interfaces for FG-NET-002 (CIS 1.3).
# Kept in sync with the audit's _WAN_FORBIDDEN_SERVICES; ping/snmp/radius-acct
# are intentionally NOT touched (per client scope).
WAN_MGMT_FORBIDDEN = ["http", "https", "ssh", "telnet"]

# NTP re-sync after switching to a new server is not instant. When the config
# side of FG-BL-040 is already right (ntpsync on, custom mode, no FortiGuard
# servers) and ONLY the `synchronized` flag is still missing, verification
# polls for a short while instead of failing immediately.
NTP_SYNC_VERIFY_ATTEMPTS = 4        # 1 initial check + 3 retries
NTP_SYNC_VERIFY_DELAY_SECONDS = 10  # ~30s total wait


class FortiGateHardeningExecutionError(Exception):
    """Raised when FortiGate command execution fails."""


class FortiGateHardeningVerificationError(Exception):
    """Raised when post-execution verification fails."""


class FortiGateHardeningExecutor:
    """Executes hardening commands on FortiGate devices."""

    def __init__(self, ip: str, username: str, password: str, port: int = 22,
                 vdom: Optional[str] = None):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.default_vdom = vdom
        self.ssh_client: Optional[FortiGateSSHClient] = None

    def __enter__(self):
        self.ssh_client = FortiGateSSHClient(self.ip, self.username, self.password, port=self.port)
        self.ssh_client.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ssh_client:
            self.ssh_client.disconnect()
        return False

    # ------------------------------------------------------------------
    def backup_config(self) -> str:
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        try:
            t0 = time.perf_counter()
            config = self.ssh_client.send_raw("show full-configuration")
            logger.info("FG timing: backup_config -> %.2fs (%d chars) on %s",
                        time.perf_counter() - t0, len(config or ""), self.ip)
            header = (
                f"#\n# FortiGate Configuration Backup\n"
                f"# Backup taken at: {datetime.utcnow().isoformat()}\n"
                f"# Device: {self.ip}\n#\n"
            )
            return header + config
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate config backup failed on %s", self.ip, exc_info=True)
            raise FortiGateHardeningExecutionError(f"Failed to backup config: {e}")

    def execute_commands(
        self,
        commands: List[str],
        scope: str = SCOPE_GLOBAL,
        vdom: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run a remediation block. ``commands`` are the inner config only; the
        scope wrapper is added by the SSH engine based on ``scope``/``vdom``.
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        try:
            t0 = time.perf_counter()
            result = self.ssh_client.run_config(commands, scope=scope, vdom=vdom or self.default_vdom)
            logger.info("FG timing: execute_commands %d cmd(s) -> %.2fs on %s",
                        len(commands), time.perf_counter() - t0, self.ip)
            if not result["success"]:
                logger.warning("FortiGate execution errors on %s: %s", self.ip, result["errors"])
            return result
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate command execution failed on %s (scope=%s vdom=%s)",
                         self.ip, scope, vdom or self.default_vdom, exc_info=True)
            raise FortiGateHardeningExecutionError(f"Failed to execute commands: {e}")

    def build_iface_allowaccess_fix(
        self,
        scope: str = SCOPE_GLOBAL,
        vdom: Optional[str] = None,
        forbidden: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Compute the per-interface remediation for an ``allowaccess`` control
        (e.g. FG-BL-002) from the device's LIVE config.

        Reads ``show system interface`` in the control's scope, then returns
        object-level config commands that strip only the ``forbidden`` cleartext
        services (default ``telnet``/``http``) from each interface that exposes
        one, preserving every other service. Returns ``[]`` when the device is
        already compliant. The caller feeds the result to ``execute_commands``,
        which adds the ``config global``/``config vdom`` scope wrapper.
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        forbidden = forbidden or ["telnet", "http"]
        raw = self.ssh_client.collect(
            [IFACE], scope=scope, vdom=vdom or self.default_vdom, use_cache=False
        )[IFACE]
        interfaces = _parse_interfaces(raw)
        return build_iface_allowaccess_commands(interfaces, forbidden)

    def build_wan_iface_allowaccess_blocks(
        self,
        selections: List[str],
        scope: str = SCOPE_GLOBAL,
        vdom: Optional[str] = None,
        forbidden: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Per-interface remediation blocks for FG-NET-002, computed from the LIVE
        config — the same read/strip mechanism as :meth:`build_iface_allowaccess_fix`
        (FG-BL-002), but restricted to the operator-SELECTED interfaces and shaped
        for per-target reporting.

        ``selections`` may carry the evidence label ("wan1 (http ssh)"); only the
        leading interface name is used. Returns one entry per selection:
        ``{"target", "commands", "skip_reason", "success"}``. Empty ``commands``
        + ``skip_reason`` means nothing is pushed for that interface:
          * already compliant                       -> success True
          * not found on the device / lockout guard -> success False
        The lockout guard refuses the interface holding the IP this session is
        connected to: stripping HTTPS/SSH there would cut off management access.
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        forbidden_l = sorted({s.lower() for s in (forbidden or WAN_MGMT_FORBIDDEN)})
        raw = self.ssh_client.collect(
            [IFACE], scope=scope, vdom=vdom or self.default_vdom, use_cache=False
        )[IFACE]
        live = {i["name"]: i for i in _parse_interfaces(raw)}
        report: List[Dict[str, Any]] = []
        for sel in selections:
            name = selection_object_name(sel)
            itf = live.get(name)
            if itf is None:
                report.append({"target": name, "commands": [], "success": False,
                               "skip_reason": "not found in the device's live "
                                              "interface list"})
                continue
            if itf.get("ip") and itf["ip"] == self.ip:
                report.append({"target": name, "commands": [], "success": False,
                               "skip_reason": (f"refused: interface holds {self.ip}, the "
                                               "management IP this session is connected "
                                               "through — removing HTTPS/SSH would lock out "
                                               "administration; fix it from the console or "
                                               "another interface")})
                continue
            exposed = [s for s in itf.get("allowaccess", [])
                       if s.lower() in set(forbidden_l)]
            if not exposed:
                report.append({"target": name, "commands": [], "success": True,
                               "skip_reason": "already compliant (no forbidden "
                                              "management services exposed)"})
                continue
            report.append({"target": name, "success": None, "skip_reason": None,
                           "commands": build_iface_allowaccess_commands([itf], forbidden_l)})
        return report

    def verify_check(
        self,
        control: FortiGateControl,
        vdom: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Re-read the control in its own scope/VDOM and re-evaluate its rules.

        Controls with an ``ntp_status_ok`` rule get a short poll: right after the
        fix the config is correct but the device may not have synchronized to the
        new server yet, so a one-shot read would fail on the ``synchronized``
        flag alone. We retry only while that is the sole remaining failure.
        """
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        t0 = time.perf_counter()
        try:
            has_ntp_rule = any(r.type == "ntp_status_ok" for r in control.rules)
            attempts = NTP_SYNC_VERIFY_ATTEMPTS if has_ntp_rule else 1
            passed, evidence, sync_pending = self._verify_once(control, vdom)
            for attempt in range(1, attempts):
                if passed or not sync_pending:
                    break
                logger.info("FG %s verify on %s: NTP config applied but not "
                            "synchronized yet (attempt %d/%d) — waiting %ds",
                            control.id, self.ip, attempt, attempts,
                            NTP_SYNC_VERIFY_DELAY_SECONDS)
                time.sleep(NTP_SYNC_VERIFY_DELAY_SECONDS)
                passed, evidence, sync_pending = self._verify_once(control, vdom)
            if not passed and sync_pending:
                waited = (attempts - 1) * NTP_SYNC_VERIFY_DELAY_SECONDS
                evidence = (
                    "[NTP NOT SYNCED YET] NTP configuration verified (ntpsync on, "
                    "custom servers, no FortiGuard pool) but the device has not "
                    f"synchronized after ~{waited}s. Initial sync to a new server "
                    "can take several minutes — re-run the audit shortly; no "
                    "further remediation is needed.\n\n" + evidence
                )
            logger.info("FG timing: verify_check %s -> %.2fs (passed=%s) on %s",
                        control.id, time.perf_counter() - t0, passed, self.ip)
            return passed, evidence
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate verification failed on %s (control=%s)",
                         self.ip, getattr(control, "id", "?"), exc_info=True)
            raise FortiGateHardeningVerificationError(f"Failed to verify check: {e}")

    def _verify_once(
        self,
        control: FortiGateControl,
        vdom: Optional[str] = None,
    ) -> Tuple[bool, str, bool]:
        """
        One verification pass. Returns ``(passed, evidence, sync_pending)`` where
        ``sync_pending`` means every failing rule is an ``ntp_status_ok`` whose
        only unmet condition is the ``synchronized`` flag (config already right,
        device just hasn't synced yet) — the caller may retry those.
        """
        cmds = []
        for r in control.rules:
            if r.cmd not in cmds:
                cmds.append(r.cmd)
        outputs = self.ssh_client.collect(
            cmds, scope=control.scope, vdom=vdom or self.default_vdom, use_cache=False
        )
        # An off/absent feature (na_gate) is not a verification failure — mirror
        # the audit so post-fix verify agrees with what the audit will report.
        applicable, na_reason = FortinetAuditService._applicability(control, outputs)
        if not applicable:
            return True, f"[NOT APPLICABLE] {na_reason}", False
        # Reuse the audit service's authoritative evaluator (single source of
        # truth) and its rule-combine semantics: "all" (AND) normally, "any"
        # (OR) for controls whose setting has >1 build-specific spelling (e.g.
        # FG-AV-003 machine-learning-detection vs the older heuristic node).
        # A previous local copy handled only set_*/regex_* and returned False
        # for the newer get_field_*/table_*/policy_* types, silently failing
        # post-fix verification even when the device was correctly fixed.
        evidence_parts, results, pending_flags = [], [], []
        for rule in control.rules:
            out = outputs.get(rule.cmd, "")
            evidence_parts.append(f"# {rule.cmd}\n{out[:500]}")
            ok = FortinetAuditService._evaluate_rule(rule, out)
            results.append(ok)
            if not ok:
                if rule.type == "ntp_status_ok":
                    fails = _ntp_status_failures(_parse_ntp_status(out))
                    pending_flags.append(
                        bool(fails) and all(f.startswith("synchronized") for f in fails)
                    )
                else:
                    pending_flags.append(False)
        combiner = any if getattr(control, "rule_combine", "all") == "any" else all
        passed = combiner(results) if results else False
        sync_pending = (not passed) and bool(pending_flags) and all(pending_flags)
        return passed, "\n\n".join(evidence_parts), sync_pending

    def save_config(self) -> str:
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        try:
            return self.ssh_client.send_raw("execute backup config flash")
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate config save failed on %s", self.ip, exc_info=True)
            raise FortiGateHardeningExecutionError(f"Failed to verify config save: {e}")

    def test_connectivity(self) -> bool:
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        try:
            t0 = time.perf_counter()
            # get_system_status is session-cached: the first call costs one
            # round-trip, later calls (or a status already read during connect
            # fallbacks) cost none — the old code re-sent `get system status`
            # on every action.
            meta = self.ssh_client.get_system_status()
            logger.info("FG timing: test_connectivity -> %.2fs on %s",
                        time.perf_counter() - t0, self.ip)
            return bool(meta.get("version_line"))
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate connectivity test failed on %s", self.ip, exc_info=True)
            raise FortiGateHardeningExecutionError(f"Device not responding: {e}")

    def get_system_info(self) -> Dict[str, object]:
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        try:
            return self.ssh_client.get_system_status()
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate get_system_info failed on %s", self.ip, exc_info=True)
            raise FortiGateHardeningExecutionError(f"Failed to get system info: {e}")


def redact_fortigate_secrets(output: str) -> str:
    """Redact secrets/passwords from FortiGate command output."""
    redacted = output or ""
    redacted = re.sub(r"(set\s+(?:password|passwd|secret|psksecret|ppk-secret|auth-pwd|"
                      r"priv-pwd|auth-password|key|private-key|api-key|auth-keychain)\s+)\S+",
                      r"\1<REDACTED>", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"ENC\s+[A-Za-z0-9+/=]+", "ENC <REDACTED>", redacted)
    return redacted


def format_fortigate_command_output(commands: List[str], output: str) -> str:
    """Format executed commands + device output for display."""
    lines = ["=" * 60, f"FortiGate Commands Executed: {len(commands)}", "=" * 60]
    lines += [f"> {cmd}" for cmd in commands]
    lines += ["", "=" * 60, "Device Output:", "=" * 60, output]
    return "\n".join(lines)
