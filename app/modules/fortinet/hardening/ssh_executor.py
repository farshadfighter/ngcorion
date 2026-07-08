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
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.modules.fortinet.audit.rules import FortiGateControl, IFACE
from app.modules.fortinet.audit.service import FortinetAuditService, _parse_interfaces
from app.modules.fortinet.audit.ssh_client import SCOPE_GLOBAL, FortiGateSSHClient
from .command_templates import build_iface_allowaccess_commands

logger = logging.getLogger(__name__)


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
            config = self.ssh_client.send_raw("show full-configuration")
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
            result = self.ssh_client.run_config(commands, scope=scope, vdom=vdom or self.default_vdom)
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

    def verify_check(
        self,
        control: FortiGateControl,
        vdom: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Re-read the control in its own scope/VDOM and re-evaluate its rules."""
        if not self.ssh_client:
            raise FortiGateHardeningExecutionError("Not connected to device")
        try:
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
                return True, f"[NOT APPLICABLE] {na_reason}"
            # Reuse the audit service's authoritative evaluator (single source of
            # truth) and its rule-combine semantics: "all" (AND) normally, "any"
            # (OR) for controls whose setting has >1 build-specific spelling (e.g.
            # FG-AV-003 machine-learning-detection vs the older heuristic node).
            # A previous local copy handled only set_*/regex_* and returned False
            # for the newer get_field_*/table_*/policy_* types, silently failing
            # post-fix verification even when the device was correctly fixed.
            evidence_parts, results = [], []
            for rule in control.rules:
                out = outputs.get(rule.cmd, "")
                evidence_parts.append(f"# {rule.cmd}\n{out[:500]}")
                results.append(FortinetAuditService._evaluate_rule(rule, out))
            combiner = any if getattr(control, "rule_combine", "all") == "any" else all
            passed = combiner(results) if results else False
            return passed, "\n\n".join(evidence_parts)
        except Exception as e:  # noqa: BLE001
            logger.error("FortiGate verification failed on %s (control=%s)",
                         self.ip, getattr(control, "id", "?"), exc_info=True)
            raise FortiGateHardeningVerificationError(f"Failed to verify check: {e}")

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
            output = self.ssh_client.send_raw("get system status")
            return bool(output and "Version:" in output)
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
                      r"auth-password|key|private-key|api-key|auth-keychain)\s+)\S+",
                      r"\1<REDACTED>", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"ENC\s+[A-Za-z0-9+/=]+", "ENC <REDACTED>", redacted)
    return redacted


def format_fortigate_command_output(commands: List[str], output: str) -> str:
    """Format executed commands + device output for display."""
    lines = ["=" * 60, f"FortiGate Commands Executed: {len(commands)}", "=" * 60]
    lines += [f"> {cmd}" for cmd in commands]
    lines += ["", "=" * 60, "Device Output:", "=" * 60, output]
    return "\n".join(lines)
