"""
FortiGate SSH client (scope-aware).

Owns all CLI context switching for FortiGate devices so callers (audit +
hardening) never have to manage global vs per-VDOM scope by hand.

Scope model (see rules.FortiGateControl.scope):
  - "global"     -> read/written in ``config global`` on VDOM-enabled devices,
                    or at the top-level CLI on single-VDOM (flat) devices.
  - "vdom"       -> read/written inside ``config vdom`` / ``edit <name>``.
  - "vdom_root"  -> like "vdom" but always the built-in management VDOM ("root")
                    (for settings that live in a VDOM yet are device-wide, e.g.
                    the admin password policy).

On a device with VDOMs disabled there is only one flat context, so every scope
collapses to running the command at the top-level prompt. Detection is automatic
via ``get system status`` (``Virtual domain configuration:``).

Features retained from the previous client:
  - configurable SSH port,
  - rich SSH exception mapping (``app.core.ssh_exceptions``),
  - ``--More--`` pagination handling,
  - per (scope, vdom, command) output caching.
"""

import re
import time
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

# Import paramiko exceptions for algorithm/key errors
try:
    from paramiko.ssh_exception import (
        SSHException,
        BadHostKeyException,
        NoValidConnectionsError,
    )
    from paramiko.transport import IncompatiblePeer
except ImportError:  # pragma: no cover - fallback if paramiko structure changes
    SSHException = Exception
    BadHostKeyException = Exception
    NoValidConnectionsError = Exception
    IncompatiblePeer = Exception

from app.core.ssh_exceptions import (
    SSHConnectionError,
    SSHAuthenticationError,
    SSHConnectionTimeoutError,
    SSHNetworkError,
    SSHAlgorithmMismatchError,
    SSHHostKeyError,
    map_ssh_exception,
)

# Scope constants (kept in sync with rules.FortiGateControl.scope)
SCOPE_GLOBAL = "global"
SCOPE_VDOM = "vdom"
SCOPE_VDOM_ROOT = "vdom_root"
ROOT_VDOM = "root"

# FortiGate substrings that indicate a command was rejected. Used to decide
# whether a context switch / enumeration command actually worked.
_BAD_OUTPUT_PATTERNS = (
    "command fail",
    "command parse error",
    "parse error",
    "unknown command",
    "unknown action",
    "permission denied",
    "return code -",
)


def _is_operational_command(command: str) -> bool:
    """
    Whether ``command`` is an operational command that must run at the top-level
    prompt rather than inside a config context.

    ``diagnose``/``execute`` are rejected inside ``config global`` / ``config vdom``
    (they only work at the operational prompt), so on VDOM-enabled devices they
    must be issued BEFORE entering any scope. They read device-wide/global state
    (e.g. ``diagnose sys ntp status``), so a single top-level read is correct
    regardless of the requested config scope.
    """
    c = (command or "").strip().lower()
    return c.startswith(("diagnose ", "diag ", "execute ", "exec "))


class FortiGateContextError(RuntimeError):
    """Raised when entering a global/VDOM CLI context fails."""


class FortiGateSSHClient:
    """SSH client for FortiGate devices with automatic global/VDOM scoping."""

    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self._connection: Optional[ConnectHandler] = None
        self._cmd_cache: Dict[str, Tuple[str, float]] = {}
        self._cache_ttl = 300  # 5 minutes
        self._vdom_enabled: Optional[bool] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def connect(self) -> None:
        """
        Establish the SSH connection to the FortiGate.

        Raises the appropriate ``app.core.ssh_exceptions`` subclass on failure
        (auth, timeout, network, algorithm mismatch, host key, generic).
        """
        if self._connection:
            return

        base = dict(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            fast_cli=False,
            global_delay_factor=1,
        )

        last_error = None
        for device_type in ("fortinet", "fortigate"):
            try:
                params = dict(base)
                params["device_type"] = device_type
                self._connection = ConnectHandler(**params)
                self._prime_session()
                return

            except NetmikoAuthenticationException as e:
                raise SSHAuthenticationError(self.host, original_error=e)
            except IncompatiblePeer as e:
                raise SSHAlgorithmMismatchError(self.host, original_error=e)
            except BadHostKeyException as e:
                raise SSHHostKeyError(self.host, original_error=e)
            except NoValidConnectionsError as e:
                raise SSHNetworkError(self.host, original_error=e)
            except NetmikoTimeoutException as e:
                last_error = e  # try next device type
            except OSError as e:
                if hasattr(e, "errno") and e.errno in (111, 113):
                    raise SSHNetworkError(self.host, original_error=e)
                last_error = e
            except Exception as e:  # noqa: BLE001 - mapped below
                last_error = e

        if last_error:
            raise map_ssh_exception(last_error, self.host)
        raise SSHConnectionError(
            message=f"Unable to connect to FortiGate at {self.host}",
            device_ip=self.host,
            suggestions=["Check network connectivity to the device"],
            original_error=None,
        )

    def _prime_session(self) -> None:
        """Disable the interactive pager so output is never paginated."""
        try:
            # Both forms exist across FortiOS versions; ignore failures.
            self._connection.send_command_timing(
                "config system console", strip_prompt=False, strip_command=False
            )
            self._connection.send_command_timing(
                "set output standard", strip_prompt=False, strip_command=False
            )
            self._connection.send_command_timing(
                "end", strip_prompt=False, strip_command=False
            )
        except Exception:  # pragma: no cover - best effort
            pass

    def disconnect(self) -> None:
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
            finally:
                self._connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    # ------------------------------------------------------------------
    # Low-level send
    # ------------------------------------------------------------------
    def _raw_send(self, command: str) -> str:
        """Send a single command, handling ``--More--`` pagination."""
        if not self._connection:
            raise RuntimeError("Not connected. Call connect() first.")

        output = self._connection.send_command_timing(
            command, strip_prompt=False, strip_command=False
        )
        # Defensive: drain any pager prompt that slipped through.
        guard = 0
        while output and re.search(r"--More--", output, flags=re.IGNORECASE) and guard < 50:
            output = re.sub(r"--More--", "", output, flags=re.IGNORECASE)
            output += self._connection.send_command_timing(
                " ", strip_prompt=False, strip_command=False
            )
            guard += 1
        return output or ""

    @staticmethod
    def _is_command_ok(output: str) -> bool:
        low = (output or "").lower()
        if low.startswith("__error__"):
            return False
        return not any(p in low for p in _BAD_OUTPUT_PATTERNS)

    # ------------------------------------------------------------------
    # System status / VDOM detection
    # ------------------------------------------------------------------
    def get_system_status(self) -> Dict[str, object]:
        """Parse ``get system status`` (version, hostname, serial, VDOM mode)."""
        output = self._raw_send("get system status")
        meta: Dict[str, object] = {"fortios_version": "0.0.0"}

        m_ver = re.search(r"^\s*Version:\s*(.+)$", output, flags=re.MULTILINE | re.IGNORECASE)
        if m_ver:
            version_line = m_ver.group(1).strip()
            meta["version_line"] = version_line
            mv = re.search(r"\bv(\d+\.\d+(?:\.\d+)?)\b", version_line)
            if mv:
                meta["fortios_version"] = mv.group(1)
            mb = re.search(r"\bbuild(\d+)\b", version_line)
            if mb:
                meta["build"] = mb.group(1)
            mm = re.search(r"^(.+?)\s+v\d+\.\d+", version_line)
            if mm:
                meta["model"] = mm.group(1).strip()

        m_hn = re.search(r"^\s*Hostname:\s*(.+)$", output, flags=re.MULTILINE | re.IGNORECASE)
        if m_hn:
            meta["hostname"] = m_hn.group(1).strip()

        m_sn = re.search(r"^\s*Serial-Number:\s*(.+)$", output, flags=re.MULTILINE | re.IGNORECASE)
        if m_sn:
            meta["serial"] = m_sn.group(1).strip()

        # Virtual domain configuration: disable | enable | multiple | split-task ...
        vdom_enabled = False
        m_vdom = re.search(
            r"Virtual\s+domain\s+configuration:\s*(.+)", output, flags=re.IGNORECASE
        )
        if m_vdom:
            val = m_vdom.group(1).strip().lower()
            # Anything that is not "disable" and mentions a real mode means VDOMs are on.
            vdom_enabled = bool(val) and ("disable" not in val)
        meta["vdom_enabled"] = vdom_enabled
        self._vdom_enabled = vdom_enabled
        return meta

    def is_vdom_enabled(self) -> bool:
        """Return whether VDOM mode is enabled (cached after first detection)."""
        if self._vdom_enabled is None:
            try:
                self.get_system_status()
            except Exception:
                self._vdom_enabled = False  # safest default: treat as flat device
        return bool(self._vdom_enabled)

    def enumerate_vdoms(self) -> List[str]:
        """
        Return every VDOM on the device (``root`` first). Empty list when VDOM
        mode is disabled. Always returns at least ``["root"]`` when enabled.
        """
        if not self.is_vdom_enabled():
            return []

        vdoms: List[str] = []

        # Primary: diagnose sys vdom list (works at the top level on most FortiOS).
        out = self._raw_send("diagnose sys vdom list")
        if self._is_command_ok(out):
            for m in re.finditer(r"\bname=([A-Za-z0-9._\-]+)", out):
                vdoms.append(m.group(1))
            if not vdoms:
                for m in re.finditer(r"^\s*vd\s+([A-Za-z0-9._\-]+)/", out, flags=re.MULTILINE):
                    vdoms.append(m.group(1))

        # Fallback: enumerate the config VDOM table from the global context.
        if not vdoms:
            try:
                with self.scope(SCOPE_GLOBAL):
                    cfg = self._raw_send("show system vdom-property")
                for m in re.finditer(r'^\s*edit\s+"?([A-Za-z0-9._\-]+)"?\s*$', cfg, flags=re.MULTILINE):
                    vdoms.append(m.group(1))
            except Exception:
                pass

        # De-duplicate, keep order, force root to the front, default to root.
        seen, unique = set(), []
        for v in vdoms:
            if v and v not in seen:
                seen.add(v)
                unique.append(v)
        if not unique:
            unique = [ROOT_VDOM]
        unique.sort(key=lambda v: (v != ROOT_VDOM, v))
        return unique

    # Backwards-compatible alias used by a few callers/tests.
    def discover_vdoms(self) -> List[str]:
        return self.enumerate_vdoms()

    # ------------------------------------------------------------------
    # Scope handling
    # ------------------------------------------------------------------
    @staticmethod
    def effective_vdom(scope: str, vdom: Optional[str]) -> Optional[str]:
        """The VDOM a control will actually be evaluated in for a given scope."""
        if scope == SCOPE_VDOM_ROOT:
            return ROOT_VDOM
        if scope == SCOPE_VDOM:
            return vdom or ROOT_VDOM
        return None  # global

    @contextmanager
    def scope(self, scope: str, vdom: Optional[str] = None):
        """
        Context manager that enters the correct CLI context for ``scope`` and
        always returns to the top-level prompt on exit. No-op on flat devices.
        """
        opened = self._open_scope(scope, vdom)
        try:
            yield
        finally:
            if opened:
                self._close_scope()

    def _open_scope(self, scope: str, vdom: Optional[str]) -> bool:
        if not self.is_vdom_enabled():
            return False  # flat device: single top-level context

        if scope == SCOPE_GLOBAL:
            out = self._raw_send("config global")
            if not self._is_command_ok(out):
                raise FortiGateContextError(f"Failed to enter global context: {out.strip()[:160]}")
            return True

        target = self.effective_vdom(scope, vdom) or ROOT_VDOM
        out1 = self._raw_send("config vdom")
        out2 = self._raw_send(f"edit {target}")
        if not (self._is_command_ok(out1) and self._is_command_ok(out2)):
            # Best effort to back out before failing.
            try:
                self._raw_send("end")
            except Exception:
                pass
            raise FortiGateContextError(
                f"Failed to enter VDOM '{target}': {(out1 + out2).strip()[:160]}"
            )
        return True

    def _close_scope(self) -> None:
        try:
            self._raw_send("end")
        except Exception:  # pragma: no cover - best effort
            pass

    # ------------------------------------------------------------------
    # Public read / collect (audit)
    # ------------------------------------------------------------------
    def _cache_key(self, scope: str, vdom: Optional[str], command: str) -> str:
        return f"{scope}|{self.effective_vdom(scope, vdom)}|{command}"

    def collect(
        self,
        commands: List[str],
        scope: str = SCOPE_GLOBAL,
        vdom: Optional[str] = None,
        use_cache: bool = True,
    ) -> Dict[str, str]:
        """
        Run several read commands inside one scope context and return
        ``{command: output}``. Enters the context once for efficiency.
        """
        results: Dict[str, str] = {}
        to_run: List[str] = []

        for cmd in commands:
            key = self._cache_key(scope, vdom, cmd)
            if use_cache and key in self._cmd_cache:
                out, ts = self._cmd_cache[key]
                if time.time() - ts < self._cache_ttl:
                    results[cmd] = out
                    continue
            to_run.append(cmd)

        if to_run:
            # Operational commands (diagnose/execute) can't run inside a config
            # context, so issue them at the top-level prompt BEFORE entering scope.
            # This fixes VDOM-enabled devices, where wrapping e.g.
            # `diagnose sys ntp status` in `config global` made the command fail.
            operational = [c for c in to_run if _is_operational_command(c)]
            config_cmds = [c for c in to_run if not _is_operational_command(c)]

            for cmd in operational:
                out = self._raw_send(cmd)
                results[cmd] = out
                if use_cache:
                    self._cmd_cache[self._cache_key(scope, vdom, cmd)] = (out, time.time())

            if config_cmds:
                with self.scope(scope, vdom):
                    for cmd in config_cmds:
                        out = self._raw_send(cmd)
                        results[cmd] = out
                        if use_cache:
                            self._cmd_cache[self._cache_key(scope, vdom, cmd)] = (out, time.time())

        return results

    def run(
        self,
        command: str,
        scope: str = SCOPE_GLOBAL,
        vdom: Optional[str] = None,
        use_cache: bool = True,
    ) -> str:
        """Run a single read command in the given scope and return its output."""
        return self.collect([command], scope=scope, vdom=vdom, use_cache=use_cache)[command]

    def send_raw(self, command: str) -> str:
        """
        Run a command at the top-level prompt with no scope wrapper. Use for
        device-wide operations that are valid anywhere (``get system status``,
        ``show full-configuration``, ``execute backup ...``).
        """
        return self._raw_send(command)

    # ------------------------------------------------------------------
    # Config execution (hardening)
    # ------------------------------------------------------------------
    def run_config(
        self,
        commands: List[str],
        scope: str = SCOPE_GLOBAL,
        vdom: Optional[str] = None,
    ) -> Dict[str, object]:
        """
        Execute a block of config commands inside the correct scope context.

        ``commands`` carry only the inner config (e.g. ``config system global`` /
        ``set ... `` / ``end``); the scope wrapper (``config global`` or
        ``config vdom`` / ``edit <name>``) is added automatically here.

        Returns ``{"success": bool, "output": str, "errors": [str]}``.
        """
        outputs: List[str] = []
        errors: List[str] = []

        with self.scope(scope, vdom):
            for cmd in commands:
                if not cmd.strip():
                    continue
                try:
                    out = self._raw_send(cmd)
                    outputs.append(f"# {cmd}\n{out}")
                    for line in out.splitlines():
                        low = line.lower()
                        if any(p in low for p in _BAD_OUTPUT_PATTERNS):
                            errors.append(line.strip())
                except Exception as e:  # noqa: BLE001
                    errors.append(f"Command '{cmd}' failed: {e}")
                    outputs.append(f"# {cmd}\nERROR: {e}")

        return {"success": not errors, "output": "\n\n".join(outputs), "errors": errors}

    def clear_cache(self) -> None:
        self._cmd_cache.clear()
