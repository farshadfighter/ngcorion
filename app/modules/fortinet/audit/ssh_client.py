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

import logging
import re
import time
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

try:
    from netmiko.exceptions import ReadTimeout
except ImportError:  # pragma: no cover - older netmiko layouts
    class ReadTimeout(Exception):
        pass

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

# ── Per-command read timing ─────────────────────────────────────────────────
# netmiko's send_command_timing returns once the channel has been SILENT for
# `last_read` seconds (or at the `read_timeout` hard cap). So each command costs
# roughly <device output time> + CMD_LAST_READ. 2.0s is netmiko's default and a
# deliberate choice: shortening it makes every command "faster" but raises the
# odds that a long streaming output (e.g. `get system global`, ~150 fields) gets
# cut mid-stream and must be rescued by the prompt-drain loop in _raw_send —
# which pays DRAIN_LAST_READ per extra read. Do NOT lower CMD_READ_TIMEOUT much:
# it is the only bound on genuinely long transfers (`show full-configuration`
# backups) that stream continuously with no silent gap.
CMD_LAST_READ = 2.0        # seconds of channel silence that ends a normal read
CMD_READ_TIMEOUT = 120.0   # hard cap per command (long outputs: config backups)
DRAIN_LAST_READ = 1.0      # silence window per prompt-drain read
DRAIN_READ_TIMEOUT = 15.0  # hard cap per prompt-drain read (max 8 drains)
PROMPT_READ_TIMEOUT = 30.0 # hard cap for netmiko's own find_prompt() read

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


def _ends_with_prompt(output: str) -> bool:
    """
    Whether ``output`` ends with a FortiOS CLI prompt (``… # `` for admin or
    ``… $``). FortiOS echoes the prompt once a command finishes, so its presence
    at the end is a reliable "the full output arrived" signal — used to detect a
    timing-based read that returned a long command (e.g. ``get system global``)
    before the device finished streaming.
    """
    tail = (output or "").rstrip()
    return tail.endswith("#") or tail.endswith("$")


def _is_operational_command(command: str) -> bool:
    """
    Whether ``command`` is an operational command (``diagnose``/``execute``)
    rather than a config read.

    These need special context handling (see ``_run_operational``): on a
    VDOM-enabled device the post-login prompt is the RESTRICTED inter-VDOM
    prompt — it shows no ``(context)`` suffix so it LOOKS top-level, but it
    rejects global diagnostics such as ``diagnose sys ntp status`` with
    ``8757: Unknown action 0 / Command fail. Return code -1``. Per Fortinet's
    KB they must run inside ``config global`` there. On flat devices the
    top-level prompt IS the operational prompt and ``config global`` does not
    exist. They read device-wide/global state, so a single global read is
    correct regardless of the requested config scope.
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
        # Parsed `get system status` (device-constant for a session): cached so
        # connectivity checks / metadata readers don't re-send the command.
        self._system_status: Optional[Dict[str, object]] = None

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

        t0 = time.perf_counter()

        base = dict(
            host=self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            fast_cli=False,
            global_delay_factor=2,
            session_timeout=60,
        )
        # NOTE: deliberately no read_timeout_override here. It is a hard
        # override netmiko applies to EVERY read, including the read_timeout
        # this client passes explicitly. Setting it to 30 would clamp the
        # CMD_READ_TIMEOUT (120s) budget that long outputs like config backups
        # need, truncating them; setting it to 120 would stretch the bounded
        # DRAIN_READ_TIMEOUT (15s) drain loop to eight two-minute reads. The
        # reads on this client's own paths all pass their own read_timeout, so
        # the only ones left on netmiko's 10s default are its internal prompt
        # reads — those get a scoped budget in _current_prompt() instead.

        last_error = None
        for device_type in ("fortinet", "fortigate"):
            try:
                params = dict(base)
                params["device_type"] = device_type
                self._connection = ConnectHandler(**params)
                t_conn = time.perf_counter()
                self._prime_session()
                logger.info("FG timing: connect=%.2fs prime=%.2fs on %s",
                            t_conn - t0, time.perf_counter() - t_conn, self.host)
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
            except ValueError as e:
                # netmiko raises ValueError("Unsupported device_type ...") for a
                # platform it doesn't know. 'fortigate' is NOT a valid netmiko
                # platform (only 'fortinet' is), so this fallback iteration must
                # never OVERWRITE the real transport error captured on the
                # 'fortinet' attempt — otherwise every genuine connect failure is
                # reported as a misleading "Unsupported device_type" wall of text.
                if last_error is None:
                    last_error = e
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
        """
        Post-connect session setup with ZERO extra round-trips when possible.

        netmiko's FortinetSSH ``session_preparation`` has already (a) detected
        VDOM mode (stored on ``connection._vdoms``) and (b) disabled the
        interactive pager VDOM-aware (``set output standard``, entering
        ``config global`` first when needed). Re-doing both here used to cost
        4-6 extra commands per connection — a large share of hardening wall
        time. Reuse the driver's answer instead.

        Only when ``_vdoms`` is missing (non-netmiko/custom connection) fall
        back to the old belt-and-suspenders path: detect VDOM mode via
        ``get system status`` and re-disable the pager in the global scope
        (on VDOM devices ``config system console`` is global-only and is
        rejected at the root prompt with ``8757: Unknown action``).
        ``_raw_send`` still drains any stray ``--More--`` as a safety net.
        """
        vdoms = getattr(self._connection, "_vdoms", None)
        if isinstance(vdoms, bool):
            self._vdom_enabled = vdoms
            logger.debug("FG prime: reused netmiko VDOM detection (%s) and pager "
                         "setup on %s — no extra commands", vdoms, self.host)
            return
        try:
            # Detect VDOM mode first (cached) so scope() opens the right context.
            self.is_vdom_enabled()
            with self.scope(SCOPE_GLOBAL):
                for cmd in ("config system console", "set output standard", "end"):
                    self._raw_send(cmd)
        except Exception:  # pragma: no cover - best effort
            logger.debug("FG pager priming failed on %s (best-effort; netmiko "
                         "already disables paging on connect)",
                         self.host, exc_info=True)

    def disconnect(self) -> None:
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                logger.debug("FG disconnect cleanup failed on %s (ignored)",
                             self.host, exc_info=True)
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
    def _prompt_pattern(self) -> Optional[str]:
        """
        Regex for prompt-anchored reads, or ``None`` when unavailable.

        Anchored to the hostname netmiko captured at login (``base_prompt``) so
        a bare ``#`` inside command output (e.g. ``#config-version=...`` comment
        lines) can't end a read early; the optional ``(context)`` group matches
        every config-context prompt (``host (global) #``, ``host (ntp) #``).
        ``--More--`` is included so an unexpected pager stalls the read for one
        round-trip instead of the full read-timeout (the caller's pager loop
        then drains it). ``None`` (no base_prompt / non-netmiko fake) routes the
        caller to the timing-based fallback.
        """
        conn = self._connection
        host = (getattr(conn, "base_prompt", "") or "").strip()
        if (not host
                or not callable(getattr(conn, "write_channel", None))
                or not callable(getattr(conn, "read_until_pattern", None))):
            return None
        return rf"(?:--More--|{re.escape(host)}(?:\s\([^)]*\))?\s*[#$]\s*$)"

    def _raw_send(self, command: str) -> str:
        """Send a single command, handling ``--More--`` pagination."""
        if not self._connection:
            raise RuntimeError("Not connected. Call connect() first.")

        t0 = time.perf_counter()

        # Fast path: prompt-based read — write the command and return as soon as
        # the hostname-anchored CLI prompt reappears (~1 network round-trip).
        # send_command_timing (the fallback) instead waits until the channel has
        # been SILENT for CMD_LAST_READ (2s), which used to add ~2s to EVERY
        # command and dominated hardening wall time (9-15 commands per action).
        #
        # Wrap the actual SSH send so a device-side failure on ANY command
        # (including the very first one hardening issues) is logged with the
        # exact command and a full traceback (file + line) before it propagates.
        pattern = self._prompt_pattern()
        read_mode = "prompt" if pattern else "timing"
        try:
            if pattern:
                self._connection.write_channel(command.rstrip() + "\n")
                try:
                    output = self._connection.read_until_pattern(
                        pattern=pattern, read_timeout=CMD_READ_TIMEOUT
                    )
                except ReadTimeout:
                    # No prompt within the cap (netmiko discards what it read so
                    # far). Salvage what is still arriving with a timing drain so
                    # the session isn't left mid-stream for the next command.
                    logger.warning(
                        "FG prompt read timed out (%.0fs) for %r on %s; "
                        "draining with timing read",
                        CMD_READ_TIMEOUT, command, self.host,
                    )
                    read_more = getattr(self._connection, "read_channel_timing", None)
                    output = (read_more(last_read=CMD_LAST_READ,
                                        read_timeout=CMD_READ_TIMEOUT)
                              if callable(read_more) else "")
            else:
                output = self._connection.send_command_timing(
                    command, strip_prompt=False, strip_command=False,
                    last_read=CMD_LAST_READ, read_timeout=CMD_READ_TIMEOUT,
                )
        except Exception:
            logger.error("FG command send failed: %r on %s",
                         command, self.host, exc_info=True)
            raise
        # Defensive: drain any pager prompt that slipped through.
        guard = 0
        while output and re.search(r"--More--", output, flags=re.IGNORECASE) and guard < 50:
            output = re.sub(r"--More--", "", output, flags=re.IGNORECASE)
            output += self._connection.send_command_timing(
                " ", strip_prompt=False, strip_command=False,
                last_read=CMD_LAST_READ, read_timeout=CMD_READ_TIMEOUT,
            )
            guard += 1

        # A timing-based read can return a long output (e.g. `get system global`,
        # ~150 fields) BEFORE the device has finished streaming, silently dropping
        # the tail — so alphabetically-late fields like `strong-crypto` go missing
        # and their checks then fail regardless of the real value. Keep draining
        # until the CLI prompt reappears (or we time out). This only does extra
        # reads when the output is not already prompt-terminated, so the common
        # (complete) case has no added latency.
        settle = 0
        read_more = getattr(self._connection, "read_channel_timing", None)
        while callable(read_more) and output and not _ends_with_prompt(output) and settle < 8:
            try:
                more = read_more(last_read=DRAIN_LAST_READ, read_timeout=DRAIN_READ_TIMEOUT)
            except Exception:  # noqa: BLE001 - best-effort drain; never fail a read
                logger.debug("FG drain read failed for %r on %s (best-effort)",
                             command, self.host, exc_info=True)
                break
            if not more:
                break
            if re.search(r"--More--", more, flags=re.IGNORECASE):
                more = re.sub(r"--More--", "", more, flags=re.IGNORECASE)
                more += self._connection.send_command_timing(
                    " ", strip_prompt=False, strip_command=False,
                    last_read=CMD_LAST_READ, read_timeout=CMD_READ_TIMEOUT,
                )
            output += more
            settle += 1

        if output and not _ends_with_prompt(output):
            logger.warning(
                "Command %r output may be truncated (%d chars, no trailing prompt "
                "after %d drain attempts)", command, len(output), settle,
            )
        # Per-command timing: the profiling signal for hardening slowness. With
        # timing-based reads every command pays ~CMD_LAST_READ of silence on top
        # of the device's own output time — this log shows exactly where.
        logger.info("FG timing: cmd=%r %.2fs (mode=%s, %d chars, drains=%d, complete=%s)",
                    command, time.perf_counter() - t0, read_mode, len(output or ""),
                    settle, _ends_with_prompt(output or ""))
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
        """
        Parse ``get system status`` (version, hostname, serial, VDOM mode).

        Cached for the lifetime of the session — the values are constant, and
        every caller (connectivity test, metadata, VDOM detection fallback)
        used to pay one more round-trip for the same answer.
        """
        if self._system_status is not None:
            return self._system_status
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
        # Do not overwrite VDOM state already sourced from netmiko's own
        # detection (_prime_session) — both read the same device fact anyway.
        if self._vdom_enabled is None:
            self._vdom_enabled = vdom_enabled
        self._system_status = meta
        return meta

    def is_vdom_enabled(self) -> bool:
        """Return whether VDOM mode is enabled (cached after first detection).

        A device that IS VDOM-enabled but gets misdetected here as flat
        silently collapses every per-VDOM control down to a single evaluation
        instead of one per real VDOM — the audit still "succeeds" but quietly
        under-counts. So a failure to read ``get system status`` is retried
        once before falling back, and the fallback is logged loudly (not
        swallowed at debug level) so the under-count is diagnosable.
        """
        if self._vdom_enabled is None:
            try:
                self.get_system_status()
            except Exception:
                logger.warning(
                    "FG VDOM-mode detection failed on %s ('get system status' "
                    "errored); retrying once before assuming a flat device.",
                    self.host, exc_info=True,
                )
                try:
                    self.get_system_status()
                except Exception:
                    logger.error(
                        "FG VDOM-mode detection failed twice on %s; treating as "
                        "a flat (non-VDOM) device for this audit. If this "
                        "device actually has VDOMs enabled, every per-VDOM "
                        "control will be under-counted (evaluated once instead "
                        "of once per VDOM).",
                        self.host, exc_info=True,
                    )
                    self._vdom_enabled = False
        return bool(self._vdom_enabled)

    def enumerate_vdoms(self) -> List[str]:
        """
        Return every VDOM on the device (``root`` first). Empty list when VDOM
        mode is disabled. Always returns at least ``["root"]`` when enabled.

        Undercounting here (returning fewer VDOMs than the device really has)
        silently shrinks the audit's scope, so every silent-failure path below
        is retried once and/or logged loudly instead of swallowed quietly.
        """
        if not self.is_vdom_enabled():
            return []

        vdoms: List[str] = []

        # Primary: diagnose sys vdom list (works at the top level on most
        # FortiOS). One retry: a rejected first attempt is not proof the
        # device only has one VDOM, and trusting it silently would scope the
        # rest of the audit to whatever fragment of the device we managed to
        # read.
        out = self._raw_send("diagnose sys vdom list")
        if not self._is_command_ok(out):
            logger.warning(
                "FG VDOM enumeration: 'diagnose sys vdom list' rejected on %s "
                "(%r); retrying once.",
                self.host, out.strip()[:160],
            )
            out = self._raw_send("diagnose sys vdom list")
        if self._is_command_ok(out):
            for m in re.finditer(r"\bname=([A-Za-z0-9._\-]+)", out):
                vdoms.append(m.group(1))
            if not vdoms:
                for m in re.finditer(r"^\s*vd\s+([A-Za-z0-9._\-]+)/", out, flags=re.MULTILINE):
                    vdoms.append(m.group(1))
        else:
            logger.warning(
                "FG VDOM enumeration: 'diagnose sys vdom list' rejected twice "
                "on %s (%r); falling back to 'show system vdom-property'.",
                self.host, out.strip()[:160],
            )

        # Fallback: enumerate the config VDOM table from the global context.
        # Tried whenever the primary method found nothing — whether it was
        # rejected outright or "succeeded" with zero matches, both are equally
        # inconclusive about how many VDOMs actually exist.
        if not vdoms:
            try:
                with self.scope(SCOPE_GLOBAL):
                    cfg = self._raw_send("show system vdom-property")
                for m in re.finditer(r'^\s*edit\s+"?([A-Za-z0-9._\-]+)"?\s*$', cfg, flags=re.MULTILINE):
                    vdoms.append(m.group(1))
            except Exception:
                logger.warning(
                    "FG VDOM enumeration fallback ('show system vdom-property') "
                    "failed on %s; the device may have more VDOMs than this "
                    "audit will see.",
                    self.host, exc_info=True,
                )

        # De-duplicate, keep order, force root to the front, default to root.
        seen, unique = set(), []
        for v in vdoms:
            if v and v not in seen:
                seen.add(v)
                unique.append(v)
        if not unique:
            logger.warning(
                "FG VDOM enumeration found NO VDOMs on %s despite VDOM mode "
                "being enabled; defaulting to ['root'] only. If this device "
                "actually has more VDOMs, this audit will under-count "
                "per-VDOM checks.",
                self.host,
            )
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

        # `config global` / `config vdom` are only valid from the top-level
        # (inter-VDOM) prompt. A prior command block — e.g. an earlier control in
        # a "harden all" run whose remediation opened a config sub-context and
        # errored before fully backing out — can leave the session one or more
        # levels deep; issuing `config global` from there fails silently and the
        # block that follows (e.g. FG-BL-040's NTP config, which MUST run inside
        # `config global` on VDOM devices) never applies. Back out to the top
        # first, mirroring what `collect()` does before operational commands.
        self._ensure_top_level()

        logger.info("FG timing: scope switch -> %s (vdom=%s) on %s",
                    scope, self.effective_vdom(scope, vdom), self.host)
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
            except Exception as e:
                logger.warning(
                    "[FortiGate SSH] could not back out of the VDOM context on "
                    f"{self.host}: {e}"
                )
            raise FortiGateContextError(
                f"Failed to enter VDOM '{target}': {(out1 + out2).strip()[:160]}"
            )
        return True

    def _close_scope(self) -> None:
        try:
            self._raw_send("end")
        except Exception:  # pragma: no cover - best effort
            logger.debug("FG scope close ('end') failed on %s (ignored)",
                         self.host, exc_info=True)

    def _ensure_top_level(self, max_depth: int = 8) -> None:
        """
        Guarantee the session sits at the top-level operational prompt.

        Operational commands (``diagnose``/``execute``) are rejected inside ANY
        config context (``8757: Unknown action 0 / Command fail. Return code -1``).
        Running them at the top level is normally guaranteed by ``scope()``'s
        ``finally: end``, but a preceding command block (e.g. a hardening
        ``execute_commands`` whose remediation opened an object/sub-object context)
        can leave the session one or more levels deep. Before issuing an
        operational command we therefore back out of any lingering scope.

        A FortiGate config prompt shows its context in parentheses
        (``hostname (global) #`` / ``hostname (ntp) #``); the top-level prompt has
        none. We send ``end`` until the prompt is context-free (bounded).
        """
        for step in range(max_depth):
            prompt = self._current_prompt()
            if not prompt:
                return
            # A config-context prompt has " (context) #"; a bare hostname does not.
            at_top = not re.search(r"\s\([^)]*\)\s*[#$]\s*$", prompt)
            logger.info("FG ensure-top-level on %s: prompt=%r at_top=%s (step %d)",
                        self.host, prompt, at_top, step)
            if at_top:
                return
            self._raw_send("end")

    def _current_prompt(self) -> str:
        """
        Best-effort read of the current CLI prompt ('' when unavailable).

        netmiko's find_prompt() takes no timeout and falls back to a 10s read,
        which is what raises "Pattern not detected" on a device slow to echo a
        bare newline. Scope the override to this call only — applying it at the
        connection level would also rewrite the explicit CMD/DRAIN budgets.
        """
        conn = self._connection
        find_prompt = getattr(conn, "find_prompt", None)
        if not callable(find_prompt):
            return ""
        prev = getattr(conn, "read_timeout_override", None)
        try:
            conn.read_timeout_override = PROMPT_READ_TIMEOUT
        except Exception:  # noqa: BLE001 - non-netmiko fake without the attr
            prev = None
        try:
            return find_prompt() or ""
        except Exception:  # noqa: BLE001 - best effort; never fail a read
            return ""
        finally:
            try:
                conn.read_timeout_override = prev
            except Exception:  # noqa: BLE001
                pass

    def _run_operational(self, command: str) -> str:
        """
        Run a ``diagnose``/``execute`` command in the context FortiOS accepts.

        VDOM-enabled device: the session must be INSIDE ``config global`` —
        the inter-VDOM login prompt looks top-level (bare ``hostname #``) but
        rejects global diagnostics with ``8757: Unknown action 0`` (Fortinet KB:
        "log in, config global, diagnose sys ntp status"). Flat device: run at
        the top-level prompt (``config global`` does not exist there).

        If the preferred context rejects the command anyway, retry once in the
        other context so a build-specific quirk costs one extra round-trip
        instead of a false NON-COMPLIANT / failed post-fix verification.
        """
        vdom_on = self.is_vdom_enabled()
        logger.info("FG operational %r on %s: prompt=%r vdom_enabled=%s context=%s",
                    command, self.host, self._current_prompt(), vdom_on,
                    "config global" if vdom_on else "top-level")
        if vdom_on:
            try:
                with self.scope(SCOPE_GLOBAL):
                    out = self._raw_send(command)
                if self._is_command_ok(out):
                    return out
                logger.warning("FG operational %r rejected inside config global on %s "
                               "(%r); retrying at top level",
                               command, self.host, (out or "").strip()[:160])
            except FortiGateContextError as e:
                logger.warning("FG cannot enter config global for %r on %s (%s); "
                               "retrying at top level", command, self.host, e)
            self._ensure_top_level()
            return self._raw_send(command)

        out = self._raw_send(command)
        if not self._is_command_ok(out):
            logger.warning("FG operational %r rejected at top level on flat device %s: %r",
                           command, self.host, (out or "").strip()[:160])
        return out

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
        t0 = time.perf_counter()
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
            # Operational commands (diagnose/execute) need their own context
            # handling: `config global` on VDOM-enabled devices, top level on
            # flat devices (see _run_operational). Config reads run inside the
            # requested scope as usual.
            #
            # EXCEPTION: for a VDOM scope on a VDOM-enabled device, operational
            # commands run INSIDE the `config vdom / edit <name>` context with
            # the config reads — diagnostics like `diagnose firewall iprope
            # list` read per-VDOM kernel state, and FortiOS accepts diagnose at
            # the VDOM prompt. Routing them through _run_operational's global
            # context would silently return another VDOM's data.
            vdom_scoped = self.is_vdom_enabled() and scope in (SCOPE_VDOM, SCOPE_VDOM_ROOT)
            operational = [c for c in to_run
                           if _is_operational_command(c) and not vdom_scoped]
            config_cmds = [c for c in to_run if c not in operational]

            if operational:
                # A prior command block may have left the session inside a config
                # context; back out to the top-level prompt first so the
                # `config global` / diagnose that follows starts from a known state.
                self._ensure_top_level()
                for cmd in operational:
                    out = self._run_operational(cmd)
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

        if to_run:
            logger.info("FG timing: collect %d cmd(s) scope=%s vdom=%s -> %.2fs "
                        "(%d cached)", len(to_run), scope, vdom,
                        time.perf_counter() - t0, len(commands) - len(to_run))
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
        t0 = time.perf_counter()
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
                    logger.error("FG config command failed: %r (scope=%s vdom=%s) on %s",
                                 cmd, scope, vdom, self.host, exc_info=True)
                    errors.append(f"Command '{cmd}' failed: {e}")
                    outputs.append(f"# {cmd}\nERROR: {e}")

        logger.info("FG timing: run_config %d cmd(s) scope=%s vdom=%s -> %.2fs "
                    "(errors=%d)", len(commands), scope, vdom,
                    time.perf_counter() - t0, len(errors))
        return {"success": not errors, "output": "\n\n".join(outputs), "errors": errors}

    def clear_cache(self) -> None:
        self._cmd_cache.clear()
