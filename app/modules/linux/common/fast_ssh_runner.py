"""
Fast SSH runner for Linux-shell hardening (Linux, Apache, MongoDB hosts).

The audit path uses netmiko's interactive-shell client (``LinuxSSHClient``),
which is the right tool for collecting data but is slow for one-off hardening:
every connection pays netmiko ``session_preparation`` and every command waits for
the shell prompt to be re-detected (and can stall up to the read timeout if the
output confuses prompt detection).

Hardening commands are independent, non-interactive shell commands, so they don't
need an interactive shell at all. This runner executes each command with
paramiko ``exec_command`` — its own channel that ends on EOF + exit status, with
**no prompt detection and no session_preparation** — which removes the dominant
per-fix latency.

It is used ONLY by the hardening executors. The audit ``LinuxSSHClient`` is left
untouched, so audits cannot regress.
"""

from typing import Dict, Optional
import logging
import re
import shlex
import socket
import time

import paramiko

from app.core.ssh_exceptions import map_ssh_exception
from app.modules.linux.common.ssh_client import parse_os_release

logger = logging.getLogger(__name__)

DEFAULT_CMD_TIMEOUT = 30


class HardeningSSHRunner:
    """
    Lightweight paramiko ``exec_command`` runner with the surface the hardening
    executors already call on ``LinuxSSHClient``.

    Public API kept intentionally compatible with ``LinuxSSHClient`` so it is a
    drop-in for the hardening executors:
      - ``connect()`` / ``disconnect()`` / ``is_connected()``
      - ``send_command(command, use_sudo=False, timeout=...)`` (Linux/Apache style,
        wraps sudo as ``echo <pw> | sudo -S <cmd>``)
      - ``detect_distro()`` (fallback when the distro isn't already known)
      - ``run(command, timeout=...)`` raw exec primitive (no sudo wrapping), for
        callers that build their own command string (e.g. MongoDB's
        ``sudo -S sh -c '<cmd>' 2>/dev/null``).
    """

    RETRY_DELAY = 2

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        sudo_password: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.sudo_password = sudo_password or password
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[paramiko.SSHClient] = None
        self._distro_info: Optional[Dict[str, str]] = None

    # ------------------------------------------------------------------ #
    #  Connection management                                              #
    # ------------------------------------------------------------------ #

    def connect(self) -> None:
        """
        Open an SSH connection.

        Raises one of the ``SSHConnectionError`` subclasses (via
        ``map_ssh_exception``) on failure, matching ``LinuxSSHClient.connect``.
        """
        if self.is_connected():
            return

        last_exception: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                    # Password auth only: don't probe the SSH agent or local keys,
                    # which adds latency and can cause spurious auth failures.
                    look_for_keys=False,
                    allow_agent=False,
                )
                self._client = client
                logger.info(f"Connected to {self.ip} for hardening (fast exec)")
                return
            except paramiko.AuthenticationException as e:
                # Credentials are wrong — retrying won't help.
                self._safe_close(client)
                logger.error(f"Authentication failed for {self.ip}")
                raise map_ssh_exception(e, self.ip)
            except Exception as e:  # noqa: BLE001 - mapped below
                last_exception = e
                self._safe_close(client)
                logger.warning(
                    f"Connection error to {self.ip} "
                    f"(attempt {attempt}/{self.max_retries}): {type(e).__name__}"
                )
                if attempt < self.max_retries:
                    time.sleep(self.RETRY_DELAY)

        logger.error(f"Failed to connect to {self.ip} after {self.max_retries} attempts")
        raise map_ssh_exception(last_exception, self.ip)

    def is_connected(self) -> bool:
        """True if the SSH transport is open and active."""
        if not self._client:
            return False
        transport = self._client.get_transport()
        return bool(transport and transport.is_active())

    def disconnect(self) -> None:
        """Close the SSH connection."""
        if self._client:
            self._safe_close(self._client)
            self._client = None
            logger.info(f"Disconnected from {self.ip}")

    @staticmethod
    def _safe_close(client: paramiko.SSHClient) -> None:
        try:
            client.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Command execution                                                  #
    # ------------------------------------------------------------------ #

    def run(self, command: str, timeout: int = DEFAULT_CMD_TIMEOUT) -> str:
        """
        Execute a raw command (no sudo wrapping) and return its combined
        stdout+stderr, mirroring the merged output of an interactive shell.

        Raises RuntimeError on transport failure or command timeout (matching
        ``LinuxSSHClient.send_command``'s failure contract).
        """
        return self.run_with_status(command, timeout=timeout)[0]

    def run_with_status(
        self, command: str, timeout: int = DEFAULT_CMD_TIMEOUT
    ) -> tuple:
        """
        Same as ``run``, but also returns the command's exit status.

        Returns ``(output, exit_status)``. Callers that need to know whether a
        remediation command actually worked must use this: an ``exec_command``
        that fails (sudo denied, package missing, permission error) still
        returns cleanly, so output alone cannot distinguish success from a
        silent no-op.
        """
        if not self.is_connected():
            raise RuntimeError("Not connected. Call connect() first.")

        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            try:
                stdin.close()
            except Exception:
                pass
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()
        except socket.timeout:
            raise RuntimeError(f"Command timed out after {timeout}s: {command[:60]}...")
        except Exception as e:
            logger.error(f"Command execution failed on {self.ip}: {command[:50]}... - {e}")
            raise RuntimeError(f"Command execution failed: {e}")

        # Merge stderr into the result the way a shared shell session would, so
        # callers that scan output (verification PASS/FAIL, error detection) see
        # everything the command emitted.
        if err.strip():
            out = f"{out}\n{err}" if out else err
        return out, exit_status

    def send_command(
        self,
        command: str,
        use_sudo: bool = False,
        timeout: int = DEFAULT_CMD_TIMEOUT,
    ) -> str:
        """
        Linux/Apache-style command execution, drop-in for
        ``LinuxSSHClient.send_command``.

        With ``use_sudo`` the command is wrapped as ``echo <pw> | sudo -S <cmd>``
        and the ``[sudo] password ...`` prompt is stripped from the output —
        identical to the netmiko client's behavior.
        """
        return self.send_command_with_status(command, use_sudo, timeout)[0]

    def send_command_with_status(
        self,
        command: str,
        use_sudo: bool = False,
        timeout: int = DEFAULT_CMD_TIMEOUT,
    ) -> tuple:
        """``send_command`` that also returns the exit status: ``(output, status)``."""
        if use_sudo:
            full_command = f"echo {shlex.quote(self.sudo_password)} | sudo -S {command}"
            output, exit_status = self.run_with_status(full_command, timeout=timeout)
            output = re.sub(r"^\[sudo\].*?:\s*", "", output, flags=re.M)
            return output, exit_status
        return self.run_with_status(command, timeout=timeout)

    def detect_distro(self) -> Dict[str, str]:
        """
        Detect the Linux distribution (fallback for callers that don't already
        know it). Uses the same parser as the audit client so the resolved
        profile/id is identical.
        """
        if self._distro_info:
            return self._distro_info

        output = self.run("cat /etc/os-release", timeout=15)
        self._distro_info = parse_os_release(output)
        logger.info(
            f"Detected distro on {self.ip}: {self._distro_info['name']} "
            f"(profile: {self._distro_info['profile']})"
        )
        return self._distro_info

    # ------------------------------------------------------------------ #
    #  Context manager                                                    #
    # ------------------------------------------------------------------ #

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False
