"""
Base classes for the self-contained CIS benchmark services.

A benchmark service subclasses :class:`CISCheck`, implements ``audit()`` and
returns a ``list[CISResult]``. The base class provides the reusable plumbing:
an SSH transport (paramiko), sudo-aware command execution, and safe remote
file read / stat / backup / write helpers.

Design goals
------------
* **Read-only unless asked.** When ``auto_fix`` is ``False`` the service must
  make zero changes to the target. The write/backup helpers here are only ever
  invoked by a service's fix path, which is itself gated on ``auto_fix``.
* **Fail closed, never crash the run.** Individual checks collect their own
  results; the base helpers raise on genuine transport errors so a check can
  turn that into a ``CheckStatus.ERROR`` result rather than aborting the audit.
"""

from __future__ import annotations

import base64
import enum
import logging
import shlex
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, NamedTuple, Optional

import paramiko

logger = logging.getLogger(__name__)


class CheckStatus(str, enum.Enum):
    """Outcome of a single CIS control.

    Distinct from :class:`app.models.audit.CheckStatus` (which lacks
    ``SKIPPED``); this subsystem needs a four-state result so a control that
    could not be evaluated at all (e.g. an optional dependency is missing) is
    reported separately from a control that ran but failed.
    """

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class CISResult:
    """The result of evaluating one benchmark control."""

    id: str
    title: str
    status: CheckStatus
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    fix_applied: bool = False
    error_msg: Optional[str] = None
    # Extra context (harmless defaults; not part of the minimum contract).
    section: Optional[str] = None
    scored: bool = True

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class CommandResult(NamedTuple):
    """Return value of :meth:`CISCheck.run`."""

    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class CISCheck(ABC):
    """Base class for an SSH-driven CIS benchmark service.

    Subclasses implement :meth:`audit` and typically expose fix methods that
    are only reachable when ``self.auto_fix`` is ``True``.
    """

    def __init__(
        self,
        host: str,
        ssh_username: str,
        ssh_password: Optional[str] = None,
        ssh_key_file: Optional[str] = None,
        ssh_port: int = 22,
        *,
        sudo: bool = True,
        auto_fix: bool = False,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        self.ssh_key_file = ssh_key_file
        self.ssh_port = ssh_port
        self.sudo = sudo
        self.auto_fix = auto_fix
        self.timeout = timeout
        self._client: Optional[paramiko.SSHClient] = None

    # ------------------------------------------------------------------ #
    # Connection management
    # ------------------------------------------------------------------ #
    def connect(self) -> None:
        if self._client is not None:
            return
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.ssh_port,
            username=self.ssh_username,
            password=self.ssh_password,
            key_filename=self.ssh_key_file,
            timeout=self.timeout,
            allow_agent=bool(self.ssh_key_file is None and self.ssh_password is None),
            look_for_keys=bool(self.ssh_key_file is None and self.ssh_password is None),
        )
        self._client = client
        logger.debug("SSH connected to %s:%s", self.host, self.ssh_port)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            finally:
                self._client = None

    def __enter__(self) -> "CISCheck":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # Command execution
    # ------------------------------------------------------------------ #
    def run(self, command: str, *, sudo: bool = False) -> CommandResult:
        """Execute ``command`` on the target and capture rc/stdout/stderr.

        ``sudo=True`` wraps the command in ``sudo sh -c '<command>'`` so pipes
        and redirections run with elevated privileges as a single unit.
        """
        if self._client is None:
            self.connect()
        assert self._client is not None

        if sudo and self.sudo:
            command = f"sudo sh -c {shlex.quote(command)}"

        logger.debug("run: %s", command)
        stdin, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return CommandResult(rc=rc, stdout=out, stderr=err)

    # ------------------------------------------------------------------ #
    # Remote file helpers
    # ------------------------------------------------------------------ #
    def read_file(self, path: str) -> str:
        """Return the contents of a remote file (raises on failure)."""
        res = self.run(f"cat {shlex.quote(path)}", sudo=True)
        if not res.ok:
            raise FileNotFoundError(f"cannot read {path}: {res.stderr.strip() or res.stdout.strip()}")
        return res.stdout

    def file_exists(self, path: str) -> bool:
        return self.run(f"test -e {shlex.quote(path)}", sudo=True).ok

    def stat_file(self, path: str) -> Optional["FileStat"]:
        """Return mode/owner/group for ``path`` or ``None`` if it doesn't exist."""
        res = self.run(f"stat -c '%a %U %G' {shlex.quote(path)}", sudo=True)
        if not res.ok:
            return None
        parts = res.stdout.split()
        if len(parts) != 3:
            return None
        return FileStat(mode=parts[0], owner=parts[1], group=parts[2])

    def backup_file(self, path: str) -> str:
        """Copy ``path`` to ``<path>.bak.<timestamp>`` and return the backup path.

        Only ever called from a fix path (which is gated on ``auto_fix``).
        """
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        backup_path = f"{path}.bak.{ts}"
        res = self.run(f"cp -p {shlex.quote(path)} {shlex.quote(backup_path)}", sudo=True)
        if not res.ok:
            raise IOError(f"backup of {path} failed: {res.stderr.strip()}")
        logger.info("backed up %s -> %s", path, backup_path)
        return backup_path

    def write_file(self, path: str, content: str) -> None:
        """Overwrite a remote file atomically-ish via base64 + sudo tee.

        base64 avoids any quoting/escaping hazards from the file's contents.
        """
        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        cmd = f"echo {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"
        res = self.run(cmd, sudo=True)
        if not res.ok:
            raise IOError(f"write to {path} failed: {res.stderr.strip()}")

    # ------------------------------------------------------------------ #
    # Contract
    # ------------------------------------------------------------------ #
    @abstractmethod
    def audit(self) -> List[CISResult]:
        """Run every control and return the full list of results.

        Implementations must never abort on a single failing control.
        """
        raise NotImplementedError


class FileStat(NamedTuple):
    mode: str   # octal permission string, e.g. "600"
    owner: str
    group: str
