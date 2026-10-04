"""
Per-family device access for restores. Every family is reached over SSH through
the same clients auditing and hardening use (so host-key pinning applies).

A driver exposes one contract the restore service drives:

    open() / close()
    read_live()              configuration text, same shape as a backup
    snapshot()               configuration text for the "Before restore" backup
    source_ip()              the address the device sees NGCorion connecting from
    auto_revert_available()  (bool, reason)
    plan(backup_text, live)  -> RestorePlan (diff + what to send)
    apply(plan, minutes)     arm the auto-revert, then push the plan
    confirm()                keep the changes: save them and disarm auto-revert
    revert_now()             undo the unsaved changes immediately
"""
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.modules.backup.restore import config_tree, file_bundle, risk

logger = logging.getLogger(__name__)

SUPPORTED_FAMILIES = ("cisco", "fortinet", "linux", "apache", "mongodb")


class RestoreApplyError(RuntimeError):
    """The device rejected the restore; nothing further was sent."""


@dataclass
class Credentials:
    """Connection details for one restore; held in memory for the run only, never stored."""
    host: str
    username: str
    password: str
    port: int = 22
    secret: Optional[str] = None     # Cisco enable secret
    sudo_password: Optional[str] = None


@dataclass
class RestorePlan:
    """What a restore will do: the diff, the device commands (or file bundle) and the risks found.
    """
    diff: config_tree.ConfigDiff
    commands: List[str] = field(default_factory=list)
    bundle: Optional[file_bundle.BundlePlan] = None
    risks: List[Dict[str, str]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return self.diff.is_empty and not (self.bundle and (self.bundle.write or self.bundle.remove))


def _sock_ip(transport) -> Optional[str]:
    try:
        return transport.sock.getsockname()[0]
    except Exception:  # noqa: BLE001 - best effort, only feeds a warning
        return None


# --------------------------------------------------------------------------- #
#  Cisco IOS                                                                  #
# --------------------------------------------------------------------------- #

class CiscoDriver:
    """Restores a Cisco IOS configuration line by line in configuration mode, under IOS's own
    "configure terminal revert timer" when the archive feature is set up.
    """
    family = "cisco"

    def __init__(self, creds: Credentials):
        self.creds = creds
        self.executor = None
        self.armed = False

    def open(self):
        """Connect over SSH (host key pinned by the executor)."""
        from app.modules.cisco.hardening.ssh_executor import CiscoHardeningExecutor
        self.executor = CiscoHardeningExecutor(
            ip=self.creds.host, username=self.creds.username, password=self.creds.password,
            secret=self.creds.secret, port=self.creds.port,
        ).__enter__()

    def close(self):
        if self.executor:
            self.executor.__exit__(None, None, None)
            self.executor = None

    @property
    def _conn(self):
        return self.executor.ssh_client.connection

    def read_live(self) -> str:
        return self.executor.ssh_client.send_command("show running-config", timeout=120)

    def snapshot(self) -> str:
        return self.executor.backup_config()

    def source_ip(self) -> Optional[str]:
        return _sock_ip(self._conn.remote_conn.get_transport())

    def auto_revert_available(self) -> Tuple[bool, str]:
        """Whether IOS can roll back on its own: the revert timer needs the archive feature."""
        out = self.executor.ssh_client.send_command("show archive", timeout=30)
        if re.search(r"not enabled|invalid input|% ?incomplete", out or "", re.I) or "archive" not in (out or "").lower():
            return False, ("The device's archive feature is not configured, so IOS cannot "
                           "roll back on its own (configure 'archive' + 'path' to enable it).")
        return True, "configure terminal revert timer"

    def plan(self, backup_text: str, live_text: str) -> RestorePlan:
        diff = config_tree.diff_cisco(backup_text, live_text)
        return RestorePlan(diff=diff, commands=diff.commands,
                           risks=risk.cisco_risks(diff, backup_text, self.creds.username))

    def _ensure_enable(self):
        client = self.executor.ssh_client
        if not getattr(client, "_in_enable_mode", False):
            if not client._ensure_enable_mode():
                raise RestoreApplyError("Cannot enter privileged mode: provide the enable secret.")

    def apply(self, plan: RestorePlan, revert_minutes: Optional[int]):
        """Enter configuration mode (with the revert timer if asked) and send the plan's commands; a
        command the device rejects stops the run with RestoreApplyError.
        """
        self._ensure_enable()
        conn = self._conn
        if revert_minutes:
            conn.config_mode(config_command=f"configure terminal revert timer {int(revert_minutes)}")
            if not conn.check_config_mode():
                raise RestoreApplyError("The device refused 'configure terminal revert timer'.")
            self.armed = True
        else:
            conn.config_mode()
        output = conn.send_config_set(
            plan.commands, enter_config_mode=False, exit_config_mode=False,
            cmd_verify=False, read_timeout=180, bypass_commands=r"^banner",
        )
        conn.exit_config_mode()
        errors = self.executor._check_for_errors(output)
        if errors:
            raise RestoreApplyError(f"The device rejected a command: {errors[0]}")

    def confirm(self):
        if self.armed:
            self._conn.send_command("configure confirm", expect_string=r"#")
        self.executor.save_config()

    def revert_now(self):
        if self.armed:
            self._conn.send_command_timing("configure revert now")


# --------------------------------------------------------------------------- #
#  FortiGate                                                                  #
# --------------------------------------------------------------------------- #

_FORTI_BAD = re.compile(r"command fail|parse error|unknown action|permission denied|return code -", re.I)


class FortiGateDriver:
    """Restores a FortiGate configuration with the CLI, protected by FortiOS's "cfg-save revert" mode:
    unless confirmed, the device reloads its saved configuration after the timeout.
    """
    family = "fortinet"

    def __init__(self, creds: Credentials):
        self.creds = creds
        self.executor = None
        self.armed = False
        self.original_cfg_save = "automatic"
        self.vdom_mode = False

    def open(self):
        """Connect over SSH (host key pinned) and find out whether VDOMs are enabled, which changes how
        global settings are entered.
        """
        from app.modules.fortinet.hardening.ssh_executor import FortiGateHardeningExecutor
        self.executor = FortiGateHardeningExecutor(
            ip=self.creds.host, username=self.creds.username, password=self.creds.password,
            port=self.creds.port,
        ).__enter__()
        try:
            self.vdom_mode = bool(self.executor.ssh_client.is_vdom_enabled())
        except Exception:  # noqa: BLE001
            self.vdom_mode = False

    def close(self):
        if self.executor:
            self.executor.__exit__(None, None, None)
            self.executor = None

    @property
    def _client(self):
        return self.executor.ssh_client

    def read_live(self) -> str:
        """The running configuration; also remembers the current cfg-save mode so confirm() can put it
        back.
        """
        text = self._client.send_raw("show full-configuration")
        m = re.search(r"set cfg-save (\w+)", text or "")
        if m:
            self.original_cfg_save = m.group(1)
        return text

    def snapshot(self) -> str:
        return self.executor.backup_config()

    def source_ip(self) -> Optional[str]:
        return _sock_ip(self._client._connection.remote_conn.get_transport())

    def auto_revert_available(self) -> Tuple[bool, str]:
        return True, "cfg-save revert"

    def plan(self, backup_text: str, live_text: str) -> RestorePlan:
        diff = config_tree.diff_fortios(backup_text, live_text)
        return RestorePlan(diff=diff, commands=diff.commands, risks=risk.fortios_risks(
            diff, backup_text, self.creds.username, self.source_ip(), self.creds.port))

    def _global(self, lines: List[str]) -> List[str]:
        return ["config global", *lines, "end"] if self.vdom_mode else lines

    def _send(self, cmd: str) -> str:
        out = self._client._raw_send(cmd)
        if _FORTI_BAD.search(out or ""):
            bad = next((l for l in out.splitlines() if _FORTI_BAD.search(l)), out.strip()[:200])
            raise RestoreApplyError(f"The device rejected '{cmd.strip()}': {bad.strip()}")
        return out

    def apply(self, plan: RestorePlan, revert_minutes: Optional[int]):
        """Arm the revert timeout (cfg-save revert) if asked, then send the plan's commands."""
        if revert_minutes:
            for cmd in self._global([
                "config system global",
                f"set cfg-revert-timeout {int(revert_minutes) * 60}",
                "set cfg-save revert",
                "end",
            ]):
                self._send(cmd)
            self.armed = True
        for cmd in plan.commands:
            self._send(cmd)

    def confirm(self):
        """Keep the restored configuration: save it and put the original cfg-save mode back."""
        if self.armed:
            self._send("execute cfg save")
        for cmd in self._global(["config system global", f"set cfg-save {self.original_cfg_save}", "end"]):
            self._send(cmd)
        if self.original_cfg_save != "automatic":
            self._send("execute cfg save")

    def revert_now(self):
        """Undo now: reload the saved configuration (only possible when the revert mode was armed).
        """
        if self.armed:
            conn = self._client._connection
            out = conn.send_command_timing("execute cfg reload", strip_prompt=False, strip_command=False)
            if re.search(r"\(y/n\)", out or "", re.I):
                conn.send_command_timing("y", strip_prompt=False, strip_command=False)


# --------------------------------------------------------------------------- #
#  Linux / Apache / MongoDB (file bundles)                                    #
# --------------------------------------------------------------------------- #

class FileBundleDriver:
    """Restores the configuration files of a Linux, Apache or MongoDB server from a file bundle:
    snapshot of the current files, a timer on the host that puts them back unless disarmed, then the
    writes.
    """
    def __init__(self, family: str, creds: Credentials, job_id: int):
        self.family = family
        self.creds = creds
        self.workdir = f"/var/tmp/ngcorion-restore-{int(job_id)}"
        self.runner = None
        self.timer_pid: Optional[str] = None
        self._plan: Optional[file_bundle.BundlePlan] = None

    def open(self):
        """Connect over SSH with sudo (host key pinned)."""
        from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner
        self.runner = HardeningSSHRunner(
            ip=self.creds.host, username=self.creds.username, password=self.creds.password,
            sudo_password=self.creds.sudo_password or self.creds.password, port=self.creds.port,
        )
        self.runner.connect()

    def close(self):
        if self.runner:
            self.runner.disconnect()
            self.runner = None

    def _sudo(self, command: str, timeout: int = 120) -> Tuple[str, int]:
        return self.runner.send_command_with_status(f"sh -c {shlex.quote(command)}", use_sudo=True, timeout=timeout)

    def _must(self, command: str, what: str, timeout: int = 120) -> str:
        out, status = self._sudo(command, timeout)
        if status != 0:
            raise RestoreApplyError(f"{what} failed: {(out or '').strip()[-300:] or f'exit {status}'}")
        return out

    def read_live(self) -> str:
        from app.modules.shared.hardening_backup import build_file_bundle_command
        return self._must(build_file_bundle_command(file_bundle.family_paths(self.family)), "Reading configuration files")

    def snapshot(self) -> str:
        from app.modules.shared.hardening_backup import bundle_header
        return bundle_header(self.family, self.creds.host) + self.read_live()

    def source_ip(self) -> Optional[str]:
        client = getattr(self.runner, "_client", None)
        return _sock_ip(client.get_transport()) if client else None

    def auto_revert_available(self) -> Tuple[bool, str]:
        return True, "revert timer on the host"

    def plan(self, backup_text: str, live_text: str) -> RestorePlan:
        """Compare the backup bundle with the live files (only allowlisted paths) and assess the
        SSH-lockout risk of the result.
        """
        bundle = file_bundle.plan_bundle(backup_text, live_text, self.family)
        after = {**file_bundle.parse_bundle(live_text), **bundle.write}
        for path in bundle.remove:
            after.pop(path, None)
        return RestorePlan(diff=bundle.diff, bundle=bundle, risks=risk.bundle_risks(
            bundle.diff, after, self.family, self.creds.username, self.creds.port))

    def apply(self, plan: RestorePlan, revert_minutes: Optional[int]):
        """Snapshot the current files, arm the auto-revert timer on the host if asked, then write and
        remove files as planned.
        """
        bundle = plan.bundle
        self._plan = bundle
        self._must(file_bundle.snapshot_command(bundle, self.workdir), "Saving the current files")
        revert = file_bundle.revert_script(bundle, self.family, self.workdir)
        if revert_minutes:
            out = self._must(file_bundle.arm_timer_command(self.workdir, revert_minutes, revert),
                             "Arming the auto-revert timer")
            self.timer_pid = (out or "").strip().splitlines()[-1].strip() if out and out.strip() else None
        for path, content in bundle.write.items():
            self._must(file_bundle.write_command(path, content), f"Writing {path}")
        for path in bundle.remove:
            self._must(file_bundle.remove_command(path), f"Removing {path}")
        for cmd in file_bundle.validate_commands(bundle, self.family):
            out, status = self._sudo(cmd)
            if status != 0:
                raise RestoreApplyError(f"The restored configuration did not validate: {(out or '').strip()[-300:]}")
        for cmd in file_bundle.reload_commands(bundle, self.family):
            self._must(cmd, "Reloading the service", timeout=180)

    def confirm(self):
        self._sudo(file_bundle.disarm_command(self.timer_pid, self.workdir))

    def revert_now(self):
        """Put the snapshot back and disarm the timer."""
        if self._plan is None:
            return
        self._sudo(file_bundle.revert_script(self._plan, self.family, self.workdir), timeout=180)
        self._sudo(file_bundle.disarm_command(self.timer_pid, self.workdir))


def make_driver(family: str, creds: Credentials, job_id: int = 0):
    """The restore driver for a device family; ValueError for a family that cannot be restored."""
    if family == "cisco":
        return CiscoDriver(creds)
    if family == "fortinet":
        return FortiGateDriver(creds)
    if family in ("linux", "apache", "mongodb"):
        return FileBundleDriver(family, creds, job_id)
    raise ValueError(f"Restore is not supported for device type '{family}'")


def configs_match(family: str, backup_text: str, live_text: str) -> Tuple[bool, int]:
    """(matches, number of remaining differing lines)."""
    if family == "cisco":
        d = config_tree.diff_cisco(backup_text, live_text)
    elif family == "fortinet":
        d = config_tree.diff_fortios(backup_text, live_text)
    else:
        d = file_bundle.plan_bundle(backup_text, live_text, family).diff
        return (not d.sections, sum(len(s.lines) for s in d.sections))
    return d.is_empty, d.added + d.removed
