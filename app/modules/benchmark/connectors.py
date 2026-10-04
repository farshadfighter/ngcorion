"""
How a benchmark module reaches its target.

A connector turns the credentials from a request into an open connection with
two calls:

    run(script)      audit path: never raises, returns the output or an
                     "<KIND>_ERROR: ..." marker the rule engine reports as
                     "not evaluated"
    execute(script)  hardening path: returns the output, raises on failure so
                     a fix is never reported as applied when it was not

Opening a connection raises PermissionError for rejected credentials and
ConnectionError when the host cannot be reached; the routers turn those into
401 / 503 the same way the older modules do. Credentials are used for the one
connection and never stored.
"""

import logging
import re
import shlex
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, Tuple

from pydantic import Field

from app.core.config import settings
from app.modules.hardening.harden_all.contract import CredentialField
from app.modules.windows.winrm_endpoint import DEFAULT_WINRM_PORT

logger = logging.getLogger(__name__)


class Connector:
    """Base class. Subclasses fill in the field sets and open()."""

    key: str = ""
    # pydantic field definitions merged into the execute / execute-single bodies
    request_fields: Dict[str, Tuple[Any, Any]] = {}
    # what the Harden All credentials step renders
    credential_fields: List[CredentialField] = []
    # names a scheduled audit must carry (stored encrypted by scheduling)
    required_for_schedule: frozenset = frozenset()

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]) -> Iterator[Any]:  # pragma: no cover - abstract
        raise NotImplementedError
        yield

    def port_of(self, creds: Dict[str, Any]) -> Optional[int]:
        return None


# ── WinRM (Windows Server roles: AD, DNS, DHCP, IIS) ───────────────────────

class WinRMConnection:
    """One WinRM session. Wraps the Windows hardening executor, which already
    has the connect/retry/auth handling the Windows module relies on."""

    def __init__(self, executor):
        self._ex = executor
        self.ip = executor.ip

    def execute(self, script: str) -> str:
        return self._ex._execute(script)

    def run(self, script: str) -> str:
        """Run one collection script; an error comes back as text ("PS_ERROR: ...") so that one failing
        section does not stop the audit.
        """
        try:
            out = self._ex._execute(script)
        except Exception as exc:  # noqa: BLE001 - reported per section
            return f"PS_ERROR: {str(exc)[:300]}"
        return "(no output)" if out == "(ok)" else out

    # The software inventory hook calls client._run_ps(...)
    _run_ps = run


class WinRMConnector(Connector):
    """Windows targets over WinRM (PowerShell): AD, DNS, DHCP, IIS. Credentials are request fields
    only, never stored.
    """
    key = "winrm"
    request_fields = {
        "windows_username": (str, Field(..., min_length=1, description="Windows admin account (DOMAIN\\user), not stored")),
        "windows_password": (str, Field(..., min_length=1, description="Password, not stored")),
        "winrm_port": (int, Field(DEFAULT_WINRM_PORT, ge=1, le=65535, description="5985 HTTP / 5986 HTTPS")),
        "transport": (str, Field("ntlm", pattern="^(ntlm|kerberos|credssp|basic)$")),
        "verify_ssl": (Optional[bool], Field(None, description="Validate the WinRM TLS certificate (server default when omitted)")),
    }
    credential_fields = [
        CredentialField(name="windows_username", label="Windows Username", type="text", required=True),
        CredentialField(name="windows_password", label="Windows Password", type="password", required=True),
        CredentialField(name="winrm_port", label="WinRM Port", type="number", default=str(DEFAULT_WINRM_PORT)),
        CredentialField(name="transport", label="Transport", type="select", default="ntlm",
                        options=["ntlm", "kerberos", "credssp", "basic"]),
    ]
    required_for_schedule = frozenset({"windows_username", "windows_password"})

    def port_of(self, creds):
        return int(creds.get("winrm_port") or DEFAULT_WINRM_PORT)

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        """Connect over WinRM and yield a WinRMConnection; authentication and connection failures
        become PermissionError / ConnectionError for the routers.
        """
        from app.modules.windows.hardening.winrm_executor import WindowsWinRMExecutor
        verify = creds.get("verify_ssl")
        executor = WindowsWinRMExecutor(
            ip=ip,
            username=creds["windows_username"],
            password=creds["windows_password"],
            port=self.port_of(creds),
            transport=creds.get("transport") or "ntlm",
            verify_ssl=settings.WINRM_VERIFY_SSL if verify is None else bool(verify),
            # Directory queries over a large domain can take a while.
            timeout=120,
        )
        with executor:
            yield WinRMConnection(executor)


# ── SSH with sudo (Linux-hosted targets: Docker, ...) ─────────────────────

SUDO_REJECTED = ("incorrect password", "a password is required", "is not in the sudoers",
                 "may not run sudo", "not allowed to execute")


def _first_line(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:300] if lines else ""


class SSHConnection:
    """One SSH session; every script runs as root (`sh -c` under sudo, or
    directly when the login is root) so redirections and pipes are root's too."""

    def __init__(self, runner, as_root: bool):
        self._runner = runner
        self._as_root = as_root
        self.ip = runner.ip

    def _exec(self, script: str, timeout: int = 120):
        command = f"sh -c {shlex.quote(script)}"
        if self._as_root:
            return self._runner.run_with_status(command, timeout=timeout)
        return self._runner.send_command_with_status(command, use_sudo=True, timeout=timeout)

    def run(self, script: str) -> str:
        """Run one collection command; SSH errors and non-zero exits come back as text ("SSH_ERROR:
        ...", "CMD_ERROR: ...") so the audit records them per section.
        """
        try:
            out, status = self._exec(script)
        except Exception as exc:  # noqa: BLE001 - reported per section
            return f"SSH_ERROR: {str(exc)[:300]}"
        if status != 0:
            return f"CMD_ERROR: exit {status}: {_first_line(out)}"
        return out if out.strip() else "(no output)"

    def execute(self, script: str) -> str:
        """Run one hardening statement; a non-zero exit raises, so the fix is reported as failed."""
        out, status = self._exec(script)
        if status != 0:
            raise RuntimeError(_first_line(out) or f"command exited with status {status}")
        return out if out.strip() else "(ok)"


class SSHConnector(Connector):
    """Linux-style targets over SSH with sudo (Docker, Kubernetes nodes). The SSH host key is pinned;
    the sudo password defaults to the SSH password. Nothing is stored.
    """
    key = "ssh"
    request_fields = {
        "ssh_username": (str, Field(..., min_length=1, description="SSH account with sudo, not stored")),
        "ssh_password": (str, Field(..., min_length=1, description="Password, not stored")),
        "ssh_port": (int, Field(22, ge=1, le=65535)),
        "sudo_password": (Optional[str], Field(None, description="Leave empty to reuse the SSH password")),
    }
    credential_fields = [
        CredentialField(name="ssh_username", label="SSH Username", type="text", required=True),
        CredentialField(name="ssh_password", label="SSH Password", type="password", required=True),
        CredentialField(name="ssh_port", label="SSH Port", type="number", default="22"),
        CredentialField(name="sudo_password", label="Sudo Password", type="password",
                        help="Leave empty to reuse the SSH password"),
    ]
    required_for_schedule = frozenset({"ssh_username", "ssh_password"})

    def port_of(self, creds):
        return int(creds.get("ssh_port") or 22)

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        """Connect over SSH and yield an SSHConnection (root or sudo); authentication and connection
        failures become PermissionError / ConnectionError.
        """
        from app.core.ssh_exceptions import SSHAuthenticationError, SSHConnectionError
        from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner
        runner = HardeningSSHRunner(
            ip=ip, username=creds["ssh_username"], password=creds["ssh_password"],
            sudo_password=creds.get("sudo_password") or None, port=self.port_of(creds), max_retries=2)
        try:
            runner.connect()
        except SSHAuthenticationError as exc:
            raise PermissionError(str(exc)) from exc
        except SSHConnectionError as exc:
            raise ConnectionError(str(exc)) from exc
        try:
            as_root = creds["ssh_username"] == "root"
            if not as_root:
                out, status = runner.send_command_with_status("true", use_sudo=True, timeout=30)
                if status != 0 or any(m in out.lower() for m in SUDO_REJECTED):
                    raise PermissionError(f"sudo was refused for {creds['ssh_username']}: {_first_line(out)}")
            yield SSHConnection(runner, as_root)
        finally:
            runner.disconnect()


# ── SSH + MySQL login (MySQL servers) ────────────────────────────────────

SQL_PREFIX = "SQL:"
# "SQL[ok=3529]:..." - SQL that may fail with the listed MySQL error codes
# (e.g. "already installed"); the fix's verification still decides.
_SQL_HEAD = re.compile(r"^SQL(?:\[ok=(\d+(?:,\d+)*)\])?:")
_MYSQL_ERROR = re.compile(r"ERROR (\d+) \(")


def split_sql(script: str) -> Tuple[Optional[str], Tuple[str, ...]]:
    """(SQL text, tolerated error codes), or (None, ()) for a shell script."""
    m = _SQL_HEAD.match(script)
    if not m:
        return None, ()
    return script[m.end():], tuple(m.group(1).split(",")) if m.group(1) else ()


def mysql_client_script(sql: str, user: str, port: int, password: str) -> Tuple[str, str]:
    """(shell script, stdin) running `sql` with the mysql client on the host.

    The password travels on stdin and reaches the client as an option file
    on file descriptor 3 (a here-document): it never appears in a command
    line, the process list, the environment or a file on disk."""
    client = (f"mysql --protocol=TCP -h 127.0.0.1 -P {int(port)} -u {shlex.quote(user)} -N -B -r "
              f"-e {shlex.quote(sql)}")
    if '"' not in password or "'" not in password:
        quote = '"' if '"' not in password else "'"
        script = ("IFS= read -r pw; " + client.replace("mysql ", "mysql --defaults-extra-file=/dev/fd/3 ", 1)
                  + f" 3<<EOF\n[client]\npassword={quote}$pw{quote}\nEOF")
        # Option files read \\ as one backslash.
        return script, password.replace("\\", "\\\\") + "\n"
    # Both quote characters: the option-file syntax cannot hold it; use the
    # client's environment variable, still never on a command line.
    return "IFS= read -r MYSQL_PWD; export MYSQL_PWD; " + client, password + "\n"


class MySQLConnection:
    """Shell scripts run as root through the SSH connection; scripts starting
    with "SQL:" run as SQL through the mysql client with the MySQL login."""

    def __init__(self, shell: SSHConnection, user: str, port: int, password: str):
        self._shell = shell
        self._user, self._port, self._password = user, port, password
        self.ip = shell.ip

    def _sql(self, sql: str):
        script, data = mysql_client_script(sql, self._user, self._port, self._password)
        return self._shell._runner.run_with_input(f"sh -c {shlex.quote(script)}", data, timeout=120)

    def run(self, script: str) -> str:
        """Run one collection script: SQL statements (SQL_PREFIX) go to the mysql client with the
        password passed on stdin, anything else to the shell. Errors come back as text.
        """
        text, _tolerated = split_sql(script)
        if text is None:
            return self._shell.run(script)
        try:
            out, status = self._sql(text)
        except Exception as exc:  # noqa: BLE001 - reported per section
            return f"SSH_ERROR: {str(exc)[:300]}"
        if status != 0:
            return f"CMD_ERROR: exit {status}: {_first_line(out)}"
        return out if out.strip() else "(no output)"

    def execute(self, script: str) -> str:
        """Run one hardening statement (SQL or shell). MySQL error codes the statement lists as
        tolerated (for example "already exists") count as success; any other error raises.
        """
        text, tolerated = split_sql(script)
        if text is None:
            return self._shell.execute(script)
        out, status = self._sql(text)
        m = _MYSQL_ERROR.search(out or "")
        if status != 0 and m and m.group(1) in tolerated:
            return f"(tolerated MySQL error {m.group(1)})"
        if status != 0:
            raise RuntimeError(_first_line(out) or f"mysql exited with status {status}")
        return out if out.strip() else "(ok)"


class MySQLConnector(SSHConnector):
    """MySQL over SSH: the mysql client runs on the database host, so the database port need not be
    reachable from NGCorion. Both the SSH and the MySQL credentials are request fields only.
    """
    key = "ssh_mysql"
    request_fields = {
        **SSHConnector.request_fields,
        "mysql_username": (str, Field("root", min_length=1, description="MySQL account, not stored")),
        "mysql_password": (str, Field(..., min_length=1, description="MySQL password, not stored")),
        "mysql_port": (int, Field(3306, ge=1, le=65535)),
    }
    credential_fields = SSHConnector.credential_fields + [
        CredentialField(name="mysql_username", label="MySQL Username", type="text", default="root"),
        CredentialField(name="mysql_password", label="MySQL Password", type="password", required=True),
        CredentialField(name="mysql_port", label="MySQL Port", type="number", default="3306"),
    ]
    required_for_schedule = frozenset({"ssh_username", "ssh_password", "mysql_password"})

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        """Connect over SSH, then prove the MySQL login with SELECT 1 before yielding the
        MySQLConnection; a rejected login becomes PermissionError.
        """
        if "\n" in (creds.get("mysql_password") or ""):
            raise PermissionError("The MySQL password cannot contain a line break")
        with SSHConnector.open(self, ip, creds) as shell:
            conn = MySQLConnection(shell, creds.get("mysql_username") or "root",
                                   int(creds.get("mysql_port") or 3306), creds["mysql_password"])
            probe = conn.run(SQL_PREFIX + "SELECT 1")
            if probe.strip() != "1":
                if "Access denied" in probe:
                    raise PermissionError(f"MySQL login rejected: {probe.split(':', 2)[-1].strip()}")
                if "not found" in probe:
                    raise ConnectionError("The mysql client is not installed on this host")
                raise ConnectionError(f"Cannot reach MySQL on 127.0.0.1:{conn._port}: {probe[:200]}")
            yield conn


# ── SSH to an ESXi host (busybox shell, no sudo) ─────────────────────────

class ESXiConnector(SSHConnector):
    """ESXi has no sudo: the account itself needs the Administrator role
    (root, or a local user granted it), and scripts run directly."""
    key = "ssh_esxi"
    request_fields = {
        "ssh_username": (str, Field("root", min_length=1, description="ESXi account with the Administrator role, not stored")),
        "ssh_password": (str, Field(..., min_length=1, description="Password, not stored")),
        "ssh_port": (int, Field(22, ge=1, le=65535)),
    }
    credential_fields = [
        CredentialField(name="ssh_username", label="SSH Username", type="text", required=True, default="root"),
        CredentialField(name="ssh_password", label="SSH Password", type="password", required=True),
        CredentialField(name="ssh_port", label="SSH Port", type="number", default="22"),
    ]
    required_for_schedule = frozenset({"ssh_username", "ssh_password"})

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        """Connect to an ESXi host over SSH as root or an Administrator-role account. ESXi has no sudo,
        so commands run as that account directly.
        """
        from app.core.ssh_exceptions import SSHAuthenticationError, SSHConnectionError
        from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner
        runner = HardeningSSHRunner(ip=ip, username=creds.get("ssh_username") or "root",
                                    password=creds["ssh_password"], port=self.port_of(creds), max_retries=2)
        try:
            runner.connect()
        except SSHAuthenticationError as exc:
            raise PermissionError(str(exc)) from exc
        except SSHConnectionError as exc:
            raise ConnectionError(str(exc)) from exc
        try:
            conn = SSHConnection(runner, as_root=True)
            version = conn.run("vmware -v")
            if "VMware ESXi" not in version:
                raise ConnectionError(f"{ip} is not an ESXi host: {_first_line(version)[:120]}")
            yield conn
        finally:
            runner.disconnect()


# ── SSH + nginx configuration edits ──────────────────────────────────────

class NginxConnector(SSHConnector):
    """SSH with sudo, like Linux; the connection also performs the "NGX:"
    configuration edits (app/modules/nginx/edit.py), writing files through
    stdin so their content never appears on a command line."""
    key = "ssh_nginx"

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        """Connect over SSH and yield an NginxConnection that can also write configuration files:
        content is sent on stdin after a marker line (and after the sudo password when needed),
        never through the command line.
        """
        from app.modules.nginx.edit import MARK, NginxConnection, stdin_write_script
        with SSHConnector.open(self, ip, creds) as shell:
            runner = shell._runner

            def write(path: str, content: str) -> None:
                """Write one file on the target through stdin_write_script; raises when the write
                fails.
                """
                script = stdin_write_script(path)
                if shell._as_root:
                    command, data = f"sh -c {shlex.quote(script)}", f"{MARK}\n{content}"
                else:
                    # sudo reads the password line when it asks for one; the
                    # script drops everything up to MARK either way.
                    command = f"sudo -S -p '' sh -c {shlex.quote(script)}"
                    data = f"{runner.sudo_password}\n{MARK}\n{content}"
                out, status = runner.run_with_input(command, data, timeout=120)
                if status != 0:
                    raise RuntimeError(f"writing {path} failed: {_first_line(out)}")

            yield NginxConnection(shell, write)


# ── Sophos Firewall XML API (HTTPS) ──────────────────────────────────────

class SophosConnector(Connector):
    """The firewall's XML API: an API-enabled administrator account, and this
    server's address in the firewall's API allowed list. The certificate is
    pinned on first use (app/core/tls_pins.py)."""
    key = "sophos_api"
    request_fields = {
        "sophos_username": (str, Field(..., min_length=1, description="Administrator with API access, not stored")),
        "sophos_password": (str, Field(..., min_length=1, description="Password, not stored")),
        "sophos_port": (int, Field(4444, ge=1, le=65535, description="Web admin / API HTTPS port")),
    }
    credential_fields = [
        CredentialField(name="sophos_username", label="API Username", type="text", required=True),
        CredentialField(name="sophos_password", label="API Password", type="password", required=True),
        CredentialField(name="sophos_port", label="API Port", type="number", default="4444"),
    ]
    required_for_schedule = frozenset({"sophos_username", "sophos_password"})

    def port_of(self, creds):
        return int(creds.get("sophos_port") or 4444)

    @contextmanager
    def open(self, ip: str, creds: Dict[str, Any]):
        """Log in to the Sophos XML API (HTTPS, certificate pinned before the password is sent) and
        yield a SophosConnection.
        """
        from app.modules.sophos.api import SophosAPI, SophosAPIError
        from app.modules.sophos.edit import SophosConnection
        api = SophosAPI(ip, self.port_of(creds), creds["sophos_username"], creds["sophos_password"])
        try:
            api.login()
        except SophosAPIError as exc:
            raise ConnectionError(str(exc)) from exc
        yield SophosConnection(api)


CONNECTORS: Dict[str, Connector] = {"winrm": WinRMConnector(), "ssh": SSHConnector(), "ssh_mysql": MySQLConnector(),
                                    "ssh_esxi": ESXiConnector(), "ssh_nginx": NginxConnector(),
                                    "sophos_api": SophosConnector()}


def get_connector(key: str) -> Connector:
    return CONNECTORS[key]


def register_connector(connector: Connector) -> None:
    CONNECTORS[connector.key] = connector
