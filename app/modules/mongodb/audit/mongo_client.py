"""
MongoDB SSH Audit Client

Connects to the host server via SSH and collects configuration data for
CIS MongoDB Benchmark compliance evaluation.

Collection strategy:
1. Read /etc/mongod.conf (primary config source)
2. Gather OS-level checks (process user, file permissions)
3. Run mongosh admin commands for DB-level checks

All data is combined into a single structured dump string with section
markers, which rules.py then evaluates using regex patterns.
"""

import re
import logging
from typing import Optional, Dict

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

logger = logging.getLogger(__name__)


# Patterns to redact from audit output before storing
_REDACT_PATTERNS = [
    # Password fields in YAML config
    (re.compile(r"(password\s*:\s*)\S+", re.I), r"\1<REDACTED>"),
    # -p flag in CLI output
    (re.compile(r"(\s-p\s+)\S+"), r"\1<REDACTED>"),
    # --password flag
    (re.compile(r"(--password[= ])\S+", re.I), r"\1<REDACTED>"),
    # keyFile value
    (re.compile(r"(keyFile\s*:\s*)\S+"), r"\1<REDACTED>"),
    # clusterAuthMode secrets
    (re.compile(r"(clusterAuthMode\s*:\s*)\S+"), r"\1<REDACTED>"),
    # Passwords in JSON output from mongosh
    (re.compile(r'("pwd"\s*:\s*")[^"]*(")', re.I), r'\1<REDACTED>\2'),
]


def redact_sensitive_mongo_data(text: str) -> str:
    """Remove sensitive data from audit dump before database storage."""
    if not text:
        return text
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class MongoDBSSHClient:
    """
    SSH client for MongoDB host servers.

    Establishes an SSH connection to the server running MongoDB, then
    collects configuration data for CIS compliance evaluation.

    Args:
        ip:              Target server IP
        username:        SSH username
        password:        SSH password
        mongo_username:  MongoDB admin username (optional)
        mongo_password:  MongoDB admin password (optional)
        mongo_port:      MongoDB listen port (default 27017)
        ssh_port:        SSH port (default 22)
        timeout:         SSH command timeout in seconds
    """

    COMMAND_TIMEOUT = 30

    def __init__(
        self,
        ip: str,
        username: str,
        password: str,
        mongo_username: Optional[str] = None,
        mongo_password: Optional[str] = None,
        mongo_port: int = 27017,
        ssh_port: int = 22,
        timeout: int = 30,
    ):
        self.ip = ip
        self.username = username
        self.password = password
        self.mongo_username = mongo_username
        self.mongo_password = mongo_password
        self.mongo_port = mongo_port
        self.ssh_port = ssh_port
        self.timeout = timeout
        self._conn = None

    # ------------------------------------------------------------------ #
    #  Context manager                                                     #
    # ------------------------------------------------------------------ #

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, *_):
        self._disconnect()
        return False

    def _connect(self):
        logger.info(f"SSH connecting to {self.ip}:{self.ssh_port}")
        try:
            self._conn = ConnectHandler(
                device_type="linux",
                ip=self.ip,
                username=self.username,
                password=self.password,
                port=self.ssh_port,
                timeout=self.timeout,
                conn_timeout=self.timeout,
            )
            logger.info(f"SSH connection established to {self.ip}")
        except NetmikoTimeoutException as exc:
            raise ConnectionError(f"SSH connection timed out to {self.ip}: {exc}")
        except NetmikoAuthenticationException as exc:
            raise PermissionError(f"SSH authentication failed for {self.ip}: {exc}")
        except Exception as exc:
            raise ConnectionError(f"SSH connection failed to {self.ip}: {exc}")

    def _disconnect(self):
        if self._conn:
            try:
                self._conn.disconnect()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------ #
    #  Command execution helpers                                           #
    # ------------------------------------------------------------------ #

    def _run(self, cmd: str, use_sudo: bool = False) -> str:
        """Execute a command via SSH and return trimmed output."""
        if not self._conn:
            raise RuntimeError("SSH client is not connected")
        try:
            if use_sudo:
                cmd = f"echo '{self.password}' | sudo -S sh -c {repr(cmd)} 2>/dev/null"
            output = self._conn.send_command(
                cmd,
                read_timeout=self.COMMAND_TIMEOUT,
                expect_string=r"[\$\#]\s*$",
            )
            return (output or "").strip()
        except Exception as exc:
            logger.debug(f"Command failed [{cmd[:60]}]: {exc}")
            return ""

    def _mongosh_eval(self, js_expr: str) -> str:
        """
        Execute a JavaScript expression in mongosh (or legacy mongo).

        The expression must use only single quotes internally so the
        surrounding shell single-quote wrapper remains valid.
        """
        auth = ""
        if self.mongo_username and self.mongo_password:
            auth = (
                f" -u '{self.mongo_username}'"
                f" -p '{self.mongo_password}'"
                f" --authenticationDatabase admin"
            )

        # Try mongosh first, fall back to mongo
        for cli in ("mongosh", "mongo"):
            cmd = (
                f"{cli} --port {self.mongo_port}{auth}"
                f" --quiet --norc"
                f" --eval '{js_expr}'"
                f" admin 2>/dev/null"
            )
            result = self._run(cmd)
            if result and "command not found" not in result.lower():
                return result

        return "MONGOSH_UNAVAILABLE"

    # ------------------------------------------------------------------ #
    #  Main data collection                                                #
    # ------------------------------------------------------------------ #

    def collect_audit_data(self) -> str:
        """
        Collect all MongoDB audit data via SSH.

        Returns:
            A single structured string with section markers, suitable for
            rule evaluation. Example:

                ===SECTION:CONFIG_FILE===
                net:
                  port: 27017
                  bindIp: 127.0.0.1
                ...
                ===SECTION:PROCESS_INFO===
                mongodb  1234  ...
        """
        sections: Dict[str, str] = {}

        # ---- 1. Configuration file ------------------------------------ #
        sections["CONFIG_FILE"] = self._run(
            "cat /etc/mongod.conf 2>/dev/null"
            " || cat /etc/mongodb.conf 2>/dev/null"
            " || echo 'CONFIG_FILE_NOT_FOUND'"
        )

        # ---- 2. OS / process level ------------------------------------ #
        sections["PROCESS_INFO"] = self._run(
            "ps aux 2>/dev/null | grep -E '[m]ongod' | head -5"
            " || echo 'NO_MONGOD_PROCESS'"
        )

        sections["MONGOD_USER"] = self._run(
            "ps -o user= -p $(pgrep -x mongod 2>/dev/null | head -1) 2>/dev/null"
            " || ps aux | grep '[m]ongod' | awk '{print $1}' | head -1"
            " || echo 'unknown'"
        )

        sections["DATA_DIR_PERMS"] = self._run(
            "stat -c '%a %U %G %n' /var/lib/mongodb 2>/dev/null"
            " || stat -c '%a %U %G %n' /var/lib/mongo 2>/dev/null"
            " || echo 'DATA_DIR_NOT_FOUND'",
            use_sudo=True,
        )

        sections["LOG_DIR_PERMS"] = self._run(
            "stat -c '%a %U %G %n' /var/log/mongodb 2>/dev/null"
            " || stat -c '%a %U %G %n' /var/log/mongo 2>/dev/null"
            " || echo 'LOG_DIR_NOT_FOUND'",
            use_sudo=True,
        )

        sections["CONFIG_FILE_PERMS"] = self._run(
            "stat -c '%a %U %G %n' /etc/mongod.conf 2>/dev/null"
            " || stat -c '%a %U %G %n' /etc/mongodb.conf 2>/dev/null"
            " || echo 'CONFIG_PERMS_NOT_FOUND'",
            use_sudo=True,
        )

        sections["MONGOD_VERSION"] = self._run(
            "mongod --version 2>/dev/null | head -2"
            " || mongos --version 2>/dev/null | head -2"
            " || echo 'VERSION_NOT_FOUND'"
        )

        sections["SERVICE_CONFIG"] = self._run(
            "systemctl show mongod --property=User,ExecStart 2>/dev/null"
            " || systemctl show mongodb --property=User,ExecStart 2>/dev/null"
            " || echo 'SERVICE_NOT_FOUND'"
        )

        # ---- 3. Network ----------------------------------------------- #
        sections["LISTENING_PORTS"] = self._run(
            f"ss -tlnp 2>/dev/null | grep :{self.mongo_port}"
            f" || netstat -tlnp 2>/dev/null | grep :{self.mongo_port}"
            " || echo 'PORT_CHECK_FAILED'"
        )

        # ---- 4. MongoDB admin commands (via mongosh) ------------------ #
        sections["CMDLINE_OPTS"] = self._mongosh_eval(
            "printjson(db.adminCommand({getCmdLineOpts:1}))"
        )

        sections["AUTH_MECHANISMS"] = self._mongosh_eval(
            "printjson(db.adminCommand({getParameter:1,authenticationMechanisms:1}))"
        )

        sections["USERS_LIST"] = self._mongosh_eval(
            "printjson(db.system.users.find().toArray())"
        )

        sections["ROLES_LIST"] = self._mongosh_eval(
            "printjson(db.getRoles({showBuiltinRoles:false}))"
        )

        sections["BUILD_INFO"] = self._mongosh_eval(
            "var b=db.adminCommand({buildInfo:1}); print(b.version)"
        )

        sections["TLS_PARAMS"] = self._mongosh_eval(
            "printjson(db.adminCommand({getParameter:1,tlsMode:1}))"
        )

        sections["PROFILING"] = self._mongosh_eval(
            "printjson(db.getProfilingStatus())"
        )

        # ---- 5. Assemble structured dump ------------------------------ #
        parts = []
        for section_key, content in sections.items():
            parts.append(f"===SECTION:{section_key}===")
            parts.append(content or "(empty)")

        return "\n".join(parts)
