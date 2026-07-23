"""
CIS MongoDB Benchmark v1.0.0 — auditing and hardening service.

Implements every control across the seven benchmark sections. The service is
driven over SSH (paramiko, via :class:`app.cis.base.CISCheck`) and, for the
controls that require querying the live database, over a pymongo connection.

Operating rules
---------------
* ``auto_fix=False`` (the default) is **audit only** — no change is ever made
  to the target host or database.
* Every config-file fix takes a timestamped backup of ``/etc/mongod.conf``
  first (``/etc/mongod.conf.bak.<timestamp>``).
* A single failing/erroring control never aborts the run: :meth:`audit`
  iterates a registry, and any unexpected exception from a control is captured
  as a :class:`CheckStatus.ERROR` result so the remaining controls still run.
* ``fix_applied`` is ``True`` only when ``auto_fix`` is enabled *and* the fix
  was applied successfully.

pymongo is an optional dependency: the module imports and its config-file
controls run even when pymongo is absent; controls that need a live connection
then report ``ERROR`` explaining the missing dependency rather than raising.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

from app.cis.base import CheckStatus, CISCheck, CISResult

logger = logging.getLogger(__name__)

try:  # pymongo is optional; live-DB controls degrade to ERROR when it's absent.
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    _PYMONGO_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the deployment environment
    MongoClient = None  # type: ignore[assignment]
    PyMongoError = Exception  # type: ignore[assignment,misc]
    _PYMONGO_AVAILABLE = False


CONF_PATH = "/etc/mongod.conf"

# Newest patch releases of currently-supported major branches at the time the
# benchmark module was authored. 1.1 warns when the running version predates
# the oldest supported branch; keeping the list conservative avoids nagging on
# recent-but-not-latest patch levels.
SUPPORTED_MAJOR_MINOR = {"6.0", "7.0", "8.0"}
OLDEST_SUPPORTED = (6, 0)

# Roles that grant broad or administrative privilege (CIS 3.6).
SUPERUSER_ROLES = {
    "dbOwner",
    "userAdmin",
    "userAdminAnyDatabase",
    "root",
    "readWriteAnyDatabase",
    "dbAdminAnyDatabase",
    "clusterAdmin",
    "hostManager",
}

# MongoDB's own built-in roles; anything else in rolesInfo is user-defined.
BUILTIN_ROLES = {
    "read", "readWrite", "dbAdmin", "dbOwner", "userAdmin",
    "clusterAdmin", "clusterManager", "clusterMonitor", "hostManager",
    "backup", "restore", "readAnyDatabase", "readWriteAnyDatabase",
    "userAdminAnyDatabase", "dbAdminAnyDatabase", "root",
    "__system", "enableSharding", "directShardOperations",
}


class MongoDBBenchmark(CISCheck):
    """CIS MongoDB Benchmark v1.0.0 auditor / hardener."""

    BENCHMARK = "CIS MongoDB Benchmark v1.0.0"

    def __init__(
        self,
        host: str,
        ssh_username: str,
        ssh_password: Optional[str] = None,
        ssh_key_file: Optional[str] = None,
        ssh_port: int = 22,
        *,
        mongo_host: Optional[str] = None,
        mongo_port: int = 27017,
        mongo_username: Optional[str] = None,
        mongo_password: Optional[str] = None,
        mongo_auth_db: str = "admin",
        mongo_tls: bool = False,
        sudo: bool = True,
        auto_fix: bool = False,
        timeout: int = 30,
    ) -> None:
        super().__init__(
            host=host,
            ssh_username=ssh_username,
            ssh_password=ssh_password,
            ssh_key_file=ssh_key_file,
            ssh_port=ssh_port,
            sudo=sudo,
            auto_fix=auto_fix,
            timeout=timeout,
        )
        # Where pymongo connects. Defaults to the SSH target host.
        self.mongo_host = mongo_host or host
        self.mongo_port = mongo_port
        self.mongo_username = mongo_username
        self.mongo_password = mongo_password
        self.mongo_auth_db = mongo_auth_db
        self.mongo_tls = mongo_tls
        self._conf_cache: Optional[Dict[str, Any]] = None

    # ================================================================== #
    # Orchestration
    # ================================================================== #
    def audit(self) -> List[CISResult]:
        """Run every control and return the complete list of results."""
        registry: List[Tuple[str, str, bool, Callable[[str, str], CISResult]]] = [
            # id,   title,                                                        scored, method
            ("1.1", "MongoDB version is up to date", True, self._check_1_1),
            ("2.1", "Authentication is enabled", True, self._check_2_1),
            ("2.2", "Localhost exception is disabled", True, self._check_2_2),
            ("2.3", "Authentication is enabled in the sharded cluster", True, self._check_2_3),
            ("2.4", "Industry standard authentication mechanism is used", True, self._check_2_4),
            ("3.1", "Role-based access control is enabled and configured", True, self._check_3_1),
            ("3.2", "MongoDB only listens on authorized interfaces", True, self._check_3_2),
            ("3.3", "MongoDB runs as a non-privileged, dedicated service account", True, self._check_3_3),
            ("3.4", "Each role grants only the necessary privileges", True, self._check_3_4),
            ("3.5", "User-defined roles are reviewed", True, self._check_3_5),
            ("3.6", "Superuser / admin roles are reviewed", True, self._check_3_6),
            ("4.1", "TLS/SSL protects all network communications", True, self._check_4_1),
            ("4.2", "Database files and partition are encrypted", True, self._check_4_2),
            ("4.3", "FIPS is enabled", True, self._check_4_3),
            ("5.1", "System activity is audited", True, self._check_5_1),
            ("5.2", "Audit filters are configured", True, self._check_5_2),
            ("5.3", "Logging captures the maximum amount of information", False, self._check_5_3),
            ("5.4", "New entries are appended to the log", False, self._check_5_4),
            ("6.1", "HTTP status interface is disabled", True, self._check_6_1),
            ("6.2", "MongoDB uses a non-default port", True, self._check_6_2),
            ("6.3", "Operating system resource limits are set", False, self._check_6_3),
            ("6.4", "Server-side scripting is disabled if not needed", False, self._check_6_4),
            ("6.5", "HTTP interface is disabled", False, self._check_6_5),
            ("6.6", "JSONP access is disabled", False, self._check_6_6),
            ("6.7", "REST API is disabled", False, self._check_6_7),
            ("7.1", "Key file permissions are set correctly", True, self._check_7_1),
            ("7.2", "Database file permissions are set correctly", True, self._check_7_2),
        ]

        results: List[CISResult] = []
        for cid, title, scored, method in registry:
            try:
                result = method(cid, title)
                result.scored = scored
            except Exception as exc:  # never let one control abort the run
                logger.exception("control %s crashed", cid)
                result = CISResult(
                    id=cid,
                    title=title,
                    status=CheckStatus.ERROR,
                    error_msg=str(exc),
                    scored=scored,
                )
            result.section = cid.split(".", 1)[0]
            results.append(result)
        return results

    # ================================================================== #
    # Result builders
    # ================================================================== #
    @staticmethod
    def _result(
        cid: str,
        title: str,
        status: CheckStatus,
        current: Any = None,
        expected: Any = None,
        fix_applied: bool = False,
        error_msg: Optional[str] = None,
    ) -> CISResult:
        return CISResult(
            id=cid,
            title=title,
            status=status,
            current_value=None if current is None else str(current),
            expected_value=None if expected is None else str(expected),
            fix_applied=fix_applied,
            error_msg=error_msg,
        )

    # ================================================================== #
    # Config helpers
    # ================================================================== #
    def _load_conf(self, *, force: bool = False) -> Dict[str, Any]:
        """Read and parse ``/etc/mongod.conf`` (cached within a run)."""
        if self._conf_cache is not None and not force:
            return self._conf_cache
        raw = self.read_file(CONF_PATH)
        parsed = yaml.safe_load(raw) or {}
        if not isinstance(parsed, dict):
            raise ValueError(f"{CONF_PATH} did not parse to a mapping")
        self._conf_cache = parsed
        return parsed

    @staticmethod
    def _get(conf: Dict[str, Any], dotted: str, default: Any = None) -> Any:
        """Nested lookup, e.g. ``_get(conf, 'security.authorization')``."""
        node: Any = conf
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @staticmethod
    def _set(conf: Dict[str, Any], dotted: str, value: Any) -> None:
        node = conf
        parts = dotted.split(".")
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = value

    def _apply_conf_changes(self, changes: Dict[str, Any]) -> None:
        """Backup then rewrite ``mongod.conf`` with the given dotted-key changes.

        Caller must have already checked ``self.auto_fix``.
        """
        conf = self._load_conf(force=True)
        self.backup_file(CONF_PATH)
        for dotted, value in changes.items():
            self._set(conf, dotted, value)
        new_yaml = yaml.safe_dump(conf, default_flow_style=False, sort_keys=False)
        self.write_file(CONF_PATH, new_yaml)
        self._conf_cache = conf
        logger.info("applied mongod.conf changes: %s", ", ".join(changes))

    def _restart_mongod(self) -> bool:
        res = self.run("systemctl restart mongod", sudo=True)
        if not res.ok:
            logger.warning("mongod restart failed: %s", res.stderr.strip())
        return res.ok

    # ================================================================== #
    # pymongo helpers
    # ================================================================== #
    def _connect_mongo(self, *, authenticate: bool = True):
        """Return a connected ``MongoClient`` (caller closes it).

        Raises ``RuntimeError`` when pymongo is unavailable so callers can turn
        that into an ERROR result.
        """
        if not _PYMONGO_AVAILABLE:
            raise RuntimeError("pymongo is not installed; live-database check skipped")
        kwargs: Dict[str, Any] = {
            "host": self.mongo_host,
            "port": self.mongo_port,
            "serverSelectionTimeoutMS": max(2000, self.timeout * 1000),
            "tls": self.mongo_tls,
        }
        if authenticate and self.mongo_username:
            kwargs.update(
                username=self.mongo_username,
                password=self.mongo_password,
                authSource=self.mongo_auth_db,
            )
        client = MongoClient(**kwargs)
        client.admin.command("ping")  # force server selection now
        return client

    # ================================================================== #
    # Section 1 — Installation
    # ================================================================== #
    def _check_1_1(self, cid: str, title: str) -> CISResult:
        expected = f"a supported release ({', '.join(sorted(SUPPORTED_MAJOR_MINOR))} branch)"
        if not _PYMONGO_AVAILABLE:
            return self._result(
                cid, title, CheckStatus.ERROR, expected=expected,
                error_msg="pymongo not installed; cannot read db.version()",
            )
        client = None
        try:
            client = self._connect_mongo(authenticate=True)
            version = client.server_info().get("version", "")
        except PyMongoError as exc:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg=str(exc))
        finally:
            if client is not None:
                client.close()

        match = re.match(r"(\d+)\.(\d+)", version)
        if not match:
            return self._result(
                cid, title, CheckStatus.ERROR, current=version, expected=expected,
                error_msg="could not parse version string",
            )
        major, minor = int(match.group(1)), int(match.group(2))
        supported = (major, minor) >= OLDEST_SUPPORTED
        status = CheckStatus.PASS if supported else CheckStatus.FAIL
        return self._result(cid, title, status, current=version, expected=expected)

    # ================================================================== #
    # Section 2 — Authentication
    # ================================================================== #
    def _check_2_1(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        authz = self._get(conf, "security.authorization")
        conf_enabled = str(authz).lower() == "enabled"

        # Independent evidence: an unauthenticated connection must NOT be able
        # to enumerate databases.
        unauth_detail = "not tested (pymongo unavailable)"
        unauth_open = False
        if _PYMONGO_AVAILABLE:
            client = None
            try:
                client = self._connect_mongo(authenticate=False)
                client.list_database_names()
                unauth_open = True
                unauth_detail = "unauthenticated connection could list databases"
            except PyMongoError:
                unauth_detail = "unauthenticated connection was rejected"
            finally:
                if client is not None:
                    client.close()

        current = f"security.authorization={authz!r}; {unauth_detail}"
        expected = 'security.authorization="enabled" and unauthenticated access rejected'

        if conf_enabled and not unauth_open:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)

        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)

        # Fix: enable authorization + restart so it takes effect.
        try:
            self._apply_conf_changes({"security.authorization": "enabled"})
            restarted = self._restart_mongod()
        except Exception as exc:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected, error_msg=str(exc))
        return self._result(
            cid, title, CheckStatus.FAIL, current=current, expected=expected,
            fix_applied=restarted,
            error_msg=None if restarted else "config updated but mongod restart failed",
        )

    def _check_2_2(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        value = self._get(conf, "setParameter.enableLocalhostAuthBypass")
        expected = "setParameter.enableLocalhostAuthBypass=false"
        # Default is true when unset, so absent == non-compliant.
        compliant = value is False
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=value, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=value, expected=expected)
        self._apply_conf_changes({"setParameter.enableLocalhostAuthBypass": False})
        return self._result(cid, title, CheckStatus.FAIL, current=value, expected=expected, fix_applied=True)

    def _check_2_3(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        key_file = self._get(conf, "security.keyFile")
        expected = "security.keyFile set to an existing key file (sharded cluster / replica set)"
        if not key_file:
            # keyFile generation is a manual step: warn, don't fabricate a key.
            return self._result(
                cid, title, CheckStatus.FAIL, current="security.keyFile not set",
                expected=expected,
                error_msg="keyFile must be generated manually (openssl rand -base64 756); reported only",
            )
        if not self.file_exists(key_file):
            return self._result(
                cid, title, CheckStatus.FAIL, current=f"security.keyFile={key_file} (missing on disk)",
                expected=expected,
            )
        return self._result(cid, title, CheckStatus.PASS, current=f"security.keyFile={key_file}", expected=expected)

    def _check_2_4(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        cluster_auth = self._get(conf, "security.clusterAuthMode")
        mechanisms = self._get(conf, "setParameter.authenticationMechanisms")
        mech_list = self._normalise_list(mechanisms)
        expected = "clusterAuthMode=x509 OR authenticationMechanisms includes GSSAPI/SCRAM-SHA-256"

        strong = {"GSSAPI", "SCRAM-SHA-256"}
        compliant = str(cluster_auth).lower() == "x509" or bool(strong & set(mech_list))
        current = f"clusterAuthMode={cluster_auth!r}, authenticationMechanisms={mech_list}"
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        self._apply_conf_changes({"setParameter.authenticationMechanisms": "SCRAM-SHA-256"})
        return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True)

    @staticmethod
    def _normalise_list(value: Any) -> List[str]:
        """Accept a scalar, comma string, or list and return a list of tokens."""
        if value is None:
            return []
        if isinstance(value, (list, tuple)):
            return [str(v).strip() for v in value]
        return [tok.strip() for tok in str(value).split(",") if tok.strip()]

    # ================================================================== #
    # Section 3 — Access Control
    # ================================================================== #
    def _check_3_1(self, cid: str, title: str) -> CISResult:
        expected = "at least one non-root user exists with limited (non-superuser) roles"
        if not _PYMONGO_AVAILABLE:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg="pymongo not installed")
        client = None
        try:
            client = self._connect_mongo(authenticate=True)
            users = client.admin.command({"usersInfo": {"forAllDBs": True}}).get("users", [])
        except PyMongoError as exc:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg=str(exc))
        finally:
            if client is not None:
                client.close()

        limited_users = []
        for user in users:
            role_names = {r.get("role") for r in user.get("roles", [])}
            if "root" in role_names:
                continue
            if role_names and not role_names.issubset(SUPERUSER_ROLES):
                limited_users.append(f"{user.get('db')}.{user.get('user')}")
        current = f"{len(users)} users total; limited non-root users: {limited_users or 'none'}"
        status = CheckStatus.PASS if limited_users else CheckStatus.FAIL
        return self._result(cid, title, status, current=current, expected=expected)

    def _check_3_2(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        bind_ip = self._get(conf, "net.bindIp")
        bind_all = self._get(conf, "net.bindIpAll")
        listening = self._ss_mongo_listeners()
        expected = "net.bindIp restricted to specific interfaces (not 0.0.0.0 / not unset)"

        exposed = (
            bind_ip is None
            or bind_all is True
            or "0.0.0.0" in self._normalise_list(bind_ip)
            or any(addr.startswith("0.0.0.0") or addr.startswith("*") or addr.startswith(":::")
                   for addr in listening)
        )
        current = f"net.bindIp={bind_ip!r}, bindIpAll={bind_all!r}; listeners={listening or 'none'}"
        if not exposed:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        self._apply_conf_changes({"net.bindIp": "127.0.0.1"})
        return self._result(
            cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True,
            error_msg="bound to 127.0.0.1; restart mongod and set the real internal IP if remote access is required",
        )

    def _ss_mongo_listeners(self) -> List[str]:
        res = self.run("ss -tlnp 2>/dev/null | grep -i mongo", sudo=True)
        addrs = []
        for line in res.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 4:
                addrs.append(fields[3])
        return addrs

    def _check_3_3(self, cid: str, title: str) -> CISResult:
        expected = "mongod/mongos owned by a dedicated non-root account (e.g. mongodb)"
        res = self.run('ps -eo user,comm | grep -E "mongo(s|d)$"', sudo=False)
        owners = {line.split()[0] for line in res.stdout.splitlines() if line.split()}
        if not owners:
            return self._result(
                cid, title, CheckStatus.ERROR, expected=expected,
                error_msg="no running mongod/mongos process found",
            )
        current = f"process owner(s): {sorted(owners)}"
        status = CheckStatus.FAIL if "root" in owners else CheckStatus.PASS
        return self._result(cid, title, status, current=current, expected=expected)

    def _check_3_4(self, cid: str, title: str) -> CISResult:
        expected = "no role grants privileges beyond its intended scope"
        if not _PYMONGO_AVAILABLE:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg="pymongo not installed")
        client = None
        try:
            client = self._connect_mongo(authenticate=True)
            info = client.admin.command(
                {"rolesInfo": 1, "showPrivileges": True, "showBuiltinRoles": True}
            )
            roles = info.get("roles", [])
        except PyMongoError as exc:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg=str(exc))
        finally:
            if client is not None:
                client.close()

        # Flag user-defined roles that hold cluster-wide "anyResource" privileges.
        flagged = []
        for role in roles:
            if role.get("isBuiltin"):
                continue
            for priv in role.get("privileges", []):
                resource = priv.get("resource", {})
                if resource.get("anyResource") or resource.get("cluster"):
                    flagged.append(role.get("role"))
                    break
        current = f"user-defined roles with cluster/anyResource privileges: {flagged or 'none'}"
        status = CheckStatus.FAIL if flagged else CheckStatus.PASS
        return self._result(cid, title, status, current=current, expected=expected)

    def _check_3_5(self, cid: str, title: str) -> CISResult:
        expected = "user-defined roles inventoried for review"
        if not _PYMONGO_AVAILABLE:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg="pymongo not installed")
        client = None
        try:
            client = self._connect_mongo(authenticate=True)
            db_names = client.list_database_names()
            user_roles = []
            for db_name in db_names:
                info = client[db_name].command({"rolesInfo": 1})
                for role in info.get("roles", []):
                    if not role.get("isBuiltin") and role.get("role") not in BUILTIN_ROLES:
                        user_roles.append(f"{db_name}.{role.get('role')}")
        except PyMongoError as exc:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg=str(exc))
        finally:
            if client is not None:
                client.close()
        current = f"user-defined roles: {user_roles or 'none'}"
        # Informational review control: passes as long as it could be enumerated.
        return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)

    def _check_3_6(self, cid: str, title: str) -> CISResult:
        expected = f"only expected accounts hold superuser roles ({', '.join(sorted(SUPERUSER_ROLES))})"
        if not _PYMONGO_AVAILABLE:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg="pymongo not installed")
        client = None
        try:
            client = self._connect_mongo(authenticate=True)
            users = client.admin.command({"usersInfo": {"forAllDBs": True}}).get("users", [])
        except PyMongoError as exc:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg=str(exc))
        finally:
            if client is not None:
                client.close()

        holders = {}
        for user in users:
            for role in user.get("roles", []):
                name = role.get("role")
                if name in SUPERUSER_ROLES:
                    holders.setdefault(name, []).append(f"{user.get('db')}.{user.get('user')}")
        current = f"superuser role holders: {holders or 'none'}"
        # Report for manual confirmation; flag when any privileged role is held.
        status = CheckStatus.FAIL if holders else CheckStatus.PASS
        return self._result(
            cid, title, status, current=current, expected=expected,
            error_msg=None if not holders else "confirm each holder is authorised; removal is manual",
        )

    # ================================================================== #
    # Section 4 — Data Encryption
    # ================================================================== #
    def _check_4_1(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        mode = self._get(conf, "net.tls.mode") or self._get(conf, "net.ssl.mode")
        cert = self._get(conf, "net.tls.certificateKeyFile") or self._get(conf, "net.ssl.PEMKeyFile")
        expected = 'net.tls.mode="requireTLS" with an existing certificateKeyFile'

        mode_ok = str(mode) in {"requireTLS", "requireSSL"}
        cert_ok = bool(cert) and self.file_exists(cert)
        current = f"tls.mode={mode!r}, certificateKeyFile={cert!r} (exists={cert_ok})"
        if mode_ok and cert_ok:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        if not cert_ok:
            # Won't force requireTLS without a valid cert — that would break mongod.
            return self._result(
                cid, title, CheckStatus.FAIL, current=current, expected=expected,
                error_msg="certificateKeyFile missing; provision the cert before enabling requireTLS",
            )
        self._apply_conf_changes({"net.tls.mode": "requireTLS"})
        return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True)

    def _check_4_2(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        enc = self._get(conf, "security.enableEncryption")
        luks = self.run("lsblk -o NAME,FSTYPE 2>/dev/null | grep -i crypt", sudo=True)
        luks_present = bool(luks.stdout.strip())
        expected = "encryption at rest enabled (WiredTiger enableEncryption or LUKS-encrypted volume)"
        current = f"security.enableEncryption={enc!r}; LUKS volume present={luks_present}"
        compliant = enc is True or luks_present
        status = CheckStatus.PASS if compliant else CheckStatus.FAIL
        error = None if compliant else "enabling encryption at rest requires data migration; reported only"
        return self._result(cid, title, status, current=current, expected=expected, error_msg=error)

    def _check_4_3(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        fips = self._get(conf, "net.tls.FIPSMode")
        if fips is None:
            fips = self._get(conf, "net.ssl.FIPSMode")
        expected = "net.tls.FIPSMode=true and FIPS 140-2 mode activated in the log"
        log_hit = self.run(
            "grep -i 'FIPS 140-2 mode activated' /var/log/mongodb/mongod.log 2>/dev/null",
            sudo=True,
        )
        log_activated = bool(log_hit.stdout.strip())
        current = f"net.tls.FIPSMode={fips!r}; log shows activation={log_activated}"
        if fips is True and log_activated:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        self._apply_conf_changes({"net.tls.FIPSMode": True})
        return self._result(
            cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True,
            error_msg="FIPSMode set; requires a FIPS-capable OpenSSL and mongod restart to activate",
        )

    # ================================================================== #
    # Section 5 — Auditing
    # ================================================================== #
    def _check_5_1(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        dest = self._get(conf, "auditLog.destination")
        expected = "auditLog.destination set (syslog | file | console)"
        if dest in {"syslog", "file", "console"}:
            return self._result(cid, title, CheckStatus.PASS, current=f"auditLog.destination={dest}", expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=f"auditLog.destination={dest!r}", expected=expected)
        self._apply_conf_changes(
            {
                "auditLog.destination": "file",
                "auditLog.format": "BSON",
                "auditLog.path": "/var/log/mongodb/auditLog.bson",
            }
        )
        return self._result(cid, title, CheckStatus.FAIL, current=f"auditLog.destination={dest!r}", expected=expected, fix_applied=True)

    def _check_5_2(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        filt = self._get(conf, "auditLog.filter")
        expected = "auditLog.filter configured to capture relevant events"
        if filt:
            return self._result(cid, title, CheckStatus.PASS, current=f"auditLog.filter={filt}", expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current="auditLog.filter not set", expected=expected)
        # Capture authentication, admin commands, and CRUD operations.
        default_filter = (
            '{ atype: { $in: [ "authenticate", "authCheck", "createUser", '
            '"dropUser", "createRole", "dropRole", "createCollection", '
            '"dropCollection", "createDatabase", "dropDatabase" ] } }'
        )
        self._apply_conf_changes({"auditLog.filter": default_filter})
        return self._result(cid, title, CheckStatus.FAIL, current="auditLog.filter not set", expected=expected, fix_applied=True)

    def _check_5_3(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        quiet = self._get(conf, "systemLog.quiet")
        expected = "systemLog.quiet=false or absent"
        compliant = quiet is not True
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=f"systemLog.quiet={quiet!r}", expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=f"systemLog.quiet={quiet!r}", expected=expected)
        self._apply_conf_changes({"systemLog.quiet": False})
        return self._result(cid, title, CheckStatus.FAIL, current=f"systemLog.quiet={quiet!r}", expected=expected, fix_applied=True)

    def _check_5_4(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        append = self._get(conf, "systemLog.logAppend")
        expected = "systemLog.logAppend=true"
        if append is True:
            return self._result(cid, title, CheckStatus.PASS, current=f"systemLog.logAppend={append!r}", expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=f"systemLog.logAppend={append!r}", expected=expected)
        self._apply_conf_changes({"systemLog.logAppend": True})
        return self._result(cid, title, CheckStatus.FAIL, current=f"systemLog.logAppend={append!r}", expected=expected, fix_applied=True)

    # ================================================================== #
    # Section 6 — OS Hardening
    # ================================================================== #
    def _http_disabled_check(self, cid: str, title: str, dotted: str) -> CISResult:
        """Shared logic for the several 'net.http.* must be false' controls."""
        conf = self._load_conf()
        value = self._get(conf, dotted)
        legacy_nohttp = self._get(conf, "net.http.enabled") is None and self._get(conf, "nohttpinterface")
        expected = f"{dotted}=false"
        compliant = value is False or value is None or legacy_nohttp is True
        current = f"{dotted}={value!r}"
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        self._apply_conf_changes({dotted: False})
        return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True)

    def _check_6_1(self, cid: str, title: str) -> CISResult:
        return self._http_disabled_check(cid, title, "net.http.enabled")

    def _check_6_2(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        port = self._get(conf, "net.port")
        listening = self._ss_mongo_listeners()
        on_default = port == 27017 or (port is None and any(":27017" in a for a in listening))
        expected = "net.port set to a non-default value (not 27017)"
        current = f"net.port={port!r}; listeners={listening or 'none'}"
        status = CheckStatus.FAIL if on_default else CheckStatus.PASS
        error = None
        if on_default:
            error = "changing the port also requires updating every client/application; reported only"
        return self._result(cid, title, status, current=current, expected=expected, error_msg=error)

    def _check_6_3(self, cid: str, title: str) -> CISResult:
        expected = "open files >= 64000 and max processes >= 64000 for the mongod process"
        pid = self._mongod_pid()
        if pid is None:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg="mongod process not found")
        limits_raw = self.run(f"cat /proc/{pid}/limits", sudo=True)
        if not limits_raw.ok:
            return self._result(cid, title, CheckStatus.ERROR, expected=expected, error_msg="cannot read /proc/<pid>/limits")
        nofile = self._parse_limit(limits_raw.stdout, "Max open files")
        nproc = self._parse_limit(limits_raw.stdout, "Max processes")
        current = f"open files(soft)={nofile}, max processes(soft)={nproc}"
        compliant = (nofile is not None and nofile >= 64000) and (nproc is not None and nproc >= 64000)
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        limits_conf = (
            "mongod soft nofile 64000\n"
            "mongod hard nofile 64000\n"
            "mongod soft nproc 64000\n"
            "mongod hard nproc 64000\n"
        )
        self.write_file("/etc/security/limits.d/99-mongodb.conf", limits_conf)
        return self._result(
            cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True,
            error_msg="limits written to /etc/security/limits.d/99-mongodb.conf; restart mongod to apply",
        )

    @staticmethod
    def _parse_limit(text: str, label: str) -> Optional[int]:
        for line in text.splitlines():
            if line.startswith(label):
                # columns: <name...> <soft> <hard> <units>
                tail = line[len(label):].split()
                if tail:
                    val = tail[0]
                    if val.lower() == "unlimited":
                        return 1 << 62
                    if val.isdigit():
                        return int(val)
        return None

    def _mongod_pid(self) -> Optional[str]:
        res = self.run("pgrep -x mongod", sudo=False)
        pid = res.stdout.strip().splitlines()
        if pid:
            return pid[0]
        # Fallback via ps.
        res = self.run('ps -eo pid,comm | grep -E " mongod$"', sudo=False)
        for line in res.stdout.splitlines():
            fields = line.split()
            if fields and fields[0].isdigit():
                return fields[0]
        return None

    def _check_6_4(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        js = self._get(conf, "security.javascriptEnabled")
        expected = "security.javascriptEnabled=false (unless server-side JS is required)"
        compliant = js is False
        current = f"security.javascriptEnabled={js!r}"
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        self._apply_conf_changes({"security.javascriptEnabled": False})
        return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=True)

    def _check_6_5(self, cid: str, title: str) -> CISResult:
        return self._http_disabled_check(cid, title, "net.http.enabled")

    def _check_6_6(self, cid: str, title: str) -> CISResult:
        return self._http_disabled_check(cid, title, "net.http.JSONPEnabled")

    def _check_6_7(self, cid: str, title: str) -> CISResult:
        return self._http_disabled_check(cid, title, "net.http.RESTInterfaceEnabled")

    # ================================================================== #
    # Section 7 — File Permissions
    # ================================================================== #
    def _check_7_1(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        key_file = self._get(conf, "security.keyFile")
        expected = "keyFile mode 600, owner mongodb"
        if not key_file:
            return self._result(
                cid, title, CheckStatus.SKIPPED, current="security.keyFile not set", expected=expected,
                error_msg="no keyFile configured; nothing to check",
            )
        return self._check_perms(cid, title, key_file, want_mode="600", want_owner="mongodb", want_group="mongodb", expected=expected)

    def _check_7_2(self, cid: str, title: str) -> CISResult:
        conf = self._load_conf()
        db_path = self._get(conf, "storage.dbPath")
        expected = "dbPath mode 660, owner mongodb:mongodb"
        if not db_path:
            return self._result(
                cid, title, CheckStatus.ERROR, current="storage.dbPath not set", expected=expected,
                error_msg="storage.dbPath missing from config",
            )
        return self._check_perms(cid, title, db_path, want_mode="660", want_owner="mongodb", want_group="mongodb", expected=expected)

    def _check_perms(
        self,
        cid: str,
        title: str,
        path: str,
        *,
        want_mode: str,
        want_owner: str,
        want_group: str,
        expected: str,
    ) -> CISResult:
        stat = self.stat_file(path)
        if stat is None:
            return self._result(cid, title, CheckStatus.ERROR, current=f"{path} not found", expected=expected, error_msg="path does not exist")
        current = f"{path}: mode={stat.mode}, owner={stat.owner}:{stat.group}"
        compliant = stat.mode == want_mode and stat.owner == want_owner and stat.group == want_group
        if compliant:
            return self._result(cid, title, CheckStatus.PASS, current=current, expected=expected)
        if not self.auto_fix:
            return self._result(cid, title, CheckStatus.FAIL, current=current, expected=expected)
        chmod = self.run(f"chmod {want_mode} {path!r}", sudo=True)
        chown = self.run(f"chown {want_owner}:{want_group} {path!r}", sudo=True)
        applied = chmod.ok and chown.ok
        return self._result(
            cid, title, CheckStatus.FAIL, current=current, expected=expected, fix_applied=applied,
            error_msg=None if applied else (chmod.stderr.strip() or chown.stderr.strip()),
        )
