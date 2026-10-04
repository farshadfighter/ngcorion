"""
MySQL 8 rules after the CIS Oracle MySQL Community Server 8.0 Benchmark:
1 operating system, 2 installation and planning, 3 file permissions,
4 general, 5 MySQL permissions, 6 auditing and logging, 7 authentication,
8 network, 9 replication.

Server settings are read from the running server (performance_schema),
startup options from the mysqld command line and the option files. The
administrative accounts are root on the local host and MySQL's own system
accounts (mysql.session, mysql.sys, mysql.infoschema); every other account
holding an administrative privilege is a finding. Item numbers follow the
benchmark's content rather than a specific edition's PDF and can differ
slightly from the edition in use.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from app.modules.benchmark.rules import BenchmarkRule, json_section, section

from .collect import NO_MYSQL

JSON_SECTIONS = frozenset({"MYSQL_VARS", "MYSQL_USERS", "MYSQL_GLOBAL_GRANTS", "MYSQL_DB_PRIVS", "MYSQL_SCHEMAS",
                           "MYSQL_PLUGINS", "MYSQL_COMPONENTS", "MYSQL_ROUTINES", "MYSQL_REPLICATION"})
SYSTEM_ACCOUNTS = ("mysql.session", "mysql.sys", "mysql.infoschema")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
SYSTEM_MOUNTS = ("/", "/var", "/usr")
PASSWORD_PLUGINS = ("caching_sha2_password", "mysql_native_password", "sha256_password")


# ── data access ──────────────────────────────────────────────────────────

def vars_(d) -> Dict[str, Any]:
    v = json_section(d, "MYSQL_VARS")
    return v if isinstance(v, dict) else {}


def var(d, name, default=None):
    return vars_(d).get(name, default)


def on(value) -> bool:
    return str(value).upper() in ("ON", "1", "YES", "TRUE")


def _list(d, name) -> List[Any]:
    v = json_section(d, name)
    return v if isinstance(v, list) else []


def users(d) -> List[Dict[str, Any]]:
    return [u for u in _list(d, "MYSQL_USERS") if isinstance(u, dict)]


def account(u) -> str:
    return f"'{u.get('user')}'@'{u.get('host')}'"


def is_admin(u) -> bool:
    return (u.get("user") == "root" and u.get("host") in LOCAL_HOSTS) or u.get("user") in SYSTEM_ACCOUNTS


def priv(u, name) -> bool:
    return bool((u.get("privs") or {}).get(name))


FULL_DATA = ("select", "insert", "update", "delete", "create", "drop")


def is_replication_account(u) -> bool:
    """An account for replication: REPLICATION SLAVE without full data access."""
    return priv(u, "repl_slave") and not all(priv(u, p) for p in FULL_DATA)


def non_admins_with(d, name) -> List[str]:
    return [account(u) for u in users(d) if not is_admin(u) and priv(u, name)]


def proc(d) -> Tuple[Optional[str], str]:
    for line in section(d, "MYSQLD_PROC").splitlines():
        if "|" in line and line != "END":
            owner, cmd = line.split("|", 1)
            return owner, cmd.strip()
    return None, ""


def option_files(d) -> Dict[str, str]:
    out, cur, buf = {}, None, []
    for line in section(d, "MYCNF").split("\n"):
        if line.startswith("### "):
            if cur:
                out[cur] = "\n".join(buf)
            cur, buf = line[4:].strip(), []
        elif line != "END":
            buf.append(line)
    if cur:
        out[cur] = "\n".join(buf)
    return out


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def startup_option(d, name) -> Optional[str]:
    """An option given on the mysqld command line or in an option file
    (the last occurrence; "" for a bare flag)."""
    name = _norm(name)
    found = None
    for text in option_files(d).values():
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("[", "!")):
                continue
            k, _, v = line.partition("=")
            if _norm(k) in (name, "loose-" + name):
                found = v.strip()
    for tok in proc(d)[1].split()[1:]:
        k, _, v = tok.lstrip("-").partition("=")
        if _norm(k) == name:
            found = v
    return found


def files(d) -> Dict[str, List[Tuple[str, str, str, str, str]]]:
    out: Dict[str, List[Tuple[str, str, str, str, str]]] = {}
    for line in section(d, "FILES").splitlines():
        parts = line.split("|")
        if len(parts) == 6:
            out.setdefault(parts[0], []).append(tuple(parts[1:]))
    return out


def mounts(d) -> Dict[str, Tuple[str, str]]:
    out = {}
    for line in section(d, "MOUNTS").splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            out[parts[0]] = (parts[1], parts[2])
    return out


def host(d) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for line in section(d, "HOST").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def plugins(d) -> Dict[str, str]:
    return {str(p.get("name")): str(p.get("status")) for p in _list(d, "MYSQL_PLUGINS") if isinstance(p, dict)}


def components(d) -> List[str]:
    return [str(c) for c in _list(d, "MYSQL_COMPONENTS")]


def _names(items, limit=15) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(str(i) for i in items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _mode_ok(mode: str, maximum: int) -> bool:
    try:
        return int(mode, 8) & ~maximum & 0o7777 == 0
    except ValueError:
        return False


def _int(v, default=0) -> int:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return default


# ── rule builders ────────────────────────────────────────────────────────

def _rule(rules, sec, title, severity, check, evidence, remediation, sections, level="L1", manual=False):
    rules.append(BenchmarkRule(
        id=f"MYSQL-{sec}", section=sec, title=title, severity=severity, level=level,
        check_fn=check, evidence_fn=evidence, remediation=remediation, description=title,
        manual=manual, data_sections=list(sections), source="CIS"))


def _manual(rules, sec, title, severity, guidance, evidence=None, level="L1", sections=()):
    _rule(rules, sec, title, severity, lambda d: False, evidence or (lambda d: "Review with the database owner."),
          guidance, sections, level=level, manual=True)


def _var_rule(rules, sec, title, severity, name, ok, remediation, level="L1", default=None):
    _rule(rules, sec, title, severity, lambda d: ok(var(d, name, default)),
          lambda d: f"{name} = {var(d, name, default if default is not None else 'not set')!r}",
          remediation, ["MYSQL_VARS"], level=level)


def _priv_rule(rules, sec, title, severity, name, remediation):
    _rule(rules, sec, title, severity, lambda d: not non_admins_with(d, name),
          lambda d: f"Non-administrative accounts with {name.upper().replace('_', ' ')}: " + _names(non_admins_with(d, name)),
          remediation, ["MYSQL_USERS"])


FILE_RULES = (
    ("3.1", "datadir", "'datadir'", 0o750, "high"),
    ("3.2", "binlog", "'log_bin_basename' files", 0o660, "medium"),
    ("3.3", "error_log", "'log_error'", 0o660, "medium"),
    ("3.4", "slow_log", "'slow_query_log'", 0o660, "medium"),
    ("3.5", "relay_log", "'relay_log_basename' files", 0o660, "medium"),
    ("3.6", "general_log", "'general_log_file'", 0o660, "medium"),
    ("3.7", "ssl_key", "SSL key files", 0o400, "high"),
    ("3.8", "plugin_dir", "plugin directory", 0o550, "medium"),
    ("3.9", "audit_log", "'audit_log_file'", 0o660, "medium"),
    ("3.10", "keyring", "keyring file", 0o600, "high"),
)


def _file_rule(rules, sec, tag, label, mode, severity):
    def entries(d):
        return [e for e in files(d).get(tag, []) if e[4] != "missing"]

    def bad(d):
        out = []
        for path, o, g, m, _k in entries(d):
            if (o, g) != ("mysql", "mysql") and not (tag == "plugin_dir" and o == "root" and g == "mysql"):
                out.append(f"{path} ({o}:{g})")
            if not _mode_ok(m, mode):
                out.append(f"{path} ({m})")
        return out
    _rule(rules, sec, f"Ensure {label} has appropriate permissions", severity, lambda d: not bad(d),
          lambda d: (f"Not compliant: {_names(bad(d))}" if bad(d) else
                     f"Compliant ({mode:o} or stricter, mysql:mysql): {_names(e[0] for e in entries(d))}" if entries(d)
                     else f"{label}: not present on this host"),
          f"chown mysql:mysql and chmod {mode:o} (or more restrictive).", ["FILES"])


def build_rules() -> List[BenchmarkRule]:
    r: List[BenchmarkRule] = []
    V, U, H = ["MYSQL_VARS"], ["MYSQL_USERS"], ["HOST"]

    # 1 Operating system ──────────────────────────────────────────────────
    def system_mount(d, tag):
        path, mp = mounts(d).get(tag, ("", ""))
        return mp in SYSTEM_MOUNTS, f"{path} on {mp or 'unknown'}"
    _rule(r, "1.1", "Place databases on non-system partitions", "medium",
          lambda d: "datadir" in mounts(d) and not system_mount(d, "datadir")[0],
          lambda d: "datadir " + system_mount(d, "datadir")[1],
          "Move datadir to its own file system (not /, /var or /usr).", ["MOUNTS"], level="L2")
    _rule(r, "1.2", "Use dedicated least privileged account for MySQL daemon/service", "high",
          lambda d: proc(d)[0] not in (None, "root"),
          lambda d: f"mysqld runs as {proc(d)[0] or 'not found'}", "Run mysqld as the mysql account (user=mysql).",
          ["MYSQLD_PROC"])
    _rule(r, "1.3", "Disable MySQL command history", "low",
          lambda d: all(h.split("|", 1)[1] == "/dev/null" for h in host(d).get("history", [])),
          lambda d: "history files: " + _names(host(d).get("history", [])),
          "ln -sf /dev/null ~/.mysql_history for each user (MYSQL_HISTFILE=/dev/null).", H, level="L2")
    _rule(r, "1.4", "Verify that the MYSQL_PWD environment variable is not in use", "high",
          lambda d: (host(d).get("pwd_env") or ["0"])[0] == "0",
          lambda d: f"processes with MYSQL_PWD in their environment: {(host(d).get('pwd_env') or ['?'])[0]}",
          "Use option files or login paths instead of MYSQL_PWD.", H)
    _rule(r, "1.5", "Ensure interactive login is disabled", "medium",
          lambda d: re.search(r":(/usr)?/s?bin/(nologin|false)$", (host(d).get("account") or [""])[0]) is not None,
          lambda d: f"mysql account: {(host(d).get('account') or ['?'])[0]}",
          "usermod -s /sbin/nologin mysql", H, level="L2")
    _rule(r, "1.6", "Verify that 'MYSQL_PWD' is not set in users' profiles", "high",
          lambda d: not (host(d).get("pwd_profiles") or [""])[0].strip(),
          lambda d: "profiles setting MYSQL_PWD: " + ((host(d).get("pwd_profiles") or [""])[0].strip() or "none"),
          "Remove MYSQL_PWD from the profiles.", H)
    _manual(r, "1.7", "Ensure MySQL is run under a sandbox environment", "low",
            "Run mysqld in a chroot, under systemd sandboxing or in a container.",
            lambda d: f"running in a container: {(host(d).get('container') or ['?'])[0]}", level="L2", sections=H)

    # 2 Installation and planning ─────────────────────────────────────────
    for sec, title, guidance in (
        ("2.1.1", "Backup policy in place", "Back up the databases on a schedule (mysqldump, MySQL Enterprise Backup, xtrabackup)."),
        ("2.1.2", "Verify backups are good", "Restore backups regularly into a test server."),
        ("2.1.3", "Secure backup credentials", "Keep backup account passwords in protected option files or a vault."),
        ("2.1.4", "The backups should be properly secured", "Encrypt backups and restrict who can read them."),
    ):
        _manual(r, sec, title, "medium", guidance)
    _var_rule(r, "2.1.5", "Point-in-time recovery", "medium", "log_bin", on,
              "Enable the binary log (log_bin) so changes after the last backup can be replayed.")
    _manual(r, "2.1.6", "Disaster recovery (DR) plan", "medium", "Document and test a recovery plan (replica, off-site backups).")
    _manual(r, "2.1.7", "Backup of configuration and related files", "low",
            "Back up option files, keys and certificates with the data.")
    _manual(r, "2.2", "Dedicate the machine running MySQL", "low", "Run no other services on the database host.",
            level="L2")
    _manual(r, "2.3", "Do not specify passwords in the command line", "high",
            "Never pass -p<password> on the command line; use option files or login paths.")
    _manual(r, "2.4", "Do not reuse usernames", "low", "Give each application and person its own account.",
            lambda d: "accounts: " + _names(account(u) for u in users(d)), sections=U)
    _manual(r, "2.5", "Do not use default or non-MySQL-specific cryptographic keys", "medium",
            "Replace the auto-generated certificates with CA-issued ones for this server.",
            lambda d: f"ssl_cert = {var(d, 'ssl_cert')}, ssl_ca = {var(d, 'ssl_ca')}", sections=V)
    _var_rule(r, "2.6", "Ensure a password expiration policy is in place", "medium", "default_password_lifetime",
              lambda v: 0 < _int(v) <= 365, "SET PERSIST default_password_lifetime = 365;")
    _manual(r, "2.7", "Lock out accounts if not currently in use", "medium",
            "ALTER USER ... ACCOUNT LOCK for accounts that are not in use.",
            lambda d: "unlocked accounts: " + _names(account(u) for u in users(d) if not u.get("locked")), sections=U)
    _manual(r, "2.8", "Ensure socket peer-credential authentication is used appropriately", "medium",
            "Use auth_socket only for local administration accounts that map to OS users.",
            lambda d: "auth_socket accounts: " + _names(account(u) for u in users(d) if u.get("plugin") == "auth_socket"),
            sections=U)

    # 3 File permissions ──────────────────────────────────────────────────
    for sec, tag, label, mode, sev in FILE_RULES:
        _file_rule(r, sec, tag, label, mode, sev)

    # 4 General ───────────────────────────────────────────────────────────
    _manual(r, "4.1", "Ensure the latest security patches are applied", "high",
            "Compare with the current MySQL 8 release and the CVE findings for this asset.",
            lambda d: f"MySQL {section(d, 'MYSQL_VERSION').strip()}", sections=["MYSQL_VERSION"])
    _rule(r, "4.2", "Ensure example or test databases are not installed on production servers", "medium",
          lambda d: not [s for s in _list(d, "MYSQL_SCHEMAS") if str(s).lower() in ("test", "employees", "sakila", "world")],
          lambda d: "schemas: " + _names(_list(d, "MYSQL_SCHEMAS")), "DROP DATABASE test;", ["MYSQL_SCHEMAS"])
    _rule(r, "4.3", "Ensure 'allow-suspicious-udfs' is set to 'OFF'", "medium",
          lambda d: startup_option(d, "allow-suspicious-udfs") in (None, "0", "OFF", "off", "FALSE", "false"),
          lambda d: f"allow-suspicious-udfs = {startup_option(d, 'allow-suspicious-udfs')}",
          "Remove allow-suspicious-udfs from the options.", ["MYCNF", "MYSQLD_PROC"])
    _var_rule(r, "4.4", "Ensure 'local_infile' is disabled", "medium", "local_infile", lambda v: not on(v),
              "SET PERSIST local_infile = 0;")
    _rule(r, "4.5", "Ensure 'mysqld' is not started with '--skip-grant-tables'", "high",
          lambda d: startup_option(d, "skip-grant-tables") is None,
          lambda d: f"skip-grant-tables = {startup_option(d, 'skip-grant-tables')}",
          "Remove skip-grant-tables from the options.", ["MYCNF", "MYSQLD_PROC"])
    _var_rule(r, "4.6", "Ensure symbolic links are disabled", "medium", "have_symlink",
              lambda v: str(v).upper() == "DISABLED", "Add skip-symbolic-links to [mysqld] and restart.",
              default="DISABLED")
    _rule(r, "4.7", "Ensure the 'daemon_memcached' plugin is disabled", "medium",
          lambda d: plugins(d).get("daemon_memcached", "NOT INSTALLED") != "ACTIVE",
          lambda d: f"daemon_memcached: {plugins(d).get('daemon_memcached', 'not installed')}",
          "UNINSTALL PLUGIN daemon_memcached;", ["MYSQL_PLUGINS"])
    _rule(r, "4.8", "Ensure the 'secure_file_priv' is configured correctly", "high",
          lambda d: var(d, "secure_file_priv", "") not in ("",),
          lambda d: f"secure_file_priv = {var(d, 'secure_file_priv')!r} (empty = any directory)",
          "Set secure_file_priv to a dedicated directory (or NULL) in [mysqld].", V)
    _var_rule(r, "4.9", "Ensure 'sql_mode' contains 'STRICT_ALL_TABLES'", "medium", "sql_mode",
              lambda v: "STRICT_ALL_TABLES" in str(v).split(","),
              "SET PERSIST sql_mode = CONCAT(@@sql_mode, ',STRICT_ALL_TABLES');", level="L2")
    _manual(r, "4.10", "Use MySQL TDE for at-rest data encryption", "medium",
            "Install a keyring component and encrypt tablespaces (default_table_encryption=ON).",
            lambda d: f"default_table_encryption = {var(d, 'default_table_encryption')}", level="L2", sections=V)

    # 5 MySQL permissions ─────────────────────────────────────────────────
    def full_access(d):
        out = [account(u) for u in users(d) if not is_admin(u)
               and all(priv(u, p) for p in FULL_DATA)]
        out += [f"'{p.get('user')}'@'{p.get('host')}' on {p.get('db')}" for p in _list(d, "MYSQL_DB_PRIVS")
                if isinstance(p, dict) and p.get("user") not in SYSTEM_ACCOUNTS and any((p.get("privs") or {}).values())
                and not (p.get("user") == "root" and p.get("host") in LOCAL_HOSTS)]
        return out
    _rule(r, "5.1", "Ensure only administrative users have full database access", "high", lambda d: not full_access(d),
          lambda d: "Non-administrative accounts with full or mysql-schema access: " + _names(full_access(d)),
          "REVOKE global and mysql.* privileges from application accounts; grant per schema.",
          ["MYSQL_USERS", "MYSQL_DB_PRIVS"])
    _priv_rule(r, "5.2", "Ensure 'FILE' is not granted to non-administrative users", "high", "file",
               "REVOKE FILE ON *.* FROM <account>;")
    _priv_rule(r, "5.3", "Ensure 'PROCESS' is not granted to non-administrative users", "medium", "process",
               "REVOKE PROCESS ON *.* FROM <account>;")
    _priv_rule(r, "5.4", "Ensure 'SUPER' is not granted to non-administrative users", "high", "super",
               "REVOKE SUPER ON *.* FROM <account>; grant specific dynamic privileges instead.")
    _priv_rule(r, "5.5", "Ensure 'SHUTDOWN' is not granted to non-administrative users", "medium", "shutdown",
               "REVOKE SHUTDOWN ON *.* FROM <account>;")
    _priv_rule(r, "5.6", "Ensure 'CREATE USER' is not granted to non-administrative users", "high", "create_user",
               "REVOKE CREATE USER ON *.* FROM <account>;")
    _priv_rule(r, "5.7", "Ensure 'GRANT OPTION' is not granted to non-administrative users", "high", "grant",
               "REVOKE GRANT OPTION ON *.* FROM <account>;")
    _manual(r, "5.8", "Ensure 'REPLICATION SLAVE' is not granted to non-administrative users", "medium",
            "Grant REPLICATION SLAVE only to dedicated replication accounts.",
            lambda d: "accounts with REPLICATION SLAVE: " + _names(non_admins_with(d, "repl_slave")), sections=U)
    _manual(r, "5.9", "Ensure DML/DDL grants are limited to specific databases and users", "medium",
            "Grant data and schema privileges per schema, to the accounts that need them.",
            lambda d: "accounts with global DDL: " + _names(
                account(u) for u in users(d) if not is_admin(u) and (priv(u, "create") or priv(u, "drop") or priv(u, "alter"))),
            sections=U)
    _manual(r, "5.10", "Securely define stored procedures and functions DEFINER and INVOKER", "medium",
            "Use SQL SECURITY INVOKER unless DEFINER is needed, with a least-privileged definer.",
            lambda d: "DEFINER routines: " + _names(_list(d, "MYSQL_ROUTINES")), sections=["MYSQL_ROUTINES"])

    # 6 Auditing and logging ──────────────────────────────────────────────
    _var_rule(r, "6.1", "Ensure 'log_error' is configured correctly", "medium", "log_error",
              lambda v: bool(str(v or "").strip()), "Set log_error to a file in [mysqld].")
    _rule(r, "6.2", "Ensure log files are stored on a non-system partition", "low",
          lambda d: not any(system_mount(d, t)[0] for t in ("error_log", "binlog") if t in mounts(d)),
          lambda d: "; ".join(f"{t}: {system_mount(d, t)[1]}" for t in ("error_log", "binlog") if t in mounts(d))
          or "logs go to stderr",
          "Point log_error and log_bin to a file system other than /, /var and /usr.", ["MOUNTS"], level="L2")
    _var_rule(r, "6.3", "Ensure 'log_error_verbosity' is set to '2'", "low", "log_error_verbosity",
              lambda v: str(v) == "2", "SET PERSIST log_error_verbosity = 2;", level="L2")

    def audit_plugins(d):
        return [n for n, s in plugins(d).items() if s == "ACTIVE" and re.search(r"audit", n, re.I)] + \
               [c for c in components(d) if "audit" in c]
    _rule(r, "6.4", "Ensure audit logging is enabled", "medium", lambda d: bool(audit_plugins(d)),
          lambda d: "active audit plugins/components: " + _names(audit_plugins(d)),
          "Install an audit plugin (MySQL Enterprise Audit, or the Percona/MariaDB audit plugin).",
          ["MYSQL_PLUGINS", "MYSQL_COMPONENTS"], level="L2")
    _rule(r, "6.5", "Ensure 'log-raw' is set to 'OFF'", "medium",
          lambda d: not on(var(d, "log_raw", startup_option(d, "log-raw") or "OFF")),
          lambda d: f"log_raw = {var(d, 'log_raw', startup_option(d, 'log-raw'))}",
          "Remove log-raw from the options (it writes passwords to the logs).", ["MYSQL_VARS", "MYCNF"])
    _manual(r, "6.6", "Ensure audit filters capture connection attempts", "medium",
            "Log connect and failed-connect events in the audit filters.", level="L2")

    # 7 Authentication ────────────────────────────────────────────────────
    def auth_plugin(d):
        v = var(d, "default_authentication_plugin")
        if v:
            return v
        return str(var(d, "authentication_policy", "")).split(",")[0].lstrip("*:") or "caching_sha2_password"
    _rule(r, "7.1", "Ensure default_authentication_plugin is set to a secure option", "high",
          lambda d: auth_plugin(d) in ("caching_sha2_password", "sha256_password"),
          lambda d: f"default authentication plugin = {auth_plugin(d)}",
          "Set default_authentication_plugin=caching_sha2_password (authentication_policy on 8.4).", V)

    def stored_passwords(d):
        return [f for f, text in option_files(d).items()
                if re.search(r"^\s*password\s*=\s*\S", text, re.M | re.I)]
    _rule(r, "7.2", "Ensure passwords are not stored in the global configuration", "high",
          lambda d: not stored_passwords(d), lambda d: "option files containing a password: " + _names(stored_passwords(d)),
          "Remove password= lines from option files; use login paths (mysql_config_editor).", ["MYCNF"])

    def no_password(d):
        return [account(u) for u in users(d) if u.get("plugin") in PASSWORD_PLUGINS and not u.get("has_password")
                and not u.get("locked")]
    _rule(r, "7.3", "Ensure passwords are set for all MySQL accounts", "high", lambda d: not no_password(d),
          lambda d: "accounts without a password: " + _names(no_password(d)), "ALTER USER <account> IDENTIFIED BY '...';", U)
    _rule(r, "7.4", "Ensure password reuse is restricted", "medium",
          lambda d: _int(var(d, "password_history")) >= 5 and _int(var(d, "password_reuse_interval")) >= 365,
          lambda d: f"password_history = {var(d, 'password_history')}, password_reuse_interval = {var(d, 'password_reuse_interval')}",
          "SET PERSIST password_history = 5; SET PERSIST password_reuse_interval = 365;", V)

    def complexity(d):
        v = vars_(d)
        return {k: v.get(f"validate_password.{k}", v.get(f"validate_password_{k}")) for k in
                ("length", "mixed_case_count", "number_count", "special_char_count", "policy")}
    _rule(r, "7.5", "Ensure password complexity is in place", "high",
          lambda d: _int(complexity(d)["length"]) >= 14 and _int(complexity(d)["mixed_case_count"]) >= 1
          and _int(complexity(d)["number_count"]) >= 1 and _int(complexity(d)["special_char_count"]) >= 1
          and str(complexity(d)["policy"]).upper() in ("MEDIUM", "STRONG", "1", "2"),
          lambda d: "validate_password: " + (", ".join(f"{k}={v}" for k, v in complexity(d).items()) if any(complexity(d).values())
                                             else "not installed"),
          "INSTALL COMPONENT 'file://component_validate_password'; set length 14, policy MEDIUM.", V)
    _rule(r, "7.6", "Ensure no users have wildcard hostnames", "high",
          lambda d: not [u for u in users(d) if "%" in str(u.get("host"))],
          lambda d: "accounts with wildcard hosts: " + _names(account(u) for u in users(d) if "%" in str(u.get("host"))),
          "Recreate the accounts for the specific hosts they connect from.", U)
    _rule(r, "7.7", "Ensure no anonymous accounts exist", "high",
          lambda d: not [u for u in users(d) if not u.get("user")],
          lambda d: "anonymous accounts: " + _names(account(u) for u in users(d) if not u.get("user")),
          "DROP USER ''@'<host>';", U)

    # 8 Network ───────────────────────────────────────────────────────────
    _rule(r, "8.1", "Ensure 'require_secure_transport' is set to 'ON' and/or 'have_ssl' is set to 'YES'", "high",
          lambda d: on(var(d, "require_secure_transport")),
          lambda d: f"require_secure_transport = {var(d, 'require_secure_transport')}, have_ssl = {var(d, 'have_ssl')}",
          "SET PERSIST require_secure_transport = ON;", V)

    def remote_no_ssl(d):
        return [account(u) for u in users(d) if u.get("host") not in LOCAL_HOSTS and u.get("user") not in SYSTEM_ACCOUNTS
                and str(u.get("ssl_type") or "") not in ("ANY", "X509", "SPECIFIED")]
    _rule(r, "8.2", "Ensure 'ssl_type' is set to 'ANY', 'X509', or 'SPECIFIED' for all remote users", "high",
          lambda d: not remote_no_ssl(d), lambda d: "remote accounts without REQUIRE SSL: " + _names(remote_no_ssl(d)),
          "ALTER USER <account> REQUIRE SSL;", U)
    _var_rule(r, "8.3", "Set maximum connection limits for server and per user", "low", "max_user_connections",
              lambda v: _int(v) > 0, "SET PERSIST max_user_connections = <limit>;", level="L2")
    _var_rule(r, "8.4", "Ensure only approved TLS versions are used", "high", "tls_version",
              lambda v: bool(v) and not {"TLSv1", "TLSv1.1"} & set(str(v).split(",")),
              "SET PERSIST tls_version = 'TLSv1.2,TLSv1.3'; ALTER INSTANCE RELOAD TLS;")
    _manual(r, "8.5", "Ensure only approved ciphers are used", "medium",
            "Restrict ssl_cipher and tls_ciphersuites to AEAD suites (ECDHE with AES-GCM or ChaCha20).",
            lambda d: f"ssl_cipher = {var(d, 'ssl_cipher')!r}, tls_ciphersuites = {var(d, 'tls_ciphersuites')!r}",
            sections=V)

    # 9 Replication ───────────────────────────────────────────────────────
    def channels(d):
        return [c for c in _list(d, "MYSQL_REPLICATION") if isinstance(c, dict) and c.get("host")]
    _manual(r, "9.1", "Ensure replication traffic is secured", "high",
            "Run replication over TLS (SOURCE_SSL=1) or a private network.",
            lambda d: "replication channels: " + _names(f"{c.get('channel') or 'default'} from {c.get('host')}"
                                                         for c in channels(d)), level="L2", sections=["MYSQL_REPLICATION"])
    _rule(r, "9.2", "Ensure 'SOURCE_SSL_VERIFY_SERVER_CERT' is set to 'YES' or '1'", "high",
          lambda d: all(str(c.get("ssl_verify_server_cert")).upper() in ("YES", "1") for c in channels(d)),
          lambda d: ("channels: " + _names(f"{c.get('channel') or 'default'}: verify={c.get('ssl_verify_server_cert')}"
                                           for c in channels(d))) if channels(d) else "not a replica",
          "CHANGE REPLICATION SOURCE TO SOURCE_SSL_VERIFY_SERVER_CERT=1;", ["MYSQL_REPLICATION"], level="L2")
    _var_rule(r, "9.3", "Ensure 'master_info_repository' is set to 'TABLE'", "medium", "master_info_repository",
              lambda v: str(v).upper() == "TABLE", "SET PERSIST master_info_repository = 'TABLE';", level="L2",
              default="TABLE")

    def repl_super(d):
        return [account(u) for u in users(d) if is_replication_account(u) and priv(u, "super") and not is_admin(u)]
    _rule(r, "9.4", "Ensure 'super_priv' is not set to 'Y' for replication users", "high", lambda d: not repl_super(d),
          lambda d: "replication accounts with SUPER: " + _names(repl_super(d)), "REVOKE SUPER ON *.* FROM <account>;", U,
          level="L2")

    def repl_wildcard(d):
        return [account(u) for u in users(d) if is_replication_account(u) and "%" in str(u.get("host"))]
    _rule(r, "9.5", "Ensure no replication users have wildcard hostnames", "high", lambda d: not repl_wildcard(d),
          lambda d: "replication accounts with wildcard hosts: " + _names(repl_wildcard(d)),
          "Recreate replication accounts for the replicas' addresses.", U, level="L2")

    r.sort(key=lambda x: tuple(int(p) for p in x.section.split(".")))
    return r


def rules_for(dump: str) -> List[BenchmarkRule]:
    v = section(dump, "MYSQL_VERSION").strip()
    if v == NO_MYSQL:
        raise ValueError("The mysql client was not found on this host.")
    if not re.match(r"^\d+\.\d+", v):
        raise ValueError(f"MySQL could not be queried: {v.splitlines()[0][:200] if v else 'no output'}")
    if not v.startswith("8."):
        raise ValueError(f"This benchmark covers MySQL 8; the server reports {v}.")
    return build_rules()


def all_rules() -> List[BenchmarkRule]:
    return build_rules()


def describe(dump: str) -> str:
    return (f"MySQL {section(dump, 'MYSQL_VERSION').strip()}, {len(users(dump))} accounts, "
            f"{len([s for s in _list(dump, 'MYSQL_SCHEMAS') if s not in ('mysql', 'information_schema', 'performance_schema', 'sys')])} application schemas")
