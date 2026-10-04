"""
Read-only collection for a MySQL 8 audit: SQL with the MySQL login (scripts
starting with "SQL:", run through the mysql client on the host, see
app/modules/benchmark/connectors.py) and shell commands as root over SSH.

SQL: server variables, accounts with their privileges (never the password
hashes - only whether an account has one), dynamic privileges, schemas,
plugins and components, DEFINER routines and replication channels (never
their passwords).

Host: the mysqld process (owner and options, read from /proc so it works
without ps), the option files (password values are blanked here, on this
side, before anything is stored), ownership and modes of the data directory,
logs, keys and plugin directory, mount points, the mysql account's shell,
.mysql_history files and MYSQL_PWD use. File paths come from
`mysqld --verbose --help`, which resolves the option files the server reads.
"""

import re
from typing import Dict

from app.modules.benchmark.connectors import SQL_PREFIX
from app.modules.benchmark.rules import assemble

NO_MYSQL = "NO_MYSQL"


def _sql(query: str) -> str:
    return SQL_PREFIX + query


def _agg(obj: str, source: str) -> str:
    return _sql(f"SELECT COALESCE(JSON_ARRAYAGG({obj}), JSON_ARRAY()) FROM {source}")


_PRIVS = ("Select", "Insert", "Update", "Delete", "Create", "Drop", "Reload", "Shutdown", "Process", "File",
          "Grant", "References", "Index", "Alter", "Show_db", "Super", "Create_tmp_table", "Lock_tables",
          "Execute", "Repl_slave", "Repl_client", "Create_view", "Show_view", "Create_routine", "Alter_routine",
          "Create_user", "Event", "Trigger", "Create_tablespace")
_PRIV_JSON = "JSON_OBJECT(" + ", ".join(f"'{p.lower()}', {p}_priv = 'Y'" for p in _PRIVS) + ")"
_DB_PRIVS = ("Select", "Insert", "Update", "Delete", "Create", "Drop", "Grant", "Alter", "Execute")

SQL_COMMANDS = {
    "MYSQL_VERSION": _sql("SELECT VERSION()"),
    "MYSQL_VARS": _sql("SELECT JSON_OBJECTAGG(VARIABLE_NAME, VARIABLE_VALUE) FROM performance_schema.global_variables"),
    "MYSQL_USERS": _agg(
        "JSON_OBJECT('user', User, 'host', Host, 'plugin', plugin, 'has_password', authentication_string <> '', "
        "'locked', account_locked = 'Y', 'ssl_type', ssl_type, 'max_user_connections', max_user_connections, "
        "'password_lifetime', password_lifetime, 'privs', " + _PRIV_JSON + ")", "mysql.user"),
    "MYSQL_GLOBAL_GRANTS": _agg("JSON_OBJECT('user', USER, 'host', HOST, 'priv', PRIV, 'grantable', WITH_GRANT_OPTION)",
                                "mysql.global_grants"),
    "MYSQL_DB_PRIVS": _agg(
        "JSON_OBJECT('user', User, 'host', Host, 'db', Db, 'privs', JSON_OBJECT("
        + ", ".join(f"'{p.lower()}', {p}_priv = 'Y'" for p in _DB_PRIVS) + "))",
        "mysql.db WHERE Db IN ('mysql', '%')"),
    "MYSQL_SCHEMAS": _agg("SCHEMA_NAME", "information_schema.SCHEMATA"),
    "MYSQL_PLUGINS": _agg("JSON_OBJECT('name', PLUGIN_NAME, 'status', PLUGIN_STATUS)", "information_schema.PLUGINS"),
    "MYSQL_COMPONENTS": _agg("component_urn", "mysql.component"),
    "MYSQL_ROUTINES": _agg("CONCAT(ROUTINE_SCHEMA, '.', ROUTINE_NAME, ' (', ROUTINE_TYPE, ', definer ', DEFINER, ')')",
                           "information_schema.ROUTINES WHERE SECURITY_TYPE = 'DEFINER' "
                           "AND ROUTINE_SCHEMA NOT IN ('sys', 'mysql')"),
    "MYSQL_REPLICATION": _agg("JSON_OBJECT('channel', CHANNEL_NAME, 'host', HOST, 'user', USER, "
                              "'ssl_allowed', SSL_ALLOWED, 'ssl_verify_server_cert', SSL_VERIFY_SERVER_CERTIFICATE)",
                              "performance_schema.replication_connection_configuration"),
}

# mysqld processes from /proc: "owner|command line" (no ps on minimal images).
MYSQLD_PROC = (
    "for d in /proc/[0-9]*; do c=$(tr '\\0' ' ' < $d/cmdline 2>/dev/null); [ -n \"$c\" ] || continue; "
    "set -- $c; [ \"$(basename \"$1\")\" = mysqld ] && echo \"$(stat -c %U $d)|$c\"; done; echo END"
)

MYCNF = (
    "for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.cnf /etc/mysql/conf.d/*.cnf "
    "/etc/mysql/mysql.conf.d/*.cnf /etc/my.cnf.d/*.cnf /root/.my.cnf /home/*/.my.cnf; do "
    "[ -f \"$f\" ] && { echo \"### $f\"; cat \"$f\"; }; done; echo END"
)

# Option values as mysqld resolves them from its option files.
_RESOLVE = (
    "h=$(mysqld --verbose --help 2>/dev/null); "
    "v() { echo \"$h\" | awk -v k=\"$1\" '$1==k { if ($2 !~ /^\\(No/) print $2; exit }'; }; "
    "dd=$(v datadir); dd=${dd%/}/; [ \"$dd\" = / ] && dd=/var/lib/mysql/; "
    "abs() { case \"$1\" in ''|stderr|ON|OFF|TRUE|FALSE) ;; /*) echo \"$1\" ;; *) echo \"$dd${1#./}\" ;; esac; }; "
)

# Shell expressions for each file group (also used by the fixes).
FILE_GROUPS = {
    "datadir": "$dd",
    "binlog": "$(b=$(abs \"$(v log-bin)\"); [ -n \"$b\" ] && ls -d \"$b\".[0-9]* \"$b\".index 2>/dev/null)",
    "error_log": "$(abs \"$(v log-error)\")",
    "slow_log": "$(abs \"$(v slow-query-log-file)\")",
    "relay_log": "$(r=$(abs \"$(v relay-log)\"); [ -n \"$r\" ] && ls -d \"$r\".[0-9]* \"$r\".index 2>/dev/null)",
    "general_log": "$(abs \"$(v general-log-file)\")",
    "ssl_key": "$( { abs \"$(v ssl-key)\"; ls -d \"$dd\"*key*.pem 2>/dev/null | grep -v public; } | sort -u)",
    "plugin_dir": "$(v plugin-dir)",
    "audit_log": "$(abs \"$(v audit-log-file)\")",
    "keyring": "$(abs \"$(v keyring-file-data)\")",
}

FILES = (
    _RESOLVE
    + "st() { tag=$1; shift; for f in \"$@\"; do [ -n \"$f\" ] || continue; "
    "if [ -e \"$f\" ]; then printf '%s|' \"$tag\"; stat -c '%n|%U|%G|%a|%F' \"$f\"; "
    "else echo \"$tag|$f|-|-|-|missing\"; fi; done; }; "
    + "; ".join(f"st {tag} {expr}" for tag, expr in FILE_GROUPS.items())
    + "; echo \"secure_file_priv|$(v secure-file-priv)\"; echo END"
)

MOUNTS = (
    _RESOLVE
    + "mp() { [ -n \"$2\" ] && [ -e \"$2\" ] && echo \"$1|$2|$(df -P \"$2\" 2>/dev/null | awk 'NR==2 {print $6}')\"; }; "
    "mp datadir \"$dd\"; e=$(abs \"$(v log-error)\"); [ -n \"$e\" ] && mp error_log \"$(dirname \"$e\")\"; "
    "b=$(abs \"$(v log-bin)\"); [ -n \"$b\" ] && mp binlog \"$(dirname \"$b\")\"; echo END"
)

HOST = (
    "echo \"account=$(getent passwd mysql || echo NONE)\"; "
    "for f in /root/.mysql_history /home/*/.mysql_history; do "
    "{ [ -e \"$f\" ] || [ -L \"$f\" ]; } && echo \"history=$f|$(readlink \"$f\" || echo regular)\"; done; "
    "echo \"pwd_env=$(grep -l MYSQL_PWD /proc/[0-9]*/environ 2>/dev/null | wc -l)\"; "
    "echo \"pwd_profiles=$(grep -ls MYSQL_PWD /etc/profile /etc/environment /etc/bash.bashrc /etc/bashrc "
    "/etc/profile.d/* /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile "
    "/home/*/.bash_profile 2>/dev/null | tr '\\n' ' ')\"; "
    "echo \"container=$([ -f /.dockerenv ] || grep -qa 'container=' /proc/1/environ 2>/dev/null && echo yes || echo no)\"; "
    "echo END"
)

OS_COMMANDS = {
    "OS_RELEASE": "cat /etc/os-release 2>/dev/null || uname -sr",
    "MYSQLD_PROC": MYSQLD_PROC,
    "MYCNF": MYCNF,
    "FILES": FILES,
    "MOUNTS": MOUNTS,
    "HOST": HOST,
}


def mysql_commands() -> Dict[str, str]:
    return {**SQL_COMMANDS, **OS_COMMANDS}


_PASSWORD_LINE = re.compile(r"^(\s*(?:password|ssl[-_]?key[-_]?password)\s*=\s*)(.*)$", re.I | re.M)


def redact_option_files(text: str) -> str:
    """Keep that a password is set in an option file, never its value."""
    return _PASSWORD_LINE.sub(lambda m: m.group(1) + ("***" if m.group(2).strip() else ""), text)


def collect(conn) -> str:
    """Collect the MySQL audit dump: server version first (a host without the mysql client yields a
    dump saying so), then variables, accounts, privileges, plugins, option files, file permissions
    and the mysqld process.
    """
    cmds = mysql_commands()
    version = conn.run(cmds["MYSQL_VERSION"])
    if "command not found" in version or "not found" in version.lower().split(":")[-1]:
        return assemble({"MYSQL_VERSION": NO_MYSQL})
    out = {"MYSQL_VERSION": version}
    for name, script in cmds.items():
        if name == "MYSQL_VERSION":
            continue
        text = conn.run(script)
        out[name] = redact_option_files(text) if name == "MYCNF" else text
    return assemble(out)
