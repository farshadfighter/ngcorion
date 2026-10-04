"""
MySQL 8 remediation.

Server settings are changed with SET PERSIST: they apply at once and are
kept in mysqld-auto.cnf across restarts, so no option file is edited and the
server is not restarted. File fixes find the paths the way the audit does
(`mysqld --verbose --help`) and only remove permission bits the benchmark
disallows. Changes that can break applications or clients (TLS-only
connections, strict SQL mode, LOAD DATA LOCAL, password expiry, dropping
schemas or accounts, the password policy) need an explicit confirmation.

Privilege findings (section 5), account hosts and startup-only options
(binary log, skip-symbolic-links, authentication plugin) come with guidance.
"""

from app.modules.benchmark.connectors import SQL_PREFIX
from app.modules.benchmark.templates import HardeningTemplate, ParamMeta, TemplateSet

from . import rules as R
from .collect import _RESOLVE, FILE_GROUPS

TEMPLATES = TemplateSet()
TEMPLATES.param(ParamMeta(
    name="CONFIRM", input_type="select", label="Confirm the change",
    description="This change has side effects described in the check's warning. Choose 'yes' to apply it.",
    required=True, options=["yes"]))
TEMPLATES.param(ParamMeta(
    name="MAX_USER_CONN", input_type="number", label="Connections per account",
    description="Maximum simultaneous connections for one MySQL account (0 = unlimited).",
    required=True, min_value=1, max_value=100000, placeholder="100"))


def _add(sec, description, statements, verify, warning=None, params=()):
    TEMPLATES.add(HardeningTemplate(
        check_id=f"MYSQL-{sec}", description=description, statements=statements, verify_statements=verify,
        parameters=list(params), warning=warning))


def sql(text: str) -> str:
    return SQL_PREFIX + text


def check(condition: str) -> str:
    return sql(f"SELECT IF({condition}, 'PASS', 'FAIL')")


# Server settings ────────────────────────────────────────────────────────

_add("2.6", "Expire passwords after 365 days",
     [sql("SET PERSIST default_password_lifetime = 365")], [check("@@global.default_password_lifetime BETWEEN 1 AND 365")],
     warning="Accounts whose password is older than 365 days must change it at their next login; application "
             "accounts may need PASSWORD EXPIRE NEVER.", params=["CONFIRM"])
_EXAMPLE_SCHEMAS = ("test", "employees", "sakila", "world")
_add("4.2", "Drop the example and test databases",
     [sql("; ".join(f"DROP DATABASE IF EXISTS `{s}`" for s in _EXAMPLE_SCHEMAS))],
     [check("(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ("
            + ", ".join(f"'{s}'" for s in _EXAMPLE_SCHEMAS) + ")) = 0")],
     warning="The test, employees, sakila and world schemas and their data are deleted.", params=["CONFIRM"])
_add("4.4", "Disable LOAD DATA LOCAL", [sql("SET PERSIST local_infile = 0")], [check("@@global.local_infile = 0")],
     warning="Clients can no longer load files from their own machine with LOAD DATA LOCAL INFILE.", params=["CONFIRM"])
_add("4.9", "Add STRICT_ALL_TABLES to sql_mode",
     [sql("SET PERSIST sql_mode = CONCAT_WS(',', NULLIF(@@global.sql_mode, ''), 'STRICT_ALL_TABLES')")],
     [check("FIND_IN_SET('STRICT_ALL_TABLES', @@global.sql_mode) > 0")],
     warning="Statements that today store truncated or invalid values with a warning fail instead; test the "
             "applications first. Applies to new connections.", params=["CONFIRM"])
_add("6.3", "Set log_error_verbosity to 2 (errors and warnings)",
     [sql("SET PERSIST log_error_verbosity = 2")], [check("@@global.log_error_verbosity = 2")])
_add("7.4", "Restrict password reuse (5 previous passwords, 365 days)",
     [sql("SET PERSIST password_history = 5; SET PERSIST password_reuse_interval = 365")],
     [check("@@global.password_history >= 5 AND @@global.password_reuse_interval >= 365")])
_add("7.5", "Install the password validation component (length 14, mixed case, digit, special character)",
     # 3529: already installed (INSTALL COMPONENT has no IF NOT EXISTS and is not
     # allowed in prepared statements); verification still decides.
     ["SQL[ok=3529]:INSTALL COMPONENT 'file://component_validate_password'",
      sql("SET PERSIST validate_password.length = 14; "
          "SET PERSIST validate_password.mixed_case_count = 1; SET PERSIST validate_password.number_count = 1; "
          "SET PERSIST validate_password.special_char_count = 1; SET PERSIST validate_password.policy = 'MEDIUM'")],
     [check("@@global.validate_password.length >= 14 AND @@global.validate_password.policy IN ('MEDIUM', 'STRONG')")],
     warning="New and changed passwords must meet the policy (existing passwords keep working); tools that set "
             "short passwords fail.", params=["CONFIRM"])
_add("7.7", "Drop anonymous accounts",
     [sql("SELECT GROUP_CONCAT(CONCAT(QUOTE(User), '@', QUOTE(Host))) INTO @u FROM mysql.user WHERE User = ''; "
          "SET @s = IF(@u IS NULL, 'DO 0', CONCAT('DROP USER ', @u)); PREPARE st FROM @s; EXECUTE st; DEALLOCATE PREPARE st")],
     [check("(SELECT COUNT(*) FROM mysql.user WHERE User = '') = 0")],
     warning="Clients that connect without a user name are refused.", params=["CONFIRM"])
_add("8.1", "Require TLS for every connection", [sql("SET PERSIST require_secure_transport = ON")],
     [check("@@global.require_secure_transport = 1")],
     warning="Clients connecting without TLS (old drivers, sslmode=disable) are refused; local socket connections "
             "keep working.", params=["CONFIRM"])
_add("8.3", "Limit simultaneous connections per account",
     [sql("SET PERSIST max_user_connections = {MAX_USER_CONN}")], [check("@@global.max_user_connections > 0")],
     params=["MAX_USER_CONN"])
_add("8.4", "Allow only TLS 1.2 and 1.3",
     [sql("SET PERSIST tls_version = 'TLSv1.2,TLSv1.3'; ALTER INSTANCE RELOAD TLS")],
     [check("FIND_IN_SET('TLSv1', @@global.tls_version) = 0 AND FIND_IN_SET('TLSv1.1', @@global.tls_version) = 0")],
     warning="Clients that only speak TLS 1.0/1.1 can no longer connect.", params=["CONFIRM"])


# Files ──────────────────────────────────────────────────────────────────

for _sec, _tag, _label, _mode, _sev in R.FILE_RULES:
    _paths = FILE_GROUPS[_tag]
    _add(_sec, f"Set {_label} to mysql:mysql, {_mode:o} or more restrictive",
         [_RESOLVE + f"for f in {_paths}; do [ -e \"$f\" ] || continue; chown mysql:mysql \"$f\"; "
          f"m=$(stat -c %a \"$f\"); chmod $(printf '%o' $(( 0$m & 0{_mode:o} ))) \"$f\"; done; true"],
         [_RESOLVE + f"r=PASS; for f in {_paths}; do [ -e \"$f\" ] || continue; m=$(stat -c %a \"$f\"); "
          f"[ \"$(stat -c %U:%G \"$f\")\" = mysql:mysql ] && [ $(( 0$m & ~0{_mode:o} & 07777 )) -eq 0 ] || r=FAIL; "
          "done; echo $r"])

_HISTORY = "/root/.mysql_history /home/*/.mysql_history"
_add("1.3", "Point every .mysql_history at /dev/null",
     [f"for f in {_HISTORY}; do {{ [ -e \"$f\" ] || [ -L \"$f\" ]; }} || continue; rm -f \"$f\"; ln -s /dev/null \"$f\"; done; true"],
     [f"r=PASS; for f in {_HISTORY}; do {{ [ -e \"$f\" ] || [ -L \"$f\" ]; }} || continue; "
      "[ \"$(readlink \"$f\")\" = /dev/null ] || r=FAIL; done; echo $r"])
_add("1.5", "Disable interactive login for the mysql account",
     ["command -v usermod >/dev/null 2>&1 || { echo 'usermod is not installed on this host' >&2; exit 1; }; "
      "usermod -s \"$(command -v nologin || echo /bin/false)\" mysql"],
     ["getent passwd mysql | grep -qE ':(/usr)?/s?bin/(nologin|false)$' && echo PASS || echo FAIL"],
     warning="Scripts that run commands with su - mysql stop working; use sudo -u mysql instead.", params=["CONFIRM"])


# Guidance only ──────────────────────────────────────────────────────────

_GUIDANCE = {
    "1.1": "Move datadir to its own file system (stop MySQL, copy with permissions, update datadir, start).",
    "1.2": "Set user=mysql in [mysqld] and restart.",
    "1.6": "Remove MYSQL_PWD from the listed profiles.",
    "2.1.5": "Enable the binary log (log_bin) in [mysqld] and restart.",
    "4.3": "Remove allow-suspicious-udfs from the options and restart.",
    "4.5": "Remove skip-grant-tables from the options and restart.",
    "4.6": "Add skip-symbolic-links to [mysqld] and restart.",
    "4.7": "UNINSTALL PLUGIN daemon_memcached;",
    "4.8": "Set secure_file_priv to a dedicated directory in [mysqld] and restart.",
    "6.1": "Set log_error to a file in [mysqld] and restart.",
    "6.2": "Move log_error and the binary log to a separate file system.",
    "6.4": "Install an audit plugin and log connections and administrative statements.",
    "6.5": "Remove log-raw from the options and restart.",
    "7.1": "Set default_authentication_plugin=caching_sha2_password (authentication_policy on 8.4) and move "
           "accounts to it with ALTER USER ... IDENTIFIED WITH caching_sha2_password.",
    "7.2": "Remove password= lines from option files; use mysql_config_editor login paths.",
    "7.3": "Set a password for each listed account or lock it.",
    "7.6": "Recreate each account for the hosts it connects from (CREATE USER 'app'@'10.0.0.%' ...) and drop the '%' account.",
    "8.2": "ALTER USER <account> REQUIRE SSL; for each remote account.",
    "9.2": "CHANGE REPLICATION SOURCE TO SOURCE_SSL=1, SOURCE_SSL_VERIFY_SERVER_CERT=1;",
    "9.3": "SET PERSIST master_info_repository = 'TABLE'; (the default since 8.0.23)",
    "9.4": "REVOKE SUPER ON *.* FROM <replication account>;",
    "9.5": "Recreate replication accounts for the replicas' addresses.",
}
for _r in R.all_rules():
    if _r.id not in TEMPLATES.templates:
        TEMPLATES.manual(_r.id, _GUIDANCE.get(_r.section, _r.remediation))
