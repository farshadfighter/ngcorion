"""
SQL Server CIS Benchmark Rules — version-aware (2016 / 2019 / 2022)

The rule set is built the same way the MongoDB / RHEL modules build theirs:
a single base builder for the newest benchmark (SQL Server 2022, v1.2.1) and
thin derived builders that *extend* it for the older versions — dropping the
controls a version does not ship and overriding only what genuinely differs.

Distro gate keys (the equivalent of the Linux ``rhel_10`` profile) select the
rule set:

    mssql_2016  -> build_mssql_2016_cis_rules()
    mssql_2019  -> build_mssql_2019_cis_rules()   (identical to 2022)
    mssql_2022  -> build_mssql_2022_cis_rules()

The gate key is resolved from the collected ``@@VERSION`` (``_detect_distro``)
so callers never have to know the SQL Server build number.

Check IDs are stable, topic-based slugs (``MSSQL-AHDQ``, ``MSSQL-TDE`` …) that
are shared across every version and matched 1:1 by the hardening templates —
the CIS section number, which is what actually differs between 2016 and
2019/2022, lives in the (per-version) ``section`` field.

All checks read the structured dump produced by ``MSSQLClient.collect_audit_data``
using regex over the ``===SECTION:NAME===`` markers. Manual controls (things
that cannot be proven over a T-SQL connection — service accounts, patch level,
protocol/port changes) are reported NOT_APPLICABLE and never scored.

CIS sections covered:
  1.x  Installation, Updates and Patches
  2.x  Surface Area Reduction
  3.x  Authentication and Authorization
  4.x  Password Policies
  5.x  Auditing and Logging
  6.x  Application Development
  7.x  Encryption
  8.x  Additional Considerations
"""

import re
from dataclasses import dataclass, replace
from typing import Callable, List, Dict, Any


# ============================================================ #
#  Rule dataclass                                              #
# ============================================================ #

@dataclass
class MSSQLCISRule:
    """A single CIS SQL Server compliance check."""
    id: str                          # stable slug, e.g. "MSSQL-AHDQ"
    section: str                     # CIS section number, e.g. "2.1"
    title: str
    description: str
    severity: str                    # high / medium / low / info
    level: str                       # L1 / L2
    check_fn: Callable[[str], bool]  # True = compliant
    evidence_fn: Callable[[str], str]
    remediation: str
    manual: bool = False             # Manual controls: reported NA, never scored


# ============================================================ #
#  Helper – extract a named section from the dump              #
# ============================================================ #

def _section(dump: str, name: str) -> str:
    """Extract the content of a named section from the audit dump."""
    pattern = re.compile(
        rf"===SECTION:{re.escape(name)}===\n(.*?)(?=\n===SECTION:|\Z)",
        re.S,
    )
    m = pattern.search(dump)
    return m.group(1).strip() if m else ""


def _query_ok(text: str) -> bool:
    """Inability to read a section is never evidence of compliance."""
    return bool(text) and "QUERY_ERROR" not in text


def _no_rows(text: str) -> bool:
    """True when a section returned no data rows."""
    t = text.strip()
    return (not t) or t == "(empty)" or "(no rows returned)" in t


def _config_val(dump: str, option_name: str) -> str:
    """Extract the value_in_use of a sys.configurations row (raw string)."""
    section = _section(dump, "CONFIGURATIONS")
    pattern = re.compile(rf"^{re.escape(option_name)}\s*\|\s*(\S+)", re.I | re.M)
    m = pattern.search(section)
    return m.group(1) if m else ""


def _config_is_zero(dump: str, option_name: str) -> bool:
    return _config_val(dump, option_name) == "0"


def _config_is_one(dump: str, option_name: str) -> bool:
    return _config_val(dump, option_name) == "1"


# ============================================================ #
#  Evidence extractors                                         #
# ============================================================ #

def _ev_section(dump: str, section: str, max_chars: int = 500) -> str:
    content = _section(dump, section)
    return content[:max_chars] + ("..." if len(content) > max_chars else "")


def _ev_config_row(dump: str, option_name: str) -> str:
    section = _section(dump, "CONFIGURATIONS")
    pattern = re.compile(rf"^{re.escape(option_name)}\s*\|.*$", re.I | re.M)
    m = pattern.search(section)
    return m.group(0) if m else f"(option '{option_name}' not found)"


def _manual_evidence(text: str):
    """Evidence factory for manual controls."""
    return lambda d: text


# ============================================================ #
#  Version detection                                           #
# ============================================================ #

def _detect_version(dump: str) -> int:
    """
    Return the SQL Server major version from the VERSION section.
    Known mappings: 2016=13, 2017=14, 2019=15, 2022=16. 0 if unknown.
    """
    version_text = _section(dump, "VERSION")
    m = re.search(r"Microsoft SQL Server (\d{4})", version_text, re.I)
    if m:
        year_to_major = {2016: 13, 2017: 14, 2019: 15, 2022: 16}
        return year_to_major.get(int(m.group(1)), 0)
    m = re.search(r"\b(\d{2})\.\d+\.\d+", version_text)
    if m:
        return int(m.group(1))
    return 0


def _detect_distro(dump: str) -> str:
    """
    Resolve the SQL Server dump to a distro gate key. Unknown builds fall back
    to the newest benchmark (superset), so nothing goes unscored.
    """
    major = _detect_version(dump)
    if major == 13:
        return "mssql_2016"
    if major in (14, 15):          # 2017 & 2019 share the clr-strict-security era
        return "mssql_2019"
    return "mssql_2022"            # 16 and anything newer/unknown


# ============================================================ #
#  Check helpers (fail closed on QUERY_ERROR)                  #
# ============================================================ #

def _row_cells(line: str) -> List[str]:
    return [c.strip() for c in line.split("|")]


def _no_trustworthy(dump: str) -> bool:
    """CIS 2.9 — no non-system DB (msdb excepted) has TRUSTWORTHY ON."""
    txt = _section(dump, "DATABASES")
    if not _query_ok(txt):
        return False
    for line in txt.splitlines():
        parts = _row_cells(line)
        if len(parts) < 2:
            continue
        name, trustworthy = parts[0], parts[1]
        if name.lower() == "msdb":
            continue
        if trustworthy in ("True", "1"):
            return False
    return True


def _port_ok(dump: str) -> bool:
    """CIS 2.11 — instance is not listening on the default TCP port 1433."""
    txt = _section(dump, "TCP_PORT")
    if not _query_ok(txt):
        return False
    m = re.search(r"(\d+)", txt)
    return bool(m) and m.group(1) != "1433"


def _hide_instance(dump: str) -> bool:
    """CIS 2.12 — HideInstance registry value is 1."""
    txt = _section(dump, "HIDE_INSTANCE")
    return _query_ok(txt) and bool(re.search(r"\b1\b", txt))


def _sa_disabled(dump: str) -> bool:
    """CIS 2.13 — the 'sa' login is disabled (or no longer present)."""
    txt = _section(dump, "SA_LOGIN")
    if not _query_ok(txt):
        return False
    for line in txt.splitlines():
        parts = _row_cells(line)
        if parts and parts[0].lower() == "sa":
            return len(parts) >= 2 and parts[1] in ("True", "1")
    return True  # no login named 'sa' -> nothing enabled to attack


def _sa_renamed(dump: str) -> bool:
    """CIS 2.14 — the principal with sid 0x01 is no longer named 'sa'."""
    txt = _section(dump, "SA_SID")
    if not _query_ok(txt) or _no_rows(txt):
        return False
    name = _row_cells(txt.splitlines()[0])[0]
    return name.lower() != "sa"


def _auto_close_off(dump: str) -> bool:
    """CIS 2.15 — no contained database has AUTO_CLOSE ON."""
    txt = _section(dump, "CONTAINED_DBS")
    if not _query_ok(txt):
        return False
    if _no_rows(txt):
        return True
    for line in txt.splitlines():
        parts = _row_cells(line)
        if parts and parts[-1] in ("True", "1"):
            return False
    return True


def _clr_strict_on(dump: str) -> bool:
    """CIS 2.17 — 'clr strict security' = 1 (2019/2022)."""
    return _config_is_one(dump, "clr strict security")


def _xp_cmdshell_off(dump: str) -> bool:
    """CIS 2.15 (2016) — 'xp_cmdshell' = 0."""
    return _config_is_zero(dump, "xp_cmdshell")


def _windows_auth_only(dump: str) -> bool:
    """CIS 3.1 — Windows Authentication Mode."""
    return bool(re.search(r"Windows Authentication Mode", _section(dump, "AUTH_MODE"), re.I))


def _guest_revoked(dump: str) -> bool:
    """CIS 3.2 — no user database grants CONNECT to guest."""
    txt = _section(dump, "GUEST_CONNECT")
    if not _query_ok(txt):
        return False
    if _no_rows(txt):
        return True
    for line in txt.splitlines():
        parts = _row_cells(line)
        if parts and parts[-1].lstrip("-").isdigit() and int(parts[-1]) > 0:
            return False
    return True


def _section_clean(dump: str, name: str) -> bool:
    """Generic 'pass when the section returned no offending rows' check."""
    txt = _section(dump, name)
    return _query_ok(txt) and _no_rows(txt)


def _no_builtin_logins(dump: str) -> bool:
    """CIS 3.9 — no BUILTIN\\ group exists as a SQL login."""
    txt = _section(dump, "BUILTIN_LOGINS")
    if not _query_ok(txt):
        return False
    return not re.search(r"^BUILTIN\\", txt, re.M | re.I)


def _no_local_group_logins(dump: str) -> bool:
    """CIS 3.10 — no local Windows (machine) group exists as a SQL login."""
    txt = _section(dump, "BUILTIN_LOGINS")
    if not _query_ok(txt):
        return False
    for line in txt.splitlines():
        parts = _row_cells(line)
        if not parts or not parts[0]:
            continue
        name = parts[0]
        if "\\" not in name:
            continue
        upper = name.upper()
        if upper.startswith("BUILTIN\\"):        # covered by 3.9
            continue
        if upper.startswith(("NT AUTHORITY\\", "NT SERVICE\\")):
            continue
        return False
    return True


def _check_policy_ok(dump: str) -> bool:
    """CIS 4.3 — every SQL login has CHECK_POLICY = ON."""
    txt = _section(dump, "SQL_LOGINS")
    if not _query_ok(txt):
        return False
    for line in txt.splitlines():
        parts = _row_cells(line)
        # name | is_disabled | is_policy_checked | is_expiration_checked | type_desc
        if len(parts) < 5 or parts[4] != "SQL_LOGIN":
            continue
        if parts[0].startswith("##"):
            continue
        if parts[2] == "False":
            return False
    return True


def _errlog_ok(dump: str) -> bool:
    """CIS 5.1 — NumErrorLogs >= 12."""
    txt = _section(dump, "ERRORLOG_COUNT")
    if not _query_ok(txt):
        return False
    m = re.search(r"(\d+)", txt)
    return bool(m) and int(m.group(1)) >= 12


def _login_audit_ok(dump: str) -> bool:
    """CIS 5.3 — login auditing captures at least failed logins (2 or 3)."""
    txt = _section(dump, "LOGIN_AUDIT_LEVEL")
    if not _query_ok(txt):
        return False
    m = re.search(r"(\d+)", txt)
    return bool(m) and int(m.group(1)) in (2, 3)


def _server_audit_ok(dump: str) -> bool:
    """CIS 5.4 — an enabled Server Audit captures failed AND successful logins."""
    audits = _section(dump, "SERVER_AUDITS")
    specs = _section(dump, "AUDIT_SPECIFICATIONS")
    if not _query_ok(audits) or "QUERY_ERROR" in specs:
        return False
    enabled = bool(re.search(r"\bTrue\b|STARTED|RUNNING", audits, re.I))
    return (
        enabled
        and "FAILED_LOGIN_GROUP" in specs
        and "SUCCESSFUL_LOGIN_GROUP" in specs
    )


def _clr_assemblies_safe(dump: str) -> bool:
    """CIS 6.2 — no user CLR assembly uses EXTERNAL_ACCESS/UNSAFE."""
    txt = _section(dump, "CLR_ASSEMBLIES")
    if not _query_ok(txt):
        return False
    return not re.search(r"EXTERNAL_ACCESS|UNSAFE", txt, re.I)


def _symmetric_keys_strong(dump: str) -> bool:
    """CIS 7.1 — every user symmetric key uses an AES algorithm."""
    txt = _section(dump, "SYMMETRIC_KEYS")
    if not _query_ok(txt):
        return False
    if _no_rows(txt):
        return True
    for line in txt.splitlines():
        parts = _row_cells(line)
        if len(parts) >= 3 and parts[2] and "AES" not in parts[2].upper():
            return False
    return True


def _asymmetric_keys_strong(dump: str) -> bool:
    """CIS 7.2 — every user asymmetric key is >= 2048 bits."""
    txt = _section(dump, "ASYMMETRIC_KEYS")
    if not _query_ok(txt):
        return False
    if _no_rows(txt):
        return True
    for m in re.finditer(r"\|\s*(\d{1,5})\s*\|", txt):
        if int(m.group(1)) < 2048:
            return False
    return True


def _network_encryption_on(dump: str) -> bool:
    """CIS 7.4 — ForceEncryption/Encrypt registry value is 1."""
    txt = _section(dump, "NETWORK_ENCRYPTION")
    return _query_ok(txt) and bool(re.search(r"\b1\b", txt))


def _tde_ok(dump: str) -> bool:
    """CIS 7.5 — every user database (database_id > 4) is encrypted."""
    txt = _section(dump, "TDE_DATABASES")
    if not _query_ok(txt):
        return False
    if _no_rows(txt):
        return True
    for line in txt.splitlines():
        parts = _row_cells(line)
        if len(parts) >= 2 and parts[1] in ("False", "0"):
            return False
    return True


# ============================================================ #
#  Base rule builder — SQL Server 2022 (CIS v1.2.1)            #
# ============================================================ #

def build_mssql_2022_cis_rules() -> List[MSSQLCISRule]:
    """Full CIS SQL Server 2022 Benchmark rule set (base for 2019/2016)."""
    rules: List[MSSQLCISRule] = []

    def add(id, section, title, severity, level, check_fn, evidence_fn,
            remediation, description="", manual=False):
        rules.append(MSSQLCISRule(
            id=id, section=section, title=title,
            description=description or title,
            severity=severity, level=level,
            check_fn=check_fn, evidence_fn=evidence_fn,
            remediation=remediation, manual=manual,
        ))

    def add_config_zero(id, section, title, option, severity="medium",
                        level="L1", advanced=True):
        recon = (
            "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;\n"
            if advanced else ""
        )
        add(
            id, section, title, severity, level,
            check_fn=lambda d, o=option: _config_is_zero(d, o),
            evidence_fn=lambda d, o=option: _ev_config_row(d, o),
            remediation=(
                f"{recon}EXECUTE sp_configure '{option}', 0;\nRECONFIGURE;"
                + ("\nEXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"
                   if advanced else "")
            ),
        )

    # ---- Section 1 — Installation, Updates and Patches (manual) ----
    add("MSSQL-PATCH", "1.1",
        "Ensure Latest SQL Server Cumulative and Security Updates are installed",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=lambda d: _ev_section(d, "VERSION", 300),
        remediation="Apply the latest Cumulative Update (CU) / GDR for the installed release.",
        manual=True)

    add("MSSQL-SINGLEFUNC", "1.2",
        "Ensure Single-Function Member Servers are used",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=_manual_evidence(
            "Manual check: confirm the host runs only SQL Server (no other server roles)."),
        remediation="Dedicate the server to SQL Server; move other roles to separate hosts.",
        manual=True)

    # ---- Section 2 — Surface Area Reduction ----
    add_config_zero("MSSQL-AHDQ", "2.1", "Ensure 'Ad Hoc Distributed Queries' is set to 0",
                    "Ad Hoc Distributed Queries")
    add_config_zero("MSSQL-CLR", "2.2", "Ensure 'CLR Enabled' is set to 0", "clr enabled")
    add_config_zero("MSSQL-XDBOC", "2.3", "Ensure 'Cross DB Ownership Chaining' is set to 0",
                    "cross db ownership chaining", advanced=False)
    add_config_zero("MSSQL-DBMAIL", "2.4", "Ensure 'Database Mail XPs' is set to 0",
                    "Database Mail XPs", severity="low")
    add_config_zero("MSSQL-OLEAUTO", "2.5", "Ensure 'Ole Automation Procedures' is set to 0",
                    "Ole Automation Procedures", severity="high")
    add_config_zero("MSSQL-REMACC", "2.6", "Ensure 'Remote Access' is set to 0",
                    "remote access", advanced=False)
    add_config_zero("MSSQL-REMADMIN", "2.7", "Ensure 'Remote Admin Connections' is set to 0",
                    "remote admin connections", level="L2", advanced=False)
    add("MSSQL-STARTPROC", "2.8", "Ensure 'Scan For Startup Procs' is set to 0",
        "medium", "L1",
        check_fn=lambda d: _config_is_zero(d, "scan for startup procs"),
        evidence_fn=lambda d: _ev_config_row(d, "scan for startup procs"),
        remediation="EXECUTE sp_configure 'scan for startup procs', 0;\nRECONFIGURE WITH OVERRIDE;")

    add("MSSQL-TRUSTWORTHY", "2.9",
        "Ensure 'Trustworthy' Database Property is set to Off",
        "high", "L1",
        check_fn=_no_trustworthy,
        evidence_fn=lambda d: _ev_section(d, "DATABASES", 500),
        remediation="For each non-msdb database with TRUSTWORTHY ON:\nALTER DATABASE [<db>] SET TRUSTWORTHY OFF;")

    add("MSSQL-PROTOCOLS", "2.10",
        "Ensure Unnecessary SQL Server Protocols are set to Disabled",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=_manual_evidence(
            "Manual check: SQL Server Configuration Manager -> Network Configuration -> Protocols."),
        remediation="Disable unused protocols (Named Pipes, Shared Memory) in Configuration Manager; restart the service.",
        manual=True)

    add("MSSQL-PORT", "2.11",
        "Ensure SQL Server is configured to use a non-standard port",
        "low", "L2",
        check_fn=_port_ok,
        evidence_fn=lambda d: _ev_section(d, "TCP_PORT"),
        remediation="Set a non-1433 TCP port in Configuration Manager (TCP/IP -> IP All); restart the service.")

    add("MSSQL-HIDEINST", "2.12", "Ensure 'Hide Instance' is set to 'Yes'",
        "medium", "L2",
        check_fn=_hide_instance,
        evidence_fn=lambda d: _ev_section(d, "HIDE_INSTANCE"),
        remediation=(
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            r"    N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',"
            "\n    N'HideInstance', REG_DWORD, 1;\nRestart the SQL Server service."))

    add("MSSQL-SADISABLE", "2.13", "Ensure the 'sa' Login Account is set to 'Disabled'",
        "high", "L1",
        check_fn=_sa_disabled,
        evidence_fn=lambda d: _ev_section(d, "SA_LOGIN"),
        remediation="ALTER LOGIN [sa] DISABLE;")

    add("MSSQL-SARENAME", "2.14", "Ensure the 'sa' Login Account has been renamed",
        "medium", "L2",
        check_fn=_sa_renamed,
        evidence_fn=lambda d: _ev_section(d, "SA_SID"),
        remediation="ALTER LOGIN [sa] WITH NAME = [<new_name>];")

    add("MSSQL-AUTOCLOSE", "2.15",
        "Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases",
        "medium", "L1",
        check_fn=_auto_close_off,
        evidence_fn=lambda d: _ev_section(d, "CONTAINED_DBS"),
        remediation="ALTER DATABASE [<contained_db>] SET AUTO_CLOSE OFF;")

    add("MSSQL-NOSA", "2.16", "Ensure no login exists with the name 'sa'",
        "medium", "L2",
        check_fn=lambda d: _section_clean(d, "SA_NAME_CHECK"),
        evidence_fn=lambda d: _ev_section(d, "SA_NAME_CHECK"),
        remediation="ALTER LOGIN [sa] WITH NAME = [<new_name>]; (never DROP automatically)")

    add("MSSQL-CLRSTRICT", "2.17", "Ensure 'CLR strict security' is set to 1",
        "high", "L1",
        check_fn=_clr_strict_on,
        evidence_fn=lambda d: _ev_config_row(d, "clr strict security"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;\n"
            "EXECUTE sp_configure 'clr strict security', 1;\nRECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"))

    # ---- Section 3 — Authentication and Authorization ----
    add("MSSQL-AUTHMODE", "3.1",
        "Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode'",
        "high", "L1",
        check_fn=_windows_auth_only,
        evidence_fn=lambda d: _ev_section(d, "AUTH_MODE"),
        remediation="SSMS -> Server Properties -> Security -> Windows Authentication mode; restart the service.")

    add("MSSQL-GUEST", "3.2",
        "Ensure CONNECT permissions on the 'guest' user are Revoked within all databases",
        "high", "L1",
        check_fn=_guest_revoked,
        evidence_fn=lambda d: _ev_section(d, "GUEST_CONNECT"),
        remediation="USE [<db>];\nREVOKE CONNECT FROM guest;")

    add("MSSQL-ORPHAN", "3.3", "Ensure 'Orphaned Users' are Dropped from SQL Server Databases",
        "medium", "L1",
        check_fn=lambda d: _section_clean(d, "ORPHANED_USERS"),
        evidence_fn=lambda d: _ev_section(d, "ORPHANED_USERS"),
        remediation="USE [<db>];\nDROP USER [<orphan>]; (review each user before dropping)")

    add("MSSQL-CONTAINEDAUTH", "3.4",
        "Ensure SQL Authentication is not used in contained databases",
        "medium", "L2",
        check_fn=lambda d: _section_clean(d, "CONTAINED_DB_USERS"),
        evidence_fn=lambda d: _ev_section(d, "CONTAINED_DB_USERS"),
        remediation="Migrate contained SQL users to Windows authentication (FROM EXTERNAL PROVIDER).")

    for slug, section, role in [
        ("MSSQL-SVCACCT-MSSQL", "3.5", "MSSQL Service Account"),
        ("MSSQL-SVCACCT-AGENT", "3.6", "SQLAgent Service Account"),
        ("MSSQL-SVCACCT-FT", "3.7", "Full-Text Service Account"),
    ]:
        add(slug, section, f"Ensure the {role} is not an Administrator",
            "info", "L1",
            check_fn=lambda d: False,
            evidence_fn=_manual_evidence(
                f"Manual check: confirm the {role} is not a local/domain Administrator."),
            remediation=f"Run the {role} under a least-privilege dedicated account.",
            manual=True)

    add("MSSQL-PUBLICSERVER", "3.8",
        "Ensure only the default permissions specified are granted to the public server role",
        "medium", "L1",
        check_fn=lambda d: _section_clean(d, "PUBLIC_SERVER_PERMS"),
        evidence_fn=lambda d: _ev_section(d, "PUBLIC_SERVER_PERMS"),
        remediation="REVOKE <permission> FROM public; for each non-default grant.")

    add("MSSQL-BUILTIN", "3.9",
        "Ensure Windows BUILTIN groups are not SQL Logins",
        "high", "L1",
        check_fn=_no_builtin_logins,
        evidence_fn=lambda d: _ev_section(d, "BUILTIN_LOGINS"),
        remediation="DROP LOGIN [BUILTIN\\<group>]; (grant explicit least-privilege logins instead)")

    add("MSSQL-LOCALGROUP", "3.10",
        "Ensure Windows local groups are not SQL Logins",
        "medium", "L1",
        check_fn=_no_local_group_logins,
        evidence_fn=lambda d: _ev_section(d, "BUILTIN_LOGINS"),
        remediation="DROP LOGIN [<machine>\\<local_group>]; use domain groups or individual logins.")

    add("MSSQL-PROXY", "3.11",
        "Ensure the public role in the msdb database is not granted access to SQL Agent proxies",
        "high", "L1",
        check_fn=lambda d: _section_clean(d, "AGENT_PROXIES"),
        evidence_fn=lambda d: _ev_section(d, "AGENT_PROXIES"),
        remediation="USE msdb;\nEXEC dbo.sp_revoke_login_from_proxy @name=N'public', @proxy_name=N'<proxy>';")

    add("MSSQL-SYSADMIN", "3.12",
        "Ensure the SYSADMIN role is limited to administrative/built-in accounts",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=lambda d: _ev_section(d, "SYSADMIN_MEMBERS"),
        remediation="Remove non-administrative logins: ALTER SERVER ROLE [sysadmin] DROP MEMBER [<login>];",
        manual=True)

    add("MSSQL-MSDBADMIN", "3.13",
        "Ensure membership in admin roles in the msdb database is limited",
        "medium", "L1",
        check_fn=lambda d: _section_clean(d, "MSDB_ADMIN_ROLES"),
        evidence_fn=lambda d: _ev_section(d, "MSDB_ADMIN_ROLES"),
        remediation="Remove unnecessary members from db_owner and the SSIS/policy admin roles in msdb.")

    # ---- Section 4 — Password Policies ----
    add("MSSQL-MUSTCHANGE", "4.1",
        "Ensure 'MUST_CHANGE' Option is set to 'ON' for All SQL Authenticated Logins",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=_manual_evidence(
            "Manual check: MUST_CHANGE is only observable at password-reset time."),
        remediation="Reset SQL login passwords WITH MUST_CHANGE.",
        manual=True)

    add("MSSQL-CHECKEXP", "4.2",
        "Ensure 'CHECK_EXPIRATION' Option is set to 'ON' for All SQL Authenticated Logins Within the Sysadmin Role",
        "medium", "L1",
        check_fn=lambda d: _section_clean(d, "SYSADMIN_SQL_LOGINS"),
        evidence_fn=lambda d: _ev_section(d, "SYSADMIN_SQL_LOGINS"),
        remediation="ALTER LOGIN [<login>] WITH CHECK_EXPIRATION = ON;")

    add("MSSQL-CHECKPOL", "4.3",
        "Ensure 'CHECK_POLICY' Option is set to 'ON' for All SQL Authenticated Logins",
        "high", "L1",
        check_fn=_check_policy_ok,
        evidence_fn=lambda d: _ev_section(d, "SQL_LOGINS"),
        remediation="ALTER LOGIN [<login>] WITH CHECK_POLICY = ON;")

    # ---- Section 5 — Auditing and Logging ----
    add("MSSQL-ERRLOG", "5.1",
        "Ensure 'Maximum number of error log files' is set to greater than or equal to '12'",
        "low", "L1",
        check_fn=_errlog_ok,
        evidence_fn=lambda d: _ev_section(d, "ERRORLOG_COUNT"),
        remediation=(
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            r"    N'Software\Microsoft\MSSQLServer\MSSQLServer',"
            "\n    N'NumErrorLogs', REG_DWORD, 12;"))

    add("MSSQL-DEFTRACE", "5.2", "Ensure 'Default Trace Enabled' is set to 1",
        "medium", "L1",
        check_fn=lambda d: _config_is_one(d, "default trace enabled"),
        evidence_fn=lambda d: _ev_config_row(d, "default trace enabled"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;\n"
            "EXECUTE sp_configure 'default trace enabled', 1;\nRECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"))

    add("MSSQL-LOGINAUDIT", "5.3",
        "Ensure 'Login Auditing' is set to capture failed logins (at minimum)",
        "medium", "L1",
        check_fn=_login_audit_ok,
        evidence_fn=lambda d: _ev_section(d, "LOGIN_AUDIT_LEVEL"),
        remediation=(
            "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',\n"
            r"    N'Software\Microsoft\MSSQLServer\MSSQLServer',"
            "\n    N'AuditLevel', REG_DWORD, 2;\nRestart the SQL Server service."))

    add("MSSQL-SRVAUDIT", "5.4",
        "Ensure 'SQL Server Audit' captures both 'failed' and 'successful logins'",
        "medium", "L2",
        check_fn=_server_audit_ok,
        evidence_fn=lambda d: _ev_section(d, "AUDIT_SPECIFICATIONS", 600),
        remediation="Create a Server Audit + specification adding FAILED_LOGIN_GROUP and SUCCESSFUL_LOGIN_GROUP.")

    # ---- Section 6 — Application Development ----
    add("MSSQL-SANITIZE", "6.1", "Ensure Database and Application User Input is Sanitized",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=_manual_evidence(
            "Manual check: verify application input validation / parameterized queries."),
        remediation="Use parameterized queries and validate all user input at the application tier.",
        manual=True)

    add("MSSQL-CLRSAFE", "6.2",
        "Ensure 'CLR Assembly Permission Set' is set to 'SAFE_ACCESS' for All CLR Assemblies",
        "high", "L1",
        check_fn=_clr_assemblies_safe,
        evidence_fn=lambda d: _ev_section(d, "CLR_ASSEMBLIES"),
        remediation="ALTER ASSEMBLY [<name>] WITH PERMISSION_SET = SAFE;")

    # ---- Section 7 — Encryption ----
    add("MSSQL-SYMKEY", "7.1",
        "Ensure 'Symmetric Key encryption algorithm' is set to 'AES_128' or higher in non-system databases",
        "medium", "L2",
        check_fn=_symmetric_keys_strong,
        evidence_fn=lambda d: _ev_section(d, "SYMMETRIC_KEYS"),
        remediation="Re-create symmetric keys WITH ALGORITHM = AES_256 (or AES_128/AES_192).")

    add("MSSQL-ASYMKEY", "7.2",
        "Ensure Asymmetric Key Size is set to 'greater than or equal to 2048' in non-system databases",
        "medium", "L2",
        check_fn=_asymmetric_keys_strong,
        evidence_fn=lambda d: _ev_section(d, "ASYMMETRIC_KEYS"),
        remediation="Re-create asymmetric keys WITH ALGORITHM = RSA_2048 (or larger).")

    add("MSSQL-BACKUPENC", "7.3", "Ensure Database Backups are Encrypted",
        "medium", "L2",
        check_fn=lambda d: _section_clean(d, "BACKUP_ENCRYPTION"),
        evidence_fn=lambda d: _ev_section(d, "BACKUP_ENCRYPTION"),
        remediation="Take backups WITH ENCRYPTION (ALGORITHM = AES_256, SERVER CERTIFICATE = <cert>).")

    add("MSSQL-NETENC", "7.4", "Ensure Network Encryption is configured and enabled",
        "medium", "L2",
        check_fn=_network_encryption_on,
        evidence_fn=lambda d: _ev_section(d, "NETWORK_ENCRYPTION"),
        remediation="Enable Force Encryption + a valid certificate in Configuration Manager; restart the service.")

    add("MSSQL-TDE", "7.5", "Ensure Databases are Encrypted with TDE",
        "medium", "L2",
        check_fn=_tde_ok,
        evidence_fn=lambda d: _ev_section(d, "TDE_DATABASES"),
        remediation="Create a DEK and ALTER DATABASE [<db>] SET ENCRYPTION ON; for each user database.")

    # ---- Section 8 — Additional Considerations ----
    add("MSSQL-BROWSER", "8.1", "Ensure 'SQL Server Browser Service' is configured correctly",
        "info", "L1",
        check_fn=lambda d: False,
        evidence_fn=_manual_evidence(
            "Manual check: confirm the SQL Server Browser service state matches the deployment."),
        remediation="Disable the SQL Server Browser service unless multiple/named instances require it.",
        manual=True)

    return rules


# ============================================================ #
#  Derived builders — 2019 and 2016                           #
# ============================================================ #

def build_mssql_2019_cis_rules() -> List[MSSQLCISRule]:
    """SQL Server 2019 (CIS v1.4) — identical control set to 2022."""
    return build_mssql_2022_cis_rules()


# Controls that do not ship in SQL Server 2016.
_MSSQL_2016_DROP = {"MSSQL-CLRSTRICT", "MSSQL-SYSADMIN", "MSSQL-MSDBADMIN"}

# 2016 re-numbers the tail of Section 2 (xp_cmdshell takes 2.15, pushing
# AUTO_CLOSE to 2.16 and 'no sa login' to 2.17).
_MSSQL_2016_SECTION = {"MSSQL-AUTOCLOSE": "2.16", "MSSQL-NOSA": "2.17"}


def build_mssql_2016_cis_rules() -> List[MSSQLCISRule]:
    """
    SQL Server 2016 (CIS v1.4). Extends the 2022 base: drops controls 2016 does
    not ship, re-badges the Section-2 numbering that shifted, and adds the
    2016-only 'xp_cmdshell = 0' control at 2.15.
    """
    kept: List[MSSQLCISRule] = []
    for r in build_mssql_2022_cis_rules():
        if r.id in _MSSQL_2016_DROP:
            continue
        if r.id in _MSSQL_2016_SECTION:
            r = replace(r, section=_MSSQL_2016_SECTION[r.id])
        kept.append(r)

    kept.append(MSSQLCISRule(
        id="MSSQL-XPCMDSHELL",
        section="2.15",
        title="Ensure 'xp_cmdshell' is set to 0",
        description="xp_cmdshell allows OS command execution from T-SQL and must be disabled.",
        severity="high",
        level="L1",
        check_fn=_xp_cmdshell_off,
        evidence_fn=lambda d: _ev_config_row(d, "xp_cmdshell"),
        remediation=(
            "EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;\n"
            "EXECUTE sp_configure 'xp_cmdshell', 0;\nRECONFIGURE;\n"
            "EXECUTE sp_configure 'show advanced options', 0; RECONFIGURE;"),
    ))
    return kept


# ============================================================ #
#  Dispatch                                                    #
# ============================================================ #

_VERSION_BUILDERS = {
    "mssql_2016": build_mssql_2016_cis_rules,
    "mssql_2019": build_mssql_2019_cis_rules,
    "mssql_2022": build_mssql_2022_cis_rules,
}


def build_mssql_cis_rules_for_distro(distro: str) -> List[MSSQLCISRule]:
    """Return the rule set for a resolved distro gate key (defaults to 2022)."""
    return _VERSION_BUILDERS.get(distro, build_mssql_2022_cis_rules)()


def build_all_mssql_cis_rules() -> List[MSSQLCISRule]:
    """Backward-compatible entry point — the newest (superset) rule set."""
    return build_mssql_2022_cis_rules()


# ============================================================ #
#  Profile filtering                                          #
# ============================================================ #

def filter_rules_by_profile(rules: List[MSSQLCISRule], profile: str) -> List[MSSQLCISRule]:
    """L1 returns only L1 rules (manual controls are L1); FULL returns all."""
    if profile == "L1":
        return [r for r in rules if r.level == "L1"]
    return rules


# ============================================================ #
#  Compliance evaluation                                      #
# ============================================================ #

def evaluate_compliance(dump: str, rules: List[MSSQLCISRule]) -> Dict[str, Any]:
    """
    Evaluate all rules against the collected audit dump.

    Manual controls are reported (status "skipped", surfaced NOT_APPLICABLE by
    the service) but never scored. Returns a summary + per-finding list.
    """
    SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "info": 0}

    findings = []
    passed_scored = 0
    failed_scored = 0
    manual_checks = 0
    total_weight = 0
    passed_weight = 0

    for rule in rules:
        if rule.manual:
            manual_checks += 1
            try:
                evidence = rule.evidence_fn(dump)
            except Exception:
                evidence = "(evidence extraction failed)"
            findings.append({
                "id": rule.id,
                "title": rule.title,
                "description": rule.description,
                "section": rule.section,
                "severity": rule.severity,
                "level": rule.level,
                "compliant": False,
                "manual": True,
                "status": "skipped",
                "evidence": (
                    f"SKIPPED — manual verification required. {rule.remediation}\n\n"
                    f"Collected evidence:\n{evidence}"
                )[:1000],
                "remediation": rule.remediation,
            })
            continue

        try:
            compliant = rule.check_fn(dump)
        except Exception:
            compliant = False
        try:
            evidence = rule.evidence_fn(dump)
        except Exception:
            evidence = "(evidence extraction failed)"

        weight = SEVERITY_WEIGHTS.get(rule.severity, 1)
        if rule.level != "INFO":
            total_weight += weight
            if compliant:
                passed_scored += 1
                passed_weight += weight
            else:
                failed_scored += 1

        findings.append({
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "section": rule.section,
            "severity": rule.severity,
            "level": rule.level,
            "compliant": compliant,
            "manual": False,
            "status": "pass" if compliant else "fail",
            "evidence": evidence,
            "remediation": rule.remediation,
        })

    total_scored = passed_scored + failed_scored
    compliance_pct = round(100.0 * passed_scored / total_scored, 2) if total_scored else 0.0
    weighted_pct = round(100.0 * passed_weight / total_weight, 2) if total_weight else 0.0

    return {
        "summary": {
            "total_rules_scored": total_scored,
            "manual_checks": manual_checks,
            "passed_scored": passed_scored,
            "failed_scored": failed_scored,
            "compliance_pct": compliance_pct,
            "weighted_compliance_pct": weighted_pct,
        },
        "findings": findings,
    }
