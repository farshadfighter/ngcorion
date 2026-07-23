"""
MongoDB CIS Benchmark Rules

All 27 controls of the CIS MongoDB Benchmark v1.0.0, evaluated against the
structured audit dump collected by MongoDBSSHClient.

Rule IDs follow the pattern: MONGO-L{level}-{seq:03d}
  L1 = Level 1 (basic, broadly applicable)
  L2 = Level 2 (advanced, may affect functionality)
The `section` field carries the CIS control number (e.g. "2.1").

CIS sections covered:
  1.x  Installation and Patching
  2.x  Authentication
  3.x  Access Control
  4.x  Data Encryption
  5.x  Auditing
  6.x  Operating System Hardening
  7.x  File Permissions
"""

import re
from dataclasses import dataclass
from typing import Callable, List, Dict, Any


# Oldest MongoDB release branch still supported upstream (CIS 1.1).
OLDEST_SUPPORTED = (6, 0)

# Roles that grant broad or administrative privilege (CIS 3.1 / 3.6).
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


# ============================================================ #
#  Rule dataclass                                               #
# ============================================================ #

@dataclass
class MongoDBCISRule:
    """A single CIS MongoDB compliance check."""
    id: str                          # e.g. "MONGO-L1-001"
    section: str                     # CIS control number e.g. "2.1"
    title: str
    description: str
    severity: str                    # high / medium / low / info
    level: str                       # L1 / L2
    check_fn: Callable[[str], bool]  # True = compliant
    evidence_fn: Callable[[str], str]
    remediation: str


# ============================================================ #
#  Helper – extract a named section from the dump              #
# ============================================================ #

def _section(dump: str, name: str) -> str:
    """Extract the content of a named section from the audit dump.

    The lookahead uses ``\n===SECTION:`` (newline + three equals) so that the
    lazy ``.*?`` stops *before* the newline that precedes the next marker,
    rather than consuming the first ``=`` of the next marker.
    """
    pattern = re.compile(
        rf"===SECTION:{re.escape(name)}===\n(.*?)(?=\n===SECTION:|\Z)",
        re.S,
    )
    m = pattern.search(dump)
    return m.group(1).strip() if m else ""


def _query_ok(section_text: str) -> bool:
    """True when a mongosh-backed section holds a usable result.

    Inability to query the database is never evidence of compliance —
    checks that read these sections must fail closed.
    """
    return (
        bool(section_text)
        and "MONGOSH_UNAVAILABLE" not in section_text
        and "QUERY_FAILED" not in section_text
    )


# ============================================================ #
#  Pre-compiled patterns for efficiency                         #
# ============================================================ #

class _RE:
    # Config file – authentication
    auth_enabled   = re.compile(r"authorization\s*:\s*enabled", re.I)
    localhost_off  = re.compile(r"enableLocalhostAuthBypass\s*:\s*false", re.I)

    # Config file – auth mechanisms / cluster auth
    keyfile        = re.compile(r"keyFile\s*:\s*\S+", re.I)
    cluster_x509   = re.compile(r"clusterAuthMode\s*:\s*(x509|sendX509)", re.I)
    strong_mech    = re.compile(r"SCRAM-SHA-256|GSSAPI", re.I)

    # Config file – network binding
    # bindIpAll: true is equivalent to binding 0.0.0.0 and must also fail
    bind_all       = re.compile(r"bindIp\s*:\s*\S*0\.0\.0\.0|bindIpAll\s*:\s*true", re.I)
    bind_specific  = re.compile(r"bindIp\s*:\s*\S+", re.I)
    wildcard_listen = re.compile(r"(^|\s)(0\.0\.0\.0|\*|\[?::\]?):\d+", re.M)

    # Config file – port
    default_port   = re.compile(r"port\s*:\s*27017\b", re.I)
    any_port       = re.compile(r"port\s*:\s*(\d+)", re.I)

    # Config file – TLS
    tls_require    = re.compile(r"mode\s*:\s*(requireTLS|requireSSL)", re.I)
    tls_cert       = re.compile(r"(certificateKeyFile|PEMKeyFile)\s*:\s*\S+", re.I)
    fips_mode      = re.compile(r"FIPSMode\s*:\s*true", re.I)

    # Config file – encryption at rest
    enc_at_rest    = re.compile(r"enableEncryption\s*:\s*true", re.I)

    # Config file – audit log
    audit_dest     = re.compile(r"destination\s*:\s*(file|syslog|console)", re.I)
    audit_section  = re.compile(r"^\s*auditLog\s*:", re.I | re.M)
    audit_filter   = re.compile(r"filter\s*:\s*\S", re.I)

    # Config file – system log
    log_quiet      = re.compile(r"quiet\s*:\s*true", re.I)
    log_append     = re.compile(r"logAppend\s*:\s*true", re.I)

    # Config file – legacy HTTP interface
    jsonp_on       = re.compile(r"JSONPEnabled\s*:\s*true", re.I)
    rest_on        = re.compile(r"RESTInterfaceEnabled\s*:\s*true", re.I)

    # Config file – server-side JavaScript
    js_disabled    = re.compile(r"javascriptEnabled\s*:\s*false", re.I)

    # Process user
    root_user      = re.compile(r"^\s*root\s*$", re.I | re.M)
    dedicated_user = re.compile(r"mongod|mongodb", re.I)

    # Mongosh output – roles
    role_name      = re.compile(r'"role"\s*:\s*"([^"]+)"')
    broad_priv     = re.compile(r'"anyResource"\s*:\s*true|"cluster"\s*:\s*true', re.I)

    # Auth mechanisms output
    sha256         = re.compile(r"SCRAM-SHA-256", re.I)

    # Version strings
    version        = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


# ============================================================ #
#  Evidence extractors                                         #
# ============================================================ #

def _ev_config(dump: str, pattern: re.Pattern, section: str = "CONFIG_FILE") -> str:
    text = _section(dump, section)
    m = pattern.search(text)
    if m:
        start = max(0, m.start() - 60)
        return f"...{text[start:m.end() + 60]}..."
    return "(no matching line found)"


def _ev_section_content(dump: str, section: str, max_chars: int = 400) -> str:
    content = _section(dump, section)
    return content[:max_chars] + ("..." if len(content) > max_chars else "")


# ============================================================ #
#  Check helpers                                                #
# ============================================================ #

def _version_supported(dump: str) -> bool:
    """CIS 1.1 — running version belongs to a supported release branch."""
    text = _section(dump, "BUILD_INFO")
    if not _query_ok(text):
        text = _section(dump, "MONGOD_VERSION")
    if not text or "VERSION_NOT_FOUND" in text:
        return False
    m = _RE.version.search(text)
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2))) >= OLDEST_SUPPORTED


def _http_block(conf: str) -> str:
    """Extract the indented body of a net.http: block, if any."""
    m = re.search(r"^\s*http\s*:\s*\n((?:[ \t]+\S.*\n?)*)", conf, re.M)
    return m.group(1) if m else ""


def _http_interface_disabled(dump: str) -> bool:
    """CIS 6.1 / 6.5 — net.http.enabled must not be true (absent = disabled)."""
    block = _http_block(_section(dump, "CONFIG_FILE"))
    return not re.search(r"enabled\s*:\s*true", block, re.I)


def _has_limited_user(dump: str) -> bool:
    """CIS 3.1 — at least one user holds a role outside the superuser set."""
    users = _section(dump, "USERS_LIST")
    if not _query_ok(users):
        return False
    roles = _RE.role_name.findall(users)
    return any(r not in SUPERUSER_ROLES for r in roles)


def _no_superuser_roles(dump: str) -> bool:
    """CIS 3.6 — no account holds a broad administrative role."""
    users = _section(dump, "USERS_LIST")
    if not _query_ok(users):
        return False
    roles = _RE.role_name.findall(users)
    return not any(r in SUPERUSER_ROLES for r in roles)


def _superuser_holders_evidence(dump: str) -> str:
    users = _section(dump, "USERS_LIST")
    if not _query_ok(users):
        return _ev_section_content(dump, "USERS_LIST", 300)
    held = sorted({r for r in _RE.role_name.findall(users) if r in SUPERUSER_ROLES})
    return f"Superuser roles in use: {held or 'none'}"


def _keyfile_ok(dump: str) -> bool:
    """CIS 2.3 — keyFile configured AND present on disk, or x.509 cluster auth."""
    conf = _section(dump, "CONFIG_FILE")
    if _RE.cluster_x509.search(conf):
        return True
    info = _section(dump, "KEYFILE_INFO")
    return bool(
        _RE.keyfile.search(conf)
        and info
        and "KEYFILE_NOT_CONFIGURED" not in info
        and "KEYFILE_MISSING_ON_DISK" not in info
    )


def _keyfile_perms_ok(dump: str) -> bool:
    """CIS 7.1 — keyFile mode 600/400 owned by the mongod account.

    When no keyFile is configured there is nothing to protect (2.3 flags
    missing cluster auth separately), so the control passes.
    """
    info = _section(dump, "KEYFILE_INFO")
    if not info or "KEYFILE_NOT_CONFIGURED" in info:
        return True
    if "KEYFILE_MISSING_ON_DISK" in info:
        return False
    m = re.match(r"(\d+)\s+(\S+)\s+(\S+)", info)
    if not m:
        return False
    mode, owner = m.group(1), m.group(2).lower()
    return mode in ("400", "600") and owner in ("mongod", "mongodb")


def _dbpath_perms_ok(dump: str) -> bool:
    """CIS 7.2 — dbPath owned by the mongod account with no 'other' access."""
    info = _section(dump, "DBPATH_PERMS")
    if not info or "DBPATH_NOT_FOUND" in info:
        return False
    m = re.match(r"(\d+)\s+(\S+)\s+(\S+)", info)
    if not m:
        return False
    mode, owner = m.group(1), m.group(2).lower()
    return mode[-1] == "0" and owner in ("mongod", "mongodb")


def _limit_at_least(text: str, label: str, minimum: int) -> bool:
    for line in text.splitlines():
        if line.startswith(label):
            # columns: <name...> <soft> <hard> <units>
            tail = line[len(label):].split()
            if tail:
                value = tail[0]
                if value.lower() == "unlimited":
                    return True
                if value.isdigit():
                    return int(value) >= minimum
    return False


def _resource_limits_ok(dump: str) -> bool:
    """CIS 6.3 — open files and processes >= 64000 for the mongod process."""
    limits = _section(dump, "PROC_LIMITS")
    if not limits or "NO_MONGOD_PROCESS" in limits:
        return False
    return (
        _limit_at_least(limits, "Max open files", 64000)
        and _limit_at_least(limits, "Max processes", 64000)
    )


def _bind_restricted(dump: str) -> bool:
    """CIS 3.2 — explicit bindIp, no 0.0.0.0/bindIpAll, no wildcard listener."""
    conf = _section(dump, "CONFIG_FILE")
    if _RE.bind_all.search(conf) or not _RE.bind_specific.search(conf):
        return False
    listening = _section(dump, "LISTENING_PORTS")
    if listening and "PORT_CHECK_FAILED" not in listening:
        if _RE.wildcard_listen.search(listening):
            return False
    return True


def _non_default_port(dump: str) -> bool:
    """CIS 6.2 — explicit port that is not 27017 (missing = default 27017)."""
    conf = _section(dump, "CONFIG_FILE")
    return bool(
        conf
        and "CONFIG_FILE_NOT_FOUND" not in conf
        and not _RE.default_port.search(conf)
        and _RE.any_port.search(conf)
    )


# ============================================================ #
#  Rule builder                                                 #
# ============================================================ #

def build_all_mongodb_cis_rules() -> List[MongoDBCISRule]:
    """Return all 27 CIS MongoDB Benchmark v1.0.0 controls."""

    rules: List[MongoDBCISRule] = []

    # ---------------------------------------------------------------- #
    #  Section 1 – Installation and Patching                            #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-001",
        section="1.1",
        title="Ensure the appropriate MongoDB software version/patches are installed",
        description=(
            "MongoDB should run a release branch that still receives security "
            "patches from the vendor (6.0 or newer)."
        ),
        severity="medium",
        level="L1",
        check_fn=_version_supported,
        evidence_fn=lambda d: (
            _ev_section_content(d, "BUILD_INFO", 200)
            or _ev_section_content(d, "MONGOD_VERSION", 200)
        ),
        remediation=(
            "Upgrade to a supported MongoDB release branch (6.0/7.0/8.0) "
            "following the official upgrade path for your current version."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 2 – Authentication                                       #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-002",
        section="2.1",
        title="Ensure authentication is configured",
        description=(
            "Without authentication enabled any user with network access can "
            "read, modify, or delete all data."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.auth_enabled.search(_section(d, "CONFIG_FILE"))
            or _RE.auth_enabled.search(_section(d, "CMDLINE_OPTS"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.auth_enabled),
        remediation=(
            "Add the following to /etc/mongod.conf and restart:\n"
            "security:\n"
            "  authorization: enabled"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-003",
        section="2.2",
        title="Ensure that MongoDB does not bypass authentication via the localhost exception",
        description=(
            "The localhost exception allows unauthenticated access from the "
            "local host until the first user is created. It defaults to on, "
            "so it must be explicitly disabled."
        ),
        severity="medium",
        level="L1",
        # Default is true when unset, so an absent setting is non-compliant.
        check_fn=lambda d: bool(
            _RE.localhost_off.search(_section(d, "CONFIG_FILE"))
            or _RE.localhost_off.search(_section(d, "CMDLINE_OPTS"))
        ),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"enableLocalhostAuthBypass\s*:\s*\S+", re.I)),
        remediation=(
            "In /etc/mongod.conf:\n"
            "setParameter:\n"
            "  enableLocalhostAuthBypass: false"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-004",
        section="2.3",
        title="Ensure authentication is enabled in the sharded cluster",
        description=(
            "Replica set and sharded cluster members must authenticate each "
            "other with a keyFile or x.509 certificates so rogue nodes cannot "
            "join the cluster. The configured keyFile must exist on disk."
        ),
        severity="high",
        level="L1",
        check_fn=_keyfile_ok,
        evidence_fn=lambda d: (
            f"Config: {_ev_config(d, _RE.keyfile)}\n"
            f"KeyFile on disk: {_ev_section_content(d, 'KEYFILE_INFO', 200)}"
        ),
        remediation=(
            "Generate a key (openssl rand -base64 756 > /etc/mongodb/keyfile), "
            "set mode 600 and owner mongod, then in /etc/mongod.conf:\n"
            "security:\n"
            "  keyFile: /etc/mongodb/keyfile\n"
            "Or use x.509: clusterAuthMode: x509"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-005",
        section="2.4",
        title="Ensure an industry standard authentication mechanism is used",
        description=(
            "Authentication should use SCRAM-SHA-256, GSSAPI (Kerberos) or "
            "x.509 rather than legacy mechanisms such as SCRAM-SHA-1 or "
            "MONGODB-CR."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: bool(
            _RE.cluster_x509.search(_section(d, "CONFIG_FILE"))
            or _RE.strong_mech.search(_section(d, "CONFIG_FILE"))
            or _RE.sha256.search(_section(d, "AUTH_MECHANISMS"))
        ),
        evidence_fn=lambda d: (
            _ev_section_content(d, "AUTH_MECHANISMS", 300)
            or _ev_config(d, _RE.strong_mech)
        ),
        remediation=(
            "In /etc/mongod.conf:\n"
            "setParameter:\n"
            "  authenticationMechanisms: SCRAM-SHA-256\n"
            "Existing passwords must be re-set after changing the mechanism."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 3 – Access Control                                       #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-006",
        section="3.1",
        title="Ensure that role-based access control is enabled and configured",
        description=(
            "Beyond enabling authorization, at least one application/operator "
            "account must exist with limited (non-superuser) roles, proving "
            "least-privilege RBAC is actually in use."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.auth_enabled.search(_section(d, "CONFIG_FILE"))
            and _has_limited_user(d)
        ),
        evidence_fn=lambda d: _ev_section_content(d, "USERS_LIST", 500),
        remediation=(
            "Enable security.authorization and create users with narrowly "
            "scoped roles via db.createUser() (e.g. readWrite on one database)."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-007",
        section="3.2",
        title="Ensure that MongoDB only listens for network connections on authorized interfaces",
        description=(
            "MongoDB must be bound to explicit, trusted interfaces. Binding "
            "to 0.0.0.0 (or bindIpAll) exposes the database on every network "
            "interface."
        ),
        severity="high",
        level="L1",
        check_fn=_bind_restricted,
        evidence_fn=lambda d: (
            f"Config: {_ev_config(d, _RE.bind_specific)}\n"
            f"Listeners: {_ev_section_content(d, 'LISTENING_PORTS', 200)}"
        ),
        remediation=(
            "In /etc/mongod.conf:\n"
            "net:\n"
            "  bindIp: 127.0.0.1,<trusted-ip>\n"
            "List only the interfaces MongoDB should listen on."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-008",
        section="3.3",
        title="Ensure that MongoDB is run using a non-privileged, dedicated service account",
        description=(
            "MongoDB should run under a dedicated, unprivileged account "
            "(mongod/mongodb). Running as root gives the process unrestricted "
            "OS access."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            not _RE.root_user.search(_section(d, "MONGOD_USER"))
            and _RE.dedicated_user.search(_section(d, "MONGOD_USER"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "MONGOD_USER"),
        remediation=(
            "Create a dedicated 'mongod' system user with no login shell, set "
            "User=mongod in the service unit, and restart the service."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-009",
        section="3.4",
        title="Ensure that each role for each MongoDB database is needed and grants only the necessary privileges",
        description=(
            "User-defined roles must not carry cluster-wide or anyResource "
            "privileges, which would bypass per-database least privilege."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: (
            _query_ok(_section(d, "ROLES_PRIVS"))
            and not _RE.broad_priv.search(_section(d, "ROLES_PRIVS"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "ROLES_PRIVS", 500),
        remediation=(
            "Review db.getRoles({showPrivileges: true}) and rebuild any "
            "user-defined role that grants cluster or anyResource privileges "
            "with database-scoped privileges instead."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-010",
        section="3.5",
        title="Review user-defined roles",
        description=(
            "User-defined roles must be enumerable so they can be reviewed "
            "periodically. This control verifies the role inventory can be "
            "collected for review."
        ),
        severity="low",
        level="L2",
        check_fn=lambda d: _query_ok(_section(d, "ROLES_LIST")),
        evidence_fn=lambda d: _ev_section_content(d, "ROLES_LIST", 500),
        remediation=(
            "Ensure administrative credentials are available so "
            "db.getRoles({showBuiltinRoles: false}) can be executed, then "
            "review each role against business need."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-011",
        section="3.6",
        title="Review superuser/admin roles",
        description=(
            "Roles such as root, userAdminAnyDatabase, readWriteAnyDatabase or "
            "clusterAdmin grant sweeping privileges and should not be assigned "
            "to day-to-day accounts."
        ),
        severity="medium",
        level="L2",
        check_fn=_no_superuser_roles,
        evidence_fn=_superuser_holders_evidence,
        remediation=(
            "Revoke broad roles (root, *AnyDatabase, clusterAdmin, dbOwner, "
            "userAdmin, hostManager) and assign database-scoped roles instead."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 4 – Data Encryption                                      #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-012",
        section="4.1",
        title="Ensure Encryption of Data in Transit — TLS/SSL is configured",
        description=(
            "All network communication must be TLS-protected: net.tls.mode "
            "requireTLS with a valid certificateKeyFile."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            (
                _RE.tls_require.search(_section(d, "CONFIG_FILE"))
                or _RE.tls_require.search(_section(d, "TLS_PARAMS"))
            )
            and _RE.tls_cert.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"tls\s*:|mode\s*:\s*\S+", re.I)),
        remediation=(
            "In /etc/mongod.conf:\n"
            "net:\n"
            "  tls:\n"
            "    mode: requireTLS\n"
            "    certificateKeyFile: /etc/ssl/mongod.pem\n"
            "    CAFile: /etc/ssl/ca.pem"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-013",
        section="4.2",
        title="Ensure Encryption of Data at Rest",
        description=(
            "Database files should be encrypted at rest, either via the "
            "WiredTiger encrypted storage engine (security.enableEncryption) "
            "or an encrypted volume (LUKS/dm-crypt)."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(
            _RE.enc_at_rest.search(_section(d, "CONFIG_FILE"))
            or (
                _section(d, "DISK_ENCRYPTION")
                and "NO_ENCRYPTED_VOLUME" not in _section(d, "DISK_ENCRYPTION")
            )
        ),
        evidence_fn=lambda d: (
            f"Config: {_ev_config(d, _RE.enc_at_rest)}\n"
            f"Volumes: {_ev_section_content(d, 'DISK_ENCRYPTION', 200)}"
        ),
        remediation=(
            "Enable the encrypted storage engine (MongoDB Enterprise: "
            "security.enableEncryption: true) or move dbPath onto a "
            "LUKS-encrypted volume. Both require a data migration."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-014",
        section="4.3",
        title="Ensure Federal Information Processing Standard (FIPS) is enabled",
        description=(
            "FIPS 140-2 mode constrains cryptography to validated modules. "
            "Requires net.tls.FIPSMode plus a FIPS-capable OpenSSL, confirmed "
            "by the activation message in the mongod log."
        ),
        severity="low",
        level="L2",
        check_fn=lambda d: bool(
            _RE.fips_mode.search(_section(d, "CONFIG_FILE"))
            and "NO_FIPS_ACTIVATION_LOG" not in _section(d, "FIPS_LOG")
            and _section(d, "FIPS_LOG")
        ),
        evidence_fn=lambda d: (
            f"Config: {_ev_config(d, _RE.fips_mode)}\n"
            f"Log: {_ev_section_content(d, 'FIPS_LOG', 200)}"
        ),
        remediation=(
            "On a FIPS-enabled OS with FIPS-capable OpenSSL set in "
            "/etc/mongod.conf:\n"
            "net:\n"
            "  tls:\n"
            "    FIPSMode: true\n"
            "then restart and confirm 'FIPS 140-2 mode activated' in the log."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 5 – Auditing                                             #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-015",
        section="5.1",
        title="Ensure that system activity is audited",
        description=(
            "Audit logging records authentication attempts, DDL and "
            "administrative actions for accountability and forensics "
            "(requires MongoDB Enterprise)."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: bool(
            _RE.audit_section.search(_section(d, "CONFIG_FILE"))
            and _RE.audit_dest.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.audit_section),
        remediation=(
            "Add an auditLog section to /etc/mongod.conf:\n"
            "auditLog:\n"
            "  destination: file\n"
            "  format: JSON\n"
            "  path: /var/log/mongodb/auditLog.json"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-016",
        section="5.2",
        title="Ensure that audit filters are configured properly",
        description=(
            "An auditLog.filter should scope the audit trail to the "
            "security-relevant events the organisation needs (authentication, "
            "user/role changes, schema changes)."
        ),
        severity="low",
        level="L2",
        check_fn=lambda d: bool(
            _RE.audit_section.search(_section(d, "CONFIG_FILE"))
            and _RE.audit_filter.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.audit_filter),
        remediation=(
            "In /etc/mongod.conf add a filter to the auditLog section, e.g.:\n"
            "auditLog:\n"
            "  filter: '{ atype: { $in: [ \"authenticate\", \"createUser\", "
            "\"dropUser\", \"createRole\", \"dropRole\" ] } }'"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-017",
        section="5.3",
        title="Ensure that logging captures as much information as possible",
        description=(
            "systemLog.quiet suppresses connection, command and replication "
            "events, blinding security monitoring. It must not be enabled."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: not _RE.log_quiet.search(_section(d, "CONFIG_FILE")),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"quiet\s*:\s*\S+", re.I)),
        remediation=(
            "In /etc/mongod.conf set:\n"
            "systemLog:\n"
            "  quiet: false\n"
            "(or remove the quiet setting entirely)."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-018",
        section="5.4",
        title="Ensure that new entries are appended to the end of the log file",
        description=(
            "When logAppend is false, MongoDB overwrites the log file on "
            "restart, destroying historical audit records."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: bool(_RE.log_append.search(_section(d, "CONFIG_FILE"))),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"logAppend\s*:\s*\S+", re.I)),
        remediation=(
            "In /etc/mongod.conf:\n"
            "systemLog:\n"
            "  logAppend: true"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 6 – Operating System Hardening                           #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-019",
        section="6.1",
        title="Ensure that the HTTP status interface is disabled",
        description=(
            "The legacy HTTP status interface exposes server details over an "
            "unauthenticated web page. It must not be enabled (absent on "
            "modern releases counts as disabled)."
        ),
        severity="medium",
        level="L1",
        check_fn=_http_interface_disabled,
        evidence_fn=lambda d: _ev_config(d, re.compile(r"http\s*:", re.I)),
        remediation=(
            "Remove net.http.enabled: true from /etc/mongod.conf (the option "
            "was removed entirely in MongoDB 3.6+)."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-020",
        section="6.2",
        title="Ensure that MongoDB uses a non-default port",
        description=(
            "Using the default port 27017 makes the service trivially "
            "discoverable by automated scanners."
        ),
        severity="low",
        level="L2",
        check_fn=_non_default_port,
        evidence_fn=lambda d: _ev_config(d, _RE.any_port),
        remediation=(
            "Change the port in /etc/mongod.conf:\n"
            "net:\n"
            "  port: <non-default-port>\n"
            "Update firewall rules and client connection strings accordingly."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-021",
        section="6.3",
        title="Ensure that operating system resource limits are set for MongoDB",
        description=(
            "The mongod process needs raised ulimits (open files and "
            "processes >= 64000) so it cannot be starved into a denial of "
            "service under load."
        ),
        severity="low",
        level="L1",
        check_fn=_resource_limits_ok,
        evidence_fn=lambda d: _ev_section_content(d, "PROC_LIMITS", 400),
        remediation=(
            "Create /etc/security/limits.d/99-mongodb.conf with:\n"
            "mongod soft nofile 64000\nmongod hard nofile 64000\n"
            "mongod soft nproc 64000\nmongod hard nproc 64000\n"
            "then restart mongod."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-022",
        section="6.4",
        title="Ensure that server-side scripting is disabled if not needed",
        description=(
            "Server-side JavaScript ($where, mapReduce) introduces additional "
            "attack surface. Disable it unless explicitly required."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(_RE.js_disabled.search(_section(d, "CONFIG_FILE"))),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"javascriptEnabled\s*:\s*\S+", re.I)),
        remediation=(
            "In /etc/mongod.conf:\n"
            "security:\n"
            "  javascriptEnabled: false"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-023",
        section="6.5",
        title="Ensure that the HTTP interface is disabled",
        description=(
            "The embedded HTTP interface (net.http.enabled) must be off; it "
            "serves unauthenticated diagnostics on port+1000."
        ),
        severity="medium",
        level="L1",
        check_fn=_http_interface_disabled,
        evidence_fn=lambda d: _ev_config(d, re.compile(r"http\s*:", re.I)),
        remediation=(
            "In /etc/mongod.conf ensure the net.http block is absent or:\n"
            "net:\n"
            "  http:\n"
            "    enabled: false"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-024",
        section="6.6",
        title="Ensure that JSONP access via an HTTP interface is disabled",
        description=(
            "JSONP on the HTTP interface allows cross-site data reads without "
            "authentication. It must not be enabled."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: not _RE.jsonp_on.search(_section(d, "CONFIG_FILE")),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"JSONPEnabled\s*:\s*\S+", re.I)),
        remediation=(
            "Remove net.http.JSONPEnabled: true from /etc/mongod.conf "
            "(or set it to false)."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-025",
        section="6.7",
        title="Ensure that the REST API is disabled",
        description=(
            "The legacy REST interface performs no authorization checks and "
            "exposes database contents over HTTP. It must not be enabled."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: not _RE.rest_on.search(_section(d, "CONFIG_FILE")),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"RESTInterfaceEnabled\s*:\s*\S+", re.I)),
        remediation=(
            "Remove net.http.RESTInterfaceEnabled: true from /etc/mongod.conf "
            "(or set it to false)."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 7 – File Permissions                                     #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-026",
        section="7.1",
        title="Ensure that key file permissions are set correctly",
        description=(
            "The cluster authentication keyFile is a shared secret and must "
            "be readable only by the mongod service account (mode 600 or "
            "400, owner mongod)."
        ),
        severity="high",
        level="L1",
        check_fn=_keyfile_perms_ok,
        evidence_fn=lambda d: _ev_section_content(d, "KEYFILE_INFO", 200),
        remediation=(
            "Run: chmod 600 <keyFile> && chown mongod:mongod <keyFile>"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-027",
        section="7.2",
        title="Ensure that database file permissions are set correctly",
        description=(
            "The dbPath directory must be owned by the mongod service account "
            "with no access for 'other' users, so database files cannot be "
            "read or tampered with directly."
        ),
        severity="high",
        level="L1",
        check_fn=_dbpath_perms_ok,
        evidence_fn=lambda d: _ev_section_content(d, "DBPATH_PERMS", 200),
        remediation=(
            "Run: chmod 750 /var/lib/mongodb && "
            "chown -R mongod:mongod /var/lib/mongodb"
        ),
    ))

    return rules


# ============================================================ #
#  Profile filtering                                            #
# ============================================================ #

def filter_rules_by_profile(rules: List[MongoDBCISRule], profile: str) -> List[MongoDBCISRule]:
    """
    Filter rules by CIS profile level.

    Args:
        rules:   Full rule list
        profile: "L1" returns only L1 rules; "FULL" returns all rules

    Returns:
        Filtered list of rules
    """
    if profile == "L1":
        return [r for r in rules if r.level == "L1"]
    return rules  # FULL includes L1 + L2


# ============================================================ #
#  Compliance evaluation                                        #
# ============================================================ #

def evaluate_compliance(dump: str, rules: List[MongoDBCISRule]) -> Dict[str, Any]:
    """
    Evaluate all rules against the collected audit dump.

    Args:
        dump:  Structured audit dump from MongoDBSSHClient.collect_audit_data()
        rules: List of MongoDBCISRule to evaluate

    Returns:
        {
            "summary": {
                "total_rules_scored": int,
                "passed_scored": int,
                "failed_scored": int,
                "compliance_pct": float,
                "weighted_compliance_pct": float,
            },
            "findings": [
                {
                    "id": str,
                    "title": str,
                    "description": str,
                    "section": str,
                    "severity": str,
                    "level": str,
                    "compliant": bool,
                    "evidence": str,
                    "remediation": str,
                },
                ...
            ]
        }
    """
    SEVERITY_WEIGHTS = {"high": 3, "medium": 2, "low": 1, "info": 0}

    findings = []
    total_weight = 0
    passed_weight = 0

    for rule in rules:
        try:
            compliant = rule.check_fn(dump)
        except Exception:
            compliant = False

        try:
            evidence = rule.evidence_fn(dump)
        except Exception:
            evidence = "(evidence extraction failed)"

        weight = SEVERITY_WEIGHTS.get(rule.severity, 1)
        total_weight += weight
        if compliant:
            passed_weight += weight

        findings.append({
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "section": rule.section,
            "severity": rule.severity,
            "level": rule.level,
            "compliant": compliant,
            "evidence": evidence,
            "remediation": rule.remediation,
        })

    total = len(findings)
    passed = sum(1 for f in findings if f["compliant"])
    failed = total - passed

    compliance_pct = round(100.0 * passed / total, 2) if total else 0.0
    weighted_pct = round(100.0 * passed_weight / total_weight, 2) if total_weight else 0.0

    return {
        "summary": {
            "total_rules_scored": total,
            "passed_scored": passed,
            "failed_scored": failed,
            "compliance_pct": compliance_pct,
            "weighted_compliance_pct": weighted_pct,
        },
        "findings": findings,
    }
