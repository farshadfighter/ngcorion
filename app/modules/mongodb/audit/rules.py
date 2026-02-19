"""
MongoDB CIS Benchmark Rules

~25 predefined security checks based on the CIS MongoDB Benchmark.
Each rule evaluates a specific aspect of MongoDB security by searching
the structured audit dump collected by MongoDBSSHClient.

Rule IDs follow the pattern: MONGO-L{level}-{seq:03d}
  L1 = Level 1 (basic, broadly applicable)
  L2 = Level 2 (advanced, may affect functionality)

CIS sections covered:
  1.x  OS Level Configuration
  2.x  Authentication
  3.x  Access Control
  4.x  Transport Encryption
  5.x  Auditing & Logging
  6.x  Replication Security
"""

import re
from dataclasses import dataclass
from typing import Callable, List, Dict, Any


# ============================================================ #
#  Rule dataclass                                               #
# ============================================================ #

@dataclass
class MongoDBCISRule:
    """A single CIS MongoDB compliance check."""
    id: str                          # e.g. "MONGO-L1-001"
    section: str                     # CIS section number e.g. "2.1"
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
    """Extract the content of a named section from the audit dump."""
    pattern = re.compile(
        rf"===SECTION:{re.escape(name)}===\n(.*?)(?===SECTION:|\Z)",
        re.S,
    )
    m = pattern.search(dump)
    return m.group(1).strip() if m else ""


# ============================================================ #
#  Pre-compiled patterns for efficiency                         #
# ============================================================ #

class _RE:
    # Config file – authentication
    auth_enabled  = re.compile(r"authorization\s*:\s*enabled", re.I)
    auth_disabled = re.compile(r"authorization\s*:\s*disabled", re.I)

    # Config file – network binding
    bind_all      = re.compile(r"bindIp\s*:\s*0\.0\.0\.0", re.I)
    bind_specific = re.compile(r"bindIp\s*:", re.I)

    # Config file – port
    default_port  = re.compile(r"port\s*:\s*27017\b", re.I)

    # Config file – TLS
    tls_mode      = re.compile(r"mode\s*:\s*(requireTLS|allowTLS|preferTLS|disabled)", re.I)
    tls_disabled  = re.compile(r"mode\s*:\s*disabled", re.I)
    tls_require   = re.compile(r"mode\s*:\s*requireTLS", re.I)
    tls_block     = re.compile(r"^\s*(net\.)?tls\s*:", re.I | re.M)
    tls_min_ver   = re.compile(r"disabledProtocols\s*:\s*\S+", re.I)

    # Config file – audit log
    audit_dest    = re.compile(r"destination\s*:\s*(file|syslog)", re.I)
    audit_section = re.compile(r"^\s*auditLog\s*:", re.I | re.M)

    # Config file – profiling
    slowms        = re.compile(r"slowOpThresholdMs\s*:\s*(\d+)", re.I)
    profiling_lvl = re.compile(r"operationProfiling\s*:", re.I)

    # Config file – keyFile / clusterAuth
    keyfile       = re.compile(r"keyFile\s*:\s*\S+", re.I)
    cluster_auth  = re.compile(r"clusterAuthMode\s*:\s*(keyFile|x509|sendKeyFile|sendX509)", re.I)

    # Config file – JS
    js_enabled    = re.compile(r"javascriptEnabled\s*:\s*true", re.I)
    js_disabled   = re.compile(r"javascriptEnabled\s*:\s*false", re.I)

    # Process user
    root_user     = re.compile(r"^\s*root\s*$", re.I | re.M)

    # Data/log directory permissions
    perm_700      = re.compile(r"^700\s", re.M)
    perm_750      = re.compile(r"^750\s", re.M)
    perm_open     = re.compile(r"^7[5-7][5-7]\s|^[0-7][4-7][1-7]\s", re.M)

    # Config file permissions (should be 600 or 640)
    conf_perm_ok  = re.compile(r"^6[04]0\s", re.M)

    # Mongosh output – superuser roles
    root_role     = re.compile(r'"role"\s*:\s*"root"', re.I)
    dbadmin_all   = re.compile(r'"role"\s*:\s*"dbAdminAnyDatabase"', re.I)
    readwrite_all = re.compile(r'"role"\s*:\s*"readWriteAnyDatabase"', re.I)

    # Auth mechanisms
    sha256        = re.compile(r"SCRAM-SHA-256", re.I)
    sha1_only     = re.compile(r"SCRAM-SHA-1", re.I)

    # Listening on localhost only
    loopback      = re.compile(r"127\.0\.0\.1|::1|localhost", re.I)


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
#  Rule builder                                                 #
# ============================================================ #

def build_all_mongodb_cis_rules() -> List[MongoDBCISRule]:
    """Return the full list of MongoDB CIS rules."""

    rules: List[MongoDBCISRule] = []

    # ---------------------------------------------------------------- #
    #  Section 1 – OS Level Configuration                               #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-001",
        section="1.1",
        title="Ensure MongoDB does not run as root",
        description=(
            "MongoDB should run under a dedicated, unprivileged service account. "
            "Running as root gives the process unrestricted OS access."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            not _RE.root_user.search(_section(d, "MONGOD_USER"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "MONGOD_USER"),
        remediation=(
            "Create a dedicated 'mongod' or 'mongodb' system user with no login shell. "
            "Update the service unit file (User=mongod) and restart the service."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-002",
        section="1.2",
        title="Ensure a dedicated MongoDB service account exists",
        description=(
            "MongoDB should run under a named, dedicated account (e.g. 'mongod') "
            "rather than a shared or privileged account."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: bool(
            re.search(r"mongod|mongodb", _section(d, "MONGOD_USER"), re.I)
        ),
        evidence_fn=lambda d: _ev_section_content(d, "MONGOD_USER"),
        remediation=(
            "Create a system account named 'mongod' with no login shell and "
            "configure the service to run under that account."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-003",
        section="1.3",
        title="Ensure MongoDB data directory permissions are restrictive",
        description=(
            "The MongoDB data directory should be readable and writable only by the "
            "mongod service account (permissions 700 or 750)."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.perm_700.search(_section(d, "DATA_DIR_PERMS"))
            or _RE.perm_750.search(_section(d, "DATA_DIR_PERMS"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "DATA_DIR_PERMS"),
        remediation=(
            "Run: chmod 700 /var/lib/mongodb && chown -R mongod:mongod /var/lib/mongodb"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-004",
        section="1.4",
        title="Ensure MongoDB log directory permissions are restrictive",
        description=(
            "The MongoDB log directory should not be world-readable or writable."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: (
            "LOG_DIR_NOT_FOUND" not in _section(d, "LOG_DIR_PERMS")
            and not _RE.perm_open.search(_section(d, "LOG_DIR_PERMS"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "LOG_DIR_PERMS"),
        remediation=(
            "Run: chmod 750 /var/log/mongodb && chown -R mongod:mongod /var/log/mongodb"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-005",
        section="1.5",
        title="Ensure MongoDB configuration file permissions are restrictive",
        description=(
            "The mongod.conf file may contain sensitive settings. "
            "It should only be readable by root/mongod (permissions 600 or 640)."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: bool(
            _RE.conf_perm_ok.search(_section(d, "CONFIG_FILE_PERMS"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "CONFIG_FILE_PERMS"),
        remediation=(
            "Run: chmod 600 /etc/mongod.conf && chown root:mongod /etc/mongod.conf"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 2 – Authentication                                       #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-006",
        section="2.1",
        title="Ensure MongoDB authentication is enabled",
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
        id="MONGO-L1-007",
        section="2.2",
        title="Ensure SCRAM-SHA-256 is the active authentication mechanism",
        description=(
            "SCRAM-SHA-256 is significantly stronger than the legacy SCRAM-SHA-1 "
            "or MONGODB-CR mechanisms."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.sha256.search(_section(d, "AUTH_MECHANISMS"))
            or _RE.sha256.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: (
            _ev_section_content(d, "AUTH_MECHANISMS", 300)
            or _ev_config(d, _RE.sha256)
        ),
        remediation=(
            "In /etc/mongod.conf:\n"
            "security:\n"
            "  authenticationMechanisms: SCRAM-SHA-256\n"
            "Existing passwords must be re-set after changing the mechanism."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-008",
        section="2.3",
        title="Ensure MongoDB does not use the default port 27017",
        description=(
            "Using the default MongoDB port makes it easier for attackers to "
            "discover and target the service."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: not bool(
            _RE.default_port.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.default_port),
        remediation=(
            "Change the port in /etc/mongod.conf:\n"
            "net:\n"
            "  port: <non-default-port>\n"
            "Update firewall rules and client connection strings accordingly."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-009",
        section="2.4",
        title="Ensure MongoDB does not bind to all interfaces (0.0.0.0)",
        description=(
            "Binding to 0.0.0.0 exposes MongoDB on every network interface, "
            "unnecessarily increasing the attack surface."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: not bool(
            _RE.bind_all.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.bind_all),
        remediation=(
            "In /etc/mongod.conf:\n"
            "net:\n"
            "  bindIp: 127.0.0.1,<trusted-ip>\n"
            "List only the interfaces MongoDB should listen on."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-010",
        section="2.5",
        title="Ensure MongoDB listens only on localhost or specified interfaces",
        description=(
            "MongoDB should be explicitly bound to specific IP addresses rather "
            "than implicitly accepting connections from any source."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: bool(
            _RE.bind_specific.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.bind_specific),
        remediation=(
            "Explicitly configure net.bindIp in /etc/mongod.conf with only the "
            "interfaces required for your deployment."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 3 – Access Control                                       #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-011",
        section="3.1",
        title="Ensure role-based access control (RBAC) is enabled",
        description=(
            "RBAC ensures that users have only the minimum permissions required. "
            "This requires authentication to be enabled."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.auth_enabled.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.auth_enabled),
        remediation=(
            "Enable authentication (security.authorization: enabled) and "
            "assign roles using db.createUser() with the principle of least privilege."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-012",
        section="3.2",
        title="Ensure no users are assigned the unrestricted 'root' role",
        description=(
            "The 'root' role grants complete unrestricted access. "
            "Administrative users should use more specific roles instead."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: (
            "QUERY_FAILED" in _section(d, "USERS_LIST")
            or not _RE.root_role.search(_section(d, "USERS_LIST"))
        ),
        evidence_fn=lambda d: _ev_section_content(d, "USERS_LIST", 500),
        remediation=(
            "Revoke the 'root' role and assign narrower roles such as "
            "'dbAdmin', 'readWrite', or 'userAdminAnyDatabase' as appropriate."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-013",
        section="3.3",
        title="Ensure no users are assigned 'readWriteAnyDatabase' or 'dbAdminAnyDatabase'",
        description=(
            "These roles grant access across all databases and should be avoided "
            "in favour of per-database permissions."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: (
            "QUERY_FAILED" in _section(d, "USERS_LIST")
            or (
                not _RE.dbadmin_all.search(_section(d, "USERS_LIST"))
                and not _RE.readwrite_all.search(_section(d, "USERS_LIST"))
            )
        ),
        evidence_fn=lambda d: _ev_section_content(d, "USERS_LIST", 500),
        remediation=(
            "Replace any-database roles with database-specific roles "
            "(e.g. readWrite on the specific database only)."
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 4 – Transport Encryption                                 #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-014",
        section="4.1",
        title="Ensure TLS/SSL is configured for client connections",
        description=(
            "Data in transit between clients and MongoDB should be encrypted "
            "to prevent eavesdropping or tampering."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.tls_block.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.tls_block),
        remediation=(
            "Add a TLS block to /etc/mongod.conf:\n"
            "net:\n"
            "  tls:\n"
            "    mode: requireTLS\n"
            "    certificateKeyFile: /etc/ssl/mongod.pem\n"
            "    CAFile: /etc/ssl/ca.pem"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-015",
        section="4.2",
        title="Ensure TLS mode is not set to 'disabled'",
        description=(
            "Setting net.tls.mode to 'disabled' turns off all transport "
            "encryption, exposing data to interception."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: not bool(
            _RE.tls_disabled.search(_section(d, "CONFIG_FILE"))
            or _RE.tls_disabled.search(_section(d, "TLS_PARAMS"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.tls_disabled),
        remediation=(
            "Set net.tls.mode to 'requireTLS' or at minimum 'allowTLS' in "
            "/etc/mongod.conf and provide valid certificates."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-016",
        section="4.3",
        title="Ensure TLS mode is set to 'requireTLS'",
        description=(
            "'requireTLS' ensures that all incoming connections must use TLS. "
            "Modes like 'allowTLS' still permit unencrypted connections."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(
            _RE.tls_require.search(_section(d, "CONFIG_FILE"))
            or _RE.tls_require.search(_section(d, "TLS_PARAMS"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.tls_require),
        remediation=(
            "Set net.tls.mode: requireTLS in /etc/mongod.conf to enforce "
            "encrypted connections for all clients."
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L2-017",
        section="4.4",
        title="Ensure legacy SSL protocols are disabled",
        description=(
            "Older SSL/TLS versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) have known "
            "vulnerabilities and should be explicitly disabled."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(
            _RE.tls_min_ver.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.tls_min_ver),
        remediation=(
            "In /etc/mongod.conf set:\n"
            "net:\n"
            "  tls:\n"
            "    disabledProtocols: TLS1_0,TLS1_1"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 5 – Auditing & Logging                                   #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L2-018",
        section="5.1",
        title="Ensure MongoDB audit logging is enabled",
        description=(
            "Audit logging records authentication attempts, CRUD operations, "
            "and administrative actions for accountability and forensics."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(
            _RE.audit_section.search(_section(d, "CONFIG_FILE"))
            and _RE.audit_dest.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.audit_section),
        remediation=(
            "Add an auditLog section to /etc/mongod.conf (requires MongoDB Enterprise):\n"
            "auditLog:\n"
            "  destination: file\n"
            "  format: JSON\n"
            "  path: /var/log/mongodb/auditLog.json"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-019",
        section="5.2",
        title="Ensure slow operation profiling is configured",
        description=(
            "Configuring operationProfiling.slowOpThresholdMs helps detect and "
            "investigate unusually slow queries which may indicate abuse."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: bool(
            _RE.profiling_lvl.search(_section(d, "CONFIG_FILE"))
            or _RE.slowms.search(_section(d, "CONFIG_FILE"))
            or (
                "QUERY_FAILED" not in _section(d, "PROFILING")
                and "MONGOSH_UNAVAILABLE" not in _section(d, "PROFILING")
                and _section(d, "PROFILING").strip() != ""
            )
        ),
        evidence_fn=lambda d: (
            _ev_config(d, _RE.profiling_lvl)
            or _ev_section_content(d, "PROFILING", 300)
        ),
        remediation=(
            "In /etc/mongod.conf:\n"
            "operationProfiling:\n"
            "  mode: slowOp\n"
            "  slowOpThresholdMs: 100"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-020",
        section="5.3",
        title="Ensure MongoDB is configured to log to a file",
        description=(
            "Logs written to a persistent file can be reviewed for security events, "
            "unlike transient console-only logs."
        ),
        severity="medium",
        level="L1",
        check_fn=lambda d: bool(
            re.search(r"destination\s*:\s*file", _section(d, "CONFIG_FILE"), re.I)
            or re.search(r"path\s*:\s*/", _section(d, "CONFIG_FILE"), re.I)
        ),
        evidence_fn=lambda d: _ev_config(d, re.compile(r"destination\s*:\s*file", re.I)),
        remediation=(
            "In /etc/mongod.conf:\n"
            "systemLog:\n"
            "  destination: file\n"
            "  path: /var/log/mongodb/mongod.log\n"
            "  logAppend: true"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Section 6 – Replication Security                                 #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L1-021",
        section="6.1",
        title="Ensure keyFile or x.509 authentication is configured for replica sets",
        description=(
            "Internal replica set/sharding communication must be authenticated "
            "to prevent rogue members from joining the cluster."
        ),
        severity="high",
        level="L1",
        check_fn=lambda d: bool(
            _RE.keyfile.search(_section(d, "CONFIG_FILE"))
            or _RE.cluster_auth.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.keyfile),
        remediation=(
            "For replica sets, add to /etc/mongod.conf:\n"
            "security:\n"
            "  keyFile: /etc/mongodb/keyfile\n"
            "Or use x.509 certificates:\n"
            "  clusterAuthMode: x509"
        ),
    ))

    # ---------------------------------------------------------------- #
    #  Additional Hardening Checks                                      #
    # ---------------------------------------------------------------- #

    rules.append(MongoDBCISRule(
        id="MONGO-L2-022",
        section="7.1",
        title="Ensure server-side JavaScript execution is disabled",
        description=(
            "Server-side JavaScript ($where, mapReduce) introduces additional "
            "attack surface. Disable it unless explicitly required."
        ),
        severity="medium",
        level="L2",
        check_fn=lambda d: bool(
            _RE.js_disabled.search(_section(d, "CONFIG_FILE"))
        ),
        evidence_fn=lambda d: _ev_config(d, _RE.js_disabled),
        remediation=(
            "In /etc/mongod.conf:\n"
            "security:\n"
            "  javascriptEnabled: false"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-023",
        section="7.2",
        title="Ensure MongoDB systemLog.logAppend is enabled",
        description=(
            "When logAppend is false, MongoDB overwrites the log file on restart, "
            "destroying historical audit records."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: bool(
            re.search(r"logAppend\s*:\s*true", _section(d, "CONFIG_FILE"), re.I)
        ),
        evidence_fn=lambda d: _ev_config(
            d, re.compile(r"logAppend\s*:\s*\S+", re.I)
        ),
        remediation=(
            "In /etc/mongod.conf:\n"
            "systemLog:\n"
            "  logAppend: true"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-024",
        section="7.3",
        title="Ensure net.ipv6 is explicitly configured if not required",
        description=(
            "If IPv6 is not required, it should be disabled to reduce the "
            "network attack surface."
        ),
        severity="low",
        level="L1",
        check_fn=lambda d: bool(
            re.search(r"ipv6\s*:", _section(d, "CONFIG_FILE"), re.I)
        ),
        evidence_fn=lambda d: _ev_config(
            d, re.compile(r"ipv6\s*:", re.I)
        ),
        remediation=(
            "In /etc/mongod.conf explicitly set:\n"
            "net:\n"
            "  ipv6: false   # or true if IPv6 is intentionally used"
        ),
    ))

    rules.append(MongoDBCISRule(
        id="MONGO-L1-025",
        section="7.4",
        title="Ensure MongoDB process is running (service is active)",
        description=(
            "Confirms that the MongoDB service is currently active. "
            "A stopped service may indicate a misconfiguration or incident."
        ),
        severity="info",
        level="L1",
        check_fn=lambda d: bool(
            re.search(r"mongod", _section(d, "PROCESS_INFO"), re.I)
            and "NO_MONGOD_PROCESS" not in _section(d, "PROCESS_INFO")
        ),
        evidence_fn=lambda d: _ev_section_content(d, "PROCESS_INFO", 300),
        remediation=(
            "Start the MongoDB service:\n"
            "  systemctl start mongod\n"
            "  systemctl enable mongod"
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
