"""
MongoDB Hardening Command Templates

Remediation commands for each CIS MongoDB Benchmark v1.0.0 check. Commands are
shell one-liners that edit /etc/mongod.conf via sed/grep patterns or perform
OS-level fixes.

Each template includes:
- check_id: CIS check ID this template fixes
- description: Human-readable description
- commands: List of shell commands; {PARAM} placeholders are substituted before execution
- verify_commands: Commands that output PASS or FAIL
- requires_service_restart: Whether mongod must restart for the change to take effect

Config edit pattern used throughout:
  if grep -qE '^[[:space:]]+KEY:' /etc/mongod.conf;
  then sed -i -E 's/^([[:space:]]+KEY:[[:space:]]*).*/\\1VALUE/' /etc/mongod.conf;
  elif grep -q '^SECTION:' /etc/mongod.conf;
  then sed -i '/^SECTION:/a\\  KEY: VALUE' /etc/mongod.conf;
  else printf '\\nSECTION:\\n  KEY: VALUE\\n' >> /etc/mongod.conf; fi

Checks with no template here (1.1 version upgrade, 3.1/3.4/3.5/3.6 role
reviews, 4.2 encryption at rest, 4.3 FIPS) require mongosh work, data
migration, or human review and are intentionally not auto-fixable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class MongoDBHardeningTemplate:
    """Template for hardening a specific CIS MongoDB check."""
    check_id: str
    description: str
    commands: List[str]
    verify_commands: List[str] = field(default_factory=list)
    requires_service_restart: bool = True


# Registry
MONGODB_HARDENING_TEMPLATES: Dict[str, MongoDBHardeningTemplate] = {}


def _register(t: MongoDBHardeningTemplate) -> None:
    MONGODB_HARDENING_TEMPLATES[t.check_id] = t


# ===================================================================
# AUTO-FIXABLE TEMPLATES (no required parameters)
# ===================================================================

# MONGO-L1-002 (CIS 2.1): Enable authorization
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-002",
    description="Enable MongoDB authorization (access control)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+authorization[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+authorization[[:space:]]*:[[:space:]]*).*/\\1enabled/' /etc/mongod.conf; elif grep -q '^security:' /etc/mongod.conf; then sed -i '/^security:/a\\  authorization: enabled' /etc/mongod.conf; else printf '\\nsecurity:\\n  authorization: enabled\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+authorization[[:space:]]*:[[:space:]]*enabled' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-003 (CIS 2.2): Disable the localhost authentication bypass
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-003",
    description="Disable the localhost authentication bypass exception",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+enableLocalhostAuthBypass[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+enableLocalhostAuthBypass[[:space:]]*:[[:space:]]*).*/\\1false/' /etc/mongod.conf; elif grep -q '^setParameter:' /etc/mongod.conf; then sed -i '/^setParameter:/a\\  enableLocalhostAuthBypass: false' /etc/mongod.conf; else printf '\\nsetParameter:\\n  enableLocalhostAuthBypass: false\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+enableLocalhostAuthBypass[[:space:]]*:[[:space:]]*false' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-005 (CIS 2.4): Enforce SCRAM-SHA-256 authentication
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-005",
    description="Configure SCRAM-SHA-256 as the authentication mechanism",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+authenticationMechanisms[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+authenticationMechanisms[[:space:]]*:[[:space:]]*).*/\\1SCRAM-SHA-256/' /etc/mongod.conf; elif grep -q '^setParameter:' /etc/mongod.conf; then sed -i '/^setParameter:/a\\  authenticationMechanisms: SCRAM-SHA-256' /etc/mongod.conf; else printf '\\nsetParameter:\\n  authenticationMechanisms: SCRAM-SHA-256\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+authenticationMechanisms[[:space:]]*:[[:space:]]*SCRAM-SHA-256' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-017 (CIS 5.3): Do not suppress log detail
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-017",
    description="Disable systemLog.quiet so logging captures full detail",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+quiet[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+quiet[[:space:]]*:[[:space:]]*).*/\\1false/' /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+quiet[[:space:]]*:[[:space:]]*true' /etc/mongod.conf && echo 'FAIL' || echo 'PASS'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-018 (CIS 5.4): Enable log appending
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-018",
    description="Enable systemLog.logAppend to preserve log history across restarts",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+logAppend[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+logAppend[[:space:]]*:[[:space:]]*).*/\\1true/' /etc/mongod.conf; elif grep -q '^systemLog:' /etc/mongod.conf; then sed -i '/^systemLog:/a\\  logAppend: true' /etc/mongod.conf; else printf '\\nsystemLog:\\n  logAppend: true\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+logAppend[[:space:]]*:[[:space:]]*true' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-019 (CIS 6.1) — HTTP status interface must be off.
# Only flip an explicit `enabled: true` inside the http: block; the audit
# passes when the block is absent, so a failing host always has the line.
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-019",
    description="Disable the legacy HTTP status interface (net.http.enabled)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "sed -i -E '/^[[:space:]]*http:/,/^[^[:space:]]/ s/^([[:space:]]+enabled[[:space:]]*:[[:space:]]*)true/\\1false/' /etc/mongod.conf",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "sed -n '/^[[:space:]]*http:/,/^[^[:space:]]/p' /etc/mongod.conf | grep -qE 'enabled[[:space:]]*:[[:space:]]*true' && echo 'FAIL' || echo 'PASS'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-021 (CIS 6.3): OS resource limits for mongod
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-021",
    description="Raise OS resource limits (nofile/nproc 64000) for mongod",
    commands=[
        "printf 'mongod soft nofile 64000\\nmongod hard nofile 64000\\nmongod soft nproc 64000\\nmongod hard nproc 64000\\n' > /etc/security/limits.d/99-mongodb.conf",
        "mkdir -p /etc/systemd/system/mongod.service.d && printf '[Service]\\nLimitNOFILE=64000\\nLimitNPROC=64000\\n' > /etc/systemd/system/mongod.service.d/limits.conf",
        "systemctl daemon-reload 2>/dev/null || true",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "PID=$(pgrep -x mongod | head -1); [ -n \"$PID\" ] && grep -E 'Max open files' /proc/$PID/limits | awk '{exit ($4>=64000)?0:1}' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L2-022 (CIS 6.4): Disable server-side JavaScript execution
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L2-022",
    description="Disable JavaScript execution (security.javascriptEnabled: false)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+javascriptEnabled[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+javascriptEnabled[[:space:]]*:[[:space:]]*).*/\\1false/' /etc/mongod.conf; elif grep -q '^security:' /etc/mongod.conf; then sed -i '/^security:/a\\  javascriptEnabled: false' /etc/mongod.conf; else printf '\\nsecurity:\\n  javascriptEnabled: false\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+javascriptEnabled[[:space:]]*:[[:space:]]*false' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-023 (CIS 6.5): HTTP interface off (same edit as 6.1)
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-023",
    description="Disable the embedded HTTP interface (net.http.enabled)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "sed -i -E '/^[[:space:]]*http:/,/^[^[:space:]]/ s/^([[:space:]]+enabled[[:space:]]*:[[:space:]]*)true/\\1false/' /etc/mongod.conf",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "sed -n '/^[[:space:]]*http:/,/^[^[:space:]]/p' /etc/mongod.conf | grep -qE 'enabled[[:space:]]*:[[:space:]]*true' && echo 'FAIL' || echo 'PASS'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-024 (CIS 6.6): Disable JSONP access
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-024",
    description="Disable JSONP access via the HTTP interface",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "sed -i -E 's/^([[:space:]]+JSONPEnabled[[:space:]]*:[[:space:]]*)true/\\1false/' /etc/mongod.conf",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+JSONPEnabled[[:space:]]*:[[:space:]]*true' /etc/mongod.conf && echo 'FAIL' || echo 'PASS'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-025 (CIS 6.7): Disable the REST API
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-025",
    description="Disable the legacy REST API interface",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "sed -i -E 's/^([[:space:]]+RESTInterfaceEnabled[[:space:]]*:[[:space:]]*)true/\\1false/' /etc/mongod.conf",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+RESTInterfaceEnabled[[:space:]]*:[[:space:]]*true' /etc/mongod.conf && echo 'FAIL' || echo 'PASS'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-026 (CIS 7.1): Key file permissions
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-026",
    description="Restrict permissions on the cluster authentication keyFile",
    commands=[
        "KF=$(grep -E '^[[:space:]]*keyFile[[:space:]]*:' /etc/mongod.conf | awk '{print $2}' | head -1); if [ -n \"$KF\" ] && [ -e \"$KF\" ]; then chmod 600 \"$KF\"; chown mongod:mongod \"$KF\" 2>/dev/null || chown mongodb:mongodb \"$KF\" 2>/dev/null || true; fi",
    ],
    verify_commands=[
        "KF=$(grep -E '^[[:space:]]*keyFile[[:space:]]*:' /etc/mongod.conf | awk '{print $2}' | head -1); if [ -z \"$KF\" ]; then echo 'FAIL - no keyFile configured (fix MONGO-L1-004 first)'; elif stat -c '%a' \"$KF\" 2>/dev/null | grep -qE '^(400|600)$'; then echo 'PASS'; else echo 'FAIL'; fi",
    ],
    requires_service_restart=False,
))

# MONGO-L1-027 (CIS 7.2): Database file permissions
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-027",
    description="Restrict ownership and permissions on the dbPath directory",
    commands=[
        "DP=$(grep -E '^[[:space:]]*dbPath[[:space:]]*:' /etc/mongod.conf | awk '{print $2}' | head -1); DP=${DP:-/var/lib/mongodb}; chmod 750 \"$DP\"; chown -R mongod:mongod \"$DP\" 2>/dev/null || chown -R mongodb:mongodb \"$DP\" 2>/dev/null || true",
    ],
    verify_commands=[
        "DP=$(grep -E '^[[:space:]]*dbPath[[:space:]]*:' /etc/mongod.conf | awk '{print $2}' | head -1); DP=${DP:-/var/lib/mongodb}; stat -c '%a %U' \"$DP\" 2>/dev/null | grep -qE '^7[05]0 (mongod|mongodb)$' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=False,
))


# ===================================================================
# PARAMETERIZED TEMPLATES (require user-supplied values or defaults)
# ===================================================================

# MONGO-L1-004 (CIS 2.3): Configure keyfile for internal authentication
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-004",
    description="Configure internal authentication keyfile ({KEYFILE_PATH})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "mkdir -p $(dirname {KEYFILE_PATH}) 2>/dev/null || true",
        "test -f {KEYFILE_PATH} || openssl rand -base64 756 > {KEYFILE_PATH}",
        "chmod 400 {KEYFILE_PATH}",
        "chown mongod:mongod {KEYFILE_PATH} 2>/dev/null || chown mongodb:mongodb {KEYFILE_PATH} 2>/dev/null || true",
        "if grep -qE '^[[:space:]]+keyFile[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's|^([[:space:]]+keyFile[[:space:]]*:[[:space:]]*).*|\\1{KEYFILE_PATH}|' /etc/mongod.conf; elif grep -q '^security:' /etc/mongod.conf; then sed -i '/^security:/a\\  keyFile: {KEYFILE_PATH}' /etc/mongod.conf; else printf '\\nsecurity:\\n  keyFile: {KEYFILE_PATH}\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+keyFile[[:space:]]*:' /etc/mongod.conf && test -f {KEYFILE_PATH} && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-007 (CIS 3.2): Restrict network binding
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-007",
    description="Restrict MongoDB network binding to authorized interfaces ({MONGO_BIND_IP})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+bindIpAll[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+bindIpAll[[:space:]]*:[[:space:]]*).*/\\1false/' /etc/mongod.conf; fi",
        "if grep -qE '^[[:space:]]+bindIp[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+bindIp[[:space:]]*:[[:space:]]*).*/\\1{MONGO_BIND_IP}/' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  bindIp: {MONGO_BIND_IP}' /etc/mongod.conf; else printf '\\nnet:\\n  bindIp: {MONGO_BIND_IP}\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+bindIp[[:space:]]*:[[:space:]]*{MONGO_BIND_IP}' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-008 (CIS 3.3): Run mongod as a dedicated non-root service account
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-008",
    description="Ensure mongod runs as a dedicated non-root service user ({MONGO_SERVICE_USER})",
    commands=[
        "id {MONGO_SERVICE_USER} 2>/dev/null || useradd -r -s /bin/false -d /var/lib/mongodb {MONGO_SERVICE_USER}",
        "chown -R {MONGO_SERVICE_USER}:{MONGO_SERVICE_USER} /var/lib/mongodb 2>/dev/null || true",
        "chown -R {MONGO_SERVICE_USER}:{MONGO_SERVICE_USER} /var/log/mongodb 2>/dev/null || true",
        "test -f /lib/systemd/system/mongod.service && sed -i 's/^User=.*/User={MONGO_SERVICE_USER}/' /lib/systemd/system/mongod.service || true",
        "systemctl daemon-reload 2>/dev/null || true",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "ps -o user= -p $(pgrep -x mongod 2>/dev/null | head -1) 2>/dev/null | grep -q '{MONGO_SERVICE_USER}' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-012 (CIS 4.1): Configure TLS with certificate files.
# Guarded on certificateKeyFile: requireTLS without a certificate keeps mongod
# from starting, so the mode is only applied together with valid cert paths.
# The mode sed is scoped to the tls: block so operationProfiling.mode is never
# touched.
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-012",
    description="Configure TLS encryption with certificate and CA files",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if sed -n '/^[[:space:]]*tls:/,/^[^[:space:]]/p' /etc/mongod.conf | grep -qE '^[[:space:]]+mode[[:space:]]*:'; then sed -i -E '/^[[:space:]]*tls:/,/^[^[:space:]]/ s/^([[:space:]]+mode[[:space:]]*:[[:space:]]*).*/\\1{TLS_MODE}/' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    mode: {TLS_MODE}' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  tls:\\n    mode: {TLS_MODE}' /etc/mongod.conf; else printf '\\nnet:\\n  tls:\\n    mode: {TLS_MODE}\\n' >> /etc/mongod.conf; fi",
        "if grep -qE '^[[:space:]]+certificateKeyFile[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's|^([[:space:]]+certificateKeyFile[[:space:]]*:[[:space:]]*).*|\\1{TLS_CERT_FILE}|' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    certificateKeyFile: {TLS_CERT_FILE}' /etc/mongod.conf; fi",
        "if grep -qE '^[[:space:]]+CAFile[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's|^([[:space:]]+CAFile[[:space:]]*:[[:space:]]*).*|\\1{TLS_CA_FILE}|' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    CAFile: {TLS_CA_FILE}' /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+mode[[:space:]]*:[[:space:]]*{TLS_MODE}' /etc/mongod.conf && grep -qE '^[[:space:]]+certificateKeyFile[[:space:]]*:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-015 (CIS 5.1): Configure audit logging
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-015",
    description="Configure audit logging to file ({AUDIT_LOG_PATH})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "grep -q '^auditLog:' /etc/mongod.conf || printf '\\nauditLog:\\n  destination: file\\n  format: {AUDIT_FORMAT}\\n  path: {AUDIT_LOG_PATH}\\n' >> /etc/mongod.conf",
        "mkdir -p $(dirname {AUDIT_LOG_PATH}) 2>/dev/null || true",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -q '^auditLog:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L2-016 (CIS 5.2): Configure an audit filter
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L2-016",
    description="Configure an auditLog filter for security-relevant events",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "grep -q '^auditLog:' /etc/mongod.conf || printf '\\nauditLog:\\n  destination: file\\n  format: JSON\\n  path: /var/log/mongodb/auditLog.json\\n' >> /etc/mongod.conf",
        "grep -qE '^[[:space:]]+filter[[:space:]]*:' /etc/mongod.conf || sed -i '/^auditLog:/a\\  filter: \"{AUDIT_FILTER}\"' /etc/mongod.conf",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+filter[[:space:]]*:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L2-020 (CIS 6.2): Set a non-default MongoDB listen port
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L2-020",
    description="Configure MongoDB to listen on a non-default port ({MONGO_PORT})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+port[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+port[[:space:]]*:[[:space:]]*).*/\\1{MONGO_PORT}/' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  port: {MONGO_PORT}' /etc/mongod.conf; else printf '\\nnet:\\n  port: {MONGO_PORT}\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+port[[:space:]]*:[[:space:]]*{MONGO_PORT}' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))


# ===================================================================
# Helper functions
# ===================================================================

def get_mongodb_hardening_template(check_id: str) -> Optional[MongoDBHardeningTemplate]:
    """Get hardening template for a specific check."""
    return MONGODB_HARDENING_TEMPLATES.get(check_id)


def get_all_supported_checks() -> Set[str]:
    """Return the set of all check IDs that have a hardening template."""
    return set(MONGODB_HARDENING_TEMPLATES.keys())


def get_mongodb_template_commands(
    check_id: str,
    parameters: Dict[str, str] = None,
) -> List[str]:
    """Return commands for a check with {PARAM} placeholders substituted."""
    template = get_mongodb_hardening_template(check_id)
    if not template:
        return []

    parameters = parameters or {}
    result = []
    for cmd in template.commands:
        for name, value in parameters.items():
            cmd = cmd.replace(f"{{{name}}}", str(value))
        result.append(cmd)
    return result


def get_mongodb_verify_commands(
    check_id: str,
    parameters: Dict[str, str] = None,
) -> List[str]:
    """Return verification commands with {PARAM} placeholders substituted."""
    template = get_mongodb_hardening_template(check_id)
    if not template:
        return []

    parameters = parameters or {}
    result = []
    for cmd in template.verify_commands:
        for name, value in parameters.items():
            cmd = cmd.replace(f"{{{name}}}", str(value))
        result.append(cmd)
    return result
