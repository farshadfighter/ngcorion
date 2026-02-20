"""
MongoDB Hardening Command Templates

Remediation commands for each CIS MongoDB check. Commands are shell one-liners
that edit /etc/mongod.conf via sed/grep patterns or perform OS-level fixes.

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

# MONGO-L1-003: Data directory permissions
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-003",
    description="Set restrictive permissions on MongoDB data directory",
    commands=[
        "chmod 700 /var/lib/mongodb 2>/dev/null || chmod 700 /var/lib/mongo 2>/dev/null || true",
        "chown -R mongod:mongod /var/lib/mongodb 2>/dev/null || chown -R mongodb:mongodb /var/lib/mongodb 2>/dev/null || true",
    ],
    verify_commands=[
        "stat -c '%a' /var/lib/mongodb 2>/dev/null | grep -q '700' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=False,
))

# MONGO-L1-004: Log directory permissions
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-004",
    description="Set restrictive permissions on MongoDB log directory",
    commands=[
        "chmod 750 /var/log/mongodb 2>/dev/null || chmod 750 /var/log/mongo 2>/dev/null || true",
        "chown -R mongod:mongod /var/log/mongodb 2>/dev/null || chown -R mongodb:mongodb /var/log/mongodb 2>/dev/null || true",
    ],
    verify_commands=[
        "stat -c '%a' /var/log/mongodb 2>/dev/null | grep -q '750' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=False,
))

# MONGO-L1-005: Config file permissions
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-005",
    description="Set restrictive permissions on /etc/mongod.conf",
    commands=[
        "chmod 600 /etc/mongod.conf",
        "chown root:mongod /etc/mongod.conf 2>/dev/null || chown root:mongodb /etc/mongod.conf 2>/dev/null || chown root:root /etc/mongod.conf",
    ],
    verify_commands=[
        "stat -c '%a' /etc/mongod.conf | grep -q '600' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=False,
))

# MONGO-L1-006: Enable authorization
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-006",
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

# MONGO-L1-007: Enforce SCRAM-SHA-256 authentication
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-007",
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

# MONGO-L1-009: Restrict bindIp to localhost
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-009",
    description="Restrict MongoDB network binding to 127.0.0.1",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+bindIp[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+bindIp[[:space:]]*:[[:space:]]*).*/\\1127.0.0.1/' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  bindIp: 127.0.0.1' /etc/mongod.conf; else printf '\\nnet:\\n  bindIp: 127.0.0.1\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+bindIp[[:space:]]*:[[:space:]]*127\\.0\\.0\\.1' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-011: Enable RBAC (same fix as L1-006 — authorization: enabled)
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-011",
    description="Enable Role-Based Access Control (RBAC) via authorization",
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

# MONGO-L1-015: Set TLS mode to allowTLS
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-015",
    description="Configure TLS mode to allowTLS (accepts both TLS and non-TLS connections)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+mode[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+mode[[:space:]]*:[[:space:]]*).*/\\1allowTLS/' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    mode: allowTLS' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  tls:\\n    mode: allowTLS' /etc/mongod.conf; else printf '\\nnet:\\n  tls:\\n    mode: allowTLS\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+mode[[:space:]]*:[[:space:]]*allowTLS' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L2-016: Set TLS mode to requireTLS
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L2-016",
    description="Configure TLS mode to requireTLS (enforces TLS for all connections)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+mode[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+mode[[:space:]]*:[[:space:]]*).*/\\1requireTLS/' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    mode: requireTLS' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  tls:\\n    mode: requireTLS' /etc/mongod.conf; else printf '\\nnet:\\n  tls:\\n    mode: requireTLS\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+mode[[:space:]]*:[[:space:]]*requireTLS' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-020: Enable file-based system logging
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-020",
    description="Configure MongoDB to log to a file (systemLog.destination: file)",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+destination[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+destination[[:space:]]*:[[:space:]]*).*/\\1file/' /etc/mongod.conf; elif grep -q '^systemLog:' /etc/mongod.conf; then sed -i '/^systemLog:/a\\  destination: file' /etc/mongod.conf; else printf '\\nsystemLog:\\n  destination: file\\n  path: /var/log/mongodb/mongod.log\\n' >> /etc/mongod.conf; fi",
        "if ! grep -qE '^[[:space:]]+path[[:space:]]*:.*log' /etc/mongod.conf && grep -q '^systemLog:' /etc/mongod.conf; then sed -i '/^systemLog:/a\\  path: /var/log/mongodb/mongod.log' /etc/mongod.conf; fi",
        "mkdir -p /var/log/mongodb && chown mongod:mongod /var/log/mongodb 2>/dev/null || true",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+destination[[:space:]]*:[[:space:]]*file' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-023: Enable log appending
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-023",
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

# MONGO-L2-022: Disable server-side JavaScript execution
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

# MONGO-L1-025: Enable and start mongod service
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-025",
    description="Enable and start the mongod service at boot",
    commands=[
        "systemctl enable mongod 2>/dev/null || systemctl enable mongodb 2>/dev/null || true",
        "systemctl start mongod 2>/dev/null || systemctl start mongodb 2>/dev/null || true",
    ],
    verify_commands=[
        "(systemctl is-enabled mongod 2>/dev/null || systemctl is-enabled mongodb 2>/dev/null) | grep -q 'enabled' && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=False,
))


# ===================================================================
# PARAMETERIZED TEMPLATES (require user-supplied values)
# ===================================================================

# MONGO-L1-002: Run mongod as a dedicated non-root service account
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-002",
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

# MONGO-L1-008: Set MongoDB listen port
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-008",
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

# MONGO-L1-010: Set bindIp to specific address
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-010",
    description="Restrict MongoDB network binding to a specific IP address ({MONGO_BIND_IP})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+bindIp[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+bindIp[[:space:]]*:[[:space:]]*).*/\\1{MONGO_BIND_IP}/' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  bindIp: {MONGO_BIND_IP}' /etc/mongod.conf; else printf '\\nnet:\\n  bindIp: {MONGO_BIND_IP}\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+bindIp[[:space:]]*:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-014: Configure TLS with certificate files
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-014",
    description="Configure TLS encryption with certificate and CA files",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        # Set TLS mode
        "if grep -qE '^[[:space:]]+mode[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+mode[[:space:]]*:[[:space:]]*).*/\\1{TLS_MODE}/' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    mode: {TLS_MODE}' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  tls:\\n    mode: {TLS_MODE}' /etc/mongod.conf; else printf '\\nnet:\\n  tls:\\n    mode: {TLS_MODE}\\n' >> /etc/mongod.conf; fi",
        # Set certificateKeyFile
        "if grep -qE '^[[:space:]]+certificateKeyFile[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's|^([[:space:]]+certificateKeyFile[[:space:]]*:[[:space:]]*).*|\\1{TLS_CERT_FILE}|' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    certificateKeyFile: {TLS_CERT_FILE}' /etc/mongod.conf; fi",
        # Set CAFile
        "if grep -qE '^[[:space:]]+CAFile[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's|^([[:space:]]+CAFile[[:space:]]*:[[:space:]]*).*|\\1{TLS_CA_FILE}|' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    CAFile: {TLS_CA_FILE}' /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+mode[[:space:]]*:[[:space:]]*{TLS_MODE}' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L2-017: Disable weak TLS protocols
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L2-017",
    description="Disable weak TLS protocol versions ({DISABLED_PROTOCOLS})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+disabledProtocols[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+disabledProtocols[[:space:]]*:[[:space:]]*).*/\\1{DISABLED_PROTOCOLS}/' /etc/mongod.conf; elif grep -q '^  tls:' /etc/mongod.conf; then sed -i '/^  tls:/a\\    disabledProtocols: {DISABLED_PROTOCOLS}' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  tls:\\n    disabledProtocols: {DISABLED_PROTOCOLS}' /etc/mongod.conf; else printf '\\nnet:\\n  tls:\\n    disabledProtocols: {DISABLED_PROTOCOLS}\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+disabledProtocols[[:space:]]*:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L2-018: Configure audit logging
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L2-018",
    description="Configure audit logging to file ({AUDIT_LOG_PATH})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "grep -q '^auditLog:' /etc/mongod.conf || printf '\\nauditLog:\\n  destination: file\\n  format: {AUDIT_FORMAT}\\n  path: {AUDIT_LOG_PATH}\\n' >> /etc/mongod.conf",
        "if grep -qE '^[[:space:]]+format[[:space:]]*:' /etc/mongod.conf && grep -q '^auditLog:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+format[[:space:]]*:[[:space:]]*).*/\\1{AUDIT_FORMAT}/' /etc/mongod.conf; fi",
        "mkdir -p $(dirname {AUDIT_LOG_PATH}) 2>/dev/null || true",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -q '^auditLog:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-019: Configure operation profiling
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-019",
    description="Configure operation profiling (mode={PROFILING_MODE}, slowOpMs={SLOW_OP_MS})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "grep -q '^operationProfiling:' /etc/mongod.conf || printf '\\noperationProfiling:\\n  mode: {PROFILING_MODE}\\n  slowOpThresholdMs: {SLOW_OP_MS}\\n' >> /etc/mongod.conf",
        "if grep -q '^operationProfiling:' /etc/mongod.conf && grep -qE '^[[:space:]]+slowOpThresholdMs[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+slowOpThresholdMs[[:space:]]*:[[:space:]]*).*/\\1{SLOW_OP_MS}/' /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -q '^operationProfiling:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-021: Configure keyfile for internal authentication
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-021",
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
        "grep -qE '^[[:space:]]+keyFile[[:space:]]*:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
    ],
    requires_service_restart=True,
))

# MONGO-L1-024: Configure IPv6 support
_register(MongoDBHardeningTemplate(
    check_id="MONGO-L1-024",
    description="Configure IPv6 support (net.ipv6: {ENABLE_IPV6})",
    commands=[
        "cp -f /etc/mongod.conf /etc/mongod.conf.bak",
        "if grep -qE '^[[:space:]]+ipv6[[:space:]]*:' /etc/mongod.conf; then sed -i -E 's/^([[:space:]]+ipv6[[:space:]]*:[[:space:]]*).*/\\1{ENABLE_IPV6}/' /etc/mongod.conf; elif grep -q '^net:' /etc/mongod.conf; then sed -i '/^net:/a\\  ipv6: {ENABLE_IPV6}' /etc/mongod.conf; else printf '\\nnet:\\n  ipv6: {ENABLE_IPV6}\\n' >> /etc/mongod.conf; fi",
        "systemctl restart mongod 2>/dev/null || service mongod restart 2>/dev/null || true",
    ],
    verify_commands=[
        "grep -qE '^[[:space:]]+ipv6[[:space:]]*:' /etc/mongod.conf && echo 'PASS' || echo 'FAIL'",
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
