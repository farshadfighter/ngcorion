# Frontend Developer Guide — Audit & Hardening APIs

> Comprehensive reference for all audit and hardening endpoints across every supported device type.

> ### ⚠️ Outdated: the per-family "Harden All" endpoints were removed
>
> The three-mode Harden All flow described below no longer exists. These
> endpoints were removed from **all seven** device families (cisco, fortinet,
> linux, apache, mongodb, mssql, windows):
>
> - `GET  /api/hardening/{family}/session/{id}/parameters`
> - `GET  /api/hardening/{family}/session/{id}/auto-preview`
> - `POST /api/hardening/{family}/auto-harden-defaults`
> - `POST /api/hardening/{family}/batch-execute`
>
> They are replaced by two device-agnostic endpoints:
>
> - `GET  /api/hardening/harden-all/session/{id}/plan` — returns the fixable
>   checks, the unfixable ones with reasons, the parameters to collect, the
>   credential fields to render, and the supported options (`backup`, `dry_run`).
> - `POST /api/hardening/harden-all/execute` — body:
>   `{ session_id, credentials{}, parameters{}, result_ids[]?, create_backup?, dry_run? }`;
>   returns `{ successful, failed, skipped, results[{result_id, check_number, vdom, status, detail, commands[]}] }`.
>
> The response shape is identical for every device family, so clients must not
> branch on device type. Single-check remediation (`/preview`, `/execute`,
> `/execute-single`) is unchanged. Sections below that describe the old flow are
> retained only as history.

---


## Table of Contents

1. [Authentication](#1-authentication)
2. [Common Patterns](#2-common-patterns)
3. [Audit API](#3-audit-api)
   - [Cisco IOS/IOS-XE](#31-cisco-audit)
   - [FortiGate](#32-fortinet-audit)
   - [Linux](#33-linux-audit)
   - [MongoDB](#34-mongodb-audit)
   - [MSSQL](#35-mssql-audit)
   - [Windows Server](#36-windows-audit)
   - [Apache HTTP Server](#37-apache-audit)
4. [Hardening API](#4-hardening-api)
   - [Cisco Hardening](#41-cisco-hardening)
   - [FortiGate Hardening](#42-fortinet-hardening)
   - [Linux Hardening](#43-linux-hardening)
   - [MongoDB Hardening](#44-mongodb-hardening)
   - [MSSQL Hardening](#45-mssql-hardening)
   - [Schema-Driven Hardening (Shared)](#46-schema-driven-hardening)
5. [Response Schemas](#5-response-schemas)
6. [Error Handling](#6-error-handling)
7. [Device-Specific Notes](#7-device-specific-notes)

---

## 1. Authentication

All API endpoints (except `/api/auth/login`) require a JWT bearer token.

### POST `/api/auth/login`

**Request:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "username": "admin",
  "role": "admin",
  "permissions": {
    "AUDIT": { "read": true, "write": true, "delete": true },
    "HARDENING": { "read": true, "write": true, "delete": true },
    "ASSET_MANAGEMENT": { "read": true, "write": true, "delete": true }
  }
}
```

**Errors:**
| Code | Meaning |
|------|---------|
| 401 | Incorrect username or password |
| 403 | Account is inactive |

### Using the Token

Include in every request header:

```
Authorization: Bearer <access_token>
```

---

## 2. Common Patterns

### 2.1 Audit Workflow (All Device Types)

```
1. POST  /api/audit/{device}/execute        → Run audit, returns session summary
2. GET   /api/audit/{device}/sessions        → List all sessions (paginated)
3. GET   /api/audit/{device}/sessions/{id}   → Get single session summary
4. GET   /api/audit/{device}/sessions/{id}/results → Get individual check results
5. DELETE /api/audit/{device}/sessions/{id}  → Delete a session
```

### 2.2 Hardening Workflow (All Device Types)

**Option A — Single Check Fix:**
```
1. POST  /api/hardening/{device}/preview     → Preview commands for one check
2. POST  /api/hardening/{device}/execute     → Execute the fix
```

**Option B — Automatic Hardening (safe defaults):**
```
1. GET   /api/hardening/{device}/session/{id}/auto-preview  → See auto-fixable checks
2. POST  /api/hardening/{device}/auto-harden-defaults       → Apply all safe defaults
```

**Option C — Batch Execution (user selects checks):**
```
1. GET   /api/hardening/{device}/session/{id}/parameters    → Get required parameters
2. POST  /api/hardening/{device}/batch-execute              → Execute selected checks
```

### 2.3 Profile/Level Options

| Profile | Description |
|---------|-------------|
| `L1` | Level 1 — Basic security checks (recommended baseline) |
| `L2` | Level 2 — Advanced checks (FortiGate only supports L1/L2 separately) |
| `FULL` | All checks (L1 + L2 + INFO) |

### 2.4 Pagination

Most list endpoints accept:
- `limit` (int, default 50, max 100) — number of items
- `offset` (int, default 0) — skip N items

### 2.5 Credentials Are Never Stored

SSH/DB credentials are used only during the session and are **never** persisted to the database. The frontend must collect them each time.

---

## 3. Audit API

### 3.1 Cisco Audit

**Base:** `/api/audit/cisco`
**Permission:** `AUDIT` (read for GET, write for POST/DELETE)

#### POST `/api/audit/cisco/execute`

Run a CIS Benchmark audit against a Cisco IOS/IOS-XE device.

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "ssh_secret": "enable_secret_or_null",
  "profile": "L1",
  "job_name": "Q1 Compliance Check"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | Must exist in asset inventory |
| `ssh_username` | string | Yes | SSH login |
| `ssh_password` | string | Yes | SSH password |
| `ssh_secret` | string | No | Enable secret for privileged mode |
| `profile` | string | No | `"L1"` (default) or `"FULL"` |
| `job_name` | string | No | Human-readable label |

**Response (200):** [AuditSessionResponse](#audit-session-response)

#### GET `/api/audit/cisco/sessions`

List audit sessions. Query params: `limit`, `offset`.

**Response:** Array of [AuditSessionResponse](#audit-session-response)

#### GET `/api/audit/cisco/sessions/count`

**Response:**
```json
{ "total": 42 }
```

#### GET `/api/audit/cisco/sessions/{session_id}`

**Response:** Single [AuditSessionResponse](#audit-session-response)

#### GET `/api/audit/cisco/sessions/{session_id}/results`

**Response:** Array of [AuditResultResponse](#audit-result-response)

```json
[
  {
    "id": 1,
    "check_number": "CISCO-L1-001",
    "check_title": "Ensure 'aaa new-model' is enabled",
    "severity": "high",
    "level": "L1",
    "status": "pass",
    "evidence_snippet": "aaa new-model is configured",
    "checked_at": "2026-02-27T10:30:00"
  }
]
```

#### GET `/api/audit/cisco/sessions/{session_id}/cis-table`

Returns results formatted as a CIS Benchmark table (useful for PDF-style reports).

#### POST `/api/audit/cisco/cis-benchmark/execute`

Full CIS Benchmark audit (70+ checks). Same request body as `/execute`.

#### GET `/api/audit/cisco/asset/{asset_id}/history`

Query params: `limit` (default 10). Returns audit history for a specific asset.

#### DELETE `/api/audit/cisco/sessions/{session_id}`

Deletes a session and all its results. Requires `AUDIT` write permission.

---

### 3.2 FortiNet Audit

**Base:** `/api/audit/fortinet`
**Permission:** `AUDIT`

#### POST `/api/audit/fortinet/execute`

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "vdom": "root",
  "profile": "L1",
  "job_name": "FortiGate Audit"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | |
| `ssh_username` | string | Yes | |
| `ssh_password` | string | Yes | |
| `vdom` | string | No | Virtual Domain name (null = global) |
| `profile` | string | No | `"L1"`, `"L2"`, or `"FULL"` |
| `job_name` | string | No | |

#### POST `/api/audit/fortinet/vdoms/discover`

Discover available VDOMs on a FortiGate device.

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "admin",
  "ssh_password": "secret"
}
```

**Response:**
```json
{
  "asset_id": 1,
  "asset_name": "FW-01",
  "target_ip": "192.168.1.1",
  "vdoms": ["root", "dmz", "internal"]
}
```

#### Other Endpoints

Same pattern as Cisco: `/sessions`, `/sessions/count`, `/sessions/{id}`, `/sessions/{id}/results`, `/asset/{id}/history`, `DELETE /sessions/{id}`.

---

### 3.3 Linux Audit

**Base:** `/api/audit/linux`
**Permission:** `AUDIT`

#### POST `/api/audit/linux/execute`

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "root",
  "ssh_password": "secret",
  "sudo_password": "sudo_pass_or_null",
  "profile": "L1",
  "job_name": "Ubuntu Server Audit"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | |
| `ssh_username` | string | Yes | |
| `ssh_password` | string | Yes | |
| `sudo_password` | string | No | Required if not root |
| `profile` | string | No | `"L1"` or `"FULL"` |
| `job_name` | string | No | |

**Supported distros** (auto-detected): Ubuntu 22.04/24.04, Rocky Linux 8/9/10, RHEL 8/9/10.

#### GET `/api/audit/linux/supported-distros`

**Response:** List of supported distributions with IDs and version details.

#### GET `/api/audit/linux/statistics`

Query params: `asset_id` (optional). Returns aggregated audit statistics.

#### GET `/api/audit/linux/sessions/{session_id}/failed`

Returns only failed checks — useful for the hardening workflow.

**Response:** Array of failed check objects.

#### Other Endpoints

`/sessions`, `/sessions/count`, `/sessions/{id}`, `/sessions/{id}/results`, `/asset/{id}/history`, `DELETE /sessions/{id}`.

---

### 3.4 MongoDB Audit

**Base:** `/api/audit/mongodb`
**Permission:** `AUDIT`

#### POST `/api/audit/mongodb/execute`

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "admin",
  "ssh_password": "ssh_secret",
  "mongo_username": "mongoAdmin",
  "mongo_password": "mongo_secret",
  "mongo_port": 27017,
  "profile": "L1",
  "job_name": "MongoDB Audit"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | |
| `ssh_username` | string | Yes | SSH access to the host |
| `ssh_password` | string | Yes | |
| `mongo_username` | string | No | MongoDB admin user |
| `mongo_password` | string | No | MongoDB admin password |
| `mongo_port` | int | No | Default: 27017 |
| `profile` | string | No | `"L1"` or `"FULL"` |
| `job_name` | string | No | |

#### Other Endpoints

`/sessions`, `/sessions/count`, `/sessions/{id}`, `/sessions/{id}/results`, `/asset/{id}/history`, `DELETE /sessions/{id}`.

---

### 3.5 MSSQL Audit

**Base:** `/api/audit/mssql`
**Permission:** `AUDIT`

**Important:** MSSQL uses **direct T-SQL connection** (pymssql), NOT SSH. Only SQL credentials are needed.

#### POST `/api/audit/mssql/execute`

**Request:**
```json
{
  "asset_id": 1,
  "mssql_username": "sa",
  "mssql_password": "YourStrong!Pass",
  "mssql_port": 1433,
  "profile": "L1",
  "job_name": "SQL Server Audit"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | |
| `mssql_username` | string | Yes | SA or sysadmin user |
| `mssql_password` | string | Yes | |
| `mssql_port` | int | No | Default: 1433 |
| `profile` | string | No | `"L1"` or `"FULL"` |
| `job_name` | string | No | |

#### Other Endpoints

`/sessions`, `/sessions/count`, `/sessions/{id}`, `/sessions/{id}/results`, `/asset/{id}/history`, `DELETE /sessions/{id}`.

---

### 3.6 Windows Audit

**Base:** `/api/audit/windows`
**Permission:** `AUDIT`

**Important:** Uses **WinRM over HTTPS** (port 5986 by default), NOT SSH.

#### POST `/api/audit/windows/execute`

**Request:**
```json
{
  "asset_id": 1,
  "windows_username": "Administrator",
  "windows_password": "P@ssw0rd",
  "winrm_port": 5986,
  "transport": "ntlm",
  "profile": "L1",
  "job_name": "Windows Server 2022 Audit"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | |
| `windows_username` | string | Yes | `DOMAIN\user` or local admin |
| `windows_password` | string | Yes | |
| `winrm_port` | int | No | Default: 5986 (HTTPS) |
| `transport` | string | No | `"ntlm"` (default), `"kerberos"`, `"credssp"`, `"basic"` |
| `profile` | string | No | `"L1"` or `"FULL"` |
| `job_name` | string | No | |

#### Other Endpoints

`/sessions`, `/sessions/count`, `/sessions/{id}`, `/sessions/{id}/results`, `/asset/{id}/history`, `DELETE /sessions/{id}`.

---

### 3.7 Apache Audit

**Base:** `/api/audit/apache`
**Permission:** `AUDIT`

#### POST `/api/audit/apache/execute`

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "sudo_password": "sudo_pass_or_null",
  "profile": "L1",
  "job_name": "Apache CIS Audit"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `asset_id` | int | Yes | |
| `ssh_username` | string | Yes | |
| `ssh_password` | string | Yes | |
| `sudo_password` | string | No | Required if not root |
| `profile` | string | No | `"L1"` or `"FULL"` |
| `job_name` | string | No | |

**Supported:** Apache 2.4.x on Ubuntu/Debian and RHEL/Rocky/CentOS.

#### GET `/api/audit/apache/supported-configs`

Returns supported distributions and Apache service names.

#### GET `/api/audit/apache/benchmark-info`

Returns CIS Apache HTTP Server Benchmark details.

#### GET `/api/audit/apache/statistics`

Query params: `asset_id` (optional). Returns aggregated statistics.

#### GET `/api/audit/apache/sessions/{session_id}/failed`

Returns only failed checks.

#### Other Endpoints

`/sessions`, `/sessions/count`, `/sessions/{id}`, `/sessions/{id}/results`, `/asset/{id}/history`, `DELETE /sessions/{id}`.

---

## 4. Hardening API

### 4.1 Cisco Hardening

**Base:** `/api/hardening/cisco`
**Permission:** `HARDENING`

#### POST `/api/hardening/cisco/preview`

Preview the commands that will be executed for a single check.

**Request:**
```json
{
  "audit_result_id": 42,
  "parameters": { "NTP_SERVER": "10.0.0.1" }
}
```

**Response:**
```json
{
  "action_id": 1,
  "check_number": "CISCO-L1-015",
  "check_title": "Ensure NTP is configured",
  "commands": ["ntp server 10.0.0.1"],
  "requires_config_mode": true,
  "required_parameters": ["NTP_SERVER"],
  "optional_parameters": [],
  "warnings": []
}
```

#### POST `/api/hardening/cisco/execute`

Execute a previewed hardening action.

**Request:**
```json
{
  "action_id": 1,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "ssh_secret": "enable_secret",
  "parameters": { "NTP_SERVER": "10.0.0.1" },
  "skip_backup": false
}
```

#### POST `/api/hardening/cisco/auto-audit`

Run audit and categorize results into fixable/unfixable.

**Request:**
```json
{
  "ip_address": "192.168.1.1",
  "ssh_username": "admin",
  "ssh_password": "secret",
  "ssh_secret": "enable_secret",
  "profile": "L1",
  "asset_id": 1
}
```

#### GET `/api/hardening/cisco/session/{session_id}/parameters`

Get aggregated parameters needed for batch execution of failed checks.

Query params: `check_ids` (comma-separated, optional — filter to specific checks).

#### GET `/api/hardening/cisco/session/{session_id}/auto-preview`

Preview all auto-fixable checks with their default parameter values.

#### POST `/api/hardening/cisco/auto-harden-defaults`

Apply all auto-fixable checks using safe default values.

**Request:**
```json
{
  "audit_session_id": 10,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "ssh_secret": "enable_secret",
  "confirmed": true,
  "skip_backup": false
}
```

> `confirmed` must be `true` — acts as a safety gate.

#### POST `/api/hardening/cisco/batch-execute`

Execute multiple selected checks at once.

**Request:**
```json
{
  "audit_session_id": 10,
  "check_ids": [1, 2, 3],
  "parameters": { "NTP_SERVER": "10.0.0.1" },
  "ssh_username": "admin",
  "ssh_password": "secret",
  "ssh_secret": "enable_secret",
  "skip_backup": false
}
```

#### POST `/api/hardening/cisco/auto-fix`

Auto-fix all fixable failures from an audit session.

**Request:**
```json
{
  "audit_session_id": 10,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "ssh_secret": "enable_secret",
  "parameters": {},
  "skip_backup": false
}
```

#### GET `/api/hardening/cisco/actions`

List hardening actions. Query params: `asset_id`, `user_id`, `status_filter`, `limit` (50), `offset` (0).

#### GET `/api/hardening/cisco/actions/{action_id}`

Get detailed action with commands and verification result.

#### DELETE `/api/hardening/cisco/actions/{action_id}`

Delete a hardening action record.

---

### 4.2 FortiNet Hardening

**Base:** `/api/hardening/fortinet`
**Permission:** `HARDENING`

Same endpoint structure as Cisco with these differences:

- **VDOM support:** Most endpoints accept an optional `vdom` parameter.
- **No `ssh_secret`:** FortiGate doesn't use enable secret.

#### Key Request Differences

```json
{
  "audit_session_id": 10,
  "ssh_username": "admin",
  "ssh_password": "secret",
  "vdom": "root",
  "confirmed": true,
  "skip_backup": false
}
```

All endpoints follow the same pattern: `/preview`, `/execute`, `/session/{id}/parameters`, `/session/{id}/auto-preview`, `/auto-harden-defaults`, `/batch-execute`, `/actions`, `/actions/{id}`.

---

### 4.3 Linux Hardening

**Base:** `/api/hardening/linux`
**Permission:** `HARDENING`

#### GET `/api/hardening/linux/session/{session_id}/parameters`

Get required parameters for all failed checks.

**Response:**
```json
{
  "session_id": 10,
  "total_failed": 15,
  "auto_fixable": 10,
  "needs_parameters": 3,
  "manual_only": 2,
  "categories": {
    "auto_fixable": [
      {
        "check_id": "LINUX-L1-005",
        "check_title": "Ensure permissions on /etc/passwd are configured",
        "parameters": {}
      }
    ],
    "parameterized": [
      {
        "check_id": "LINUX-L1-020",
        "check_title": "Ensure SSH access is limited",
        "parameters": {
          "ALLOWED_SSH_USERS": {
            "description": "Space-separated list of allowed SSH users",
            "default": "root",
            "required": true
          }
        }
      }
    ],
    "manual_only": [...]
  }
}
```

#### GET `/api/hardening/linux/session/{session_id}/auto-preview`

Preview all auto-fixable checks.

#### POST `/api/hardening/linux/auto-harden-defaults`

**Request:**
```json
{
  "session_id": 10,
  "asset_id": 1,
  "ssh_username": "root",
  "ssh_password": "secret",
  "sudo_password": "sudo_pass_or_null"
}
```

#### POST `/api/hardening/linux/batch-execute`

**Request:**
```json
{
  "session_id": 10,
  "asset_id": 1,
  "ssh_username": "root",
  "ssh_password": "secret",
  "sudo_password": "sudo_pass_or_null",
  "checks": [
    {
      "check_id": "LINUX-L1-020",
      "parameters": { "ALLOWED_SSH_USERS": "admin deploy" }
    },
    {
      "check_id": "LINUX-L1-005",
      "parameters": {}
    }
  ]
}
```

#### POST `/api/hardening/linux/execute-single`

Execute a single hardening check.

**Request:**
```json
{
  "asset_id": 1,
  "ssh_username": "root",
  "ssh_password": "secret",
  "sudo_password": "sudo_pass_or_null",
  "check_id": "LINUX-L1-005",
  "parameters": {}
}
```

#### GET `/api/hardening/linux/supported-checks`

List all checks that have hardening templates.

#### GET `/api/hardening/linux/check/{check_id}/template`

Get template details including commands, verify commands, parameters, and defaults.

---

### 4.4 MongoDB Hardening

**Base:** `/api/hardening/mongodb`
**Permission:** `HARDENING`

Same endpoint structure as Linux with these differences:

- **No `sudo_password` field** — uses `ssh_password` for sudo internally.
- **Service restart** is automatic when needed (restarts `mongod`).
- **No distro detection** — `mongod.conf` is consistent across distributions.

#### Key Request Differences

```json
{
  "session_id": 10,
  "asset_id": 1,
  "ssh_username": "admin",
  "ssh_password": "secret"
}
```

Endpoints: `/session/{id}/parameters`, `/session/{id}/auto-preview`, `/auto-harden-defaults`, `/batch-execute`, `/execute-single`, `/supported-checks`, `/check/{id}/template`.

---

### 4.5 MSSQL Hardening

**Base:** `/api/hardening/mssql`
**Permission:** `HARDENING`

**Important:** Uses **T-SQL** (pymssql) — no SSH. Commands are SQL statements, not shell commands.

#### Key Request Format

```json
{
  "session_id": 10,
  "asset_id": 1,
  "mssql_username": "sa",
  "mssql_password": "YourStrong!Pass",
  "mssql_port": 1433
}
```

#### Hardening Capabilities

| Category | Count | Examples |
|----------|-------|---------|
| Auto-fixable | 12 | `sp_configure` options, disable SA account |
| Parameterized | 9 | Rename SA account, set audit level |
| Manual-only | 5 | Install patches, change auth mode, TDE encryption |

#### Manual-Only Checks (cannot be auto-fixed)

- `MSSQL-L1-001` — Latest patches (requires manual download/install)
- `MSSQL-L1-013` — Authentication mode (requires SSMS)
- `MSSQL-L2-018` — Public role permissions (complex per-DB review)
- `MSSQL-L2-025` — TDE encryption (requires certificate setup)
- `MSSQL-L1-026` — Change default port (requires service restart)

Endpoints: `/session/{id}/parameters`, `/session/{id}/auto-preview`, `/auto-harden-defaults`, `/batch-execute`, `/execute-single`, `/supported-checks`, `/check/{id}/template`.

---

### 4.6 Schema-Driven Hardening (Shared)

**Base:** `/api/hardening/schema`
**Permission:** `HARDENING`

A newer, unified approach that generates dynamic forms from schema definitions.

#### POST `/api/hardening/schema/form`

Get a complete form schema with all controls and input fields.

**Request:**
```json
{
  "device_type": "cisco",
  "mode": "post_audit",
  "session_id": 10,
  "check_numbers": ["CISCO-L1-001", "CISCO-L1-002"]
}
```

| Field | Type | Notes |
|-------|------|-------|
| `device_type` | string | `"cisco"`, `"fortinet"`, `"linux"`, `"windows"`, `"apache"` |
| `mode` | string | `"post_audit"` (uses session) or `"full"` (all checks) |
| `session_id` | int | Required for `post_audit` mode |
| `check_numbers` | array | Optional — filter to specific checks |

#### POST `/api/hardening/schema/validate`

Validate user inputs before execution.

**Request:**
```json
{
  "device_type": "cisco",
  "control_states": [
    {
      "control_id": "CISCO-L1-001",
      "state": "APPLY",
      "inputs": { "NTP_SERVER": "10.0.0.1" }
    }
  ],
  "shared_fields": {}
}
```

Control states: `"SKIP"`, `"AUDIT"` (check only), `"APPLY"` (fix).

#### POST `/api/hardening/schema/execute`

Execute hardening based on validated form data.

**Request:**
```json
{
  "device_type": "cisco",
  "device_ip": "192.168.1.1",
  "session_id": 10,
  "control_states": [...],
  "shared_fields": {},
  "ssh_credentials": {
    "username": "admin",
    "password": "secret",
    "secret": "enable_secret"
  },
  "skip_backup": false
}
```

#### GET `/api/hardening/schema/devices`

List supported device types.

#### GET `/api/hardening/schema/control/{device_type}/{control_id}`

Get a single control definition.

---

## 5. Response Schemas

### Audit Session Response

```json
{
  "session_id": 10,
  "job_name": "Q1 Audit",
  "asset_id": 1,
  "asset_name": "web-server-01",
  "target_ip": "192.168.1.100",
  "device_type": "cisco",
  "status": "completed",
  "started_at": "2026-02-27T10:00:00",
  "completed_at": "2026-02-27T10:02:30",
  "duration_seconds": 150.0,
  "compliance": {
    "total_checks": 72,
    "passed": 58,
    "failed": 12,
    "errors": 2,
    "compliance_pct": 80.6,
    "weighted_compliance_pct": 82.3
  },
  "connection_error": null
}
```

| Field | Type | Notes |
|-------|------|-------|
| `status` | string | `"completed"`, `"failed"`, `"executing"` |
| `connection_error` | string/null | Non-null when connection failed |
| `compliance_pct` | float | 0–100, simple pass/total ratio |
| `weighted_compliance_pct` | float/null | Severity-weighted score |

### Audit Result Response

```json
{
  "id": 1,
  "check_number": "CISCO-L1-001",
  "check_title": "Ensure 'aaa new-model' is enabled",
  "severity": "high",
  "level": "L1",
  "status": "pass",
  "evidence_snippet": "aaa new-model is configured",
  "checked_at": "2026-02-27T10:01:15"
}
```

| Field | Type | Values |
|-------|------|--------|
| `severity` | string | `"high"`, `"medium"`, `"low"` |
| `level` | string | `"L1"`, `"L2"`, `"INFO"` |
| `status` | string | `"pass"`, `"fail"`, `"error"` |
| `checked_at` | string/null | ISO 8601 timestamp |

### Hardening Action Response

```json
{
  "id": 1,
  "audit_result_id": 42,
  "asset_id": 1,
  "check_number": "CISCO-L1-015",
  "check_title": "Ensure NTP is configured",
  "action_type": "execute",
  "status": "success",
  "requires_config_mode": true,
  "verification_passed": true,
  "created_at": "2026-02-27T11:00:00",
  "executed_at": "2026-02-27T11:00:05",
  "completed_at": "2026-02-27T11:00:10"
}
```

| Field | Type | Values |
|-------|------|--------|
| `action_type` | string | `"preview"`, `"execute"` |
| `status` | string | `"pending"`, `"success"`, `"failed"`, `"blocked"` |
| `verification_passed` | bool/null | Whether post-fix verification succeeded |

---

## 6. Error Handling

### Standard Error Response

```json
{
  "detail": "Human-readable error message"
}
```

### HTTP Status Codes

| Code | Meaning | Common Causes |
|------|---------|---------------|
| 400 | Bad Request | Invalid parameters, missing required fields |
| 401 | Unauthorized | SSH/WinRM/SQL auth failed, expired JWT |
| 403 | Forbidden | Insufficient permissions for the operation |
| 404 | Not Found | Session/asset/action does not exist |
| 409 | Conflict | Session already in progress (some modules) |
| 500 | Internal Server Error | Unexpected backend error |
| 502 | Bad Gateway | SSH algorithm mismatch, host key error |
| 503 | Service Unavailable | Device unreachable |
| 504 | Gateway Timeout | Connection timeout |

### Frontend Error Handling Recommendations

```javascript
try {
  const response = await api.post('/api/audit/cisco/execute', data);
  // Handle success
} catch (error) {
  const status = error.response?.status;
  const detail = error.response?.data?.detail;

  if (status === 401) {
    // Credential error — show "Invalid credentials" message
  } else if (status === 503) {
    // Device offline — show "Device unreachable" message
  } else if (status === 504) {
    // Timeout — show "Connection timed out" with retry option
  } else {
    // Generic error — show detail message
  }
}
```

---

## 7. Device-Specific Notes

### Cisco IOS/IOS-XE
- Requires **enable secret** (`ssh_secret`) for privileged commands.
- Hardening may require **config mode** — the `requires_config_mode` flag in preview responses indicates this.
- Config backup is taken automatically before hardening (unless `skip_backup: true`).

### FortiGate
- **VDOM support** — use `/vdoms/discover` to list available VDOMs, then pass `vdom` to audit/hardening endpoints.
- Supports separate **L1** and **L2** profiles (not just L1/FULL).
- No enable secret needed.

### Linux (Ubuntu, Rocky, RHEL)
- **Distro auto-detection** — the backend detects the OS and uses distro-specific commands.
- `sudo_password` is required when connecting as a non-root user.
- Use `/supported-distros` to show users which distributions are supported.
- Hardening may require **service restarts** — the template metadata indicates this.

### MongoDB
- Requires **both SSH and MongoDB credentials** — SSH for host-level checks, MongoDB for database-level checks.
- Hardening uses SSH only (edits `mongod.conf` and restarts `mongod`).
- No `sudo_password` field — `ssh_password` is used for sudo internally.

### MSSQL
- **No SSH** — connects directly via T-SQL (pymssql on port 1433).
- Hardening commands are SQL statements (`sp_configure`, `ALTER LOGIN`, etc.), not shell commands.
- Same credentials for both audit and hardening.
- 5 checks require manual intervention (see section 4.5).

### Windows Server
- **WinRM over HTTPS** (port 5986) — the target server must have WinRM configured.
- Transport options: `ntlm` (most common), `kerberos` (domain), `credssp`, `basic`.
- Username format: `DOMAIN\username` for domain accounts, `username` for local.
- 80-110+ CIS checks (comprehensive Windows Server benchmark).

### Apache HTTP Server
- Accessed via **SSH** to the host running Apache.
- Supports both Debian-family (`apache2`) and RHEL-family (`httpd`) installations.
- `sudo_password` required for config file modifications.
- Use `/supported-configs` to show supported distributions.
