# Linux CIS Audit & Hardening - Frontend Integration Guide

> **Last Updated:** 2026-02-12
> **Backend Status:** Ready
> **API Version:** 1.0

---

## Quick Summary

| Component | Status | Endpoints | Notes |
|-----------|--------|-----------|-------|
| Linux Audit API | Ready | 10 endpoints | Full CIS audit workflow |
| Linux Hardening API | Ready | 7 endpoints | 3 hardening modes |
| Redux Integration | Pre-wired | `deviceType: 'linux'` | Uses existing hardeningSlice |

---

## Table of Contents

1. [Linux Audit API](#part-1-linux-audit-api)
2. [Linux Hardening API](#part-2-linux-hardening-api)
3. [Parameter Types Reference](#part-3-parameter-types-reference)
4. [Frontend Integration Guide](#part-4-frontend-integration-guide)
5. [Workflow Examples](#part-5-workflow-examples)
6. [Error Handling](#part-6-error-handling)
7. [Device Type Badge](#part-7-device-type-badge)
8. [Testing Checklist](#part-8-testing-checklist)

---

## Part 1: Linux Audit API

**Base URL**: `/api/audit/linux`

### 1.1 Execute Linux Audit

```
POST /api/audit/linux/execute
```

**Request:**
```json
{
  "asset_id": 25,
  "ssh_username": "admin",
  "ssh_password": "password",
  "sudo_password": "optional_sudo_pass",
  "profile": "L1"
}
```

**Response:**
```json
{
  "session_id": 10,
  "asset_id": 25,
  "asset_name": "Ubuntu Server",
  "target_ip": "192.168.1.100",
  "device_type": "linux",
  "status": "completed",
  "started_at": "2026-02-12T10:30:00Z",
  "completed_at": "2026-02-12T10:32:45Z",
  "duration_seconds": 165.5,
  "compliance": {
    "total_checks": 145,
    "passed": 120,
    "failed": 25,
    "errors": 0,
    "compliance_pct": 82.76,
    "weighted_compliance_pct": 85.50
  }
}
```

**Notes:**
- `profile` can be `"L1"` (Level 1 - Server) or `"L2"` (Level 2 - Server)
- `sudo_password` is optional, falls back to `ssh_password` if not provided
- Supports Ubuntu 22.04/24.04 and Rocky Linux 8/9

---

### 1.2 List Audit Sessions

```
GET /api/audit/linux/sessions?limit=50&offset=0
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 50 | Max sessions to return |
| `offset` | int | 0 | Pagination offset |

**Response:**
```json
{
  "sessions": [
    {
      "id": 10,
      "asset_id": 25,
      "asset_name": "Ubuntu Server",
      "target_ip": "192.168.1.100",
      "status": "completed",
      "started_at": "2026-02-12T10:30:00Z",
      "compliance_pct": 82.76
    }
  ],
  "total": 45
}
```

---

### 1.3 Get Session Count

```
GET /api/audit/linux/sessions/count
```

**Response:**
```json
{
  "total": 45
}
```

---

### 1.4 Get Session Details

```
GET /api/audit/linux/sessions/{session_id}
```

**Response:**
```json
{
  "id": 10,
  "asset_id": 25,
  "asset_name": "Ubuntu Server",
  "target_ip": "192.168.1.100",
  "device_type": "linux",
  "distro": "ubuntu",
  "distro_version": "22.04",
  "status": "completed",
  "started_at": "2026-02-12T10:30:00Z",
  "completed_at": "2026-02-12T10:32:45Z",
  "duration_seconds": 165.5,
  "profile": "L1",
  "compliance": {
    "total_checks": 145,
    "passed": 120,
    "failed": 25,
    "errors": 0,
    "compliance_pct": 82.76,
    "weighted_compliance_pct": 85.50
  }
}
```

---

### 1.5 Get Detailed Results

```
GET /api/audit/linux/sessions/{session_id}/results
```

**Response:**
```json
{
  "session_id": 10,
  "results": [
    {
      "id": 1,
      "check_number": "LNX-L1-1.1.1.1",
      "check_title": "Ensure mounting of cramfs filesystems is disabled",
      "section": "1.1.1",
      "severity": "medium",
      "level": "L1",
      "status": "pass",
      "evidence_snippet": "install /bin/true",
      "checked_at": "2026-02-12T10:30:45Z"
    },
    {
      "id": 2,
      "check_number": "LNX-L1-1.1.1.2",
      "check_title": "Ensure mounting of squashfs filesystems is disabled",
      "section": "1.1.1",
      "severity": "medium",
      "level": "L1",
      "status": "fail",
      "evidence_snippet": "Module not disabled",
      "checked_at": "2026-02-12T10:30:46Z"
    }
  ]
}
```

**Status Values:**
- `pass` - Check passed
- `fail` - Check failed (remediation needed)
- `error` - Check could not be executed

---

### 1.6 Get Failed Checks Only (For Hardening)

```
GET /api/audit/linux/sessions/{session_id}/failed
```

**Response:**
```json
{
  "session_id": 10,
  "failed_count": 25,
  "results": [
    {
      "id": 2,
      "check_number": "LNX-L1-1.1.1.2",
      "check_title": "Ensure mounting of squashfs filesystems is disabled",
      "severity": "medium",
      "level": "L1",
      "status": "fail",
      "evidence_snippet": "Module not disabled"
    }
  ]
}
```

---

### 1.7 Get Asset Audit History

```
GET /api/audit/linux/asset/{asset_id}/history?limit=10
```

**Response:**
```json
{
  "asset_id": 25,
  "sessions": [
    {
      "id": 10,
      "started_at": "2026-02-12T10:30:00Z",
      "compliance_pct": 82.76,
      "status": "completed"
    },
    {
      "id": 8,
      "started_at": "2026-02-10T14:15:00Z",
      "compliance_pct": 75.00,
      "status": "completed"
    }
  ]
}
```

---

### 1.8 Delete Session

```
DELETE /api/audit/linux/sessions/{session_id}
```

**Response:**
```json
{
  "message": "Session deleted successfully",
  "session_id": 10
}
```

---

### 1.9 Get Statistics

```
GET /api/audit/linux/statistics?asset_id=25
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `asset_id` | int | No | Filter by specific asset |

**Response:**
```json
{
  "total_sessions": 45,
  "avg_compliance_pct": 78.5,
  "most_failed_checks": [
    {
      "check_number": "LNX-L1-1.6.1",
      "check_title": "Ensure local login warning banner is configured",
      "failure_count": 38
    }
  ],
  "compliance_trend": [
    { "date": "2026-02-10", "avg_compliance": 75.0 },
    { "date": "2026-02-11", "avg_compliance": 78.5 },
    { "date": "2026-02-12", "avg_compliance": 82.0 }
  ]
}
```

---

### 1.10 Get Supported Distributions

```
GET /api/audit/linux/supported-distros
```

**Response:**
```json
{
  "distributions": [
    {
      "name": "ubuntu",
      "display_name": "Ubuntu",
      "versions": ["22.04", "24.04"],
      "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0"
    },
    {
      "name": "rocky",
      "display_name": "Rocky Linux",
      "versions": ["8", "9"],
      "benchmark": "CIS Rocky Linux 8 Benchmark v2.0.0"
    }
  ]
}
```

---

## Part 2: Linux Hardening API

**Base URL**: `/api/hardening/linux`

### 2.1 Get Session Parameters

```
GET /api/hardening/linux/session/{session_id}/parameters
```

**Response:**
```json
{
  "session_id": 10,
  "total_failed": 25,
  "parameters": {
    "BANNER_TEXT": {
      "type": "textarea",
      "label": "Warning Banner Text",
      "description": "Login warning banner displayed to users",
      "required": true,
      "default": null,
      "checks": ["LNX-L1-1.6.1", "LNX-L1-1.6.2"]
    },
    "SSH_MAX_AUTH_TRIES": {
      "type": "number",
      "label": "SSH Max Auth Tries",
      "description": "Maximum authentication attempts before disconnect",
      "default": "4",
      "min_value": 1,
      "max_value": 10,
      "checks": ["LNX-L1-5.2.7"]
    },
    "PASS_MIN_LEN": {
      "type": "number",
      "label": "Minimum Password Length",
      "description": "Minimum number of characters for passwords",
      "default": "14",
      "min_value": 8,
      "max_value": 32,
      "checks": ["LNX-L1-5.3.1"]
    }
  },
  "categorized_checks": {
    "auto_fixable": ["LNX-L1-1.1.1.1", "LNX-L1-2.2.1", "LNX-L1-3.1.1"],
    "needs_params": ["LNX-L1-1.6.1", "LNX-L1-1.6.2"],
    "not_supported": ["LNX-L1-6.1.10"]
  },
  "failed_checks": [
    {
      "check_number": "LNX-L1-1.1.1.1",
      "check_title": "Ensure mounting of cramfs filesystems is disabled",
      "severity": "medium",
      "level": "L1",
      "has_template": true,
      "auto_fixable": true
    },
    {
      "check_number": "LNX-L1-1.6.1",
      "check_title": "Ensure local login warning banner is configured",
      "severity": "low",
      "level": "L1",
      "has_template": true,
      "auto_fixable": false
    }
  ]
}
```

**Categorization Logic:**
- `auto_fixable` - Has template with all defaults, can be fixed automatically
- `needs_params` - Has template but requires user input (e.g., banner text)
- `not_supported` - No hardening template available

---

### 2.2 Preview Auto-Hardening

```
GET /api/hardening/linux/session/{session_id}/auto-preview
```

**Response:**
```json
{
  "session_id": 10,
  "total_failed": 25,
  "auto_fixable_count": 20,
  "needs_params_count": 4,
  "not_supported_count": 1,
  "preview": [
    {
      "check_number": "LNX-L1-1.1.1.1",
      "check_title": "Ensure mounting of cramfs filesystems is disabled",
      "section": "1.1.1",
      "description": "Disable unused cramfs filesystem module",
      "defaults": {}
    },
    {
      "check_number": "LNX-L1-5.3.1",
      "check_title": "Ensure password creation requirements are configured",
      "section": "5.3.1",
      "description": "Set minimum password length",
      "defaults": {
        "PASS_MIN_LEN": "14"
      }
    }
  ],
  "skipped": {
    "needs_params": [
      {
        "check_number": "LNX-L1-1.6.1",
        "check_title": "Ensure local login warning banner is configured",
        "reason": "Requires BANNER_TEXT parameter"
      }
    ],
    "not_supported": [
      {
        "check_number": "LNX-L1-6.1.10",
        "check_title": "Ensure no unowned files or directories exist",
        "reason": "No hardening template available"
      }
    ]
  }
}
```

---

### 2.3 Execute Auto-Hardening

```
POST /api/hardening/linux/auto-harden-defaults
```

**Request:**
```json
{
  "session_id": 10,
  "asset_id": 25,
  "ssh_username": "admin",
  "ssh_password": "password",
  "sudo_password": "optional"
}
```

**Response:**
```json
{
  "session_id": 10,
  "asset_id": 25,
  "target_ip": "192.168.1.100",
  "executed_at": "2026-02-12T15:30:45Z",
  "auto_fixable": 20,
  "successful": 19,
  "failed": 1,
  "results": [
    {
      "check_id": "LNX-L1-1.1.1.1",
      "check_title": "Ensure mounting of cramfs filesystems is disabled",
      "status": "success",
      "message": "Applied successfully",
      "verified": true
    },
    {
      "check_id": "LNX-L1-3.1.2",
      "check_title": "Ensure wireless interfaces are disabled",
      "status": "failed",
      "message": "No wireless interface found",
      "verified": false
    }
  ],
  "skipped": {
    "needs_params": ["LNX-L1-1.6.1"],
    "not_supported": ["LNX-L1-6.1.10"]
  }
}
```

---

### 2.4 Batch Execute Selected Checks

```
POST /api/hardening/linux/batch-execute
```

**Request:**
```json
{
  "session_id": 10,
  "asset_id": 25,
  "ssh_username": "admin",
  "ssh_password": "password",
  "sudo_password": "optional",
  "checks": [
    {
      "check_id": "LNX-L1-1.1.1.1",
      "parameters": {}
    },
    {
      "check_id": "LNX-L1-1.6.1",
      "parameters": {
        "BANNER_TEXT": "Authorized users only! All activity is monitored."
      }
    },
    {
      "check_id": "LNX-L1-5.2.7",
      "parameters": {
        "SSH_MAX_AUTH_TRIES": "3"
      }
    }
  ]
}
```

**Response:**
```json
{
  "session_id": 10,
  "asset_id": 25,
  "target_ip": "192.168.1.100",
  "executed_at": "2026-02-12T15:35:00Z",
  "total": 3,
  "successful": 3,
  "failed": 0,
  "results": [
    {
      "check_id": "LNX-L1-1.1.1.1",
      "check_title": "Ensure mounting of cramfs filesystems is disabled",
      "status": "success",
      "message": "Applied successfully",
      "verified": true
    },
    {
      "check_id": "LNX-L1-1.6.1",
      "check_title": "Ensure local login warning banner is configured",
      "status": "success",
      "message": "Banner configured in /etc/issue",
      "verified": true
    },
    {
      "check_id": "LNX-L1-5.2.7",
      "check_title": "Ensure SSH MaxAuthTries is set to 4 or less",
      "status": "success",
      "message": "MaxAuthTries set to 3",
      "verified": true
    }
  ]
}
```

---

### 2.5 Execute Single Check

```
POST /api/hardening/linux/execute-single
```

**Request:**
```json
{
  "asset_id": 25,
  "ssh_username": "admin",
  "ssh_password": "password",
  "sudo_password": "optional",
  "check_id": "LNX-L1-5.2.10",
  "parameters": {
    "SSH_CLIENT_ALIVE_INTERVAL": "300",
    "SSH_CLIENT_ALIVE_COUNT_MAX": "3"
  }
}
```

**Response:**
```json
{
  "asset_id": 25,
  "target_ip": "192.168.1.100",
  "check_id": "LNX-L1-5.2.10",
  "check_title": "Ensure SSH Idle Timeout Interval is configured",
  "executed_at": "2026-02-12T15:40:00Z",
  "status": "success",
  "message": "SSH idle timeout configured (ClientAliveInterval=300, ClientAliveCountMax=3)",
  "verified": true,
  "commands_executed": [
    "sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config",
    "sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 3/' /etc/ssh/sshd_config",
    "systemctl restart sshd"
  ]
}
```

---

### 2.6 Get Supported Checks

```
GET /api/hardening/linux/supported-checks
```

**Response:**
```json
{
  "total_templates": 102,
  "auto_fixable": 99,
  "needs_params": 3,
  "checks": [
    {
      "check_id": "LNX-L1-1.1.1.1",
      "check_title": "Ensure mounting of cramfs filesystems is disabled",
      "section": "1.1.1",
      "level": "L1",
      "auto_fixable": true,
      "parameters": []
    },
    {
      "check_id": "LNX-L1-1.6.1",
      "check_title": "Ensure local login warning banner is configured",
      "section": "1.6",
      "level": "L1",
      "auto_fixable": false,
      "parameters": ["BANNER_TEXT"]
    }
  ]
}
```

---

### 2.7 Get Check Template Details

```
GET /api/hardening/linux/check/{check_id}/template
```

**Response:**
```json
{
  "check_id": "LNX-L1-5.2.7",
  "check_title": "Ensure SSH MaxAuthTries is set to 4 or less",
  "section": "5.2.7",
  "level": "L1",
  "severity": "medium",
  "has_template": true,
  "auto_fixable": true,
  "description": "Set the SSH MaxAuthTries parameter to limit failed authentication attempts",
  "remediation_steps": [
    "Edit /etc/ssh/sshd_config",
    "Set MaxAuthTries to 4 or less",
    "Restart SSH daemon"
  ],
  "commands_preview": [
    "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries {SSH_MAX_AUTH_TRIES}/' /etc/ssh/sshd_config",
    "systemctl restart sshd"
  ],
  "verify_command": "grep -E '^MaxAuthTries\\s+[1-4]$' /etc/ssh/sshd_config",
  "parameters": {
    "SSH_MAX_AUTH_TRIES": {
      "type": "number",
      "label": "Max Auth Tries",
      "description": "Maximum authentication attempts (1-4)",
      "default": "4",
      "min_value": 1,
      "max_value": 4
    }
  }
}
```

---

## Part 3: Parameter Types Reference

### Input Types

| Type | UI Component | Properties | Example |
|------|-------------|------------|---------|
| `text` | Text input | - | Username, file path |
| `textarea` | Multi-line textarea | - | Banner text, MOTD |
| `password` | Password with show/hide | - | Credentials |
| `number` | Number input | `min_value`, `max_value` | Port, timeout |
| `ip` | Text input with validation | IP regex pattern | Server address |
| `select` | Dropdown | `options` array | Log level |

### Common Parameters Reference

#### Banner/MOTD
| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `BANNER_TEXT` | textarea | - | Yes | Login warning banner text |
| `MOTD_TEXT` | textarea | - | No | Message of the day |

#### Password Policy
| Parameter | Type | Default | Min | Max | Description |
|-----------|------|---------|-----|-----|-------------|
| `PASS_MAX_DAYS` | number | 365 | 1 | 999 | Maximum password age (days) |
| `PASS_MIN_DAYS` | number | 1 | 0 | 30 | Minimum password age (days) |
| `PASS_WARN_AGE` | number | 7 | 1 | 30 | Password expiry warning (days) |
| `PASS_MIN_LEN` | number | 14 | 8 | 32 | Minimum password length |
| `PASS_REMEMBER` | number | 5 | 1 | 24 | Password history to remember |

#### SSH Configuration
| Parameter | Type | Default | Min | Max | Description |
|-----------|------|---------|-----|-----|-------------|
| `SSH_MAX_AUTH_TRIES` | number | 4 | 1 | 10 | Max authentication attempts |
| `SSH_CLIENT_ALIVE_INTERVAL` | number | 300 | 60 | 900 | Idle timeout interval (seconds) |
| `SSH_CLIENT_ALIVE_COUNT_MAX` | number | 3 | 0 | 5 | Max alive messages |
| `SSH_LOGIN_GRACE_TIME` | number | 60 | 30 | 120 | Login grace period (seconds) |
| `SSH_LOG_LEVEL` | select | INFO | - | - | Options: INFO, VERBOSE |

#### PAM/Account Lockout
| Parameter | Type | Default | Min | Max | Description |
|-----------|------|---------|-----|-----|-------------|
| `FAILLOCK_DENY` | number | 5 | 3 | 10 | Failed attempts before lockout |
| `FAILLOCK_UNLOCK_TIME` | number | 900 | 300 | 3600 | Lockout duration (seconds) |
| `INACTIVE_DAYS` | number | 30 | 7 | 90 | Days before inactive account locked |

#### Audit/System
| Parameter | Type | Default | Min | Max | Description |
|-----------|------|---------|-----|-----|-------------|
| `AUDIT_MAX_LOG_FILE` | number | 8 | 4 | 32 | Max audit log size (MB) |
| `FIREWALL_DEFAULT_POLICY` | select | deny | - | - | Options: deny, reject |
| `UMASK_VALUE` | text | 027 | - | - | Default file creation mask |

---

## Part 4: Frontend Integration Guide

### Redux Already Pre-Wired

The existing `hardeningSlice.jsx` already supports Linux:

```javascript
// Line 32 in hardeningSlice.jsx
const prefixes = {
    cisco: '/api/hardening',
    fortinet: '/api/hardening/fortinet',
    linux: '/api/hardening/linux',  // ← Already defined!
};
```

### Use Existing Components

**No new components needed!** Reuse the existing hardening components:

| Component | File | Purpose |
|-----------|------|---------|
| `Hardening.jsx` | Main container | Tab navigation, session selection |
| `AuditResultsTable.jsx` | Results table | Checkbox selection, Fix buttons |
| `FixSingleModal.jsx` | Single fix | Preview → Params → SSH → Execute |
| `FixAllModal.jsx` | Batch fix | Summary → Params → SSH → Execute |
| `AutoHardenModal.jsx` | Auto-harden | Preview → SSH → Execute |
| `ConfigurationForm.jsx` | Parameter form | Dynamic input rendering |
| `SSHCredentialsForm.jsx` | SSH credentials | Username, password, sudo |

### Calling APIs from Redux

#### Fetch Parameters for Failed Checks

```javascript
import { fetchSessionParameters } from '../store/hardeningSlice';

dispatch(fetchSessionParameters({
  sessionId: 10,
  deviceType: 'linux'
}));
```

#### Preview Auto-Hardening

```javascript
import { fetchAutoHardenPreview } from '../store/hardeningSlice';

dispatch(fetchAutoHardenPreview({
  sessionId: 10,
  deviceType: 'linux'
}));
```

#### Execute Auto-Hardening

```javascript
import { executeAutoHarden } from '../store/hardeningSlice';

dispatch(executeAutoHarden({
  sessionId: 10,
  assetId: 25,
  credentials: {
    username: 'admin',
    password: 'password',
    sudo_password: 'sudo_pass'  // Optional for Linux
  },
  deviceType: 'linux'
}));
```

#### Batch Execute Selected Checks

```javascript
import { executeBatchHarden } from '../store/hardeningSlice';

dispatch(executeBatchHarden({
  sessionId: 10,
  assetId: 25,
  checks: [
    { check_id: 'LNX-L1-1.1.1.1', parameters: {} },
    { check_id: 'LNX-L1-1.6.1', parameters: { BANNER_TEXT: 'Authorized only!' } }
  ],
  credentials: {
    username: 'admin',
    password: 'password',
    sudo_password: 'sudo_pass'
  },
  deviceType: 'linux'
}));
```

#### Execute Single Check

```javascript
import { executeSingleHarden } from '../store/hardeningSlice';

dispatch(executeSingleHarden({
  assetId: 25,
  checkId: 'LNX-L1-5.2.7',
  parameters: { SSH_MAX_AUTH_TRIES: '3' },
  credentials: {
    username: 'admin',
    password: 'password'
  },
  deviceType: 'linux'
}));
```

---

## Part 5: Workflow Examples

### Workflow 1: Auto-Harden with Defaults

Best for quickly applying all safe, default-based fixes.

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User selects Linux audit session from dropdown           │
├─────────────────────────────────────────────────────────────┤
│ 2. Clicks "Automatic Hardening" button                      │
├─────────────────────────────────────────────────────────────┤
│ 3. Frontend: GET /session/{id}/auto-preview                 │
│    → Modal shows what will be fixed (count + list)          │
│    → Shows what will be skipped (needs params, unsupported) │
├─────────────────────────────────────────────────────────────┤
│ 4. User enters SSH credentials (including sudo if needed)   │
├─────────────────────────────────────────────────────────────┤
│ 5. Frontend: POST /auto-harden-defaults                     │
│    → Backend executes all auto-fixable checks               │
├─────────────────────────────────────────────────────────────┤
│ 6. Modal shows results:                                     │
│    ✓ 19 successful                                          │
│    ✗ 1 failed (with error message)                          │
│    ○ 5 skipped (needs params or unsupported)                │
└─────────────────────────────────────────────────────────────┘
```

### Workflow 2: Fix Selected Checks (Batch)

Best for fixing multiple checks with custom parameters.

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User views failed checks in results table                │
├─────────────────────────────────────────────────────────────┤
│ 2. Selects checks via checkboxes                            │
│    ☑ LNX-L1-1.1.1.1 - Disable cramfs                       │
│    ☑ LNX-L1-1.6.1 - Configure login banner                 │
│    ☑ LNX-L1-5.2.7 - SSH MaxAuthTries                       │
├─────────────────────────────────────────────────────────────┤
│ 3. Clicks "Fix Selected" button                             │
├─────────────────────────────────────────────────────────────┤
│ 4. Frontend: GET /session/{id}/parameters                   │
│    → Modal shows aggregated parameters for selected checks  │
├─────────────────────────────────────────────────────────────┤
│ 5. User fills parameter form:                               │
│    Banner Text: [Authorized users only!_______________]     │
│    SSH Max Auth Tries: [3]                                  │
├─────────────────────────────────────────────────────────────┤
│ 6. User enters SSH credentials                              │
├─────────────────────────────────────────────────────────────┤
│ 7. Frontend: POST /batch-execute                            │
│    → Backend executes selected checks with parameters       │
├─────────────────────────────────────────────────────────────┤
│ 8. Modal shows per-check results:                           │
│    ✓ LNX-L1-1.1.1.1 - Success                              │
│    ✓ LNX-L1-1.6.1 - Banner configured                      │
│    ✓ LNX-L1-5.2.7 - MaxAuthTries set to 3                  │
└─────────────────────────────────────────────────────────────┘
```

### Workflow 3: Fix Single Check

Best for detailed control over individual remediations.

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User clicks "Fix" button on a specific failed check row  │
│    → LNX-L1-5.2.10: SSH Idle Timeout Interval              │
├─────────────────────────────────────────────────────────────┤
│ 2. Frontend: GET /check/{id}/template                       │
│    → Modal shows remediation details:                       │
│      - Description                                          │
│      - Commands that will be executed                       │
│      - Required parameters                                  │
├─────────────────────────────────────────────────────────────┤
│ 3. User fills parameters (if any):                          │
│    Client Alive Interval: [300] seconds                     │
│    Client Alive Count Max: [3]                              │
├─────────────────────────────────────────────────────────────┤
│ 4. User enters SSH credentials                              │
├─────────────────────────────────────────────────────────────┤
│ 5. Frontend: POST /execute-single                           │
│    → Backend executes remediation                           │
│    → Backend runs verification command                      │
├─────────────────────────────────────────────────────────────┤
│ 6. Modal shows result:                                      │
│    ✓ Success - SSH idle timeout configured                  │
│    Verification: Passed                                     │
│    Commands executed: (shows actual commands)               │
└─────────────────────────────────────────────────────────────┘
```

---

## Part 6: Error Handling

### HTTP Status Codes

| Status | Meaning | Example |
|--------|---------|---------|
| 200 | Success | Operation completed |
| 400 | Bad request | Missing required fields, invalid check ID |
| 401 | Unauthorized | Invalid session token |
| 404 | Not found | Session not found, asset not found |
| 422 | Validation error | Invalid parameter value |
| 500 | Server error | SSH connection failed, command execution error |

### Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `"Session not found"` | Invalid session_id | Verify session exists |
| `"Asset not found"` | Invalid asset_id | Check asset registration |
| `"SSH connection failed"` | Wrong credentials or network | Verify credentials and connectivity |
| `"Permission denied"` | Sudo required | Provide sudo_password |
| `"Check has no template"` | Unsupported check | Check is in "not_supported" category |
| `"Missing required parameter: X"` | Parameter not provided | Fill required parameter |

### Redux Error Handling

```javascript
// In component
const { error, loading } = useSelector(state => state.hardening);

useEffect(() => {
  if (error) {
    notification.error({
      message: 'Hardening Failed',
      description: error.detail || error.message || 'Unknown error'
    });
  }
}, [error]);
```

---

## Part 7: Device Type Badge

Update device type labels to include Linux:

```javascript
// In your constants or component
const deviceTypeLabels = {
  cisco: 'Cisco IOS',
  fortinet: 'FortiGate',
  linux: 'Linux',      // ← Add this
  windows: 'Windows',
  apache: 'Apache',
};

// Badge color mapping
const deviceTypeColors = {
  cisco: 'blue',
  fortinet: 'orange',
  linux: 'green',     // ← Add this
  windows: 'purple',
  apache: 'red',
};
```

### Check ID Format

Linux checks use the format: `LNX-{Level}-{Section}`

| Pattern | Example | Description |
|---------|---------|-------------|
| `LNX-L1-1.1.1.1` | Level 1, Section 1.1.1.1 | cramfs disabled |
| `LNX-L2-4.1.2.1` | Level 2, Section 4.1.2.1 | audit log storage |

---

## Part 8: Testing Checklist

Before deployment, verify the following:

### Session Management
- [ ] Linux sessions appear in session dropdown
- [ ] Session details show distro info (Ubuntu/Rocky)
- [ ] Session list pagination works
- [ ] Delete session removes from list

### Results Display
- [ ] Results table shows Linux CIS checks (LNX-L1-x.x.x format)
- [ ] Pass/Fail status displays correctly
- [ ] Severity badges render (low/medium/high/critical)
- [ ] Evidence snippets display in expandable rows

### Fix Single Mode
- [ ] "Fix" button opens FixSingleModal
- [ ] Template preview shows correct commands
- [ ] Parameters form renders for checks that need input
- [ ] SSH credentials form includes sudo_password field
- [ ] Execute shows success/failure result
- [ ] Verification status displays

### Fix Selected Mode
- [ ] Checkbox selection works for failed checks
- [ ] "Fix Selected" button disabled when nothing selected
- [ ] FixAllModal shows aggregated parameters
- [ ] All parameter types render correctly (text, number, select, textarea)
- [ ] Batch execute handles multiple checks
- [ ] Results show per-check status

### Auto-Harden Mode
- [ ] "Automatic Hardening" button opens AutoHardenModal
- [ ] Preview shows correct counts (auto-fixable, needs params, unsupported)
- [ ] Preview list shows checks that will be fixed
- [ ] Skipped checks list shows with reasons
- [ ] Execute applies all auto-fixable checks
- [ ] Results show success/failure counts

### History & State
- [ ] History tab shows Linux actions
- [ ] Actions persist after page refresh
- [ ] Re-audit reflects fixed checks

### Error Handling
- [ ] SSH connection errors display properly
- [ ] Permission denied errors suggest sudo
- [ ] Missing parameter errors highlight fields
- [ ] Network errors show retry option

---

## Appendix: CIS Benchmark Sections

The 145 Linux CIS checks are organized into these sections:

| Section | Title | Check Count |
|---------|-------|-------------|
| 1 | Initial Setup | 32 |
| 2 | Services | 24 |
| 3 | Network Configuration | 14 |
| 4 | Logging and Auditing | 19 |
| 5 | Access, Authentication and Authorization | 34 |
| 6 | System Maintenance | 22 |

### Section Details

**Section 1 - Initial Setup:**
- Filesystem configuration
- Software updates
- Filesystem integrity checking
- Secure boot settings
- Warning banners

**Section 2 - Services:**
- inetd/xinetd services
- Special purpose services
- Service clients

**Section 3 - Network Configuration:**
- Network parameters (sysctl)
- TCP wrappers
- Firewall configuration
- Wireless

**Section 4 - Logging and Auditing:**
- rsyslog configuration
- journald configuration
- auditd configuration
- Log file permissions

**Section 5 - Access, Authentication and Authorization:**
- SSH server configuration
- PAM configuration
- Password policies
- User account settings
- Privilege escalation

**Section 6 - System Maintenance:**
- File permissions
- User/group settings
- Shadow file audit

---

## Support

For backend issues or API questions, contact the backend team.

For frontend integration issues, refer to:
- `front/src/store/hardeningSlice.jsx` - Redux actions
- `front/src/components/Hardening/*.jsx` - UI components
