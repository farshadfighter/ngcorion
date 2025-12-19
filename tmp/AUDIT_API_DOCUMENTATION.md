# Cisco CIS Audit API Documentation

## Overview

The Audit API provides automated security compliance auditing for Cisco IOS/IOS-XE devices based on CIS (Center for Internet Security) benchmarks.

**Base URL:** `http://localhost:8000`

---

## Authentication

All audit endpoints require authentication via JWT Bearer token.

```bash
# Login first to get token
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}'

# Use the returned token in subsequent requests
TOKEN="<your_jwt_token>"
```

---

## Endpoints

### 1. Execute Cisco CIS Audit

**POST** `/api/audit/cisco/execute`

Executes a complete CIS compliance audit on a Cisco device.

#### Request Body

```json
{
  "asset_id": 25,
  "ssh_username": "admin",
  "ssh_password": "cisco123",
  "ssh_secret": "enable_secret",
  "profile": "L1"
}
```

**Parameters:**
- `asset_id` (required): Asset ID from Asset List (must have IP address)
- `ssh_username` (required): SSH username (NOT stored in database)
- `ssh_password` (required): SSH password (NOT stored in database)
- `ssh_secret` (optional): Enable secret for privileged mode (NOT stored)
- `profile` (optional): CIS profile - `"L1"` (basic, ~30 rules) or `"FULL"` (~50 rules). Default: `"L1"`

#### Example Request

```bash
curl -X POST "http://localhost:8000/api/audit/cisco/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 25,
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "enable_secret",
    "profile": "L1"
  }'
```

#### Success Response (200 OK)

```json
{
  "session_id": 1,
  "asset_id": 25,
  "asset_name": "Core-Switch-01",
  "target_ip": "192.168.1.1",
  "device_type": "cisco",
  "status": "completed",
  "started_at": "2025-12-15T10:30:00.000Z",
  "completed_at": "2025-12-15T10:32:15.000Z",
  "duration_seconds": 135.5,
  "compliance": {
    "total_checks": 30,
    "passed": 22,
    "failed": 8,
    "errors": 0,
    "compliance_pct": 73.33,
    "weighted_compliance_pct": 68.42
  },
  "connection_error": null
}
```

#### Error Responses

**400 Bad Request** - Invalid input
```json
{
  "detail": "Asset 'Core-Switch-01' has no IP address configured"
}
```

**500 Internal Server Error** - SSH connection failed
```json
{
  "detail": "Audit execution failed: Authentication failed"
}
```

---

### 2. Get Audit Session Details

**GET** `/api/audit/sessions/{session_id}`

Retrieves details and compliance summary for a specific audit session.

#### Example Request

```bash
curl -X GET "http://localhost:8000/api/audit/sessions/1" \
  -H "Authorization: Bearer $TOKEN"
```

#### Success Response (200 OK)

Same format as Execute Audit response.

---

### 3. Get Audit Results (Detailed)

**GET** `/api/audit/sessions/{session_id}/results`

Retrieves detailed results for all individual CIS checks in an audit session.

#### Example Request

```bash
curl -X GET "http://localhost:8000/api/audit/sessions/1/results" \
  -H "Authorization: Bearer $TOKEN"
```

#### Success Response (200 OK)

```json
[
  {
    "id": 1,
    "check_number": "IOS-L1-001",
    "check_title": "Use 'enable secret' only (no 'enable password')",
    "severity": "high",
    "level": "L1",
    "status": "pass",
    "evidence_snippet": "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0",
    "checked_at": "2025-12-15T10:31:45.000Z"
  },
  {
    "id": 2,
    "check_number": "IOS-L1-010",
    "check_title": "Telnet disabled; SSH only on VTY",
    "severity": "high",
    "level": "L1",
    "status": "fail",
    "evidence_snippet": "line vty 0 4\n transport input telnet ssh",
    "checked_at": "2025-12-15T10:31:46.000Z"
  }
]
```

**Status Values:**
- `"pass"` - Compliant (green ✓)
- `"fail"` - Non-compliant (red ✗)
- `"error"` - Check could not be evaluated

---

### 4. Get Asset Audit History

**GET** `/api/audit/asset/{asset_id}/history`

Retrieves audit history for a specific asset (most recent first).

#### Query Parameters
- `limit` (optional): Maximum number of sessions to return (default: 10)

#### Example Request

```bash
curl -X GET "http://localhost:8000/api/audit/asset/25/history?limit=5" \
  -H "Authorization: Bearer $TOKEN"
```

#### Success Response (200 OK)

```json
[
  {
    "session_id": 3,
    "asset_id": 25,
    "asset_name": "Core-Switch-01",
    "target_ip": "192.168.1.1",
    "status": "completed",
    "started_at": "2025-12-15T10:30:00.000Z",
    "compliance": {
      "total_checks": 30,
      "passed": 24,
      "failed": 6,
      "compliance_pct": 80.0
    }
  },
  {
    "session_id": 2,
    "asset_id": 25,
    "status": "completed",
    "started_at": "2025-12-10T14:20:00.000Z",
    "compliance": {
      "total_checks": 30,
      "passed": 20,
      "failed": 10,
      "compliance_pct": 66.67
    }
  }
]
```

---

## Workflow Example

### Complete Audit Workflow

```bash
#!/bin/bash

TOKEN="your_jwt_token_here"

# Step 1: Execute audit
SESSION_ID=$(curl -s -X POST "http://localhost:8000/api/audit/cisco/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": 25,
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "profile": "L1"
  }' | jq -r '.session_id')

echo "Audit session ID: $SESSION_ID"

# Step 2: Get compliance summary
curl -s -X GET "http://localhost:8000/api/audit/sessions/$SESSION_ID" \
  -H "Authorization: Bearer $TOKEN" | jq '.compliance'

# Step 3: Get detailed results (only failed checks)
curl -s -X GET "http://localhost:8000/api/audit/sessions/$SESSION_ID/results" \
  -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.status=="fail")'

# Step 4: Get audit history for this asset
curl -s -X GET "http://localhost:8000/api/audit/asset/25/history?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
```

---

## CIS Checks Overview

### Profile: L1 (Basic - ~30 rules)

**Identity & DNS**
- IOS-L1-0010: Hostname configured
- IOS-L1-0011: IP domain-name configured
- IOS-L1-0012: DNS lookup disabled

**Enable Secret**
- IOS-L1-001: Use 'enable secret' only (no 'enable password')

**VTY & Console**
- IOS-L1-002: Exec-timeout configured
- IOS-L1-003: VTY restricted by access-class
- IOS-L1-004: Explicit login method
- IOS-L1-005: MOTD banner configured
- IOS-L1-0051: Login banner configured

**SSH Hardening**
- IOS-L1-010: Telnet disabled; SSH only
- IOS-L1-011: SSH version 2 enforced
- IOS-L1-0112: SSH timeout configured
- IOS-L1-0113: SSH auth-retries configured
- IOS-L1-0120: RSA key size >= 2048 bits

**Login Controls**
- IOS-L1-0130: Login block-for configured
- IOS-L1-0131: Login logging enabled

**AAA**
- IOS-L1-020: AAA new-model enabled
- IOS-L1-021: AAA authentication defined
- IOS-L1-022: AAA accounting commands 15

**Logging**
- IOS-L1-024: Remote syslog configured
- IOS-L1-0241: Log timestamps configured
- IOS-L1-0242: Logging buffered configured
- IOS-L1-0243: Logging trap level set
- IOS-L1-0244: Archive config logging enabled

**SNMP**
- IOS-L1-030A: SNMPv3 preferred
- IOS-L1-030B: SNMP communities must have ACL

**Passwords**
- IOS-L1-070: Service password-encryption enabled
- IOS-L1-071: No plaintext passwords

**NTP**
- IOS-L1-080: NTP authentication configured
- IOS-L1-081: Timezone configured

**Interfaces**
- IOS-L1-061: Interface ingress ACL configured

**Boot**
- IOS-L1-090: Config-register is 0x2102

### Profile: FULL (~50 rules)

Includes all L1 rules plus:
- L2 rules (advanced security)
- INFO rules (evidence-only, no compliance impact)

---

## Security Notes

1. **SSH Credentials NOT Stored**
   - Credentials are used only during audit execution
   - Never persisted to database
   - Exist only in memory during the session

2. **Sensitive Data Redacted**
   - Passwords, secrets, SNMP communities automatically masked
   - Evidence stored in database is redacted
   - Full raw output stored separately (redacted)

3. **Permissions Required**
   - Execute audit: `AUDIT` write permission
   - View results: `AUDIT` read permission

4. **Audit Storage**
   - All audit sessions permanently stored
   - Results include compliance status, not full evidence
   - History available via `/asset/{id}/history`

---

## Common Issues & Troubleshooting

### SSH Connection Fails

**Error:** `"Audit execution failed: Authentication failed"`

**Solutions:**
1. Verify SSH credentials are correct
2. Ensure SSH is enabled on device: `ip ssh version 2`
3. Check VTY access-class allows source IP
4. Verify enable secret if privilege mode required

### Asset Has No IP Address

**Error:** `"Asset 'Device-01' has no IP address configured"`

**Solution:** Configure IP address in Asset List before running audit

### Permission Denied

**Error:** `403 Forbidden`

**Solution:** Request `AUDIT` module permissions from administrator

---

## Next Steps

1. **Frontend Integration** (Phase 2)
   - Build UI for audit execution
   - Display results with green ✓ / red ✗ indicators
   - Show compliance trends over time

2. **Additional Device Types** (Phase 3)
   - Fortinet FortiGate
   - Linux servers
   - Windows servers

3. **Service Auditing** (Phase 4)
   - Apache
   - IIS
   - Active Directory
   - SQL Server

---

## Support

For issues or questions:
- Check logs: `/var/log/netease/audit.log`
- API documentation: `http://localhost:8000/docs`
- Contact: Network Security Team
