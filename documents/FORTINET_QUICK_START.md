# FortiGate Audit - Quick Start Guide

## Overview

The FortiGate audit module provides automated CIS security compliance auditing for FortiGate firewalls. It evaluates 65+ security controls and generates compliance reports.

## API Endpoints

### Base URL
```
http://localhost:8000/api/fortinet
```

### Authentication
All endpoints require authentication:
```
Authorization: Bearer <your_jwt_token>
```

## Quick Start Examples

### 1. Discover VDOMs (Optional)

Before running an audit, you can discover which VDOMs exist on the FortiGate:

```bash
curl -X POST http://localhost:8000/api/fortinet/vdoms/discover \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "asset_id": 42,
    "ssh_username": "admin",
    "ssh_password": "your_password"
  }'
```

**Response:**
```json
{
  "asset_id": 42,
  "asset_name": "fw-hq-01",
  "target_ip": "192.168.1.1",
  "vdoms": ["root", "VDOM_1", "VDOM_2"]
}
```

### 2. Execute Audit

Run a security audit on a FortiGate device:

```bash
curl -X POST http://localhost:8000/api/fortinet/audit/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "asset_id": 42,
    "ssh_username": "admin",
    "ssh_password": "your_password",
    "vdom": "root",
    "profile": "L1"
  }'
```

**Parameters:**
- `asset_id` (required) - Asset ID from your asset inventory
- `ssh_username` (required) - SSH username (not stored)
- `ssh_password` (required) - SSH password (not stored)
- `vdom` (optional) - VDOM name, or null for global context
- `profile` (optional) - Audit profile: "L1" (default), "L2", or "FULL"

**Response:**
```json
{
  "session_id": 123,
  "asset_id": 42,
  "asset_name": "fw-hq-01",
  "target_ip": "192.168.1.1",
  "device_type": "fortinet",
  "status": "completed",
  "started_at": "2026-01-29T10:00:00Z",
  "completed_at": "2026-01-29T10:02:30Z",
  "duration_seconds": 150.5,
  "compliance": {
    "total_checks": 65,
    "passed": 52,
    "failed": 13,
    "compliance_pct": 80.0
  },
  "connection_error": null
}
```

### 3. Get Detailed Results

Retrieve individual check results:

```bash
curl http://localhost:8000/api/fortinet/audit/sessions/123/results \
  -H "Authorization: Bearer $TOKEN"
```

**Response:**
```json
[
  {
    "id": 1,
    "check_number": "FG-BL-001",
    "check_title": "Admin HTTPS enabled",
    "severity": "high",
    "level": "L1",
    "status": "pass",
    "evidence_snippet": "set admin-https enable",
    "checked_at": "2026-01-29T10:01:00Z"
  },
  {
    "id": 2,
    "check_number": "FG-BL-002",
    "check_title": "Admin HTTP disabled",
    "severity": "high",
    "level": "L1",
    "status": "fail",
    "evidence_snippet": "set admin-http enable",
    "checked_at": "2026-01-29T10:01:00Z"
  }
]
```

### 4. List All Audit Sessions

View all previous audits:

```bash
curl http://localhost:8000/api/fortinet/audit/sessions?limit=10&offset=0 \
  -H "Authorization: Bearer $TOKEN"
```

**Query Parameters:**
- `limit` (optional) - Max results per page (default: 50)
- `offset` (optional) - Results to skip (default: 0)

### 5. Get Session Details

View a specific audit session:

```bash
curl http://localhost:8000/api/fortinet/audit/sessions/123 \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Delete Audit Session

Remove an audit session and all its results:

```bash
curl -X DELETE http://localhost:8000/api/fortinet/audit/sessions/123 \
  -H "Authorization: Bearer $TOKEN"
```

## Audit Profiles

### L1 (Level 1 - Recommended)
- Basic security controls
- Low operational impact
- ~45 checks
- **Use for:** Most environments

### L2 (Level 2 - Enhanced)
- L1 + additional controls
- Medium operational impact
- ~55 checks
- **Use for:** High-security environments

### FULL (Complete)
- All available controls
- Comprehensive assessment
- 65+ checks
- **Use for:** Compliance reporting, deep audits

## Security Controls

### Categories

**Management Plane:**
- Admin HTTPS/HTTP/Telnet configuration
- Idle timeout settings
- TLS version enforcement
- Certificate validation

**Identity & Access:**
- Admin trusthost restrictions
- Default account status
- Multi-factor authentication
- Password policy enforcement

**Cryptography:**
- Strong encryption algorithms
- SSL/TLS version restrictions
- Weak cipher detection
- VPN cryptographic settings

**Logging & Monitoring:**
- Remote syslog configuration
- FortiAnalyzer integration
- Log severity levels
- Audit event logging

**Firewall Policies:**
- Any/Any/All policies
- Policy logging requirements
- Shadow rule detection
- Unused object analysis

**VPN Security:**
- SSL-VPN hardening
- IPsec configuration
- Weak proposal detection

**UTM (Unified Threat Management):**
- Security profile usage
- AV, IPS, Web Filter coverage
- Application control
- SSL inspection

## Common Use Cases

### Use Case 1: First-Time Audit
```bash
# 1. Discover VDOMs
curl -X POST .../vdoms/discover -d '{"asset_id": 42, ...}'

# 2. Run L1 audit on root VDOM
curl -X POST .../audit/execute -d '{
  "asset_id": 42,
  "vdom": "root",
  "profile": "L1",
  ...
}'

# 3. Review results
curl .../audit/sessions/123/results
```

### Use Case 2: Compliance Reporting
```bash
# Run FULL audit for comprehensive reporting
curl -X POST .../audit/execute -d '{
  "asset_id": 42,
  "profile": "FULL",
  ...
}'
```

### Use Case 3: Multi-VDOM Environment
```bash
# 1. Discover VDOMs
vdoms=$(curl -X POST .../vdoms/discover ...)

# 2. Audit each VDOM separately
curl -X POST .../audit/execute -d '{"vdom": "VDOM_1", ...}'
curl -X POST .../audit/execute -d '{"vdom": "VDOM_2", ...}'
curl -X POST .../audit/execute -d '{"vdom": "VDOM_3", ...}'
```

### Use Case 4: Historical Tracking
```bash
# List all audits for an asset
curl .../audit/sessions?limit=50

# Compare compliance over time
# - session 100: 75% (Jan 15)
# - session 105: 80% (Jan 22)
# - session 110: 85% (Jan 29)
```

## Permissions Required

### Read Operations
- `/vdoms/discover` - AUDIT read
- `/audit/sessions` - AUDIT read
- `/audit/sessions/{id}` - AUDIT read
- `/audit/sessions/{id}/results` - AUDIT read

### Write Operations
- `/audit/execute` - AUDIT write
- `/audit/sessions/{id}` (DELETE) - AUDIT write

## Error Handling

### Common Errors

**400 Bad Request**
- Invalid asset ID
- Missing IP address on asset
- Invalid profile name

**401 Unauthorized**
- Invalid or expired JWT token
- SSH authentication failure

**403 Forbidden**
- Missing AUDIT read/write permission

**404 Not Found**
- Audit session not found
- Asset not found

**500 Internal Server Error**
- SSH connection timeout
- Command execution failure
- Database error

### Example Error Response
```json
{
  "detail": "Asset ID 42 not found"
}
```

## Best Practices

### Security
1. **Never store credentials** - Always enter them per-audit
2. **Use HTTPS** - Credentials transmitted over TLS
3. **Rotate passwords** - Change SSH passwords regularly
4. **Limit permissions** - Grant AUDIT permissions only as needed
5. **Review evidence** - Check evidence_snippet for sensitive data

### Performance
1. **Cache VDOMs** - Discover once, reuse for multiple audits
2. **Run L1 first** - Faster execution, covers 80% of controls
3. **Schedule off-hours** - Avoid peak traffic times
4. **Delete old sessions** - Keep database size manageable

### Compliance
1. **Document baselines** - Record initial audit results
2. **Track remediation** - Re-audit after fixes
3. **Export results** - Save to CSV/JSON for reporting
4. **Review failures** - Prioritize high-severity findings

## Troubleshooting

### Issue: SSH Connection Fails
**Symptom:** 500 error with "Authentication or connection error"

**Solutions:**
- Verify SSH credentials
- Check FortiGate SSH access is enabled
- Verify network connectivity to FortiGate IP
- Check firewall rules allow SSH from audit server

### Issue: Slow Audit Execution
**Symptom:** Audit takes >5 minutes

**Solutions:**
- Use L1 profile instead of FULL
- Check network latency to FortiGate
- Verify FortiGate CPU/memory usage
- Reduce number of concurrent audits

### Issue: Missing Results
**Symptom:** Compliance percentage is 0%

**Solutions:**
- Check VDOM context (root vs specific VDOM)
- Verify FortiGate firmware version compatibility
- Review command outputs in turbo_dump
- Check audit logs for command failures

### Issue: Permission Denied
**Symptom:** 403 Forbidden error

**Solutions:**
- Verify user has AUDIT read/write permissions
- Check JWT token is valid and not expired
- Re-authenticate to get fresh token

## Interactive API Documentation

Visit the Swagger UI for interactive testing:

```
http://localhost:8000/docs
```

Navigate to the "Audit - FortiGate" section to:
- View all endpoints and schemas
- Test endpoints directly in browser
- See request/response examples
- Download OpenAPI spec

## Additional Resources

- **Module README:** `app/modules/fortinet/README.md`
- **Implementation Summary:** `FORTINET_IMPLEMENTATION_SUMMARY.md`
- **CIS Benchmark:** FortiGate Security Configuration Guide
- **Source Code:** `app/modules/fortinet/`

## Support

For issues or questions:
1. Check audit session `connection_error` field
2. Review API error response `detail` field
3. Check application logs for detailed stack traces
4. Verify SSH connectivity manually: `ssh admin@<fortigate-ip>`

## Quick Reference

| Action | Method | Endpoint |
|--------|--------|----------|
| Discover VDOMs | POST | `/api/fortinet/vdoms/discover` |
| Execute Audit | POST | `/api/fortinet/audit/execute` |
| List Sessions | GET | `/api/fortinet/audit/sessions` |
| Get Session | GET | `/api/fortinet/audit/sessions/{id}` |
| Get Results | GET | `/api/fortinet/audit/sessions/{id}/results` |
| Delete Session | DELETE | `/api/fortinet/audit/sessions/{id}` |

---

**Version:** 1.0
**Last Updated:** 2026-01-29
**Status:** Production Ready ✅
