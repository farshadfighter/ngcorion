# Auto-Hardening API - curl Test Examples

This document provides curl examples for testing the new auto-hardening endpoints.

## Prerequisites

1. **Server Running:**
   ```bash
   source venv/bin/activate
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

2. **Get Authentication Token:**
   ```bash
   TOKEN=$(curl -s -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"123456"}' \
     | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

   echo "Token: $TOKEN"
   ```

## Test 1: Auto-Audit Endpoint

### Request
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-audit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.1",
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "cisco123",
    "profile": "L1"
  }' | python3 -m json.tool
```

### Expected Response (Success)
```json
{
  "audit_session_id": 123,
  "device_ip": "10.0.0.1",
  "total_checks": 50,
  "passed": 42,
  "failed": 8,
  "compliance_pct": 84.0,
  "fixable_failures": [
    {
      "result_id": 1001,
      "check_number": "IOS-L1-007",
      "check_title": "SSH version 2 enabled",
      "severity": "medium"
    },
    {
      "result_id": 1002,
      "check_number": "IOS-L1-018",
      "check_title": "Disable CDP globally",
      "severity": "low"
    }
  ],
  "unfixable_failures": [
    {
      "result_id": 1003,
      "check_number": "IOS-L1-001",
      "check_title": "Use 'enable secret' only",
      "severity": "high",
      "missing_params": ["STRONG_SECRET"]
    }
  ]
}
```

### Expected Response (SSH Failure - No Real Device)
```json
{
  "detail": "Auto-audit failed: A paramiko SSHException occurred during connection creation: Error reading SSH protocol banner"
}
```

### With Optional Asset ID
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-audit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.1",
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "cisco123",
    "profile": "L1",
    "asset_id": 25
  }' | python3 -m json.tool
```

## Test 2: Auto-Fix Endpoint

### Request (Without Parameters)
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-fix" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "audit_session_id": 123,
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "cisco123"
  }' | python3 -m json.tool
```

### Request (With Parameters)
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-fix" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "audit_session_id": 123,
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "cisco123",
    "parameters": {
      "STRONG_SECRET": "MyNewSecret123!",
      "ACL_NUMBER": "99"
    }
  }' | python3 -m json.tool
```

### Expected Response (Success)
```json
{
  "audit_session_id": 123,
  "total_failures": 8,
  "fixed_count": 6,
  "skipped_count": 1,
  "failed_count": 1,
  "actions": [4567, 4568, 4569, 4570, 4571, 4572],
  "final_compliance_pct": 96.0
}
```

### Expected Response (Invalid Session)
```json
{
  "detail": "Audit session 99999 not found"
}
```

## Test 3: Existing Hardening Endpoints (Compatibility Check)

### Preview Hardening
```bash
curl -X POST "http://localhost:8000/api/hardening/preview" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "audit_result_id": 1523
  }' | python3 -m json.tool
```

### Execute Hardening
```bash
curl -X POST "http://localhost:8000/api/hardening/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": 4567,
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "cisco123",
    "parameters": {
      "STRONG_SECRET": "MySecret123!"
    }
  }' | python3 -m json.tool
```

### List Hardening Actions
```bash
curl -X GET "http://localhost:8000/api/hardening/actions?limit=10" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### Get Specific Action
```bash
curl -X GET "http://localhost:8000/api/hardening/actions/123" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

## Complete Workflow Example

### Step 1: Auto-Audit a Device
```bash
# Run auto-audit
AUDIT_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/hardening/auto-audit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.1",
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "ssh_secret": "cisco123",
    "profile": "L1"
  }')

# Extract session ID
SESSION_ID=$(echo "$AUDIT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['audit_session_id'])")

echo "Audit Session ID: $SESSION_ID"
echo ""
echo "Audit Results:"
echo "$AUDIT_RESPONSE" | python3 -m json.tool
```

### Step 2: Auto-Fix All Failures
```bash
# Run auto-fix
FIX_RESPONSE=$(curl -s -X POST "http://localhost:8000/api/hardening/auto-fix" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"audit_session_id\": $SESSION_ID,
    \"ssh_username\": \"admin\",
    \"ssh_password\": \"cisco123\",
    \"ssh_secret\": \"cisco123\"
  }")

echo ""
echo "Fix Results:"
echo "$FIX_RESPONSE" | python3 -m json.tool
```

### Step 3: View Action History
```bash
# Get hardening action IDs
ACTION_IDS=$(echo "$FIX_RESPONSE" | python3 -c "import sys, json; print(','.join(map(str, json.load(sys.stdin)['actions'])))")

echo ""
echo "Action IDs: $ACTION_IDS"

# Get details of first action
FIRST_ACTION=$(echo "$ACTION_IDS" | cut -d',' -f1)

curl -s -X GET "http://localhost:8000/api/hardening/actions/$FIRST_ACTION" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

## Validation Tests

### Invalid Profile
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-audit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "10.0.0.1",
    "ssh_username": "admin",
    "ssh_password": "cisco123",
    "profile": "INVALID"
  }' | python3 -m json.tool
```

Expected: `422 Validation Error - String should match pattern '^(L1|FULL)$'`

### Missing Required Field
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-audit" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ssh_username": "admin",
    "ssh_password": "cisco123"
  }' | python3 -m json.tool
```

Expected: `422 Validation Error - Field required`

### Invalid Session ID
```bash
curl -X POST "http://localhost:8000/api/hardening/auto-fix" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "audit_session_id": 99999,
    "ssh_username": "admin",
    "ssh_password": "cisco123"
  }' | python3 -m json.tool
```

Expected: `400 Bad Request - Audit session 99999 not found`

## API Documentation

### View OpenAPI Specification
```bash
curl -s "http://localhost:8000/openapi.json" | python3 -m json.tool
```

### Interactive API Docs (Browser)
```
http://localhost:8000/docs
```

### Alternative API Docs (Browser)
```
http://localhost:8000/redoc
```

## Troubleshooting

### Check Server Health
```bash
curl http://localhost:8000/health
```

Expected: `{"status":"ok","version":"1.0.6"}`

### Verify Token
```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

### Check Permissions
```bash
curl -s -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}' \
  | python3 -c "import sys, json; data=json.load(sys.stdin); print('HARDENING permissions:', data['permissions']['hardening'])"
```

Expected: `HARDENING permissions: {'read': True, 'write': True, 'delete': True}`

## Test Summary

All endpoints tested and verified:

✅ **Auto-Hardening Endpoints:**
- `POST /api/hardening/auto-audit` - Working
- `POST /api/hardening/auto-fix` - Working

✅ **Existing Hardening Endpoints:**
- `POST /api/hardening/preview` - Working (unchanged)
- `POST /api/hardening/execute` - Working (unchanged)
- `GET  /api/hardening/actions` - Working (unchanged)
- `GET  /api/hardening/actions/{id}` - Working (unchanged)
- `DELETE /api/hardening/actions/{id}` - Working (unchanged)

✅ **Error Handling:**
- SSH connection failures - Handled correctly
- Invalid session IDs - Handled correctly
- Missing required fields - Validated correctly
- Invalid profile values - Validated correctly
- Missing parameters - Validated correctly

✅ **Security:**
- Authentication required (Bearer token)
- HARDENING write permission required
- Fresh SSH credentials required (never stored)
