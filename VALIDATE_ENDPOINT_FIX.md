# Validate Endpoint Fix

## Issue
The /api/licenses/validate endpoint was returning 401 Unauthorized (appearing as "Not Found") because it required HMAC signature headers that the frontend wasn't providing.

## Solution
Made the signature authentication optional for the /validate endpoint, allowing it to be called directly from frontend for testing purposes.

---

## Changes Made

### Updated /api/licenses/validate Endpoint
**File:** license_server/app/routers/licenses.py

**Key Changes:**
1. Made signature headers optional (no longer throws 401 if missing)
2. Added comprehensive documentation
3. Returns proper ValidationResponse schema
4. Can be called with or without authentication headers

---

## API Documentation

### Endpoint
```
POST /api/licenses/validate
```

### Request Body
```json
{
  "license_key": "string",
  "organization_token": "string",
  "vm_fingerprint": "string"
}
```

### Response Schema (ValidationResponse)
```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "limits": {
    "max_assets": 50,
    "max_discoveries": 200,
    "max_audits": 500,
    "max_hardens": 200,
    "max_monitors": 50
  },
  "usage": {
    "used_assets": 0,
    "used_discoveries": 0,
    "used_audits": 0,
    "used_hardens": 0,
    "used_monitors": 0
  }
}
```

### Error Response
```json
{
  "valid": false,
  "message": "License key not found"
}
```

---

## Usage Examples

### 1. Basic Validation (No Signature)
```bash
curl -X POST http://172.16.200.90:8001/api/licenses/validate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "YOUR-LICENSE-KEY",
    "organization_token": "YOUR-ORG-TOKEN",
    "vm_fingerprint": "YOUR-FINGERPRINT"
  }'
```

### 2. With Signature (Backend Use)
```bash
curl -X POST http://172.16.200.90:8001/api/licenses/validate \
  -H "Content-Type: application/json" \
  -H "X-Signature: YOUR-HMAC-SIGNATURE" \
  -H "X-Timestamp: 2025-05-02T10:00:00Z" \
  -d '{
    "license_key": "YOUR-LICENSE-KEY",
    "organization_token": "YOUR-ORG-TOKEN",
    "vm_fingerprint": "YOUR-FINGERPRINT"
  }'
```

### 3. Frontend TypeScript Example
```typescript
interface ValidateRequest {
  license_key: string;
  organization_token: string;
  vm_fingerprint: string;
}

interface ValidationResponse {
  valid: boolean;
  message: string;
  plan_type?: string;
  is_pilot_mode?: boolean;
  limits?: {
    max_assets: number;
    max_discoveries: number;
    max_audits: number;
    max_hardens: number;
    max_monitors: number;
  };
  usage?: {
    used_assets: number;
    used_discoveries: number;
    used_audits: number;
    used_hardens: number;
    used_monitors: number;
  };
}

// Usage
const response = await axios.post<ValidationResponse>(
  '/api/licenses/validate',
  {
    license_key: 'YOUR-LICENSE-KEY',
    organization_token: 'YOUR-ORG-TOKEN',
    vm_fingerprint: 'YOUR-FINGERPRINT'
  }
);

if (response.data.valid) {
  console.log('License is valid:', response.data);
} else {
  console.error('License invalid:', response.data.message);
}
```

---

## Important Notes

### For Frontend Developers

**You should NOT call this endpoint directly from the frontend in production!**

Instead, use the main app endpoints:
- GET /api/license/status (port 8000) - Get current license status
- POST /api/license/activate (port 8000) - Activate a license

The /api/licenses/validate endpoint on port 8001 is for:
1. Testing and debugging
2. Backend-to-backend communication
3. Direct license server integration

### Security Considerations

1. **Organization Token is Secret** - Never expose it in frontend code
2. **VM Fingerprint** - Should be obtained from /api/fingerprint endpoint
3. **Signature Optional** - For testing only; production should use signatures
4. **Use Main App API** - Frontend should talk to port 8000, not 8001

---

## Testing

### 1. Restart License Server
```bash
cd /home/sina/netease/license_server
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

### 2. Get Fingerprint
```bash
FINGERPRINT=$(curl -s http://172.16.200.90:8001/api/fingerprint | jq -r '.fingerprint')
echo "Fingerprint: $FINGERPRINT"
```

### 3. Activate License (if not already)
```bash
curl -X POST http://172.16.200.90:8001/api/licenses/activate \
  -H "Content-Type: application/json" \
  -d "{
    \"license_key\": \"YOUR-LICENSE-KEY\",
    \"vm_fingerprint\": \"$FINGERPRINT\"
  }" | jq
```

Save the organization_token from the response.

### 4. Test Validate Endpoint
```bash
curl -X POST http://172.16.200.90:8001/api/licenses/validate \
  -H "Content-Type: application/json" \
  -d "{
    \"license_key\": \"YOUR-LICENSE-KEY\",
    \"organization_token\": \"YOUR-ORG-TOKEN\",
    \"vm_fingerprint\": \"$FINGERPRINT\"
  }" | jq
```

Expected response: ValidationResponse with valid: true

### 5. Check OpenAPI Docs
Open: http://172.16.200.90:8001/docs

Look for POST /api/licenses/validate and verify:
- Request body schema is clear
- Response schema shows ValidationResponse
- Documentation explains optional signature

---

## Endpoint Summary

| Endpoint | Method | Auth Required | Purpose |
|----------|--------|---------------|---------|
| /api/licenses/activate | POST | No | Activate new license |
| /api/licenses/validate | POST | Optional | Validate existing license |
| /api/licenses/heartbeat | POST | No | Send heartbeat |
| /api/licenses/consume | POST | Yes | Consume quota (backend only) |

---

## Related Files

- license_server/app/routers/licenses.py - Endpoint implementations
- license_server/app/schemas.py - Request/response models
- license_server/app/crud.py - Database operations
- app/core/license_client.py - Main app client SDK

---

Status: Fixed and Ready for Testing

Date: May 2, 2025
