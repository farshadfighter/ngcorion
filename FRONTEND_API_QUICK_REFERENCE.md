# Frontend API Quick Reference

## Fixed Endpoints

### 1. Get VM Fingerprint
```
GET http://172.16.200.90:8001/api/fingerprint
```

**Response:**
```json
{
  "fingerprint": "a1b2c3d4e5f6..."
}
```

**TypeScript:**
```typescript
interface FingerprintResponse {
  fingerprint: string;
}

const { data } = await axios.get<FingerprintResponse>('/api/fingerprint');
```

---

### 2. Validate License
```
POST http://172.16.200.90:8001/api/licenses/validate
```

**Request:**
```json
{
  "license_key": "string",
  "organization_token": "string",
  "vm_fingerprint": "string"
}
```

**Response:**
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

**TypeScript:**
```typescript
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

const { data } = await axios.post<ValidationResponse>(
  '/api/licenses/validate',
  {
    license_key: 'YOUR-KEY',
    organization_token: 'YOUR-TOKEN',
    vm_fingerprint: 'YOUR-FP'
  }
);
```

---

## Production Recommendation

**Use Main App Endpoints (Port 8000) instead:**

### Get License Status
```
GET http://172.16.200.90:8000/api/license/status
```

No authentication required. Returns current license state.

### Activate License
```
POST http://172.16.200.90:8000/api/license/activate
```

Request:
```json
{
  "license_key": "string"
}
```

---

## OpenAPI Documentation

**License Server:** http://172.16.200.90:8001/docs
**Main App:** http://172.16.200.90:8000/docs

---

## Testing

Both endpoints are now properly documented in OpenAPI and can be tested directly from Swagger UI.

Date: May 2, 2025
