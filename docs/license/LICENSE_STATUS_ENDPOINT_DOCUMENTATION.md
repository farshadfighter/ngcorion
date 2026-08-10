# GET /api/license/status Documentation

## Endpoint Details

**URL:** `http://172.16.200.90:8000/api/license/status`  
**Method:** GET  
**Authentication:** None required  
**Port:** 8000 (Main App)

---

## Response Schema

```typescript
interface LicenseStatusResponse {
  valid: boolean;
  plan_type: string | null;
  is_pilot_mode: boolean;
  message: string;
  limits: {
    max_audits: number;
    max_hardens: number;
  } | null;
  usage: {
    used_audits: number;
    used_hardens: number;
  } | null;
}
```

---

## Response Examples

### 1. When License is Active (Valid)

```json
{
  "valid": true,
  "plan_type": "plan_250",
  "is_pilot_mode": false,
  "message": "License is valid",
  "limits": {
    "max_audits": 250,
    "max_hardens": 250
  },
  "usage": {
    "used_audits": 45,
    "used_hardens": 8
  }
}
```

### 2. When License is Active (Pilot Mode)

```json
{
  "valid": true,
  "plan_type": "pilot",
  "is_pilot_mode": true,
  "message": "License is valid",
  "limits": {
    "max_audits": 2,
    "max_hardens": 2
  },
  "usage": {
    "used_audits": 1,
    "used_hardens": 0
  }
}
```

### 3. When No License is Activated

```json
{
  "valid": false,
  "plan_type": null,
  "is_pilot_mode": false,
  "message": "No license activated",
  "limits": null,
  "usage": null
}
```

### 4. When License Validation Failed

```json
{
  "valid": false,
  "plan_type": null,
  "is_pilot_mode": false,
  "message": "License validation failed: Connection timeout",
  "limits": null,
  "usage": null
}
```

### 5. When License is Expired

```json
{
  "valid": false,
  "plan_type": "plan_250",
  "is_pilot_mode": false,
  "message": "License has expired",
  "limits": {
    "max_audits": 250,
    "max_hardens": 250
  },
  "usage": {
    "used_audits": 245,
    "used_hardens": 150
  }
}
```

---

## Frontend Usage

### Basic Usage

```typescript
import axios from 'axios';

interface LicenseStatusResponse {
  valid: boolean;
  plan_type: string | null;
  is_pilot_mode: boolean;
  message: string;
  limits: {
    max_audits: number;
    max_hardens: number;
  } | null;
  usage: {
    used_audits: number;
    used_hardens: number;
  } | null;
}

async function checkLicenseStatus() {
  try {
    const response = await axios.get<LicenseStatusResponse>(
      'http://172.16.200.90:8000/api/license/status'
    );
    
    if (response.data.valid) {
      console.log('License is active');
      console.log('Plan:', response.data.plan_type);
      console.log('Limits:', response.data.limits);
      console.log('Usage:', response.data.usage);
    } else {
      console.log('License is not active:', response.data.message);
    }
    
    return response.data;
  } catch (error) {
    console.error('Failed to check license status:', error);
    throw error;
  }
}
```

### React Hook Example

```typescript
import { useState, useEffect } from 'react';
import axios from 'axios';

function useLicenseStatus() {
  const [status, setStatus] = useState<LicenseStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchStatus() {
      try {
        const response = await axios.get<LicenseStatusResponse>(
          '/api/license/status'
        );
        setStatus(response.data);
        setError(null);
      } catch (err) {
        setError('Failed to fetch license status');
      } finally {
        setLoading(false);
      }
    }

    fetchStatus();
    
    // Refresh every 5 minutes
    const interval = setInterval(fetchStatus, 5 * 60 * 1000);
    
    return () => clearInterval(interval);
  }, []);

  return { status, loading, error };
}

// Usage in component
function LicenseInfo() {
  const { status, loading, error } = useLicenseStatus();

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!status?.valid) return <div>No active license</div>;

  return (
    <div>
      <h3>License Status</h3>
      <p>Plan: {status.plan_type}</p>
      <p>Audits: {status.usage?.used_audits} / {status.limits?.max_audits}</p>
      <p>Hardens: {status.usage?.used_hardens} / {status.limits?.max_hardens}</p>
    </div>
  );
}
```

---

## Important Notes

### 1. In-Memory Cache
- This endpoint returns cached data from memory
- Does NOT call the license server on every request
- Very fast response time (no network calls)
- Updated automatically by background heartbeat (every hour)

### 2. When to Call This Endpoint
- On app startup/initialization
- After license activation
- When displaying license information
- Before performing quota-limited operations (optional)

### 3. No Authentication Required
- This endpoint is always accessible
- Returns "No license activated" if no license exists
- Safe to call from unauthenticated pages

### 4. Plan Types
- `"pilot"` - Trial/demo license (limited features, 30 days)
- `"plan_100"` - 100 Audit / 100 Hardening
- `"plan_250"` - 250 Audit / 250 Hardening
- `"plan_500"` - 500 Audit / 500 Hardening
- `"unlimited"` - Unlimited audits and hardens
- `null` - No license activated

### 5. Usage Updates
- Usage counters update automatically when audit/harden operations are performed
- Backend calls license server to consume quota
- Frontend just reads the current state
- No need to manually track usage
- Asset creation and Auto Discovery never touch these counters — they are not license-gated

---

## Testing

### Using curl
```bash
curl http://172.16.200.90:8000/api/license/status
```

### Using browser
Simply open: `http://172.16.200.90:8000/api/license/status`

### Using Swagger UI
Open: `http://172.16.200.90:8000/docs`  
Find: `GET /api/license/status`  
Click: "Try it out" → "Execute"

---

## Related Endpoints

### Activate License
```
POST /api/license/activate
Body: { "license_key": "string" }
```

After activation, the status endpoint will return valid: true with license details.

---
