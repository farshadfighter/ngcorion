# API Response Examples - License Validation

## Complete Response Format

Here are the **exact** response formats from `/api/licenses/validate` for different plan types.

---

## 1. PILOT Plan (1-month trial)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "pilot",
  "is_pilot_mode": true,
  "organization_token": "org_abc123def456",
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

---

## 2. PLAN_100 Plan (100 Audit / 100 Hardening)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "plan_100",
  "is_pilot_mode": false,
  "organization_token": "org_xyz789ghi012",
  "limits": {
    "max_audits": 100,
    "max_hardens": 100
  },
  "usage": {
    "used_audits": 42,
    "used_hardens": 18
  }
}
```

---

## 3. PLAN_250 Plan (250 Audit / 250 Hardening)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "plan_250",
  "is_pilot_mode": false,
  "organization_token": "org_mno345pqr678",
  "limits": {
    "max_audits": 250,
    "max_hardens": 250
  },
  "usage": {
    "used_audits": 187,
    "used_hardens": 96
  }
}
```

---

## 4. PLAN_500 Plan (500 Audit / 500 Hardening)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "plan_500",
  "is_pilot_mode": false,
  "organization_token": "org_stu901vwx234",
  "limits": {
    "max_audits": 500,
    "max_hardens": 500
  },
  "usage": {
    "used_audits": 289,
    "used_hardens": 156
  }
}
```

---

## 5. UNLIMITED Plan

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "unlimited",
  "is_pilot_mode": false,
  "organization_token": "org_ent567abc890",
  "limits": {
    "max_audits": null,
    "max_hardens": null
  },
  "usage": {
    "used_audits": 4521,
    "used_hardens": 2103
  }
}
```

**Note:** `null` in limits means **unlimited** for the Unlimited plan.

---

## 6. Invalid License Response

```json
{
  "valid": false,
  "message": "License has expired",
  "plan_type": null,
  "is_pilot_mode": false,
  "organization_token": null,
  "limits": null,
  "usage": null
}
```

---

## Field Descriptions

### Root Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | Whether the license is valid |
| `message` | string | Human-readable status message |
| `plan_type` | string | Plan type: `"pilot"`, `"plan_100"`, `"plan_250"`, `"plan_500"`, `"unlimited"` |
| `is_pilot_mode` | boolean | `true` only for pilot plan |
| `organization_token` | string | Secret token for future API calls (only on success) |
| `limits` | object | Maximum allowed operations (null if invalid) |
| `usage` | object | Current usage counters (null if invalid) |

### Limits Object

| Field | Type | Description |
|-------|------|-------------|
| `max_audits` | integer or null | Maximum audit operations (`null` = unlimited) |
| `max_hardens` | integer or null | Maximum hardening operations (`null` = unlimited) |

Asset Management (asset creation and Auto Discovery) has no corresponding entry here — it is not license-gated and has no quota dimension.

### Usage Object

| Field | Type | Description |
|-------|------|-------------|
| `used_audits` | integer | Number of audits performed |
| `used_hardens` | integer | Number of hardenings performed |

---

## Plan Comparison Table

| Plan | Audits | Hardens |
|------|--------|---------|
| **PILOT** | 2 | 2 |
| **PLAN_100** | 100 | 100 |
| **PLAN_250** | 250 | 250 |
| **PLAN_500** | 500 | 500 |
| **UNLIMITED** | ∞ | ∞ |

---

## Frontend Usage Example

```javascript
// Validate license
const response = await fetch('/api/licenses/validate', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Signature': signature,
    'X-Timestamp': timestamp
  },
  body: JSON.stringify({
    license_key: 'XXXX-XXXX-XXXX-XXXX',
    organization_token: 'org_token_here',
    vm_fingerprint: 'fingerprint_here'
  })
});

const data = await response.json();

if (data.valid) {
  console.log('Plan:', data.plan_type);
  console.log('Is Pilot:', data.is_pilot_mode);
  
  // Check limits (null means unlimited)
  if (data.limits.max_audits === null) {
    console.log('Unlimited audits!');
  } else {
    const remaining = data.limits.max_audits - data.usage.used_audits;
    console.log(`Audits: ${data.usage.used_audits}/${data.limits.max_audits} (${remaining} remaining)`);
  }
  
  // Display usage
  console.log('Audits:', data.usage.used_audits);
  console.log('Hardens:', data.usage.used_hardens);
} else {
  console.error('License invalid:', data.message);
}
```

---

## Important Notes

1. **`null` vs `0`**: In limits, `null` means unlimited (Unlimited plan), while `0` would mean not allowed
2. **Usage counters**: Always integers, never null, start at 0
3. **organization_token**: Only returned when `valid: true`, save it securely
4. **Signature required**: `/validate` endpoint requires HMAC signature in headers
5. **All fields present**: Even when `valid: false`, all fields exist (but some are null)
6. **Asset Management is unrestricted**: Asset creation and Auto Discovery scans are never quota-checked and never appear in `limits`/`usage`

---

## Testing in Swagger

1. Start the license server: `cd license_server && uvicorn app.main:app --reload`
2. Open Swagger UI: `http://localhost:8000/docs`
3. Find `POST /api/licenses/validate`
4. Click "Try it out"
5. Fill in the request body (you'll need a valid license first)
6. Execute and copy the response

---

## Activate Response (for reference)

The `/api/licenses/activate` endpoint returns the **same format** as validate:

```json
{
  "valid": true,
  "message": "License activated successfully",
  "plan_type": "plan_250",
  "is_pilot_mode": false,
  "organization_token": "org_new_token_here",
  "limits": { ... },
  "usage": {
    "used_audits": 0,
    "used_hardens": 0
  }
}
```

**Note:** After activation, all usage counters start at 0.
