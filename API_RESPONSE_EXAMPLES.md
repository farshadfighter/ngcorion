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
    "max_assets": 5,
    "max_discoveries": 10,
    "max_audits": 20,
    "max_hardens": 10,
    "max_monitors": 5
  },
  "usage": {
    "used_assets": 2,
    "used_discoveries": 5,
    "used_audits": 8,
    "used_hardens": 3,
    "used_monitors": 1
  }
}
```

---

## 2. BASIC1 Plan (Small Network - 15 devices)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "basic1",
  "is_pilot_mode": false,
  "organization_token": "org_xyz789ghi012",
  "limits": {
    "max_assets": 15,
    "max_discoveries": 50,
    "max_audits": 100,
    "max_hardens": 50,
    "max_monitors": 15
  },
  "usage": {
    "used_assets": 8,
    "used_discoveries": 25,
    "used_audits": 42,
    "used_hardens": 18,
    "used_monitors": 7
  }
}
```

---

## 3. BASIC2 Plan (Medium Network - 50 devices)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "organization_token": "org_mno345pqr678",
  "limits": {
    "max_assets": 50,
    "max_discoveries": 200,
    "max_audits": 500,
    "max_hardens": 200,
    "max_monitors": 50
  },
  "usage": {
    "used_assets": 32,
    "used_discoveries": 145,
    "used_audits": 287,
    "used_hardens": 156,
    "used_monitors": 28
  }
}
```

---

## 4. BASIC3 Plan (Large Network - 150 devices)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "basic3",
  "is_pilot_mode": false,
  "organization_token": "org_stu901vwx234",
  "limits": {
    "max_assets": 150,
    "max_discoveries": 600,
    "max_audits": 1500,
    "max_hardens": 600,
    "max_monitors": 150
  },
  "usage": {
    "used_assets": 98,
    "used_discoveries": 412,
    "used_audits": 876,
    "used_hardens": 445,
    "used_monitors": 89
  }
}
```

---

## 5. ENTERPRISE Plan (Unlimited)

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "enterprise",
  "is_pilot_mode": false,
  "organization_token": "org_ent567abc890",
  "limits": {
    "max_assets": null,
    "max_discoveries": null,
    "max_audits": null,
    "max_hardens": null,
    "max_monitors": null
  },
  "usage": {
    "used_assets": 523,
    "used_discoveries": 1847,
    "used_audits": 4521,
    "used_hardens": 2103,
    "used_monitors": 487
  }
}
```

**Note:** `null` in limits means **unlimited** for Enterprise plan.

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
| `plan_type` | string | Plan type: `"pilot"`, `"basic1"`, `"basic2"`, `"basic3"`, `"enterprise"` |
| `is_pilot_mode` | boolean | `true` only for pilot plan |
| `organization_token` | string | Secret token for future API calls (only on success) |
| `limits` | object | Maximum allowed operations (null if invalid) |
| `usage` | object | Current usage counters (null if invalid) |

### Limits Object

| Field | Type | Description |
|-------|------|-------------|
| `max_assets` | integer or null | Maximum devices that can be added (`null` = unlimited) |
| `max_discoveries` | integer or null | Maximum discovery operations (`null` = unlimited) |
| `max_audits` | integer or null | Maximum audit operations (`null` = unlimited) |
| `max_hardens` | integer or null | Maximum hardening operations (`null` = unlimited) |
| `max_monitors` | integer or null | Maximum monitoring operations (`null` = unlimited) |

### Usage Object

| Field | Type | Description |
|-------|------|-------------|
| `used_assets` | integer | Number of devices currently added |
| `used_discoveries` | integer | Number of discoveries performed |
| `used_audits` | integer | Number of audits performed |
| `used_hardens` | integer | Number of hardenings performed |
| `used_monitors` | integer | Number of monitors active |

---

## Plan Comparison Table

| Plan | Assets | Discoveries | Audits | Hardens | Monitors |
|------|--------|-------------|--------|---------|----------|
| **PILOT** | 5 | 10 | 20 | 10 | 5 |
| **BASIC1** | 15 | 50 | 100 | 50 | 15 |
| **BASIC2** | 50 | 200 | 500 | 200 | 50 |
| **BASIC3** | 150 | 600 | 1500 | 600 | 150 |
| **ENTERPRISE** | ∞ | ∞ | ∞ | ∞ | ∞ |

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
  if (data.limits.max_assets === null) {
    console.log('Unlimited assets!');
  } else {
    const remaining = data.limits.max_assets - data.usage.used_assets;
    console.log(`Assets: ${data.usage.used_assets}/${data.limits.max_assets} (${remaining} remaining)`);
  }
  
  // Display usage
  console.log('Discoveries:', data.usage.used_discoveries);
  console.log('Audits:', data.usage.used_audits);
  console.log('Hardens:', data.usage.used_hardens);
  console.log('Monitors:', data.usage.used_monitors);
} else {
  console.error('License invalid:', data.message);
}
```

---

## Important Notes

1. **`null` vs `0`**: In limits, `null` means unlimited (Enterprise plan), while `0` would mean not allowed
2. **Usage counters**: Always integers, never null, start at 0
3. **organization_token**: Only returned when `valid: true`, save it securely
4. **Signature required**: `/validate` endpoint requires HMAC signature in headers
5. **All fields present**: Even when `valid: false`, all fields exist (but some are null)

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
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "organization_token": "org_new_token_here",
  "limits": { ... },
  "usage": {
    "used_assets": 0,
    "used_discoveries": 0,
    "used_audits": 0,
    "used_hardens": 0,
    "used_monitors": 0
  }
}
```

**Note:** After activation, all usage counters start at 0.
