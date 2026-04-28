# /api/licenses/validate - Exact Response Format

## Quick Answer

Here's the **exact response format** after activating and validating a license:

```json
{
  "valid": true,
  "message": "License is valid",
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "organization_token": "org_abc123def456",
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

---

## Field Types

```typescript
interface ValidationResponse {
  valid: boolean;
  message: string;
  plan_type: "pilot" | "basic1" | "basic2" | "basic3" | "enterprise" | null;
  is_pilot_mode: boolean;
  organization_token: string | null;
  limits: {
    max_assets: number | null;      // null = unlimited (Enterprise only)
    max_discoveries: number | null;
    max_audits: number | null;
    max_hardens: number | null;
    max_monitors: number | null;
  } | null;
  usage: {
    used_assets: number;
    used_discoveries: number;
    used_audits: number;
    used_hardens: number;
    used_monitors: number;
  } | null;
}
```

---

## Key Points

1. **`limits` object**: Contains maximum allowed operations
   - For Enterprise plan: all values are `null` (meaning unlimited)
   - For other plans: all values are positive integers

2. **`usage` object**: Contains current usage counters
   - Always integers (never null)
   - Start at 0 after activation
   - Increment when you call `/api/licenses/consume`

3. **`organization_token`**: 
   - Returned on successful validation
   - Must be saved and used for all future API calls
   - Acts as the secret key for HMAC signatures

---

## Examples by Plan Type

### PILOT (Trial)
```json
"limits": {
  "max_assets": 5,
  "max_discoveries": 10,
  "max_audits": 20,
  "max_hardens": 10,
  "max_monitors": 5
}
```

### BASIC1 (15 devices)
```json
"limits": {
  "max_assets": 15,
  "max_discoveries": 50,
  "max_audits": 100,
  "max_hardens": 50,
  "max_monitors": 15
}
```

### BASIC2 (50 devices)
```json
"limits": {
  "max_assets": 50,
  "max_discoveries": 200,
  "max_audits": 500,
  "max_hardens": 200,
  "max_monitors": 50
}
```

### BASIC3 (150 devices)
```json
"limits": {
  "max_assets": 150,
  "max_discoveries": 600,
  "max_audits": 1500,
  "max_hardens": 600,
  "max_monitors": 150
}
```

### ENTERPRISE (Unlimited)
```json
"limits": {
  "max_assets": null,
  "max_discoveries": null,
  "max_audits": null,
  "max_hardens": null,
  "max_monitors": null
}
```

---

## How to Check Remaining Quota

```javascript
function checkQuota(response) {
  if (!response.valid) {
    console.error('License invalid');
    return;
  }
  
  // Check if unlimited (Enterprise)
  if (response.limits.max_assets === null) {
    console.log('Unlimited plan!');
    return;
  }
  
  // Calculate remaining
  const remaining = {
    assets: response.limits.max_assets - response.usage.used_assets,
    discoveries: response.limits.max_discoveries - response.usage.used_discoveries,
    audits: response.limits.max_audits - response.usage.used_audits,
    hardens: response.limits.max_hardens - response.usage.used_hardens,
    monitors: response.limits.max_monitors - response.usage.used_monitors
  };
  
  console.log('Remaining quota:', remaining);
  
  // Check if any quota is exhausted
  if (remaining.assets <= 0) {
    alert('Asset limit reached!');
  }
}
```

---

## Invalid License Response

When license is invalid/expired:

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

## Complete Documentation

For more examples and all plan types, see: `API_RESPONSE_EXAMPLES.md`
