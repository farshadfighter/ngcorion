# Quick Answer: GET /api/license/status

## Yes, it is implemented on port 8000!

**Endpoint:** `GET http://172.16.200.90:8000/api/license/status`

---

## What it returns when license is active:

```json
{
  "valid": true,
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "message": "License is valid",
  "limits": {
    "max_assets": 50,
    "max_discoveries": 200,
    "max_audits": 500,
    "max_hardens": 200,
    "max_monitors": 50
  },
  "usage": {
    "used_assets": 5,
    "used_discoveries": 12,
    "used_audits": 45,
    "used_hardens": 8,
    "used_monitors": 3
  }
}
```

---

## What it returns when NO license:

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

---

## TypeScript Interface:

```typescript
interface LicenseStatusResponse {
  valid: boolean;
  plan_type: string | null;
  is_pilot_mode: boolean;
  message: string;
  limits: {
    max_assets: number;
    max_discoveries: number;
    max_audits: number;
    max_hardens: number;
    max_monitors: number;
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

## Quick Test:

```bash
curl http://172.16.200.90:8000/api/license/status
```

Or open in browser: http://172.16.200.90:8000/docs

---

## Key Points:

- ✅ No authentication required
- ✅ Returns cached data (very fast)
- ✅ Updated automatically by background heartbeat
- ✅ Check `valid` field to determine if license is active
- ✅ Use `limits` and `usage` to show quota information

---

For detailed documentation, see: LICENSE_STATUS_ENDPOINT_DOCUMENTATION.md
