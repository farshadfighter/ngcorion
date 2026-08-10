# Frontend License Integration - Quick Start

## TL;DR

Your backend already has the license API ready. Frontend just needs to call these two endpoints:

### 1. Activate License
```javascript
POST /api/license/activate
Content-Type: application/json

{
  "license_key": "XXXX-XXXX-XXXX-XXXX"
}
```

### 2. Get License Status
```javascript
GET /api/license/status
Authorization: Bearer <jwt_token>
```

---

## What Frontend Developer Needs to Do

### Step 1: Create License Activation Screen
- Show input field for license key (format: XXXX-XXXX-XXXX-XXXX)
- Call `POST /api/license/activate` with the key
- Handle success: redirect to main app
- Handle errors: show error message

### Step 2: Check License on App Load
- After user logs in, call `GET /api/license/status`
- If `valid: false`, redirect to activation screen
- If `valid: true`, show main app

### Step 3: Display License Info (Optional)
- Show license status in settings/dashboard
- Display quota usage with progress bars
- Warn when quota > 70% used

### Step 4: Handle Quota Errors
- When any API call returns 403 with quota error
- Show user-friendly message
- Suggest upgrading plan

---

## API Response Examples

### Activation Success
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
    "used_audits": 0,
    "used_hardens": 0
  }
}
```

### Activation Error
```json
{
  "detail": "License key not found"
}
```

### License Status (Valid)
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
    "used_audits": 15,
    "used_hardens": 5
  }
}
```

### License Status (No License)
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

### Quota Exhausted Error (from audit/harden APIs)
```json
{
  "detail": "Audit quota exhausted (250/250). Upgrade your plan."
}
```

Note: Asset Management (asset creation and Auto Discovery) is not license-gated, so it never returns a quota-exhausted error.

---

## Plan Types Reference

| Plan Type | Display Name | Max Audits / Hardens | Duration |
|-----------|--------------|-----------------------|----------|
| `pilot` | Pilot | 2 | 30 days |
| `plan_100` | 100 Audit / 100 Hardening | 100 | 1 year |
| `plan_250` | 250 Audit / 250 Hardening | 250 | 1 year |
| `plan_500` | 500 Audit / 500 Hardening | 500 | 1 year |
| `unlimited` | Unlimited | ∞ | 1 year |

Asset Management (asset creation and Auto Discovery) is not license-gated on any plan.

---

## Minimal Implementation (React)

```jsx
// 1. Check license on app load
useEffect(() => {
  const checkLicense = async () => {
    const response = await fetch('/api/license/status', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await response.json();
    
    if (!data.valid) {
      // Redirect to activation page
      navigate('/activate-license');
    }
  };
  
  checkLicense();
}, []);

// 2. Activation form
const handleActivate = async (licenseKey) => {
  const response = await fetch('/api/license/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ license_key: licenseKey })
  });
  
  if (response.ok) {
    // Success - redirect to main app
    navigate('/dashboard');
  } else {
    const error = await response.json();
    alert(error.detail);
  }
};

// 3. Handle quota errors globally
axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 403) {
      const detail = error.response.data.detail;
      if (detail?.includes('limit reached') || detail?.includes('quota exhausted')) {
        // Show quota error notification
        showNotification(detail);
      }
    }
    return Promise.reject(error);
  }
);
```

---

## Testing

### Test with Pilot License (2 audits / 2 hardens max)
1. Get a pilot license key from admin
2. Activate it in your frontend
3. Try to run 3 audits
4. The 3rd should fail with: "Audit quota exhausted (2/2)"

### Test License Status Display
1. Activate a license
2. Run some audits and hardening operations
3. Check `/api/license/status` - usage should update
4. Display this in your UI
5. Confirm creating assets and running Auto Discovery never affects usage (they are not license-gated)

---

## Full Documentation

For complete implementation guide with full code examples:
- See `FRONTEND_LICENSE_INTEGRATION_GUIDE.md`

For backend license system details:
- See `LICENSE_SYSTEM_COMPLETE_GUIDE.md`
- See `LICENSE_PLANS_SUMMARY.md`

---

## Questions?

Contact the backend team or check the documentation files above.
