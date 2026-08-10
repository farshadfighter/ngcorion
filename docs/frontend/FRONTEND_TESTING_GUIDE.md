# Frontend License Testing Guide

Quick guide for testing the frontend license integration.

---

## Prerequisites

1. **Backend running** on port 8000
2. **License server running** on port 8001
3. **Frontend running** on port 5173

---

## Start All Services

### Terminal 1: Main App (Backend)
```bash
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Terminal 2: License Server
```bash
cd /home/sina/netease/license_server
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

### Terminal 3: Frontend
```bash
cd /home/sina/netease/front
npm install  # First time only
npm run dev
```

---

## Test 1: First-Time User (No License)

### Expected Behavior
1. Open http://localhost:5173
2. Should see "Activate Your License" screen
3. Should NOT see login or dashboard

### ✅ Pass Criteria
- Activation screen is displayed
- Input field for license key is visible
- "Activate License" button is present

---

## Test 2: License Activation

### Step 1: Generate License Key

```bash
# Login as admin
TOKEN=$(curl -s -X POST http://localhost:8001/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  | jq -r '.access_token')

# Create license
LICENSE_KEY=$(curl -s -X POST http://localhost:8001/api/admin/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan_type": "plan_250",
    "duration_days": 365,
    "organization_name": "Test Org"
  }' | jq -r '.license_key')

echo "Your License Key: $LICENSE_KEY"
```

### Step 2: Activate in Frontend

1. Copy the license key
2. Paste into the input field
3. Click "Activate License"
4. Wait for activation (should show "Activating...")

### ✅ Pass Criteria
- Success message appears
- Page reloads automatically
- Login screen is now visible
- No more activation screen

---

## Test 3: License Persistence

### Steps
1. After activation, refresh the page (F5)
2. Should NOT show activation screen again
3. Should go directly to login screen

### ✅ Pass Criteria
- License persists across page refreshes
- No re-activation required

---

## Test 4: Invalid License Key

### Steps
1. Clear localStorage: `localStorage.clear()` in browser console
2. Refresh page
3. Enter invalid key: `INVALID-KEY-1234-5678`
4. Click "Activate License"

### ✅ Pass Criteria
- Error message appears: "License key not found"
- Activation screen remains visible
- Can try again with different key

---

## Test 5: License Status Display

### Steps
1. Login to the app (username: admin, password: admin)
2. Navigate to License page in dashboard
3. Check "Active licence" tab

### ✅ Pass Criteria
- Shows plan type (e.g., "250 Audit / 250 Hardening")
- Shows usage bars (Audits, Hardens)
- Shows current usage vs limits
- All numbers are correct

---

## Test 6: Quota Consumption

### Steps
1. Check current usage in License page
2. Perform an audit
3. Wait for the audit to complete
4. Refresh License page or wait 5 minutes

### ✅ Pass Criteria
- Usage counter increments (e.g., used_audits: 0 → 1)
- Limits remain the same
- Progress bars update
- Creating assets or running Auto Discovery does NOT change any usage counter (not license-gated)

---

## Test 7: Quota Exhausted (Pilot Plan)

### Step 1: Create Pilot License

```bash
PILOT_KEY=$(curl -s -X POST http://localhost:8001/api/admin/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan_type": "pilot",
    "duration_days": 30,
    "organization_name": "Test Pilot"
  }' | jq -r '.license_key')

echo "Pilot License Key: $PILOT_KEY"
```

### Step 2: Activate Pilot License

1. Clear localStorage
2. Refresh page
3. Activate with pilot key
4. Login

### Step 3: Exhaust Quota

1. Perform 2 audits (pilot limit)
2. Try to perform a 3rd audit

### ✅ Pass Criteria
- Modal appears: "Quota Limit Reached"
- Shows error message from backend
- "Upgrade Plan" button is visible
- Can close modal

---

## Test 8: 403 Error Handling

### Steps
1. Open browser DevTools (F12)
2. Go to Network tab
3. Try to access protected endpoint without license
4. Should see 403 response

### ✅ Pass Criteria
- Axios interceptor catches 403 error
- If `license_required: true`, shows activation screen
- If quota exhausted, shows quota modal

---

## Test 9: Periodic Status Refresh

### Steps
1. Login and go to License page
2. Note current usage
3. In another tab, perform operations via API
4. Wait 5 minutes
5. Check License page again

### ✅ Pass Criteria
- Usage updates automatically after 5 minutes
- No need to manually refresh

---

## Test 10: Browser Console Errors

### Steps
1. Open browser DevTools (F12)
2. Go to Console tab
3. Navigate through the app

### ✅ Pass Criteria
- No errors in console
- No warnings about missing dependencies
- No CORS errors

---

## Common Issues & Solutions

### Issue: "Network Error" on activation

**Solution:**
```bash
# Check if backend is running
curl http://localhost:8000/api/license/status

# Should return:
# {"valid": false, "plan_type": null, ...}
```

### Issue: Activation screen loops

**Solution:**
```javascript
// Clear localStorage
localStorage.clear();
location.reload();
```

### Issue: Quota modal doesn't appear

**Solution:**
```javascript
// Test manually
window.dispatchEvent(new CustomEvent('quota-exhausted', {
  detail: { message: 'Test quota exhausted message' }
}));
```

### Issue: License status shows old data

**Solution:**
- Wait 5 minutes for auto-refresh
- Or manually refresh the page

---

## API Testing (Optional)

### Check License Status
```bash
curl http://localhost:8000/api/license/status
```

**Expected Response:**
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
    "used_audits": 1,
    "used_hardens": 0
  }
}
```

### Activate License
```bash
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "YOUR-LICENSE-KEY"}'
```

---

## Test Checklist

- [ ] Test 1: First-time user (no license)
- [ ] Test 2: License activation
- [ ] Test 3: License persistence
- [ ] Test 4: Invalid license key
- [ ] Test 5: License status display
- [ ] Test 6: Quota consumption
- [ ] Test 7: Quota exhausted
- [ ] Test 8: 403 error handling
- [ ] Test 9: Periodic status refresh
- [ ] Test 10: Browser console errors

---

## Success Criteria

All tests should pass with:
- ✅ No console errors
- ✅ Correct UI behavior
- ✅ Proper error handling
- ✅ Smooth user experience

---

**Last Updated:** April 29, 2025
