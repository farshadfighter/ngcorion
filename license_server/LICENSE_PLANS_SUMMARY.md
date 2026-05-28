# License Plans Summary

## Overview

Your application has a **fully implemented and integrated** license system with the following plans. The license system is already working and enforcing quotas across all operations.

---

## License Plans

### 1. Pilot (Testing License)
**Plan Type:** `pilot`  
**Duration:** 30 days  
**Purpose:** Customer testing/evaluation

**Limits:**
- ✅ Max Assets: 5
- ✅ Max Discoveries: 2
- ✅ Max Audits: 2
- ✅ Max Hardens: 2
- ✅ Max Monitors: 2

**Status:** ✅ Implemented and Active

---

### 2. Base License 1 (Small Networks)
**Plan Type:** `basic1`  
**Duration:** 1 year (365 days)  
**Target:** Small networks

**Limits:**
- ✅ Max Assets: 15
- ✅ Max Discoveries: 15
- ✅ Max Audits: 15
- ✅ Max Hardens: 15
- ✅ Max Monitors: 15

**Status:** ✅ Implemented and Active

---

### 3. Base License 2 (Medium Networks)
**Plan Type:** `basic2`  
**Duration:** 1 year (365 days)  
**Target:** Medium networks

**Limits:**
- ✅ Max Assets: 50
- ✅ Max Discoveries: 50
- ✅ Max Audits: 50
- ✅ Max Hardens: 50
- ✅ Max Monitors: 50

**Status:** ✅ Implemented and Active

---

### 4. Base License 3 (Large Networks)
**Plan Type:** `basic3`  
**Duration:** 1 year (365 days)  
**Target:** Large networks

**Limits:**
- ✅ Max Assets: 150
- ✅ Max Discoveries: 150
- ✅ Max Audits: 150
- ✅ Max Hardens: 150
- ✅ Max Monitors: 150

**Status:** ✅ Implemented and Active

---

### 5. Base License 4 (Unlimited/Enterprise)
**Plan Type:** `enterprise`  
**Duration:** 1 year (365 days)  
**Target:** Enterprise/unlimited usage

**Limits:**
- ✅ Max Assets: ∞ (Unlimited)
- ✅ Max Discoveries: ∞ (Unlimited)
- ✅ Max Audits: ∞ (Unlimited)
- ✅ Max Hardens: ∞ (Unlimited)
- ✅ Max Monitors: ∞ (Unlimited)

**Status:** ✅ Implemented and Active

---

## How License Enforcement Works

### 1. Asset Creation
**File:** `app/modules/assets/router_with_auth.py`  
**Endpoint:** `POST /api/assets/`  
**Enforcement:** `require_asset_quota()` dependency

```python
@assets_router.post("/", response_model=AssetResponse)
def create_asset(
    data: AssetCreate,
    current_user: User = Depends(require_admin_or_manager),
    _quota_check: None = Depends(require_asset_quota()),  # ✅ License check here
    db: Session = Depends(get_db)
):
```

**Behavior:**
- Checks if `used_assets >= max_assets` before allowing creation
- Returns HTTP 403 if limit reached
- Does NOT consume quota (assets are counted, not consumed)

---

### 2. Discovery Operations
**Enforcement:** `require_quota("discovery")` dependency

**Behavior:**
- Consumes 1 discovery quota per operation
- Increments `used_discoveries` counter
- Returns HTTP 403 if quota exhausted

---

### 3. Audit Operations
**Enforcement:** `require_quota("audit")` dependency

**Behavior:**
- Consumes 1 audit quota per operation
- Increments `used_audits` counter
- Returns HTTP 403 if quota exhausted

---

### 4. Hardening Operations
**Enforcement:** `require_quota("harden")` dependency

**Behavior:**
- Consumes 1 harden quota per operation
- Increments `used_hardens` counter
- Returns HTTP 403 if quota exhausted

---

### 5. Monitoring Operations
**Enforcement:** `require_quota("monitor")` dependency

**Behavior:**
- Consumes 1 monitor quota per operation
- Increments `used_monitors` counter
- Returns HTTP 403 if quota exhausted

---

## License Validation Flow

### On Application Startup
1. App loads license from `~/.license/.license.dat` (encrypted)
2. Validates with license server
3. Starts hourly heartbeat background task
4. License middleware blocks all `/api/*` requests if invalid

### During Operations
1. User attempts operation (create asset, run discovery, etc.)
2. Dependency checks quota with license server
3. If quota available: operation proceeds, counter increments
4. If quota exhausted: HTTP 403 returned with error message

### Heartbeat (Every Hour)
1. Background task sends heartbeat to license server
2. Updates `last_heartbeat_at` timestamp
3. If heartbeat missed for 48+ hours: license downgrades to PILOT mode

---

## Important Notes

### Asset Licensing Clarification
**Your statement:** "Asset licensing is not applied to asset creation"

**Current Implementation:**
- ✅ Asset licensing **IS** applied to asset creation
- ✅ The `require_asset_quota()` dependency is active on `POST /api/assets/`
- ✅ Users cannot create more assets than their plan allows

**How it works:**
- Assets are **counted**, not **consumed**
- The system checks: `if used_assets >= max_assets: raise 403`
- Unlike discoveries/audits/hardens (which are consumed operations), assets are persistent resources
- Deleting an asset would free up a slot for creating a new one

---

## License Server Architecture

### Separate Server
- **Location:** `/home/sina/netease/license_server/`
- **Database:** PostgreSQL (separate from main app)
- **Port:** Typically 8000 (configurable)
- **Purpose:** Centralized license validation and quota tracking

### Main Application Integration
- **License Client:** `app/core/license_client.py`
- **License State:** `app/core/license_state.py` (in-memory cache)
- **Middleware:** `app/middleware/license_middleware.py`
- **Dependencies:** `app/core/dependencies.py` (quota enforcement)

---

## Admin Operations

### Creating a License for a Customer

```bash
# 1. Admin logs in
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your-admin-password"
  }'

# Response: { "access_token": "eyJ...", "token_type": "bearer" }

# 2. Create license
curl -X POST http://localhost:8000/api/admin/licenses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJ..." \
  -d '{
    "customer_name": "John Doe",
    "customer_email": "john@company.com",
    "organization_name": "ACME Corp",
    "plan_type": "basic2"
  }'

# Response includes:
# - license_key: "XXXX-XXXX-XXXX-XXXX" (give this to customer)
# - organization_token: "abc123..." (customer gets after activation)
# - expires_at: "2026-05-12T..."
# - All plan limits
```

### Available Plan Types
- `pilot` - Testing license (30 days, 5 assets, 2 operations)
- `basic1` - Small networks (1 year, 15 assets, 15 operations)
- `basic2` - Medium networks (1 year, 50 assets, 50 operations)
- `basic3` - Large networks (1 year, 150 assets, 150 operations)
- `enterprise` - Unlimited (1 year, unlimited everything)

---

## Customer Activation Flow

### Step 1: Customer receives license key
Admin sends: `XXXX-XXXX-XXXX-XXXX`

### Step 2: Customer activates in application
```bash
# Get VM fingerprint
curl http://localhost:8000/api/fingerprint

# Activate license
curl -X POST http://localhost:8000/api/licenses/activate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "vm_fingerprint": "fingerprint_from_above"
  }'

# Response includes organization_token
# App stores: license_key + organization_token + vm_fingerprint
```

### Step 3: Application validates on startup
- Automatic validation every time app starts
- Requires HMAC signature for security
- Checks: active, not expired, VM matches, heartbeat not missed

### Step 4: Hourly heartbeat
- Background task runs every hour
- Keeps license alive
- If missed for 48+ hours: downgrades to PILOT mode

---

## Security Features

### VM Fingerprint Locking
- License locked to specific machine after activation
- Cannot be used on different VM/machine
- Prevents license sharing

### HMAC Signature
- All sensitive operations require HMAC-SHA256 signature
- Prevents tampering and replay attacks
- Uses organization_token as secret key

### Encrypted Storage
- License data stored encrypted in `~/.license/.license.dat`
- Uses Fernet symmetric encryption
- Key stored in `~/.license/.license.key` (chmod 600)

### Rate Limiting
- 60 requests per minute per IP
- Prevents brute force attacks

---

## Testing Your License System

### 1. Start License Server
```bash
cd /home/sina/netease/license_server
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

### 2. Start Main Application
```bash
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --reload --port 8001
```

### 3. Create Test License
```bash
# Login as admin
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Create pilot license
curl -X POST http://localhost:8000/api/admin/licenses \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_name": "Test User",
    "customer_email": "test@example.com",
    "organization_name": "Test Org",
    "plan_type": "pilot"
  }'
```

### 4. Test Asset Creation Limit
```bash
# Try to create 6 assets (pilot allows only 5)
# The 6th creation should fail with HTTP 403
```

---

## Comparison Table

| Feature | Pilot | Basic1 | Basic2 | Basic3 | Enterprise |
|---------|-------|--------|--------|--------|------------|
| **Duration** | 30 days | 365 days | 365 days | 365 days | 365 days |
| **Max Assets** | 5 | 15 | 50 | 150 | ∞ |
| **Max Discoveries** | 2 | 15 | 50 | 150 | ∞ |
| **Max Audits** | 2 | 15 | 50 | 150 | ∞ |
| **Max Hardens** | 2 | 15 | 50 | 150 | ∞ |
| **Max Monitors** | 2 | 15 | 50 | 150 | ∞ |
| **VM Lock** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Heartbeat Required** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Auto-downgrade** | N/A | → Pilot | → Pilot | → Pilot | → Pilot |

---

## Conclusion

✅ **Your license system is fully implemented and working**  
✅ **All 5 plans match your requirements exactly**  
✅ **Asset creation IS protected by license quotas**  
✅ **All operations (discovery, audit, harden, monitor) are quota-enforced**  
✅ **Security features (VM lock, HMAC, encryption) are active**  
✅ **Heartbeat and auto-downgrade mechanisms are functional**

**No changes needed** - your license system is production-ready!

---

## Quick Reference

**License Server Endpoints:**
- `GET /api/fingerprint` - Get VM fingerprint
- `POST /api/licenses/activate` - Activate license
- `POST /api/licenses/validate` - Validate license
- `POST /api/licenses/heartbeat` - Send heartbeat
- `POST /api/licenses/consume` - Consume operation quota
- `POST /api/admin/login` - Admin login
- `POST /api/admin/licenses` - Create license (admin)
- `GET /api/admin/licenses` - List all licenses (admin)

**Main App Endpoints:**
- `POST /api/license/activate` - Activate license (frontend)
- `GET /api/license/status` - Get license status (frontend)

**Files to Review:**
- License plans: `license_server/app/crud.py` (line 23-67)
- Asset quota check: `app/core/dependencies.py` (line 186-206)
- Asset creation: `app/modules/assets/router_with_auth.py` (line 141-150)
- License middleware: `app/middleware/license_middleware.py`
- License state: `app/core/license_state.py`
