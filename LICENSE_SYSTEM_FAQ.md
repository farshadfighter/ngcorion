# License System - Frequently Asked Questions

Complete answers to all questions about how the license system works.

---

## Questions Answered

1. [How is the license checked? How often?](#1-how-is-the-license-checked-how-often)
2. [Where is the license stored?](#2-where-is-the-license-stored)
3. [How to generate a license key?](#3-how-to-generate-a-license-key)
4. [Can users use the program without a license?](#4-can-users-use-the-program-without-a-license)
5. [Manual Testing Guide](#5-manual-testing-guide)

---

## 1. How is the license checked? How often?

### Initial Check (App Startup)

When the main application starts:

1. **Loads license from disk** (`~/.license/.license.dat`)
2. **Validates with license server** via `POST /api/licenses/validate`
3. **Updates in-memory state** with the validation result
4. **Starts heartbeat thread** if license is valid

```python
# app/main.py - lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    client = LicenseClient(settings.LICENSE_SERVER_URL, settings.LICENSE_STORAGE_DIR)
    app.state.license_client = client
    
    # Try to validate existing license
    try:
        refresh_license_state(client)
        start_heartbeat(client)
    except Exception as e:
        logger.warning(f"License validation failed on startup: {e}")
    
    yield
    
    # Shutdown
    stop_heartbeat()
```

### Continuous Checking (Heartbeat)

**Frequency:** Every **3600 seconds (1 hour)**

The heartbeat runs in a background daemon thread:

```python
# app/core/heartbeat.py
def _heartbeat_loop(client: LicenseClient):
    while not _stop_event.is_set():
        try:
            result = client.heartbeat()
            # Refresh license state after heartbeat
            refresh_license_state(client)
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")
        
        # Wait 1 hour before next heartbeat
        _stop_event.wait(3600)
```

### Per-Request Checking (Middleware)

**Every API request** goes through `LicenseMiddleware`:

```python
# app/middleware/license_middleware.py
async def dispatch(self, request: Request, call_next):
    # Check in-memory license state
    state = get_license_state()
    
    if not state.valid:
        return JSONResponse(
            status_code=403,
            content={"detail": "No valid license...", "license_required": True}
        )
    
    return await call_next(request)
```

### Summary

| Check Type | Frequency | Purpose |
|------------|-----------|---------|
| **Startup Validation** | Once at app start | Load and validate existing license |
| **Heartbeat** | Every 1 hour | Keep license state fresh, detect expiration |
| **Middleware** | Every API request | Block requests if license invalid |
| **Quota Consumption** | Per operation | Verify quota before operations |

---

## 2. Where is the license stored?

### Storage Location

**Path:** `~/.license/` (user's home directory)

**Files:**
- `~/.license/.license.dat` — Encrypted license data (Fernet encryption)
- `~/.license/.license.key` — Encryption key (auto-generated)

**Permissions:** `0600` (read/write for owner only)

### What's Stored

```json
{
  "license_key": "ABCD-EFGH-IJKL-MNOP",
  "organization_token": "org_abc123def456",
  "vm_fingerprint": "a1b2c3d4e5f6...",
  "plan_type": "basic2",
  "activated_at": "2025-04-28T10:30:00.123456"
}
```

### Storage Implementation

```python
# app/core/license_client.py - SecureStorage class
class SecureStorage:
    def __init__(self, storage_dir: str = "~/.license"):
        self.storage_dir = Path(storage_dir).expanduser()
        self.license_file = self.storage_dir / ".license.dat"
        self.key_file = self.storage_dir / ".license.key"
    
    def save_license(self, license_data: dict):
        cipher = self._get_cipher()
        json_data = json.dumps(license_data)
        encrypted = cipher.encrypt(json_data.encode())
        self.license_file.write_bytes(encrypted)
        os.chmod(self.license_file, 0o600)
```

### In-Memory State

The application also keeps license state in memory for fast access:

```python
# app/core/license_state.py
@dataclass
class LicenseState:
    valid: bool = False
    plan_type: Optional[str] = None
    is_pilot_mode: bool = False
    limits: Optional[dict] = None
    usage: Optional[dict] = None
    message: str = "No license activated"
    last_validated_at: Optional[datetime] = None
```

**Why both disk and memory?**
- **Disk:** Persists across app restarts
- **Memory:** Fast access for every API request (no disk I/O)

---

## 3. How to generate a license key?

### Important: Users CANNOT Generate Their Own License

**Only administrators can generate license keys** using the license server admin API.

### Step-by-Step Process

#### Step 1: Start the License Server

```bash
cd /home/sina/netease/license_server
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

#### Step 2: Admin Login

```bash
curl -X POST http://localhost:8001/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Save the token** — you'll need it for the next step.

#### Step 3: Create License

```bash
curl -X POST http://localhost:8001/api/admin/licenses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -d '{
    "plan_type": "basic2",
    "duration_days": 365,
    "organization_name": "Acme Corp"
  }'
```

**Response:**
```json
{
  "license_key": "ABCD-EFGH-IJKL-MNOP",
  "organization_token": "org_abc123def456",
  "plan_type": "basic2",
  "organization_name": "Acme Corp",
  "created_at": "2025-04-28T10:30:00",
  "expires_at": "2026-04-28T10:30:00",
  "is_active": true,
  "is_activated": false
}
```

#### Step 4: Give License Key to User

**Give the user ONLY the `license_key`:**
```
ABCD-EFGH-IJKL-MNOP
```

**DO NOT give them:**
- ❌ `organization_token` (secret, used for HMAC signatures)
- ❌ Admin credentials
- ❌ Access to license server

### Available Plan Types

| Plan Type | Assets | Operations | Duration |
|-----------|--------|------------|----------|
| `pilot` | 5 | 10/20/10/5 | 30 days |
| `basic1` | 15 | 50/100/50/15 | 365 days |
| `basic2` | 50 | 200/500/200/50 | 365 days |
| `basic3` | 150 | 600/1500/600/150 | 365 days |
| `enterprise` | ∞ | ∞ | 365 days |

### Using Swagger UI (Easier)

1. Open `http://localhost:8001/docs`
2. Click **Authorize** button
3. Login with admin credentials
4. Use `POST /api/admin/licenses` endpoint
5. Fill in the form and execute
6. Copy the `license_key` from the response

---

## 4. Can users use the program without a license?

### Short Answer: **NO**

Without a valid license, users **cannot use any features** of the main application.

### What Users CAN Access Without License

Only these endpoints are accessible:

1. `GET /health` — Health check
2. `GET /` — Root endpoint
3. `POST /auth/login` — Login endpoint (but pointless without license)
4. `GET /api/license/status` — Check license status
5. `POST /api/license/activate` — Activate a license

### What Users CANNOT Access Without License

**All other `/api/*` endpoints return `403 Forbidden`:**

```json
{
  "detail": "No valid license. Please activate a license first.",
  "license_required": true
}
```

**Examples of blocked endpoints:**
- `GET /api/assets/` — Cannot view assets
- `POST /api/discovery/scan` — Cannot run discovery
- `POST /api/audit/cisco/execute` — Cannot run audits
- `POST /api/harden/cisco/execute` — Cannot run hardening
- `GET /api/dashboard/stats` — Cannot view dashboard

### Middleware Implementation

```python
# app/middleware/license_middleware.py
class LicenseMiddleware(BaseHTTPMiddleware):
    PASSTHROUGH_PATHS = {
        "/auth/login",
        "/health",
        "/",
        "/api/license/activate",
        "/api/license/status",
    }
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Allow passthrough paths
        if path in self.PASSTHROUGH_PATHS:
            return await call_next(request)
        
        # Allow non-API paths (e.g., /docs)
        if not path.startswith("/api/"):
            return await call_next(request)
        
        # Check license state
        state = get_license_state()
        if not state.valid:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "No valid license. Please activate a license first.",
                    "license_required": True
                }
            )
        
        return await call_next(request)
```

### User Experience Flow

```
User opens app
    ↓
Frontend checks license status
    ↓
    ├─→ No license
    │       ↓
    │   Show activation screen
    │   User cannot proceed until they activate
    │
    └─→ Valid license
            ↓
        Show login screen
            ↓
        User can access all features
```

### Even Pilot Plan Requires Activation

**Important:** Even users on the free Pilot (trial) plan **must activate a license key**.

There is no "try without license" mode.

---

## 5. Manual Testing Guide

### Prerequisites

1. **License Server** running on port 8001
2. **Main App** running on port 8000
3. **Admin credentials** for license server

### Test Scenario 1: First-Time User (No License)

#### Step 1: Check License Status

```bash
curl http://localhost:8000/api/license/status
```

**Expected Response:**
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

#### Step 2: Try to Access Protected Endpoint

```bash
curl http://localhost:8000/api/assets/
```

**Expected Response (403):**
```json
{
  "detail": "No valid license. Please activate a license first.",
  "license_required": true
}
```

✅ **Result:** User is blocked without license.

---

### Test Scenario 2: Activate License

#### Step 1: Generate License Key (Admin)

```bash
# Login as admin
TOKEN=$(curl -X POST http://localhost:8001/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}' \
  | jq -r '.access_token')

# Create license
LICENSE_KEY=$(curl -X POST http://localhost:8001/api/admin/licenses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "plan_type": "basic2",
    "duration_days": 365,
    "organization_name": "Test Org"
  }' | jq -r '.license_key')

echo "License Key: $LICENSE_KEY"
```

#### Step 2: Activate License (User)

```bash
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d "{\"license_key\": \"$LICENSE_KEY\"}"
```

**Expected Response (200):**
```json
{
  "valid": true,
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "message": "License activated successfully",
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

✅ **Result:** License activated successfully.

#### Step 3: Verify License Status

```bash
curl http://localhost:8000/api/license/status
```

**Expected Response:**
```json
{
  "valid": true,
  "plan_type": "basic2",
  ...
}
```

✅ **Result:** License is now valid.

#### Step 4: Access Protected Endpoint

```bash
# First, login to get JWT token
JWT_TOKEN=$(curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" \
  | jq -r '.access_token')

# Now access protected endpoint
curl http://localhost:8000/api/assets/ \
  -H "Authorization: Bearer $JWT_TOKEN"
```

**Expected Response (200):**
```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "size": 50,
  "pages": 0
}
```

✅ **Result:** User can now access protected endpoints.

---

### Test Scenario 3: Quota Consumption

#### Step 1: Check Current Usage

```bash
curl http://localhost:8000/api/license/status | jq '.usage'
```

**Expected:**
```json
{
  "used_assets": 0,
  "used_discoveries": 0,
  "used_audits": 0,
  "used_hardens": 0,
  "used_monitors": 0
}
```

#### Step 2: Perform an Operation (e.g., Discovery)

```bash
curl -X POST http://localhost:8000/api/discovery/scan \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "network": "192.168.1.0/24",
    "scan_type": "quick"
  }'
```

**Expected Response (200):**
```json
{
  "task_id": "abc123",
  "status": "started"
}
```

#### Step 3: Check Updated Usage

```bash
curl http://localhost:8000/api/license/status | jq '.usage'
```

**Expected:**
```json
{
  "used_assets": 0,
  "used_discoveries": 1,  // ← Incremented
  "used_audits": 0,
  "used_hardens": 0,
  "used_monitors": 0
}
```

✅ **Result:** Quota is consumed automatically.

---

### Test Scenario 4: Quota Exhaustion

#### Step 1: Create Pilot License (Low Limits)

```bash
PILOT_KEY=$(curl -X POST http://localhost:8001/api/admin/licenses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "plan_type": "pilot",
    "duration_days": 30,
    "organization_name": "Test Pilot"
  }' | jq -r '.license_key')

echo "Pilot License: $PILOT_KEY"
```

#### Step 2: Activate Pilot License

```bash
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d "{\"license_key\": \"$PILOT_KEY\"}"
```

**Expected:**
```json
{
  "valid": true,
  "plan_type": "pilot",
  "is_pilot_mode": true,
  "limits": {
    "max_assets": 5,
    "max_discoveries": 10,
    "max_audits": 20,
    "max_hardens": 10,
    "max_monitors": 5
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

#### Step 3: Exhaust Discovery Quota

```bash
# Run 10 discoveries (pilot limit)
for i in {1..10}; do
  curl -X POST http://localhost:8000/api/discovery/scan \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"network\": \"192.168.$i.0/24\", \"scan_type\": \"quick\"}"
  echo "Discovery $i completed"
done
```

#### Step 4: Try to Exceed Quota

```bash
curl -X POST http://localhost:8000/api/discovery/scan \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.99.0/24", "scan_type": "quick"}'
```

**Expected Response (403):**
```json
{
  "detail": "Discovery quota exhausted (10/10). Upgrade your plan to continue."
}
```

✅ **Result:** User is blocked when quota is exhausted.

---

### Test Scenario 5: Asset Limit

#### Step 1: Check Asset Limit

```bash
curl http://localhost:8000/api/license/status | jq '.limits.max_assets'
```

**Expected (Pilot):** `5`

#### Step 2: Create Assets Up to Limit

```bash
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/assets/ \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"Device $i\",
      \"ip_address\": \"192.168.1.$i\",
      \"device_type\": \"cisco_ios\"
    }"
  echo "Asset $i created"
done
```

#### Step 3: Try to Exceed Asset Limit

```bash
curl -X POST http://localhost:8000/api/assets/ \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Device 6",
    "ip_address": "192.168.1.6",
    "device_type": "cisco_ios"
  }'
```

**Expected Response (403):**
```json
{
  "detail": "Asset limit reached (5/5). Upgrade your plan or delete unused assets."
}
```

✅ **Result:** User cannot create more assets than allowed.

---

### Test Scenario 6: License Persistence

#### Step 1: Restart Main App

```bash
# Stop the app (Ctrl+C)
# Start it again
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### Step 2: Check License Status

```bash
curl http://localhost:8000/api/license/status
```

**Expected Response:**
```json
{
  "valid": true,
  "plan_type": "pilot",
  ...
}
```

✅ **Result:** License persists across restarts (loaded from `~/.license/`).

---

### Test Scenario 7: Invalid License Key

#### Step 1: Try to Activate Invalid Key

```bash
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "INVALID-KEY-1234-5678"}'
```

**Expected Response (400):**
```json
{
  "detail": "License key not found"
}
```

✅ **Result:** Invalid keys are rejected.

---

### Test Scenario 8: License Already Activated on Another Machine

#### Step 1: Activate License on Machine A

```bash
# On Machine A
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d "{\"license_key\": \"$LICENSE_KEY\"}"
```

**Expected:** Success (200)

#### Step 2: Try to Activate Same License on Machine B

```bash
# On Machine B (different VM fingerprint)
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d "{\"license_key\": \"$LICENSE_KEY\"}"
```

**Expected Response (400):**
```json
{
  "detail": "License already activated on a different machine"
}
```

✅ **Result:** License is machine-locked.

---

## Summary

### How License System Works

1. **License Checking:**
   - Startup: Validates existing license
   - Heartbeat: Every 1 hour
   - Middleware: Every API request
   - Quota: Per operation

2. **License Storage:**
   - Disk: `~/.license/.license.dat` (encrypted)
   - Memory: In-memory state for fast access

3. **License Generation:**
   - Admin only via license server API
   - Users receive license key string
   - Users activate via main app

4. **Without License:**
   - Users cannot access any features
   - All `/api/*` endpoints return 403
   - Even Pilot plan requires activation

5. **Testing:**
   - Use curl commands to test all scenarios
   - Verify quota consumption
   - Test license persistence
   - Test error cases

---

## Related Documentation

- `FRONTEND_LICENSE_INTEGRATION_GUIDE.md` — Frontend implementation guide
- `LICENSE_SYSTEM_COMPLETE_GUIDE.md` — Complete backend guide
- `VALIDATE_RESPONSE_FORMAT.md` — API response formats
- `API_RESPONSE_EXAMPLES.md` — More examples

---

**Last Updated:** April 28, 2025
