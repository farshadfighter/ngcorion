# License Integration - Implementation Summary

## ✅ Implementation Complete

The license system has been fully integrated into the main application. All API endpoints now require a valid license to function.

---

## What Was Implemented

### 1. Core License Components

**Created Files:**
- `app/core/license_client.py` - Client for communicating with license server
- `app/core/license_state.py` - In-memory license state management (thread-safe)
- `app/core/heartbeat.py` - Background heartbeat service (runs every hour)
- `app/middleware/license_middleware.py` - Blocks all /api/* requests without valid license
- `app/modules/license/router.py` - License activation and status endpoints

**Modified Files:**
- `app/core/config.py` - Added LICENSE_SERVER_URL and LICENSE_STORAGE_DIR settings
- `app/core/dependencies.py` - Added require_quota() and require_asset_quota() dependencies
- `app/main.py` - Added lifespan startup, license middleware, and license router
- `.env.example` - Added license configuration
- `requirements.txt` - Added cryptography and requests

### 2. Quota Enforcement

**Asset Creation:**
- `POST /api/assets/` - Checks max_assets ceiling before allowing creation

**Discovery Operations:**
- `POST /api/discovery/scan` - Consumes 1 discovery quota

**Audit Operations (all consume 1 audit quota):**
- `POST /api/audit/cisco/execute`
- `POST /api/audit/linux/execute`
- `POST /api/audit/fortinet/execute`
- `POST /api/audit/apache/execute`
- `POST /api/audit/mongodb/execute`
- `POST /api/audit/mssql/execute`
- `POST /api/audit/windows/execute`

**Hardening Operations (all consume 1 harden quota):**
- `POST /api/hardening/cisco/execute`
- `POST /api/hardening/linux/batch-execute`
- `POST /api/hardening/fortinet/execute`
- `POST /api/hardening/apache/batch-execute`
- `POST /api/hardening/mongodb/batch-execute`
- `POST /api/hardening/mssql/batch-execute`
- `POST /api/hardening/windows/batch-execute`
- `POST /api/hardening/schema/execute`

---

## How It Works

### Startup Flow

1. Main app starts
2. Creates LicenseClient pointing to license server
3. Attempts to validate existing license (if any)
4. Starts background heartbeat thread (sends heartbeat every hour)
5. License middleware blocks all /api/* requests if license is invalid

### License Activation Flow

1. User calls `POST /api/license/activate` with license key
2. Main app calls license server to activate
3. License data saved encrypted in `~/.license/`
4. In-memory state updated
5. Heartbeat service started
6. All /api/* endpoints now accessible

### Request Flow

```
User Request → License Middleware → Check in-memory state
                                    ↓
                              Valid? → Continue to endpoint
                                    ↓
                              Invalid? → Return 403
```

### Operation Flow

```
User calls operation endpoint (e.g., POST /api/audit/cisco/execute)
    ↓
License middleware checks: valid license?
    ↓
require_quota("audit") dependency: consume 1 audit quota
    ↓
License server checks quota and decrements
    ↓
If quota available: operation proceeds
If quota exhausted: return 403
```

---

## Configuration

### Environment Variables

Add to your `.env` file:

```env
LICENSE_SERVER_URL=http://localhost:8001
LICENSE_STORAGE_DIR=~/.license
```

### License Server

The license server must be running separately. Default port: 8001

Start it with:
```bash
cd license_server
uvicorn app.main:app --reload --port 8001
```

---

## API Endpoints

### New License Endpoints

**GET /api/license/status**
- No authentication required
- Returns current license state from memory
- Response:
```json
{
  "valid": true,
  "plan_type": "basic2",
  "is_pilot_mode": false,
  "message": "License is valid",
  "limits": {
    "max_assets": 50,
    "max_discoveries": 50,
    "max_audits": 50,
    "max_hardens": 50,
    "max_monitors": 50
  },
  "usage": {
    "used_assets": 12,
    "used_discoveries": 5,
    "used_audits": 8,
    "used_hardens": 3,
    "used_monitors": 2
  }
}
```

**POST /api/license/activate**
- No authentication required
- Request body: `{"license_key": "XXXX-XXXX-XXXX-XXXX"}`
- Activates license and starts heartbeat
- Returns same format as /status

### Passthrough Endpoints (No License Required)

- `POST /auth/login`
- `GET /health`
- `GET /`
- `POST /api/license/activate`
- `GET /api/license/status`

All other `/api/*` endpoints require valid license.

---

## Error Responses

### No License

```json
{
  "detail": "No valid license. Please activate a license first.",
  "license_required": true
}
```
Status: 403

### Quota Exhausted

```json
{
  "detail": "Quota for discovery has been exhausted (50/50). Please upgrade your plan.",
  "quota_exhausted": true
}
```
Status: 403

### Asset Limit Reached

```json
{
  "detail": "Asset limit reached (50/50). Upgrade your plan or delete unused assets."
}
```
Status: 403

---

## Testing

### 1. Start License Server

```bash
cd license_server
uvicorn app.main:app --reload --port 8001
```

### 2. Start Main App

```bash
cd /home/sina/netease
uvicorn app.main:app --reload --port 8000
```

### 3. Test Without License

```bash
curl http://localhost:8000/api/assets/
# Expected: 403 with license_required: true
```

### 4. Activate License

First, create a license on the license server (see LICENSE_SYSTEM_COMPLETE_GUIDE.md), then:

```bash
curl -X POST http://localhost:8000/api/license/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "YOUR-LICENSE-KEY"}'
```

### 5. Check Status

```bash
curl http://localhost:8000/api/license/status
```

### 6. Test Operations

```bash
# Login first
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Use the token in subsequent requests
curl http://localhost:8000/api/assets/ \
  -H "Authorization: Bearer YOUR-TOKEN"
```

---

## Monitoring

### Heartbeat

The heartbeat service runs in a background thread and:
- Sends heartbeat to license server every 3600 seconds (1 hour)
- Refreshes in-memory license state after each heartbeat
- Logs success/failure to console
- If heartbeat fails for 48+ hours, license server downgrades to PILOT mode

### Logs

Check console output for:
- `Heartbeat service started (interval: 3600s)`
- `Heartbeat successful: License is valid`
- `Heartbeat failed: <error>`

---

## Troubleshooting

### "License server unreachable"

- Check LICENSE_SERVER_URL in .env
- Verify license server is running on port 8001
- Check network connectivity

### "No valid license"

- Activate a license via `POST /api/license/activate`
- Check license hasn't expired
- Verify license server has the license key

### "Quota exhausted"

- Check current usage: `GET /api/license/status`
- Upgrade plan or wait for quota reset
- Contact admin to increase limits

### Heartbeat not running

- Check logs for "Heartbeat service started"
- Verify license was activated (heartbeat starts on activation)
- Restart main app

---

## Next Steps

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure .env:**
   ```bash
   cp .env.example .env
   nano .env  # Add LICENSE_SERVER_URL
   ```

3. **Start both servers:**
   - License server on port 8001
   - Main app on port 8000

4. **Create and activate license:**
   - Use license server admin API to create license
   - Activate via main app's `/api/license/activate`

5. **Test the integration:**
   - Try accessing endpoints without license (should fail)
   - Activate license
   - Try accessing endpoints (should work)
   - Test quota limits

---

## Architecture Summary

```
Main App (port 8000)
├── Startup: Initialize LicenseClient, validate, start heartbeat
├── Middleware: Block /api/* if license invalid
├── Dependencies: require_quota() for operations
├── Endpoints: /api/license/status, /api/license/activate
└── Background: Heartbeat thread (every 3600s)
        ↓
License Server (port 8001)
├── POST /api/fingerprint
├── POST /api/licenses/activate
├── POST /api/licenses/validate
├── POST /api/licenses/heartbeat
└── POST /api/licenses/consume
```

---

## Files Created/Modified

**Created (9 files):**
- app/core/license_client.py
- app/core/license_state.py
- app/core/heartbeat.py
- app/middleware/__init__.py
- app/middleware/license_middleware.py
- app/modules/license/__init__.py
- app/modules/license/router.py
- LICENSE_INTEGRATION_SUMMARY.md (this file)

**Modified (15+ files):**
- app/core/config.py
- app/core/dependencies.py
- app/main.py
- .env.example
- requirements.txt
- app/modules/assets/router_with_auth.py
- app/modules/discovery/router.py
- app/modules/cisco/audit/router.py
- app/modules/linux/audit/router.py
- app/modules/fortinet/audit/router.py
- app/modules/apache/audit/router.py
- app/modules/mongodb/audit/router.py
- app/modules/mssql/audit/router.py
- app/modules/windows/audit/router.py
- All hardening routers (cisco, linux, fortinet, apache, mongodb, mssql, windows, shared)

---

## Success! 🎉

The license system is now fully integrated. Every operation in your application is protected by license validation and quota enforcement.
