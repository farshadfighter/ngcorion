# Quick Start - License System

## TL;DR - Answers to Your Questions

### 1. How is license checked? How often?
- **Activation:** Once (first time)
- **Validation:** Every app startup
- **Heartbeat:** Every hour (background)
- **Consume:** Before each operation

### 2. Where is license stored?
- **Server:** PostgreSQL database
- **Client:** Your app must store in localStorage/config

### 3. Who generates licenses?
- **YOU (Admin)** generate licenses via API
- **Customer CANNOT** generate their own
- You give customer the `license_key` only

### 4. Can users use app without license?
- **Currently: YES** (no license checks in main app)
- **Should be: NO** (you need to add license validation)

---

## Quick Test (5 Minutes)

### 1. Start Server
```bash
cd license_server
uvicorn app.main:app --reload --port 8000
```

### 2. Admin Login
```bash
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}'
```
Save the `access_token`

### 3. Create License
```bash
curl -X POST http://localhost:8000/api/admin/licenses \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "customer_name": "Test User",
    "customer_email": "test@test.com",
    "organization_name": "Test Org",
    "plan_type": "basic2"
  }'
```
Save the `license_key`

### 4. Get Fingerprint
```bash
curl http://localhost:8000/api/fingerprint
```
Save the `fingerprint`

### 5. Activate License
```bash
curl -X POST http://localhost:8000/api/licenses/activate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "YOUR-LICENSE-KEY",
    "vm_fingerprint": "YOUR-FINGERPRINT"
  }'
```
Save the `organization_token`

### 6. Test in Browser
Open: `http://localhost:8000/docs`

---

## What You Need to Do

### ⚠️ Critical: Main App Has NO License Integration

Your main application (`app/`) doesn't check licenses. You need to add:

1. **Startup validation**
```python
@app.on_event("startup")
async def check_license():
    # Validate license or exit
    pass
```

2. **Operation checks**
```python
@app.post("/api/discovery")
async def discover():
    # Check license quota first
    # Then perform operation
    pass
```

3. **Background heartbeat**
```python
# Send heartbeat every hour
```

---

## Plan Limits

| Plan | Assets | Operations | Duration |
|------|--------|------------|----------|
| PILOT | 5 | 2 each | 30 days |
| BASIC1 | 15 | 15 each | 365 days |
| BASIC2 | 50 | 50 each | 365 days |
| BASIC3 | 150 | 150 each | 365 days |
| ENTERPRISE | ∞ | ∞ | 365 days |

---

## Key Endpoints

```
GET  /api/fingerprint          → Get VM fingerprint
POST /api/licenses/activate    → Activate license
POST /api/licenses/validate    → Check license (needs signature)
POST /api/licenses/heartbeat   → Keep alive
POST /api/licenses/consume     → Use operation (needs signature)

POST /api/admin/login          → Admin login
POST /api/admin/licenses       → Create license (admin)
GET  /api/admin/licenses       → List licenses (admin)
```

---

## Important Notes

1. **License Key Format:** `XXXX-XXXX-XXXX-XXXX`
2. **Organization Token:** Secret, returned after activation
3. **VM Fingerprint:** Locks license to one machine
4. **Heartbeat:** Must send every hour or license downgrades
5. **Signature:** Required for validate and consume endpoints

---

## Full Documentation

See `LICENSE_SYSTEM_COMPLETE_GUIDE.md` for:
- Complete testing guide
- Integration examples
- Security notes
- Troubleshooting
- Production deployment

---

## Default Admin Credentials

**⚠️ CHANGE IN PRODUCTION!**

```
Username: admin
Password: changeme
```

Edit in `license_server/.env`:
```env
ADMIN_USERNAME=your_username
ADMIN_PASSWORD=your_secure_password
```
