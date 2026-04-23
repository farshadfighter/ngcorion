# Migration Guide: v1.0 to v2.0

This guide helps you upgrade from the basic license server (v1.0) to the enhanced version (v2.0) with security and performance improvements.

## Overview of Changes

### Breaking Changes

1. **Admin Authentication**: Changed from HTTP Basic Auth to JWT tokens
2. **Request Signing**: `/validate` and `/consume` endpoints now require HMAC signatures
3. **New Dependencies**: Redis required for rate limiting

### Non-Breaking Changes

- Database indexes added (automatic via migration)
- Connection pooling enabled
- Logging middleware added
- Configuration centralized

## Step-by-Step Migration

### 1. Backup Your Data

```bash
# Backup database
pg_dump -U postgres license_db > backup_before_upgrade.sql

# Backup environment file
cp .env .env.backup
```

### 2. Install New Dependencies

```bash
pip install -r requirements.txt
```

New packages:
- `redis==5.0.1`
- `alembic==1.13.1`
- `requests==2.31.0`

### 3. Setup Redis

```bash
# Install Redis (Ubuntu/Debian)
sudo apt-get install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Verify
redis-cli ping  # Should return PONG
```

### 4. Update Environment Configuration

Add these new variables to your `.env` file:

```bash
# JWT Configuration
JWT_EXPIRE_HOURS=24

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60

# API Configuration
API_V1_PREFIX=/api
```

Keep existing variables:
- `DATABASE_URL`
- `SECRET_KEY`
- `ALGORITHM`
- `ACCESS_TOKEN_EXPIRE_MINUTES`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`

### 5. Run Database Migrations

```bash
# Apply migrations to add indexes
alembic upgrade head
```

This will create four performance indexes without modifying existing data.

### 6. Update Admin Scripts

**Old way (HTTP Basic Auth):**

```bash
curl -X POST "http://localhost:8000/api/admin/licenses" \
  -u admin:password \
  -H "Content-Type: application/json" \
  -d '{"customer_name": "Test", ...}'
```

**New way (JWT):**

```bash
# Step 1: Login to get token
TOKEN=$(curl -X POST "http://localhost:8000/api/admin/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}' \
  | jq -r '.access_token')

# Step 2: Use token for admin operations
curl -X POST "http://localhost:8000/api/admin/licenses" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"customer_name": "Test", ...}'
```

### 7. Update Client Applications

You have two options:

#### Option A: Use the New SDK (Recommended)

```python
from client import LicenseClient, HeartbeatService

# Initialize
client = LicenseClient(server_url="http://localhost:8000")

# Activate (first time)
result = client.activate("XXXX-XXXX-XXXX-XXXX")

# Validate (automatic signing)
result = client.validate()

# Consume (automatic signing)
result = client.consume(operation_type="discovery", count=1)

# Heartbeat (no signing required)
result = client.heartbeat()

# Start automatic heartbeat
heartbeat = HeartbeatService(client, interval_seconds=3600)
heartbeat.start()
```

#### Option B: Manual Implementation

If you can't use the SDK, implement request signing manually:

```python
import hmac
import hashlib
import json
from datetime import datetime
import requests

def sign_request(data, org_token):
    timestamp = datetime.utcnow().isoformat() + 'Z'
    payload = json.dumps(data, sort_keys=True)
    message = f"{payload}:{timestamp}"
    signature = hmac.new(
        org_token.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature, timestamp

# Example: Validate request
data = {
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "organization_token": "your-org-token",
    "vm_fingerprint": "your-fingerprint"
}

signature, timestamp = sign_request(data, data["organization_token"])

response = requests.post(
    "http://localhost:8000/api/licenses/validate",
    json=data,
    headers={
        "X-Signature": signature,
        "X-Timestamp": timestamp
    }
)
```

### 8. Restart the Server

```bash
# Stop old server
# Start new server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 9. Verify Migration

**Test health endpoint:**
```bash
curl http://localhost:8000/health
```

**Test admin login:**
```bash
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'
```

**Test existing licenses still work:**
```bash
# Activate endpoint (no signature required)
curl -X POST http://localhost:8000/api/licenses/activate \
  -H "Content-Type: application/json" \
  -d '{"license_key": "XXXX-XXXX-XXXX-XXXX", "vm_fingerprint": "test"}'
```

## Rollback Procedure

If you need to rollback:

```bash
# 1. Stop the new server

# 2. Restore database (indexes are non-destructive, but if needed)
psql -U postgres license_db < backup_before_upgrade.sql

# 3. Restore old .env
cp .env.backup .env

# 4. Checkout old code version
git checkout v1.0

# 5. Reinstall old dependencies
pip install -r requirements.txt

# 6. Start old server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Compatibility Notes

### Endpoints That Still Work Without Changes

- `POST /api/licenses/activate` - No signature required
- `POST /api/licenses/heartbeat` - No signature required
- `GET /health` - Public endpoint

### Endpoints That Require Updates

- `POST /api/admin/login` - New endpoint (required for admin access)
- `POST /api/admin/licenses` - Now requires JWT token
- `GET /api/admin/licenses` - Now requires JWT token
- `GET /api/admin/licenses/{key}` - Now requires JWT token
- `DELETE /api/admin/licenses/{key}` - Now requires JWT token
- `POST /api/licenses/validate` - Now requires signature
- `POST /api/licenses/consume` - Now requires signature

## Performance Improvements

After migration, you should see:

- **Faster queries**: Database indexes improve query performance by 10-50x
- **Better concurrency**: Connection pooling handles more simultaneous requests
- **Rate limiting**: Protects against abuse (60 req/min per IP by default)
- **Structured logging**: Better observability and debugging

## Security Improvements

- **JWT tokens**: More secure than HTTP Basic Auth, with expiration
- **Request signing**: Prevents tampering and replay attacks
- **Encrypted storage**: Client-side license data encrypted at rest
- **Rate limiting**: Prevents brute force and DoS attacks
- **Timestamp validation**: 5-minute window prevents replay attacks

## Troubleshooting

### "Redis connection failed"

```bash
# Check Redis is running
sudo systemctl status redis-server

# If not running
sudo systemctl start redis-server
```

### "Invalid signature" errors

- Ensure client and server clocks are synchronized (use NTP)
- Verify `organization_token` is correct
- Check timestamp is within 5 minutes

### "Unauthorized" on admin endpoints

- Login first to get JWT token
- Include token in `Authorization: Bearer TOKEN` header
- Check token hasn't expired (24 hours by default)

### Performance issues

- Check database connection pool settings in `app/database.py`
- Monitor Redis memory usage
- Adjust rate limits in `.env` if needed

## Support

For issues during migration:

1. Check logs: `journalctl -u license-server -f`
2. Verify Redis: `redis-cli ping`
3. Check database: `psql -U postgres -d license_db -c "SELECT COUNT(*) FROM licenses;"`
4. Review `SETUP.md` for detailed configuration

## Next Steps

After successful migration:

1. Update all client applications to use the SDK or implement signing
2. Review and adjust rate limits based on your traffic
3. Set up monitoring and alerting
4. Configure production security (HTTPS, Redis auth, etc.)
5. Review `SETUP.md` for production deployment best practices
