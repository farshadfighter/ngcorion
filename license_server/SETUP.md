# License Server Setup Guide

Complete setup and deployment guide for the enhanced license server.

## Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Redis 6+

## Installation

### 1. Install Dependencies

```bash
cd license_server
pip install -r requirements.txt
```

### 2. Setup PostgreSQL Database

```bash
# Create database
createdb license_db

# Or using psql
psql -U postgres
CREATE DATABASE license_db;
\q
```

### 3. Setup Redis

```bash
# Install Redis (Ubuntu/Debian)
sudo apt-get install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Verify Redis is running
redis-cli ping
# Should return: PONG
```

### 4. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your settings
nano .env
```

**Important**: Change these values in production:
- `SECRET_KEY`: Generate with `openssl rand -hex 32`
- `ADMIN_PASSWORD`: Use a strong password
- `DATABASE_URL`: Update with your PostgreSQL credentials

### 5. Run Database Migrations

```bash
# Apply migrations to create indexes
alembic upgrade head
```

### 6. Start the Server

```bash
# Development
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production (with Gunicorn)
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## Testing the Server

### 1. Health Check

```bash
curl http://localhost:8000/health
```

### 2. Admin Login

```bash
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "change-this-password"}'
```

Save the returned `access_token` for subsequent admin requests.

### 3. Create a License

```bash
TOKEN="your-jwt-token-here"

curl -X POST http://localhost:8000/api/admin/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "customer_name": "Test Customer",
    "customer_email": "test@example.com",
    "organization_name": "Test Organization",
    "plan_type": "basic2"
  }'
```

Save the returned `license_key` and `organization_token`.

### 4. Test Client SDK

Create a test script `test_client.py`:

```python
from client import LicenseClient, HeartbeatService
import time

# Initialize client
client = LicenseClient(server_url="http://localhost:8000")

# Activate license
print("Activating license...")
result = client.activate("YOUR-LICENSE-KEY-HERE")
print(f"✓ Activated: {result['plan_type']}")

# Validate license
print("\nValidating license...")
result = client.validate()
print(f"✓ Valid: {result['valid']}")
print(f"  Limits: {result['limits']}")
print(f"  Usage: {result['usage']}")

# Consume operation
print("\nConsuming discovery operation...")
result = client.consume(operation_type="discovery", count=1)
print(f"✓ Consumed: {result['message']}")
print(f"  Updated usage: {result['usage']}")

# Start heartbeat
print("\nStarting heartbeat service...")
heartbeat = HeartbeatService(client, interval_seconds=60)
heartbeat.start()

print("Running for 5 minutes... Press Ctrl+C to stop")
try:
    time.sleep(300)
except KeyboardInterrupt:
    pass
finally:
    heartbeat.stop()
    print("\n✓ Stopped")
```

Run the test:

```bash
python test_client.py
```

## Production Deployment

### 1. Security Hardening

**Generate Secure Keys:**

```bash
# Generate SECRET_KEY
openssl rand -hex 32

# Update .env with the generated key
```

**Enable Redis Authentication:**

```bash
# Edit Redis config
sudo nano /etc/redis/redis.conf

# Add/uncomment:
requirepass your-strong-redis-password

# Restart Redis
sudo systemctl restart redis-server

# Update .env
REDIS_URL=redis://:your-strong-redis-password@localhost:6379/0
```

**PostgreSQL SSL:**

```bash
# Update DATABASE_URL in .env
DATABASE_URL=postgresql://user:pass@localhost:5432/license_db?sslmode=require
```

### 2. Setup Nginx Reverse Proxy with HTTPS

```nginx
server {
    listen 443 ssl http2;
    server_name license.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/license.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/license.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name license.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 3. Setup Systemd Service

Create `/etc/systemd/system/license-server.service`:

```ini
[Unit]
Description=License Server
After=network.target postgresql.service redis.service

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/license_server
Environment="PATH=/opt/license_server/venv/bin"
ExecStart=/opt/license_server/venv/bin/gunicorn app.main:app \
    -w 4 \
    -k uvicorn.workers.UvicornWorker \
    --bind 127.0.0.1:8000 \
    --access-logfile /var/log/license-server/access.log \
    --error-logfile /var/log/license-server/error.log

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable license-server
sudo systemctl start license-server
sudo systemctl status license-server
```

### 4. Monitoring

**Check Logs:**

```bash
# Application logs
sudo journalctl -u license-server -f

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

**Monitor Redis:**

```bash
redis-cli INFO stats
redis-cli INFO memory
```

**Monitor PostgreSQL:**

```bash
psql -U postgres -d license_db -c "SELECT COUNT(*) FROM licenses;"
psql -U postgres -d license_db -c "SELECT COUNT(*) FROM licenses WHERE is_active = true;"
```

## Troubleshooting

### Redis Connection Failed

```bash
# Check Redis is running
sudo systemctl status redis-server

# Test connection
redis-cli ping

# Check Redis logs
sudo tail -f /var/log/redis/redis-server.log
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -U user -d license_db -c "SELECT 1;"

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

### Rate Limiting Issues

If Redis is unavailable, rate limiting is automatically disabled to allow requests through.

### Signature Verification Failed

- Ensure client and server clocks are synchronized (use NTP)
- Check that `organization_token` is correct
- Verify timestamp is within 5 minutes (default `max_age_seconds=300`)

## Performance Tuning

### Database Connection Pool

Adjust in `app/database.py`:

```python
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=20,        # Increase for high traffic
    max_overflow=10,     # Additional connections
    pool_pre_ping=True,
    pool_recycle=3600
)
```

### Redis Memory

Edit `/etc/redis/redis.conf`:

```
maxmemory 256mb
maxmemory-policy allkeys-lru
```

### Rate Limiting

Adjust in `.env`:

```
RATE_LIMIT_PER_MINUTE=120  # Increase for high traffic
```

## Backup and Recovery

### Database Backup

```bash
# Backup
pg_dump -U postgres license_db > backup_$(date +%Y%m%d).sql

# Restore
psql -U postgres license_db < backup_20250423.sql
```

### Redis Backup

```bash
# Redis automatically saves to /var/lib/redis/dump.rdb
# Copy for backup
sudo cp /var/lib/redis/dump.rdb /backup/redis_$(date +%Y%m%d).rdb
```

## Security Checklist

- [ ] Changed `SECRET_KEY` to cryptographically secure random value
- [ ] Changed `ADMIN_PASSWORD` from default
- [ ] Enabled HTTPS with valid SSL certificate
- [ ] Enabled Redis authentication
- [ ] Enabled PostgreSQL SSL connections
- [ ] Configured firewall to restrict access
- [ ] Set up regular database backups
- [ ] Configured log rotation
- [ ] Reviewed and adjusted rate limits
- [ ] Tested signature verification
- [ ] Verified VM fingerprint binding works

## Support

For issues or questions, check:
- Application logs: `journalctl -u license-server`
- Redis logs: `/var/log/redis/redis-server.log`
- PostgreSQL logs: `/var/log/postgresql/`
- Nginx logs: `/var/log/nginx/`
