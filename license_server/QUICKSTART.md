# Quick Start Guide

Get the license server running in 5 minutes.

## Prerequisites

- Python 3.8+
- PostgreSQL running
- Redis running

## Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create database
createdb license_db

# 3. Start Redis (if not running)
sudo systemctl start redis-server

# 4. Configure environment
cp .env.example .env
nano .env

# 5. Run migrations
alembic upgrade head

# 6. Start server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Server running at: http://localhost:8000

## Create Your First License

### 1. Login as Admin

```bash
curl -X POST http://localhost:8000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "change-this-password"}'
```

### 2. Create a License

```bash
TOKEN="your-access-token-here"

curl -X POST http://localhost:8000/api/admin/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"customer_name": "Test", "customer_email": "test@example.com", "organization_name": "Test Org", "plan_type": "basic2"}'
```

## Test the Client SDK

```bash
python test_client.py YOUR-LICENSE-KEY
```

## API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Next Steps

- Read SETUP.md for production deployment
- Check client/README.md for SDK documentation
- Review security checklist in SETUP.md
