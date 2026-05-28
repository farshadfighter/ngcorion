# Docker Database Setup - Complete

## ✅ All Files Created Successfully

### Main Configuration
- ✅ `docker-compose.yml` - Docker Compose configuration
- ✅ `check-docker-setup.sh` - Verification script

### Database Initialization Scripts
- ✅ `docker/postgres-main/init.sql` - Main database initialization
- ✅ `docker/postgres-license/init.sql` - License database initialization
- ✅ `docker/redis/redis.conf` - Redis configuration

---

## What's Been Set Up

### 1. Main PostgreSQL Database (netease_db)
- **Port:** 5432
- **User:** netease
- **Password:** 1234
- **Purpose:** Stores all main application data
  - Users and authentication
  - Assets (network devices)
  - Discovery scans
  - Audit results
  - Hardening configurations
  - Monitoring data

### 2. License PostgreSQL Database (license_db)
- **Port:** 5433
- **User:** license_user
- **Password:** your_password
- **Purpose:** Stores licensing and quota data
  - License keys
  - Organization tokens
  - Quota limits and usage
  - Validation history
  - Heartbeat logs

### 3. Redis Server
- **Port:** 6379
- **Purpose:** In-memory caching and rate limiting
  - API rate limiting (60 requests/minute)
  - Session data
  - Temporary caching

---

## Next Steps

### Step 1: Verify Setup
```bash
cd /home/sina/netease
./check-docker-setup.sh
```

### Step 2: Install Docker (if needed)
```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Docker Compose
sudo apt-get update
sudo apt-get install docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Step 3: Start Databases
```bash
cd /home/sina/netease
docker-compose up -d
```

Expected output:
```
Creating network "netease_netease-network" with driver "bridge"
Creating netease-postgres-main    ... done
Creating netease-postgres-license ... done
Creating netease-redis            ... done
```

### Step 4: Verify Databases Are Running
```bash
docker-compose ps
```

Expected output:
```
NAME                        STATUS    PORTS
netease-postgres-main       Up        0.0.0.0:5432->5432/tcp
netease-postgres-license    Up        0.0.0.0:5433->5432/tcp
netease-redis               Up        0.0.0.0:6379->6379/tcp
```

### Step 5: Check Logs
```bash
docker-compose logs -f
```

Look for:
- "database system is ready to accept connections" (PostgreSQL)
- "Ready to accept connections" (Redis)

### Step 6: Test Connections

**Main Database:**
```bash
docker exec -it netease-postgres-main psql -U netease -d netease_db
```

**License Database:**
```bash
docker exec -it netease-postgres-license psql -U license_user -d license_db
```

**Redis:**
```bash
docker exec -it netease-redis redis-cli ping
```

### Step 7: Run Migrations

**Main App:**
```bash
cd /home/sina/netease
source .venv/bin/activate
alembic upgrade head
```

**License Server:**
```bash
cd /home/sina/netease/license_server
source .venv/bin/activate
python -c "from app.database import Base, engine; Base.metadata.create_all(bind=engine)"
```

### Step 8: Start Application Services

**Terminal 1 - License Server:**
```bash
cd /home/sina/netease/license_server
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

**Terminal 2 - Main App:**
```bash
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Terminal 3 - Frontend:**
```bash
cd /home/sina/netease/front
npm run dev
```

---

## Common Commands

### Start/Stop
```bash
docker-compose up -d          # Start all databases
docker-compose down           # Stop all databases
docker-compose restart        # Restart all databases
docker-compose stop           # Stop without removing
docker-compose start          # Start stopped containers
```

### Logs
```bash
docker-compose logs -f                    # All logs (follow)
docker-compose logs postgres-main         # Main DB logs
docker-compose logs postgres-license      # License DB logs
docker-compose logs redis                 # Redis logs
docker-compose logs --tail=100 postgres-main  # Last 100 lines
```

### Status
```bash
docker-compose ps             # Container status
docker stats                  # Resource usage
docker-compose top            # Running processes
```

### Database Access
```bash
# Main DB
docker exec -it netease-postgres-main psql -U netease -d netease_db

# License DB
docker exec -it netease-postgres-license psql -U license_user -d license_db

# Redis
docker exec -it netease-redis redis-cli
```

### Backup
```bash
# Backup main database
docker exec netease-postgres-main pg_dump -U netease netease_db > backup-main-$(date +%Y%m%d).sql

# Backup license database
docker exec netease-postgres-license pg_dump -U license_user license_db > backup-license-$(date +%Y%m%d).sql
```

### Restore
```bash
# Restore main database
docker exec -i netease-postgres-main psql -U netease netease_db < backup-main-20250504.sql

# Restore license database
docker exec -i netease-postgres-license psql -U license_user license_db < backup-license-20250504.sql
```

---

## Troubleshooting

### Issue: Port already in use

**Check what's using the port:**
```bash
sudo lsof -i :5432
sudo lsof -i :5433
sudo lsof -i :6379
```

**Stop existing services:**
```bash
sudo systemctl stop postgresql
sudo systemctl stop redis
```

### Issue: Permission denied

**Fix data directory permissions:**
```bash
sudo chown -R $USER:$USER data/
chmod -R 755 data/
```

### Issue: Container won't start

**Check logs:**
```bash
docker-compose logs postgres-main
```

**Remove and recreate:**
```bash
docker-compose down
docker-compose up -d
```

### Issue: Database connection refused

**Check container is running:**
```bash
docker-compose ps
```

**Check health status:**
```bash
docker inspect netease-postgres-main | grep -A 10 Health
```

**Test connection:**
```bash
psql -h localhost -p 5432 -U netease -d netease_db
```

### Issue: Need to reset everything

**WARNING: This deletes all data!**
```bash
docker-compose down -v
rm -rf data/
docker-compose up -d
```

---

## File Structure

```
/home/sina/netease/
├── docker-compose.yml              # Main configuration
├── check-docker-setup.sh           # Verification script
├── docker/
│   ├── postgres-main/
│   │   └── init.sql               # Main DB init
│   ├── postgres-license/
│   │   └── init.sql               # License DB init
│   └── redis/
│       └── redis.conf             # Redis config
├── data/                           # Persistent data (auto-created)
│   ├── postgres-main/
│   ├── postgres-license/
│   └── redis/
└── .env                            # Environment variables
```

---

## Environment Variables

### Main App (.env)
```bash
DATABASE_URL=postgresql://netease:1234@localhost:5432/netease_db
LICENSE_SERVER_URL=http://localhost:8001
SECRET_KEY=your-secret-key-here
```

### License Server (license_server/.env)
```bash
DATABASE_URL=postgresql://license_user:your_password@localhost:5433/license_db
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
SECRET_KEY=your-secret-key-here
```

---

## Security Notes

### For Production:

1. **Change default passwords** in docker-compose.yml
2. **Use Docker secrets** for sensitive data
3. **Don't expose ports** externally (remove ports section)
4. **Enable SSL/TLS** for PostgreSQL
5. **Set Redis password** if exposed
6. **Regular backups** (set up cron job)
7. **Monitor logs** for suspicious activity

---

## Documentation Files

1. **DOCKER_DATABASES_SETUP.md** - Complete detailed guide
2. **DOCKER_DATABASES_QUICK_START.md** - Quick reference
3. **DOCKER_SETUP_COMPLETE.md** - This file (setup summary)

---

## Status: ✅ Ready to Deploy

All Docker configuration files are created and ready to use.

**To start:** Run `docker-compose up -d`

**Date:** May 4, 2025
