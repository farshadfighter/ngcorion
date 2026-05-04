# Docker Databases Quick Start

## Quick Setup (5 Minutes)

### Step 1: Create Directories
```bash
cd /home/sina/netease
mkdir -p docker/postgres-main docker/postgres-license docker/redis
mkdir -p data/postgres-main data/postgres-license data/redis
```

### Step 2: Create Init Scripts

**Main DB:** `docker/postgres-main/init.sql`
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL PRIVILEGES ON DATABASE netease_db TO netease;
```

**License DB:** `docker/postgres-license/init.sql`
```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
GRANT ALL PRIVILEGES ON DATABASE license_db TO license_user;
```

**Redis:** `docker/redis/redis.conf`
```conf
bind 0.0.0.0
port 6379
maxmemory 256mb
maxmemory-policy allkeys-lru
save ""
appendonly no
```

### Step 3: Create docker-compose.yml

See full file in DOCKER_DATABASES_SETUP.md

### Step 4: Start Databases
```bash
docker-compose up -d
```

### Step 5: Verify
```bash
docker-compose ps
docker-compose logs
```

---

## Database Overview

| Database | Port | User | Password | Purpose |
|----------|------|------|----------|---------|
| postgres-main | 5432 | netease | 1234 | Main app data |
| postgres-license | 5433 | license_user | your_password | License data |
| redis | 6379 | - | - | Rate limiting |

---

## Common Commands

### Start/Stop
```bash
docker-compose up -d        # Start all
docker-compose down         # Stop all
docker-compose restart      # Restart all
```

### Logs
```bash
docker-compose logs -f                    # All logs
docker-compose logs -f postgres-main      # Main DB logs
docker-compose logs -f postgres-license   # License DB logs
docker-compose logs -f redis              # Redis logs
```

### Connect to Databases
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
# Main DB
docker exec netease-postgres-main pg_dump -U netease netease_db > backup-main.sql

# License DB
docker exec netease-postgres-license pg_dump -U license_user license_db > backup-license.sql
```

### Restore
```bash
# Main DB
docker exec -i netease-postgres-main psql -U netease netease_db < backup-main.sql

# License DB
docker exec -i netease-postgres-license psql -U license_user license_db < backup-license.sql
```

---

## Connection Strings

### Main App (.env)
```
DATABASE_URL=postgresql://netease:1234@localhost:5432/netease_db
```

### License Server (license_server/.env)
```
DATABASE_URL=postgresql://license_user:your_password@localhost:5433/license_db
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
```

---

## Troubleshooting

### Port already in use?
```bash
sudo lsof -i :5432
sudo systemctl stop postgresql
```

### Can't connect?
```bash
docker-compose ps              # Check status
docker-compose logs postgres-main  # Check logs
```

### Reset everything?
```bash
docker-compose down -v         # WARNING: Deletes all data
docker-compose up -d
```

---

For detailed documentation, see: **DOCKER_DATABASES_SETUP.md**
