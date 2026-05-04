# Docker Databases Setup Guide

Complete guide to dockerize all databases for the Netease project using Docker Compose.

---

## Overview

This setup includes three database services:

1. **PostgreSQL (Main App)** - Stores application data (users, assets, audits, discoveries, etc.)
2. **PostgreSQL (License Server)** - Stores license data (licenses, quotas, validations)
3. **Redis** - Used by license server for rate limiting and caching

---

## Why Separate Databases?

### Main App Database (netease_db)
- **Purpose:** Stores all application business data
- **Contains:** Users, authentication, assets, network discoveries, audit results, hardening configurations, monitoring data
- **Why separate:** Application data should be isolated from licensing data for security and maintainability
- **Access:** Only the main application (port 8000) connects to this database

### License Server Database (license_db)
- **Purpose:** Stores licensing and quota management data
- **Contains:** License keys, organization tokens, quota limits, usage tracking, validation history
- **Why separate:** Licensing is a separate service that could be reused across multiple applications
- **Access:** Only the license server (port 8001) connects to this database
- **Security:** Keeps sensitive licensing data isolated

### Redis
- **Purpose:** In-memory data store for caching and rate limiting
- **Used by:** License server for API rate limiting (60 requests/minute per IP)
- **Why needed:** Fast in-memory operations for rate limiting without database overhead
- **Data:** Temporary data (rate limit counters, session data)

---

## Directory Structure

```
/home/sina/netease/
├── docker-compose.yml          # Main Docker Compose configuration
├── .env                         # Environment variables (already exists)
├── docker/
│   ├── postgres-main/
│   │   └── init.sql            # Main database initialization
│   ├── postgres-license/
│   │   └── init.sql            # License database initialization
│   └── redis/
│       └── redis.conf          # Redis configuration (optional)
└── data/                        # Docker volumes (auto-created)
    ├── postgres-main/
    ├── postgres-license/
    └── redis/
```

---

## Step 1: Create Directory Structure

```bash
cd /home/sina/netease

# Create directories for initialization scripts
mkdir -p docker/postgres-main
mkdir -p docker/postgres-license
mkdir -p docker/redis

# Create data directories (Docker will manage these)
mkdir -p data/postgres-main
mkdir -p data/postgres-license
mkdir -p data/redis
```

**Purpose:** Organize Docker configuration files and persistent data storage.

---

## Step 2: Create Main Database Initialization Script

Create `docker/postgres-main/init.sql`:

```sql
-- Main Application Database Initialization
-- This script runs only on first container startup

-- Create database if not exists (handled by POSTGRES_DB env var)
-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE netease_db TO netease;

-- Create schema version table for migrations
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Note: Actual tables will be created by Alembic migrations
-- This script just ensures the database is ready
```

**Purpose:** 
- Ensures required PostgreSQL extensions are installed
- Sets up proper permissions
- Prepares database for Alembic migrations

---

## Step 3: Create License Database Initialization Script

Create `docker/postgres-license/init.sql`:

```sql
-- License Server Database Initialization
-- This script runs only on first container startup

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE license_db TO license_user;

-- Create schema version table for migrations
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Note: Actual license tables will be created by the license server
-- on first startup using SQLAlchemy models
```

**Purpose:**
- Sets up license database with required extensions
- Prepares for license server table creation
- Isolates licensing data from main application

---

## Step 4: Create Redis Configuration (Optional)

Create `docker/redis/redis.conf`:

```conf
# Redis Configuration for License Server

# Bind to all interfaces (Docker network)
bind 0.0.0.0

# Port
port 6379

# Max memory (adjust based on your needs)
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence (optional - rate limiting data is temporary)
save ""
appendonly no

# Logging
loglevel notice

# Security (no password needed for internal Docker network)
# If exposing externally, add: requirepass your_password_here
```

**Purpose:**
- Configures Redis for optimal rate limiting performance
- Sets memory limits to prevent resource exhaustion
- Disables persistence (not needed for temporary rate limit data)

---

## Step 5: Create Docker Compose File

Create `docker-compose.yml` in project root:

```yaml
version: '3.8'

services:
  # Main Application PostgreSQL Database
  postgres-main:
    image: postgres:15-alpine
    container_name: netease-postgres-main
    restart: unless-stopped
    environment:
      POSTGRES_DB: netease_db
      POSTGRES_USER: netease
      POSTGRES_PASSWORD: 1234
      PGDATA: /var/lib/postgresql/data/pgdata
    ports:
      - "5432:5432"
    volumes:
      - ./data/postgres-main:/var/lib/postgresql/data
      - ./docker/postgres-main/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - netease-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U netease -d netease_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  # License Server PostgreSQL Database
  postgres-license:
    image: postgres:15-alpine
    container_name: netease-postgres-license
    restart: unless-stopped
    environment:
      POSTGRES_DB: license_db
      POSTGRES_USER: license_user
      POSTGRES_PASSWORD: your_password
      PGDATA: /var/lib/postgresql/data/pgdata
    ports:
      - "5433:5432"
    volumes:
      - ./data/postgres-license:/var/lib/postgresql/data
      - ./docker/postgres-license/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - netease-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U license_user -d license_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Redis for License Server Rate Limiting
  redis:
    image: redis:7-alpine
    container_name: netease-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - ./data/redis:/data
      - ./docker/redis/redis.conf:/usr/local/etc/redis/redis.conf
    command: redis-server /usr/local/etc/redis/redis.conf
    networks:
      - netease-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

networks:
  netease-network:
    driver: bridge

volumes:
  postgres-main-data:
  postgres-license-data:
  redis-data:
```

**Key Configuration Explained:**

### postgres-main
- **Port:** 5432 (standard PostgreSQL port)
- **Database:** netease_db
- **User:** netease / Password: 1234
- **Volume:** Persists data in `./data/postgres-main`
- **Init Script:** Runs `init.sql` on first startup
- **Health Check:** Ensures database is ready before app connects

### postgres-license
- **Port:** 5433 (mapped to avoid conflict with main DB)
- **Database:** license_db
- **User:** license_user / Password: your_password
- **Volume:** Persists data in `./data/postgres-license`
- **Separate:** Completely isolated from main database
- **Health Check:** Ensures license DB is ready

### redis
- **Port:** 6379 (standard Redis port)
- **Config:** Uses custom redis.conf
- **Memory:** Limited to 256MB (configurable)
- **Persistence:** Disabled (rate limit data is temporary)
- **Health Check:** Ensures Redis is responding

### Network
- **netease-network:** All containers communicate on this private network
- **Isolation:** Containers can reach each other by service name
- **Security:** Not exposed to external networks by default

---

## Step 6: Update Environment Variables

Update `.env` file:

```bash
# Main Application Database
DATABASE_URL=postgresql://netease:1234@localhost:5432/netease_db

# License Server Database (update in license_server/.env)
# DATABASE_URL=postgresql://license_user:your_password@localhost:5433/license_db

# Redis Configuration (update in license_server/.env)
# REDIS_HOST=localhost
# REDIS_PORT=6379
# REDIS_DB=0

# Security
SECRET_KEY=your-secret-key-here-change-in-production-min-32-chars

# License Server
LICENSE_SERVER_URL=http://localhost:8001
LICENSE_STORAGE_DIR=~/.license
```

Update `license_server/.env`:

```bash
# License Server Database
DATABASE_URL=postgresql://license_user:your_password@localhost:5433/license_db

# Security
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_EXPIRE_HOURS=24

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60

# API Configuration
API_V1_PREFIX=/api

# Admin Credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_this_password
```

**Purpose:**
- Main app connects to port 5432
- License server connects to port 5433
- Redis accessible on port 6379
- All services use localhost (since they're on host network)

---

## Step 7: Start Docker Containers

```bash
cd /home/sina/netease

# Start all databases
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Check specific service
docker-compose logs postgres-main
docker-compose logs postgres-license
docker-compose logs redis
```

**Expected Output:**
```
NAME                        STATUS    PORTS
netease-postgres-main       Up        0.0.0.0:5432->5432/tcp
netease-postgres-license    Up        0.0.0.0:5433->5432/tcp
netease-redis               Up        0.0.0.0:6379->6379/tcp
```

**Purpose:**
- Starts all three database containers
- Runs initialization scripts
- Creates persistent volumes
- Sets up health checks

---

## Step 8: Verify Database Connections

### Test Main Database
```bash
# Connect to main database
docker exec -it netease-postgres-main psql -U netease -d netease_db

# Inside psql:
\l                          # List databases
\dt                         # List tables (empty until migrations run)
\q                          # Quit
```

### Test License Database
```bash
# Connect to license database
docker exec -it netease-postgres-license psql -U license_user -d license_db

# Inside psql:
\l                          # List databases
\dt                         # List tables
\q                          # Quit
```

### Test Redis
```bash
# Connect to Redis
docker exec -it netease-redis redis-cli

# Inside redis-cli:
PING                        # Should return PONG
INFO                        # Show Redis info
QUIT                        # Exit
```

**Purpose:** Verify all databases are running and accessible.

---

## Step 9: Run Database Migrations

### Main Application Migrations
```bash
cd /home/sina/netease
source .venv/bin/activate

# Run Alembic migrations
alembic upgrade head

# Verify tables created
docker exec -it netease-postgres-main psql -U netease -d netease_db -c "\dt"
```

### License Server Migrations
```bash
cd /home/sina/netease/license_server
source .venv/bin/activate

# License server creates tables automatically on first run
# Or run manually if needed
python -c "from app.database import Base, engine; Base.metadata.create_all(bind=engine)"

# Verify tables created
docker exec -it netease-postgres-license psql -U license_user -d license_db -c "\dt"
```

**Purpose:**
- Creates all application tables
- Sets up database schema
- Prepares databases for application use

---

## Step 10: Start Application Services

```bash
# Terminal 1: License Server
cd /home/sina/netease/license_server
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001

# Terminal 2: Main App
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 3: Frontend
cd /home/sina/netease/front
npm run dev
```

**Purpose:** Start all application services that connect to the databases.

---

## Docker Management Commands

### Start/Stop Services
```bash
# Start all databases
docker-compose up -d

# Stop all databases
docker-compose down

# Stop and remove volumes (WARNING: deletes all data)
docker-compose down -v

# Restart specific service
docker-compose restart postgres-main
docker-compose restart postgres-license
docker-compose restart redis
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f postgres-main
docker-compose logs -f postgres-license
docker-compose logs -f redis

# Last 100 lines
docker-compose logs --tail=100 postgres-main
```

### Database Backups
```bash
# Backup main database
docker exec netease-postgres-main pg_dump -U netease netease_db > backup-main-$(date +%Y%m%d).sql

# Backup license database
docker exec netease-postgres-license pg_dump -U license_user license_db > backup-license-$(date +%Y%m%d).sql

# Restore main database
docker exec -i netease-postgres-main psql -U netease netease_db < backup-main-20250502.sql

# Restore license database
docker exec -i netease-postgres-license psql -U license_user license_db < backup-license-20250502.sql
```

### Monitor Resources
```bash
# View resource usage
docker stats

# View specific container
docker stats netease-postgres-main
```

---

## Troubleshooting

### Issue: Port already in use

**Problem:** Port 5432 or 6379 already in use by existing services

**Solution:**
```bash
# Check what's using the port
sudo lsof -i :5432
sudo lsof -i :6379

# Stop existing services
sudo systemctl stop postgresql
sudo systemctl stop redis

# Or change ports in docker-compose.yml
# For example: "5434:5432" instead of "5432:5432"
```

### Issue: Permission denied on data directories

**Problem:** Docker can't write to data directories

**Solution:**
```bash
# Fix permissions
sudo chown -R $USER:$USER data/
chmod -R 755 data/
```

### Issue: Database connection refused

**Problem:** Application can't connect to database

**Solution:**
```bash
# Check if containers are running
docker-compose ps

# Check container logs
docker-compose logs postgres-main

# Verify health check
docker inspect netease-postgres-main | grep -A 10 Health

# Test connection from host
psql -h localhost -p 5432 -U netease -d netease_db
```

### Issue: Redis connection timeout

**Problem:** License server can't connect to Redis

**Solution:**
```bash
# Check Redis is running
docker-compose ps redis

# Test Redis connection
redis-cli -h localhost -p 6379 ping

# Check Redis logs
docker-compose logs redis
```

### Issue: Init script didn't run

**Problem:** Database tables not created

**Solution:**
```bash
# Remove volume and recreate
docker-compose down -v
docker-compose up -d

# Or run init script manually
docker exec -i netease-postgres-main psql -U netease -d netease_db < docker/postgres-main/init.sql
```

---

## Security Considerations

### Production Recommendations

1. **Change Default Passwords**
   ```bash
   # Generate strong passwords
   openssl rand -base64 32
   
   # Update in docker-compose.yml and .env files
   ```

2. **Use Docker Secrets** (for production)
   ```yaml
   services:
     postgres-main:
       environment:
         POSTGRES_PASSWORD_FILE: /run/secrets/db_password
       secrets:
         - db_password
   
   secrets:
     db_password:
       file: ./secrets/db_password.txt
   ```

3. **Restrict Network Access**
   ```yaml
   # Don't expose ports externally in production
   # Remove ports section and use Docker network only
   services:
     postgres-main:
       # ports:  # Comment out for internal access only
       #   - "5432:5432"
       networks:
         - netease-network
   ```

4. **Enable SSL/TLS**
   ```yaml
   # Add SSL certificates
   volumes:
     - ./certs/server.crt:/var/lib/postgresql/server.crt
     - ./certs/server.key:/var/lib/postgresql/server.key
   command: >
     -c ssl=on
     -c ssl_cert_file=/var/lib/postgresql/server.crt
     -c ssl_key_file=/var/lib/postgresql/server.key
   ```

5. **Regular Backups**
   ```bash
   # Create backup script
   cat > backup-databases.sh << 'SCRIPT'
   #!/bin/bash
   DATE=$(date +%Y%m%d_%H%M%S)
   docker exec netease-postgres-main pg_dump -U netease netease_db | gzip > backups/main-$DATE.sql.gz
   docker exec netease-postgres-license pg_dump -U license_user license_db | gzip > backups/license-$DATE.sql.gz
   SCRIPT
   
   chmod +x backup-databases.sh
   
   # Add to crontab (daily at 2 AM)
   crontab -e
   # Add: 0 2 * * * /home/sina/netease/backup-databases.sh
   ```

---

## Performance Tuning

### PostgreSQL Optimization

Add to `docker-compose.yml`:

```yaml
services:
  postgres-main:
    command:
      - "postgres"
      - "-c"
      - "max_connections=200"
      - "-c"
      - "shared_buffers=256MB"
      - "-c"
      - "effective_cache_size=1GB"
      - "-c"
      - "maintenance_work_mem=64MB"
      - "-c"
      - "checkpoint_completion_target=0.9"
      - "-c"
      - "wal_buffers=16MB"
      - "-c"
      - "default_statistics_target=100"
      - "-c"
      - "random_page_cost=1.1"
      - "-c"
      - "effective_io_concurrency=200"
      - "-c"
      - "work_mem=2MB"
```

### Redis Optimization

Update `docker/redis/redis.conf`:

```conf
# Increase max clients
maxclients 10000

# Optimize for rate limiting
maxmemory 512mb
maxmemory-policy allkeys-lru

# Disable slow operations
slowlog-log-slower-than 10000
slowlog-max-len 128
```

---

## Monitoring

### Health Check Script

Create `check-databases.sh`:

```bash
#!/bin/bash

echo "=== Database Health Check ==="
echo ""

# Check PostgreSQL Main
echo "Main Database:"
docker exec netease-postgres-main pg_isready -U netease -d netease_db
echo ""

# Check PostgreSQL License
echo "License Database:"
docker exec netease-postgres-license pg_isready -U license_user -d license_db
echo ""

# Check Redis
echo "Redis:"
docker exec netease-redis redis-cli ping
echo ""

# Check disk usage
echo "Disk Usage:"
du -sh data/postgres-main
du -sh data/postgres-license
du -sh data/redis
echo ""

# Check container status
echo "Container Status:"
docker-compose ps
```

```bash
chmod +x check-databases.sh
./check-databases.sh
```

---

## Summary

### What We've Set Up

1. ✅ **Main PostgreSQL Database** (port 5432)
   - Stores application data
   - Isolated from licensing
   - Persistent storage in `data/postgres-main`

2. ✅ **License PostgreSQL Database** (port 5433)
   - Stores licensing data
   - Separate from main app
   - Persistent storage in `data/postgres-license`

3. ✅ **Redis Server** (port 6379)
   - Rate limiting for license server
   - In-memory caching
   - Persistent storage in `data/redis`

### Benefits of This Setup

- **Isolation:** Each database serves a specific purpose
- **Portability:** Easy to move between environments
- **Consistency:** Same setup on dev/staging/production
- **Easy Management:** Single docker-compose command
- **Persistence:** Data survives container restarts
- **Health Checks:** Automatic monitoring
- **Scalability:** Easy to add more services

### Next Steps

1. Start databases: `docker-compose up -d`
2. Run migrations: `alembic upgrade head`
3. Start applications
4. Test connections
5. Set up backups
6. Monitor performance

---

**Status:** Ready for Implementation  
**Date:** May 2, 2025
