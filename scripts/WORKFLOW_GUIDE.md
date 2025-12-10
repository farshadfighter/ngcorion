# 🔄 Complete Workflow Guide: Local → VPS

Your corrected workflow for developing locally and syncing to VPS.

---

## 📊 Your Workflow (Correct Flow)

```
┌─────────────────────────────────────────────────────────┐
│  LOCAL DEVELOPMENT                                      │
│  1. Work on code and database locally                   │
│  2. Test everything                                     │
└─────────────────────────────────────────────────────────┘
                        ⬇
┌─────────────────────────────────────────────────────────┐
│  GIT COMMIT                                             │
│  3. git add .                                           │
│  4. git commit -m "Your changes"                        │
│  5. git push origin main                                │
└─────────────────────────────────────────────────────────┘
                        ⬇
┌─────────────────────────────────────────────────────────┐
│  DEPLOY CODE TO VPS                                     │
│  6. ./scripts/deploy_to_vps.sh                          │
│     • Pulls code from Git                               │
│     • Runs Alembic migrations (schema changes)          │
│     • Restarts application                              │
└─────────────────────────────────────────────────────────┘
                        ⬇
┌─────────────────────────────────────────────────────────┐
│  SYNC DATABASE TO VPS                                   │
│  7. ./scripts/sync_to_vps.sh                            │
│     • Backs up VPS database                             │
│     • Uploads local database                            │
│     • Restores on VPS                                   │
│     • VPS now has your local data                       │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 Typical Development Session

### Step-by-Step Commands:

```bash
# ============================================
# STEP 1: Work locally
# ============================================
# Make your changes, add features, modify database, etc.
# Test everything locally

# If you changed database models, create migration:
alembic revision --autogenerate -m "Add new feature"
alembic upgrade head  # Test migration locally


# ============================================
# STEP 2: Commit to Git
# ============================================
git add .
git commit -m "Add new feature with database changes"
git push origin main


# ============================================
# STEP 3: Deploy code to VPS
# ============================================
./scripts/deploy_to_vps.sh

# This will:
# ✓ Pull your code on VPS
# ✓ Run migrations (if any)
# ✓ Restart the app


# ============================================
# STEP 4: Sync database to VPS
# ============================================
./scripts/sync_to_vps.sh

# This will:
# ✓ Backup VPS database
# ✓ Upload your local database
# ✓ Replace VPS database with local data
```

---

## 🎯 When to Use Each Script

### `deploy_to_vps.sh`
**Use when:** You've made code changes
**Does:**
- ✅ Pulls latest code from Git
- ✅ Runs database migrations (schema changes)
- ✅ Installs dependencies
- ✅ Restarts application

**Use this for:** Code updates, schema changes

### `sync_to_vps.sh`
**Use when:** You need to sync actual data from local to VPS
**Does:**
- ✅ Backs up VPS database
- ✅ Dumps local database
- ✅ Uploads and restores on VPS

**Use this for:** Data synchronization, testing with your local data on VPS

---

## ⚠️ Important: Schema vs Data

### Schema Changes (Structure)
**Handled by:** Alembic migrations in `deploy_to_vps.sh`

Examples:
- Adding new table
- Adding new column
- Changing column type
- Adding index

**How to handle:**
```bash
# Create migration locally
alembic revision --autogenerate -m "Add users table"

# Test locally
alembic upgrade head

# Commit
git add alembic/versions/*.py
git commit -m "Add users table migration"
git push

# Deploy (migrations run automatically)
./scripts/deploy_to_vps.sh
```

### Data Changes (Content)
**Handled by:** `sync_to_vps.sh`

Examples:
- New asset records
- Updated configuration
- Test data
- User accounts

**How to handle:**
```bash
# After making data changes locally
./scripts/sync_to_vps.sh
```

---

## 📝 Example Scenarios

### Scenario 1: Added New Feature with Database Changes

```bash
# 1. Work locally, create migration
alembic revision --autogenerate -m "Add port scanning feature"
alembic upgrade head

# 2. Test locally, add some test data

# 3. Commit
git add .
git commit -m "Add port scanning feature"
git push

# 4. Deploy code and schema changes
./scripts/deploy_to_vps.sh

# 5. Sync test data to VPS
./scripts/sync_to_vps.sh
```

### Scenario 2: Only Code Changes (No Database)

```bash
# 1. Make changes, test locally

# 2. Commit
git add .
git commit -m "Fix UI bug"
git push

# 3. Deploy
./scripts/deploy_to_vps.sh

# No need to sync database!
```

### Scenario 3: Only Data Changes

```bash
# 1. Add data locally (new assets, configurations, etc.)

# 2. Sync to VPS
./scripts/sync_to_vps.sh

# No need to deploy code!
```

### Scenario 4: Fresh VPS Setup

```bash
# 1. Deploy code first
./scripts/deploy_to_vps.sh

# 2. Sync database
./scripts/sync_to_vps.sh

# Done! VPS has everything from local
```

---

## 🛡️ Safety Features

### What Gets Backed Up

**Before syncing to VPS:**
- ✅ VPS database is backed up to `~/db_backups/` on VPS
- ✅ Local dump is saved to `~/db_backups/` on your machine
- ✅ Last 7 backups are kept

### Restore VPS from Backup

If you need to restore VPS database:
```bash
# SSH to VPS
ssh srv@172.16.200.90

# List backups
ls -lh ~/db_backups/

# Restore
export PGPASSWORD="1234"
dropdb -U netease netease_db
createdb -U netease netease_db
psql -U netease netease_db < ~/db_backups/vps_backup_YYYYMMDD_HHMMSS.sql
```

---

## 🔍 Troubleshooting

### "Cannot connect to VPS"
```bash
# Test SSH
ssh srv@172.16.200.90

# If fails, check:
# - Is VPS running?
# - Is IP correct?
# - Firewall blocking SSH?
```

### "pg_dump: command not found"
```bash
# Install PostgreSQL client tools
sudo apt install postgresql-client  # Ubuntu/Debian
sudo pacman -S postgresql-libs      # Arch Linux
```

### "Permission denied"
```bash
# Make scripts executable
chmod +x scripts/*.sh
```

### Migration Fails on VPS
```bash
# SSH to VPS
ssh srv@172.16.200.90
cd /home/srv/netease
source venv/bin/activate

# Check migration status
alembic current

# Try migration manually
alembic upgrade head

# Check for errors in logs
```

---

## 📋 Quick Reference

### Scripts Available

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `deploy_to_vps.sh` | Deploy code + schema | After git push |
| `sync_to_vps.sh` | Sync database data | When you need VPS to have your local data |

### Common Commands

```bash
# Deploy everything
./scripts/deploy_to_vps.sh && ./scripts/sync_to_vps.sh

# Just deploy code
./scripts/deploy_to_vps.sh

# Just sync data
./scripts/sync_to_vps.sh

# View logs
tail -f ~/db_backups/*.log

# Check backups
ls -lh ~/db_backups/
```

---

## ✅ Checklist Before Production

Before deploying to production VPS:

- [ ] Test scripts with test/staging VPS first
- [ ] Verify SSH key authentication works
- [ ] Backup production database manually first
- [ ] Test restore from backup
- [ ] Run migrations on staging first
- [ ] Verify VPS has enough disk space
- [ ] Update `.env` file on VPS with production settings
- [ ] Change database passwords from defaults

---

**Your VPS Configuration:**
- Host: `172.16.200.90`
- User: `srv`
- Project Path: `/home/srv/netease`
- Database: `netease_db`

All set! Your workflow is now: **Work Local → Git Push → Deploy Code → Sync Database** 🚀
