# 🚀 Simple Deployment Guide

## Deploy to VPS (Manual Steps)

### 1. Push Code to Git
```bash
git add .
git commit -m "Your changes"
git push origin main
```

### 2. Pull Code on VPS
```bash
ssh srv@172.16.200.90
cd /home/srv/netease
git pull origin main
```

### 3. Run Migrations (if you changed database models)
```bash
# Still on VPS
source venv/bin/activate
alembic upgrade head
```

### 4. Restart App
```bash
# Still on VPS
sudo systemctl restart netease
# or however you restart your app
```

---

## Sync Database: Local → VPS

### One Command
```bash
# From local machine
pg_dump -U netease netease_db | ssh srv@172.16.200.90 "psql -U netease netease_db"
```

That's it! Your local database is now on the VPS.

---

## Typical Workflow

```bash
# 1. Commit and push
git push origin main

# 2. SSH to VPS and pull
ssh srv@172.16.200.90 "cd /home/srv/netease && git pull && source venv/bin/activate && alembic upgrade head && sudo systemctl restart netease"

# 3. Sync database (if needed)
pg_dump -U netease netease_db | ssh srv@172.16.200.90 "psql -U netease netease_db"
```

---

## Notes

- **Schema changes:** Use Alembic migrations (`alembic upgrade head` on VPS)
- **Data sync:** Use the pg_dump command above
- **Password:** Set `PGPASSWORD=1234` before commands if needed
