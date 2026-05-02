# Quick Start Guide

## Start All Services

### 1. License Server (Terminal 1)
```bash
cd /home/sina/netease/license_server
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

### 2. Main Backend (Terminal 2)
```bash
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 3. Frontend (Terminal 3)
```bash
cd /home/sina/netease/front
npm run dev
```

## Access URLs

- Frontend: http://172.16.200.90:5173
- Backend API: http://172.16.200.90:8000/docs
- License Server: http://172.16.200.90:8001/docs

## Verify Services Running

```bash
netstat -tlnp | grep -E ":(8000|8001|5173)"
```

Should show all three ports listening on 0.0.0.0

## Common Issues

### Cannot access from browser?

1. Check firewall (run on server):
   sudo ufw allow 5173/tcp
   sudo ufw allow 8000/tcp
   sudo ufw allow 8001/tcp

2. Verify you are on the right server:
   hostname -I  # Should show 172.16.200.90

3. Test locally first:
   curl http://localhost:5173

For detailed troubleshooting, see: STARTUP_TROUBLESHOOTING.md
