# Netease Services Startup & Troubleshooting Guide

## Current Status

**Your Current IP:** 192.168.100.67  
**Expected Server IP:** 172.16.200.90

⚠️ **IMPORTANT:** You are currently NOT on the Ubuntu server (172.16.200.90). You need to SSH into that server first!

---

## Step 1: Connect to Ubuntu Server

```bash
ssh sina@172.16.200.90
# Or use your SSH key/credentials
```

---

## Step 2: Start Services (In Order)

### Terminal 1: License Server (Port 8001)

```bash
cd /home/sina/netease/license_server
source .venv/bin/activate  # Note: it is .venv not venv
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

**Expected Output:**
```
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001
```

### Terminal 2: Main App Backend (Port 8000)

```bash
cd /home/sina/netease
source .venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Expected Output:**
```
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Terminal 3: Frontend (Port 5173)

```bash
cd /home/sina/netease/front
npm run dev
```

**Expected Output:**
```
VITE v7.x.x  ready in xxx ms

➜  Local:   http://localhost:5173/
➜  Network: http://172.16.200.90:5173/
```

---

## Step 3: Access from Browser

Once all three services are running, open your browser and go to:

**Frontend:** http://172.16.200.90:5173

**Backend API Docs:** http://172.16.200.90:8000/docs

**License Server Docs:** http://172.16.200.90:8001/docs

---

## Common Issues & Solutions

### Issue 1: Cannot see anything in browser

**Possible Causes:**

1. **Services not running**
   ```bash
   # Check if services are running
   netstat -tlnp | grep -E ":(8000|8001|5173)"
   ```
   
   Should show:
   ```
   tcp  0  0.0.0.0:8000  0.0.0.0:*  LISTEN  xxxxx/python
   tcp  0  0.0.0.0:8001  0.0.0.0:*  LISTEN  xxxxx/python
   tcp  0  0.0.0.0:5173  0.0.0.0:*  LISTEN  xxxxx/node
   ```

2. **Firewall blocking ports**
   ```bash
   # Check firewall status
   sudo ufw status
   
   # If ports are blocked, allow them:
   sudo ufw allow 5173/tcp
   sudo ufw allow 8000/tcp
   sudo ufw allow 8001/tcp
   ```

3. **Services listening on 127.0.0.1 instead of 0.0.0.0**
   - Make sure you use --host 0.0.0.0 for uvicorn
   - Vite config already has host: 0.0.0.0 in vite.config.js

4. **Wrong IP address**
   - Make sure you are accessing http://172.16.200.90:5173
   - NOT http://localhost:5173 unless you are on the server itself

### Issue 2: Connection refused

```bash
# Test from the server itself
curl http://localhost:5173
curl http://localhost:8000/docs
curl http://localhost:8001/docs

# If these work but browser does not, it is a firewall issue
```

### Issue 3: Port already in use

```bash
# Find what is using the port
sudo lsof -i :5173
sudo lsof -i :8000
sudo lsof -i :8001

# Kill the process
kill -9 <PID>
```

### Issue 4: Virtual environment not found

```bash
# Main app
cd /home/sina/netease
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# License server
cd /home/sina/netease/license_server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Issue 5: npm command not found

```bash
# Install Node.js and npm
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify installation
node --version
npm --version
```

### Issue 6: Frontend shows blank page

1. **Check browser console (F12)**
   - Look for errors
   - Check Network tab for failed requests

2. **Check if backend is accessible**
   ```bash
   curl http://172.16.200.90:8000/api/license/status
   ```

3. **Clear browser cache and localStorage**
   ```javascript
   // In browser console
   localStorage.clear();
   location.reload();
   ```

---

## Verification Checklist

After starting all services, verify:

- [ ] License server responds: curl http://localhost:8001/docs
- [ ] Main app responds: curl http://localhost:8000/docs
- [ ] Frontend responds: curl http://localhost:5173
- [ ] All ports listening on 0.0.0.0: netstat -tlnp | grep -E ":(8000|8001|5173)"
- [ ] Firewall allows ports: sudo ufw status
- [ ] Can access from browser: http://172.16.200.90:5173

---

## Quick Start Script

Run this to check everything:

```bash
cd /home/sina/netease
./start_all_services.sh
```

---

## Network Architecture

```
Browser (Your Computer)
    ↓
http://172.16.200.90:5173 (Frontend - Vite)
    ↓
http://172.16.200.90:8000 (Main App - FastAPI)
    ↓
http://172.16.200.90:8001 (License Server - FastAPI)
```

The frontend proxies API requests to the backend via vite.config.js:
- /auth/* → http://172.16.200.90:8000
- /api/* → http://172.16.200.90:8000

---

## Still Not Working?

1. **Check if you are on the right server:**
   ```bash
   hostname -I
   # Should show: 172.16.200.90
   ```

2. **Check if services are actually running:**
   ```bash
   ps aux | grep -E "(uvicorn|node)" | grep -v grep
   ```

3. **Check logs for errors:**
   - Look at the terminal output where you started each service
   - Check for Python errors, port conflicts, or missing dependencies

4. **Test network connectivity:**
   ```bash
   # From your computer
   ping 172.16.200.90
   telnet 172.16.200.90 5173
   ```

---

**Last Updated:** May 2, 2025
