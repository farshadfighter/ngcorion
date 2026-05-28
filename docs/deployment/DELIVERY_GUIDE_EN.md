# Netease Backend — Deployment Guide

---

## What Is This?

The backend is packaged as a **single executable file** (`netease_server`).
The person receiving it does **not** need Python installed — just Docker.

Docker will run the PostgreSQL database, and the executable runs the API server.

---

## Part 1 — Build the Executable (You Do This)

Do this on **your own computer** before sending anything to anyone.

**Step 1 — Open a terminal in the project folder and run:**
```bash
source venv/bin/activate
pip install -r requirements.txt
bash build.sh
```

The build takes about 5–15 minutes. When it finishes, you'll see a folder at:
```
dist_build/netease_server.dist/
```

**Step 2 — Quick test before sending:**
```bash
# Start the database
docker compose up -d

# Go into the build output
cd dist_build/netease_server.dist
cp .env.example .env

# Run the server
./netease_server
```

Open `http://localhost:8000/docs` in your browser. If you see a Swagger page, the build worked.

Press `Ctrl+C` to stop the server.

**Step 3 — Package it up:**
```bash
cd dist_build
zip -r netease_server_v1.0.zip netease_server.dist/
```

You will send two files to the server:
- `netease_server_v1.0.zip`
- `docker-compose.yml` (from the project root)

---

## Part 2 — Set Up the VPS (Fresh Server, Nothing Installed)

Connect to the server via SSH:
```bash
ssh root@YOUR_SERVER_IP
```

### Install Docker

Docker is the only thing you need to install. It will handle the database.

```bash
# Update the system first
apt update && apt upgrade -y

# Install required tools
apt install -y ca-certificates curl gnupg

# Add Docker's official key
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker's repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Make Docker start automatically on reboot
systemctl enable docker
systemctl start docker

# Confirm it worked
docker --version
```

---

## Part 3 — Upload and Run the App

### Upload the files (run this on YOUR computer, not the server)

```bash
scp dist_build/netease_server_v1.0.zip root@YOUR_SERVER_IP:/opt/
scp docker-compose.yml root@YOUR_SERVER_IP:/opt/
```

### On the server — extract and set up

```bash
# Create a folder for the app
mkdir -p /opt/netease
cd /opt/netease

# Move the files here
mv /opt/netease_server_v1.0.zip .
mv /opt/docker-compose.yml .

# Extract the zip
unzip netease_server_v1.0.zip

# Give the binary permission to run
chmod +x netease_server.dist/netease_server
```

### Create the config file

```bash
cd /opt/netease/netease_server.dist
cp .env.example .env
nano .env
```

Change these two lines in `.env`:
```env
DATABASE_URL=postgresql://netease:1234@localhost/netease_db
SECRET_KEY=REPLACE_THIS_WITH_A_LONG_RANDOM_STRING
```

To generate a secure secret key, run this on the server:
```bash
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1
```
Copy the output and paste it as your `SECRET_KEY`.

### Start the database

```bash
cd /opt/netease
docker compose up -d

# Wait a few seconds, then check it's running
docker compose ps
# You should see "running" next to postgres
```

### Start the server (test run)

```bash
cd /opt/netease/netease_server.dist
./netease_server
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Test it from your computer:
```bash
curl http://YOUR_SERVER_IP:8000/health
# Should return: {"status":"ok","version":"..."}
```

Press `Ctrl+C` to stop. Now set it up to run automatically.

---

## Part 4 — Make the Server Start Automatically

This ensures the app restarts after a server reboot without you doing anything.

```bash
nano /etc/systemd/system/netease.service
```

Paste this exactly:
```ini
[Unit]
Description=Netease Backend Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/netease/netease_server.dist
ExecStartPre=/bin/bash -c 'cd /opt/netease && docker compose up -d'
ExecStartPre=/bin/sleep 5
ExecStart=/opt/netease/netease_server.dist/netease_server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Save and close (`Ctrl+X`, then `Y`, then `Enter`), then run:

```bash
systemctl daemon-reload
systemctl enable netease
systemctl start netease

# Check it's running
systemctl status netease
```

To view logs at any time:
```bash
journalctl -u netease -f
```

---

## Part 5 — Open the Firewall Port

If the server has a firewall, open port 8000:
```bash
apt install -y ufw
ufw allow ssh
ufw allow 8000/tcp
ufw enable
```

---

## Part 6 — For the Frontend Developer (Running Locally)

The frontend developer only needs **Docker Desktop** installed.
Give them: `netease_server_v1.0.zip` + `docker-compose.yml`

**Their steps:**
```bash
# 1. Extract the zip
unzip netease_server_v1.0.zip
cd netease_server.dist

# 2. Create config
cp .env.example .env
# Open .env and set SECRET_KEY to anything (it's just local development)

# 3. Start the database
# (run this from the folder containing docker-compose.yml)
docker compose up -d

# 4. Run the server
chmod +x ./netease_server
./netease_server
```

Open `http://localhost:8000/docs` — done.

---

## Default Login (for Testing)

| | |
|---|---|
| **Username** | `admin` |
| **Password** | `123456` |
| **API docs** | `http://localhost:8000/docs` (or your server IP) |
| **Health check** | `http://localhost:8000/health` |

---

## Something Went Wrong?

| Problem | Fix |
|---------|-----|
| `Permission denied` when running | `chmod +x ./netease_server` |
| Can't reach port 8000 | Run `ufw allow 8000/tcp` on the server |
| Database connection error | Run `docker compose ps` — make sure postgres shows "running" |
| Server not starting after reboot | Run `systemctl status netease` and check the logs |
| Blank `.env` file | Make sure you copied `.env.example` to `.env` and filled in `SECRET_KEY` |
