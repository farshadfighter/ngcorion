#!/usr/bin/env bash
# Ubuntu 22.04 host hardening for the netease FastAPI service.
#
# What this script does (idempotent — safe to re-run):
#   - Enables UFW: default-deny inbound, allow SSH/HTTP/HTTPS, block direct
#     access to 8000 (FastAPI) and 5173 (Vite dev) from non-loopback.
#   - Hardens sshd: disables root login, password auth, lowers MaxAuthTries.
#   - Installs fail2ban with sshd jail and a custom fastapi-auth jail that
#     bans IPs based on FAIL log lines emitted by app/modules/auth/router.py.
#   - Enables unattended security upgrades.
#   - Applies conservative kernel sysctls.
#
# Run as root:
#     sudo bash scripts/harden_ubuntu22.sh
#
# WARNING: Disabling SSH password authentication will lock you out unless an
# SSH key is already authorized. Make sure key-based auth works first.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)." >&2
    exit 1
fi

log() { printf '\n[+] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. APT packages
# ---------------------------------------------------------------------------
log "Updating apt and installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ufw fail2ban unattended-upgrades apt-listchanges

# ---------------------------------------------------------------------------
# 2. UFW firewall
# ---------------------------------------------------------------------------
log "Configuring UFW"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
# App ports only from loopback — reverse proxy should sit in front
ufw deny 8000/tcp comment 'FastAPI: block direct external access'
ufw deny 5173/tcp comment 'Vite dev: block direct external access'
ufw --force enable
ufw status verbose

# ---------------------------------------------------------------------------
# 3. SSH hardening
# ---------------------------------------------------------------------------
log "Hardening sshd"
install -d -m 0755 /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# Managed by scripts/harden_ubuntu22.sh
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
PermitEmptyPasswords no
X11Forwarding no
EOF
sshd -t
systemctl reload ssh || systemctl reload sshd || true

# ---------------------------------------------------------------------------
# 4. fail2ban
# ---------------------------------------------------------------------------
log "Configuring fail2ban"
install -d -m 0755 /var/log/netease
touch /var/log/netease/auth.log
chmod 0644 /var/log/netease/auth.log

# Filter matches the line printed by log_login_attempt() in
# app/modules/auth/router.py:
#   [YYYY-MM-DD HH:MM:SS] Login FAIL!: User 'alice' With IP 10.0.0.1
cat >/etc/fail2ban/filter.d/fastapi-auth.conf <<'EOF'
[Definition]
failregex = ^\[.*\] Login FAIL!: User '.*' With IP <HOST>\s*$
ignoreregex =
EOF

cat >/etc/fail2ban/jail.d/netease.local <<'EOF'
[sshd]
enabled = true
maxretry = 3
findtime = 10m
bantime = 1h

[fastapi-auth]
enabled  = true
filter   = fastapi-auth
logpath  = /var/log/netease/auth.log
maxretry = 5
findtime = 15m
bantime  = 1h
EOF

systemctl enable fail2ban
systemctl restart fail2ban
fail2ban-client status || true

# ---------------------------------------------------------------------------
# 5. Unattended security upgrades
# ---------------------------------------------------------------------------
log "Enabling unattended security upgrades"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
dpkg-reconfigure -f noninteractive unattended-upgrades

# ---------------------------------------------------------------------------
# 6. Kernel sysctls
# ---------------------------------------------------------------------------
log "Applying kernel sysctls"
cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
# Managed by scripts/harden_ubuntu22.sh
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system >/dev/null

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
cat <<EOF

============================================================
Hardening complete.

Next steps you must do yourself:
  1. Point the FastAPI service stdout/stderr at /var/log/netease/auth.log
     so fail2ban can read login-failure lines. For systemd:
         StandardOutput=append:/var/log/netease/auth.log
         StandardError=append:/var/log/netease/auth.log
     For docker-compose, mount the file and redirect, or change the
     fastapi-auth jail to read journald instead.
  2. Verify you can still SSH in (key auth only).
  3. Set BACKEND_CORS_ORIGINS in .env to your real frontend origin(s).
============================================================
EOF
