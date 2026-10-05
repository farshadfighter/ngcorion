#!/bin/sh
# Lock the appliance down: no login anywhere, no way into a shell from GRUB,
# and a finalizer (Packer's shutdown_command) that removes the build account,
# SSH and every per-machine identity just before the image is sealed.
set -eux

# No passwords: root is locked; the only account with a password is the
# temporary build account, deleted by the finalizer.
passwd -l root

# No login prompts: tty1 shows the console menu (ngcorion-console.service),
# logind starts no other VTs (logind.conf.d/ngcorion.conf), and the serial
# line gets no getty. Ctrl-Alt-Del does not reboot.
systemctl mask getty@tty1.service serial-getty@ttyS0.service ctrl-alt-del.target

# GRUB: no menu, no recovery entries, and entries cannot be edited (that is
# how one would boot into a root shell). The GRUB password is random and
# thrown away: nobody, us included, can edit the boot entries.
GRUB_PW=$(head -c 32 /dev/urandom | base64)
HASH=$(printf '%s\n%s\n' "$GRUB_PW" "$GRUB_PW" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $NF}')
unset GRUB_PW
test -n "$HASH"
cat > /etc/grub.d/01_ngcorion_password <<EOG
#!/bin/sh
cat <<'EOC'
set superusers="ngcorion-grub"
password_pbkdf2 ngcorion-grub $HASH
EOC
EOG
chmod 0755 /etc/grub.d/01_ngcorion_password
# Booting the normal entries needs no password; only editing them does.
sed -i 's/^CLASS="--class gnu-linux --class gnu --class os"$/CLASS="--class gnu-linux --class gnu --class os --unrestricted"/' /etc/grub.d/10_linux
grep -q -- '--unrestricted' /etc/grub.d/10_linux
cat > /etc/default/grub.d/90-ngcorion.cfg <<'EOG'
GRUB_TIMEOUT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_RECORDFAIL_TIMEOUT=0
GRUB_DISABLE_RECOVERY=true
GRUB_DISABLE_OS_PROBER=true
EOG
update-grub

# Packer runs this as its shutdown_command, over the build account's SSH session.
cat > /usr/local/sbin/ngcorion-finalize <<'EOF2'
#!/bin/sh
set -eux
export DEBIAN_FRONTEND=noninteractive
# Build access goes: SSH server, cloud-init (and its seed), the build account.
apt-get purge -y openssh-server cloud-init cloud-guest-utils
rm -rf /etc/ssh/ssh_host_* /etc/cloud /var/lib/cloud /etc/sudoers.d/90-cloud-init-users
userdel -rf packer || true
# Per-machine identity: every deployed appliance makes its own on first boot.
# (The license fingerprint uses the machine-id; a shared one would make all
# appliances look like one machine.)
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id /var/lib/systemd/random-seed
rm -rf /var/lib/docker/network/files/local-kv.db
apt-get autoremove -y --purge
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /root/.bash_history
journalctl --rotate || true
journalctl --vacuum-time=1s || true
find /var/log -type f -name '*.log' -exec truncate -s 0 {} +
fstrim -av || true
rm -f /usr/local/sbin/ngcorion-finalize
sync
systemctl poweroff
EOF2
chmod 0700 /usr/local/sbin/ngcorion-finalize
