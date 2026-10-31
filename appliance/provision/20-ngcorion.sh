#!/bin/sh
# NGCorion: the compose bundle under /opt/ngcorion, the preloaded container
# images, the appliance console and the systemd units.
#   /tmp/stage   - made by appliance/build.sh (bundle/ and images.tar.gz)
#   /tmp/rootfs  - appliance/rootfs
set -eux

install -d -m 0755 /opt/ngcorion /etc/ngcorion /var/lib/ngcorion-appliance
cp -a /tmp/stage/bundle/. /opt/ngcorion/
# The files of appliance/rootfs, owned by root. Not `cp -a`: it also gave the existing
# directories (/etc, /etc/sudoers.d, /opt, /usr/local/sbin) the owner and mode of the uploaded
# copies, i.e. the build account's uid, and sudo then refuses /etc/sudoers.d. tar leaves the
# directories that exist alone and makes everything it creates root's.
tar -C /tmp/rootfs -cf - . | tar -C / -xf - --no-overwrite-dir --no-same-owner --no-same-permissions
chown -R root:root /opt/ngcorion /etc/systemd/system/ngcorion*.service \
    /etc/systemd/network /etc/systemd/logind.conf.d \
    /usr/local/sbin/ngcorion-ssh-console /etc/sudoers.d/ngcorion-ssh /etc/security/faillock.conf
chmod 0755 /usr/local/sbin/ngcorion-ssh-console
chmod 0440 /etc/sudoers.d/ngcorion-ssh
visudo -cf /etc/sudoers.d/ngcorion-ssh
# Nothing of the system may stay owned by the build account (deleted when the image is sealed,
# its uid then free for the next account made).
test -z "$(find /etc /opt /usr -xdev -user packer -print -quit)"
test -z "$(find /etc /etc/sudoers.d /etc/security /opt /usr/local/sbin -maxdepth 0 \( ! -user root -o -perm /022 \) -print)"
chmod -R go-w /opt/ngcorion

# Images: loaded now, so the appliance never pulls anything.
gunzip -c /tmp/stage/images.tar.gz | docker load
docker image ls

python3 -m compileall -q /opt/ngcorion/appliance
systemctl daemon-reload
systemctl enable ngcorion-console.service ngcorion-growdisk.service
rm -rf /tmp/stage /tmp/rootfs
