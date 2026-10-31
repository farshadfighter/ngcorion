#!/bin/sh
# NGCorion: the compose bundle under /opt/ngcorion, the preloaded container
# images, the appliance console and the systemd units.
#   /tmp/stage   - made by appliance/build.sh (bundle/ and images.tar.gz)
#   /tmp/rootfs  - appliance/rootfs
set -eux

install -d -m 0755 /opt/ngcorion /etc/ngcorion /var/lib/ngcorion-appliance
cp -a /tmp/stage/bundle/. /opt/ngcorion/
cp -a /tmp/rootfs/. /
chown -R root:root /opt/ngcorion /etc/systemd/system/ngcorion*.service \
    /etc/systemd/network /etc/systemd/logind.conf.d
chmod -R go-w /opt/ngcorion

# Images: loaded now, so the appliance never pulls anything.
gunzip -c /tmp/stage/images.tar.gz | docker load
docker image ls

python3 -m compileall -q /opt/ngcorion/appliance
systemctl daemon-reload
systemctl enable ngcorion-console.service ngcorion-growdisk.service
rm -rf /tmp/stage /tmp/rootfs
