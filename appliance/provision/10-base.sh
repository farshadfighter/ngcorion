#!/bin/sh
# Appliance OS: updates, Docker, hypervisor guest tools, growpart (the disk grows when the
# virtual disk is enlarged: ngcorion-growdisk.service), and systemd-networkd
# in place of cloud-init's netplan configuration. Runs as root inside the
# image being built (Packer), never on a customer machine.
set -eux
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y -o Dpkg::Options::=--force-confold full-upgrade
apt-get install -y --no-install-recommends \
    docker.io docker-compose-v2 \
    open-vm-tools qemu-guest-agent \
    snmpd rsyslog openssl ca-certificates python3 \
    cloud-guest-utils gdisk openssh-server sudo
# Not needed on an appliance.
for pkg in snapd lxd-installer landscape-common; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then apt-get purge -y "$pkg"; fi
done
apt-get autoremove -y --purge

systemctl enable docker.service

# The kernel must bring the storage and network drivers of every hypervisor
# the images are made for (VMware: pvscsi + vmxnet3, Hyper-V, KVM: virtio).
KVER=$(ls /lib/modules | sort -V | tail -n1)
for m in vmw_pvscsi vmxnet3 hv_storvsc hv_netvsc virtio_blk virtio_net; do
    modinfo -k "$KVER" "$m" >/dev/null 2>&1 || modinfo -k "$KVER" -F filename "$m" >/dev/null 2>&1 \
        || grep -q "/$m.ko" "/lib/modules/$KVER/modules.builtin" \
        || { echo "kernel $KVER lacks $m"; exit 1; }
done

# Networking: systemd-networkd files only (appliance/rootfs/etc/systemd/network);
# cloud-init's netplan file would otherwise keep DHCP on every interface.
rm -f /etc/netplan/*.yaml
systemctl enable systemd-networkd.service systemd-resolved.service
