#!/usr/bin/env bash
# qcow2 -> NGCorion OVA (VMware) and VHDX (Hyper-V).
#
#   ./make-ova.sh <image.qcow2> <version> <output-dir>
#
# The OVA is a tar of the descriptor, the streamOptimized disk and a SHA-256
# manifest, in that order (the order vSphere expects).
set -euo pipefail

QCOW2=$1
VERSION=$2
OUT=$3
CPUS=${NGCORION_OVA_CPUS:-4}
MEMORY_MB=${NGCORION_OVA_MEMORY_MB:-8192}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NAME="ngcorion-$VERSION"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

VMDK="$NAME-disk1.vmdk"
qemu-img convert -p -O vmdk -o subformat=streamOptimized "$QCOW2" "$WORK/$VMDK"
CAPACITY=$(qemu-img info --output=json "$QCOW2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
VMDK_SIZE=$(stat -c %s "$WORK/$VMDK")

sed -e "s/@VERSION@/$VERSION/g" -e "s/@VMDK_NAME@/$VMDK/g" -e "s/@VMDK_SIZE@/$VMDK_SIZE/g" \
    -e "s/@CAPACITY@/$CAPACITY/g" -e "s/@CPUS@/$CPUS/g" -e "s/@MEMORY_MB@/$MEMORY_MB/g" \
    "$HERE/ovf/ngcorion.ovf.tmpl" > "$WORK/$NAME.ovf"
python3 -c 'import sys, xml.dom.minidom; xml.dom.minidom.parse(sys.argv[1])' "$WORK/$NAME.ovf"
if grep -q '@[A-Z_]*@' "$WORK/$NAME.ovf"; then echo "unfilled placeholder in the OVF" >&2; exit 1; fi

(cd "$WORK" && for f in "$NAME.ovf" "$VMDK"; do
    echo "SHA256($f)= $(sha256sum "$f" | cut -d' ' -f1)"
done > "$NAME.mf")

mkdir -p "$OUT"
tar -C "$WORK" --format=ustar -cf "$OUT/$NAME.ova" "$NAME.ovf" "$VMDK" "$NAME.mf"
# 1 MB blocks (Microsoft's recommendation for Linux guests): with the default
# 32 MB blocks every block a filesystem touches at all is stored whole, and the
# VHDX of a mostly empty disk came out nearly three times the size of the qcow2.
qemu-img convert -p -O vhdx -o subformat=dynamic,block_size=1M "$QCOW2" "$OUT/$NAME.vhdx"
echo "Made $OUT/$NAME.ova and $OUT/$NAME.vhdx"
