#!/usr/bin/env bash
# Build the NGCorion virtual appliance: OVA (VMware), VHDX (Hyper-V) and
# qcow2 (KVM / Proxmox), all from the current checkout.
#
#   appliance/build.sh
#
# Needs on the build host: docker, packer (with the qemu plugin: `packer init`
# runs below), qemu-system-x86_64, qemu-img, xorriso (or mkisofs), python3.
# With /dev/kvm the VM build takes minutes; without it, set
# PACKER_ACCELERATOR=tcg and expect an hour or more.
#
# Environment (all optional):
#   BASE_REGISTRY, PYPI_INDEX, NPM_REGISTRY  image build mirrors, as for
#                                            docker-compose.yml (defaults: Iran)
#   NGCORION_BACKEND_IMAGE                   package this existing backend image
#                                            instead of building one
#   PACKER_ACCELERATOR                       kvm (default) or tcg
#   BASE_IMAGE_URL, BASE_IMAGE_CHECKSUM      another cloud image (e.g. Debian 13)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
VERSION="$(sed -n 's/^ *VERSION: str = "\(.*\)"/\1/p' "$REPO/app/core/config.py" | head -n1)"
OUT="$HERE/output/$VERSION"
STAGE="$OUT/stage"

: "${BASE_REGISTRY:=docker.arvancloud.ir}"
export BASE_REGISTRY PYPI_INDEX="${PYPI_INDEX:-https://mirror-pypi.runflare.com/simple}" NPM_REGISTRY="${NPM_REGISTRY:-}"

# The container images the appliance runs, by the names docker-compose.yml uses.
COMPOSE_IMAGES=(
    "docker.arvancloud.ir/traefik:v3.7"
    "docker.arvancloud.ir/postgres:17-alpine"
    "docker.arvancloud.ir/redis:8-alpine"
)

echo "[appliance] NGCorion $VERSION -> $OUT"
rm -rf "$OUT"
mkdir -p "$STAGE/bundle"

if [ -n "${NGCORION_BACKEND_IMAGE:-}" ]; then
    # An image built and tested elsewhere (e.g. by CI), packaged as it is.
    echo "[appliance] Using the backend image $NGCORION_BACKEND_IMAGE"
    docker tag "$NGCORION_BACKEND_IMAGE" "ngcorion/backend:$VERSION"
else
    echo "[appliance] Building the backend image..."
    NGCORION_TAG="$VERSION" docker compose -f "$REPO/docker-compose.yml" --project-directory "$REPO" build backend
fi
docker tag "ngcorion/backend:$VERSION" ngcorion/backend:latest

echo "[appliance] Fetching the other images..."
for image in "${COMPOSE_IMAGES[@]}"; do
    source_image="${BASE_REGISTRY}/${image#docker.arvancloud.ir/}"
    docker pull "$source_image"
    [ "$source_image" = "$image" ] || docker tag "$source_image" "$image"
done
docker save ngcorion/backend:latest "ngcorion/backend:$VERSION" "${COMPOSE_IMAGES[@]}" | gzip -1 > "$STAGE/images.tar.gz"

echo "[appliance] Staging /opt/ngcorion..."
B="$STAGE/bundle"
cp "$REPO/docker-compose.yml" "$B/"
mkdir -p "$B/db/postgres-main" "$B/db/redis" "$B/traefik/dynamic" "$B/traefik/certs" "$B/data/cve" "$B/appliance"
cp "$REPO/db/postgres-main/init.sql" "$B/db/postgres-main/"
cp "$REPO/db/redis/redis.conf" "$B/db/redis/"
cp "$REPO/traefik/dynamic/tls.yml" "$B/traefik/dynamic/"
cp -r "$HERE/ngcorion_appliance" "$B/appliance/"
find "$B/appliance" -name __pycache__ -prune -exec rm -rf {} +
echo "$VERSION" > "$B/VERSION"

echo "[appliance] Building the VM image (Packer)..."
BUILD_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
packer init "$HERE/packer"
PACKER_ARGS=(
    -var "version=$VERSION"
    -var "build_password=$BUILD_PASSWORD"
    -var "stage_dir=$STAGE"
    -var "output_dir=$OUT/qemu"
    -var "accelerator=${PACKER_ACCELERATOR:-kvm}"
)
[ -n "${BASE_IMAGE_URL:-}" ] && PACKER_ARGS+=(-var "base_image_url=$BASE_IMAGE_URL" -var "base_image_checksum=$BASE_IMAGE_CHECKSUM")
packer build "${PACKER_ARGS[@]}" "$HERE/packer"

QCOW2="$OUT/qemu/ngcorion-$VERSION.qcow2"
echo "[appliance] Making the OVA and the VHDX..."
"$HERE/make-ova.sh" "$QCOW2" "$VERSION" "$OUT"
mv "$QCOW2" "$OUT/ngcorion-$VERSION.qcow2"
rm -rf "$OUT/qemu" "$STAGE"

(cd "$OUT" && sha256sum ngcorion-"$VERSION".* > SHA256SUMS)
echo "[appliance] Done:"
ls -lh "$OUT"
