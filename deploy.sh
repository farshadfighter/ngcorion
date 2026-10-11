#!/usr/bin/env bash
# Deploy the latest code to this server: pull, build a new backend image (the
# image builds the frontend bundle itself and carries all code - nothing of
# this checkout is mounted into the container), restart it, and let
# entrypoint.sh apply pending Alembic migrations on startup.
#
# This host needs git and Docker only; Node.js is no longer required.
#
# Usage: ./deploy.sh [branch]   (default branch: main)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BRANCH="${1:-main}"

echo "[deploy] Repository: $SCRIPT_DIR"
echo "[deploy] Branch: $BRANCH"

if [ -n "$(git status --porcelain)" ]; then
    echo "[deploy] ERROR: working tree has uncommitted changes. Commit, stash, or" >&2
    echo "[deploy]        discard them first - deploying over local edits would lose them" >&2
    echo "[deploy]        or silently mix them into the running server." >&2
    exit 1
fi

echo "[deploy] Fetching and fast-forwarding to origin/$BRANCH..."
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git merge --ff-only "origin/$BRANCH"

# Tag the image with the release version (app/core/config.py), so
# `docker images` shows which release is installed and the previous image
# stays available to roll back to.
NGCORION_TAG="$(sed -n 's/^ *VERSION: str = "\(.*\)"/\1/p' app/core/config.py | head -n1)"
export NGCORION_TAG="${NGCORION_TAG:-latest}"

echo "[deploy] Building the backend image ngcorion/backend:$NGCORION_TAG (frontend included)..."
docker compose build backend
# "latest" follows the deployed release, so a plain `docker compose up -d`
# (no NGCORION_TAG set) keeps running this image instead of building one.
docker tag "ngcorion/backend:$NGCORION_TAG" ngcorion/backend:latest

echo "[deploy] Restarting the backend container..."
# --remove-orphans: stop and remove containers of services the new compose file no longer has
# (the redis service of 2.0.0); their volumes stay until removed by hand.
docker compose up -d --remove-orphans backend

echo "[deploy] Waiting for the backend to report healthy..."
DEADLINE=$((SECONDS + 60))
until docker compose exec -T backend true 2>/dev/null; do
    if [ "$SECONDS" -ge "$DEADLINE" ]; then
        echo "[deploy] ERROR: backend container did not come up within 60s." >&2
        echo "[deploy]        Check: docker compose logs backend" >&2
        exit 1
    fi
    sleep 2
done

echo "[deploy] Backend is up. Recent logs (look for 'Migrations applied'):"
docker compose logs backend --tail 20

echo "[deploy] Done."
