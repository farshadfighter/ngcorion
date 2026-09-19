#!/usr/bin/env bash
# Deploy the latest code to this server: pull, rebuild the frontend bundle,
# rebuild/restart the backend container, and let entrypoint.sh apply pending
# Alembic migrations on startup.
#
# The backend container mounts front/dist read-only (docker-compose.yml) and
# never builds the frontend itself, so that step has to happen here, outside
# Docker, before the container picks up the new bundle.
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

echo "[deploy] Building frontend (front/dist)..."
(
    cd front
    npm install
    npm run build
)

echo "[deploy] Rebuilding and restarting the backend container..."
docker compose up -d --build backend

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
