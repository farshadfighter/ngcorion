#!/usr/bin/env bash
# Build the Netease backend as a Nuitka standalone binary.
# Usage: bash build.sh
# Output: dist_build/netease_server.dist/

set -euo pipefail

VENV=./venv
PYTHON=$VENV/bin/python
OUTPUT_DIR=dist_build
BINARY_NAME=netease_server

echo "=== Nuitka standalone build ==="
echo "Python: $($PYTHON --version)"
echo "Nuitka: $($PYTHON -m nuitka --version 2>&1 | head -1)"
echo ""

$PYTHON -m nuitka \
    --standalone \
    --follow-imports \
    --output-dir="$OUTPUT_DIR" \
    --output-filename="$BINARY_NAME" \
    \
    --include-package=app \
    \
    --include-package=fastapi \
    --include-package=starlette \
    --include-package=uvicorn \
    --include-package=anyio \
    --include-package=httpx \
    \
    --include-package=sqlalchemy \
    --include-package=alembic \
    --include-package=psycopg2 \
    \
    --include-package=pydantic \
    --include-package=pydantic_settings \
    --include-package=passlib \
    --include-package=jose \
    --include-package=bcrypt \
    \
    --include-package=netmiko \
    --include-package=paramiko \
    --include-package=cryptography \
    --include-package=ntc_templates \
    --include-package=openpyxl \
    \
    --include-data-dir=app/modules=app/modules \
    --include-package-data=ntc_templates \
    \
    run.py

DIST="$OUTPUT_DIR/${BINARY_NAME}.dist"

echo ""
echo "=== Post-build: copying runtime assets ==="

# psycopg2-binary bundles libpq/libssl/libcrypto in psycopg2_binary.libs/.
# _psycopg.so's RPATH points to this directory; copy it next to the extension.
PSYCOPG2_LIBS=$(find "$VENV/lib" -type d -name "psycopg2_binary.libs" 2>/dev/null | head -1)
if [ -n "$PSYCOPG2_LIBS" ]; then
    cp -r "$PSYCOPG2_LIBS" "$DIST/"
    echo "  Copied psycopg2_binary.libs"
else
    echo "  WARNING: psycopg2_binary.libs not found — psycopg2 may fail to load"
fi

# Alembic migrations (run at first startup to create DB tables)
cp -r alembic/ "$DIST/"
cp alembic.ini "$DIST/"
echo "  Copied alembic/ and alembic.ini"

# Starter config template
cp .env.example "$DIST/.env.example"
echo "  Copied .env.example"

echo ""
echo "=== Build complete ==="
echo ""
echo "Distribute: $DIST/"
echo ""
echo "First-run instructions for the recipient:"
echo "  1. Start PostgreSQL:  docker compose up -d"
echo "  2. Edit config:       cp .env.example .env  &&  nano .env"
echo "  3. Run server:        cd $DIST && ./netease_server"
