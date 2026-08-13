#!/usr/bin/env sh
# Container entrypoint: bring the database schema/data to the current head
# BEFORE starting the app server, so every environment (dev container, staging,
# production, fresh CI DB) is migrated automatically with no manual step.
#
# `set -e` makes a failed migration fatal: we would rather the container stop
# loudly than start the app against a stale/wrong schema.
#
# CAVEAT (see RISK_MIGRATION_REPORT / project memory alembic-createall-drift):
# `app/main.py` calls Base.metadata.create_all() at import time. On a database
# whose tables were created that way but never stamped by Alembic,
# `alembic upgrade head` replays every migration from base and can fail on the
# first op.create_table with DuplicateTable. If that happens, stamp the DB to
# the correct revision once (e.g. `alembic stamp head`) and restart.
set -e

echo "[entrypoint] Applying database migrations: alembic upgrade head"
alembic upgrade head
echo "[entrypoint] Migrations applied. Launching: $*"

exec "$@"
