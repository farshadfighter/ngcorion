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

APP_UID=10001
APP_GID=10001

# Privilege drop. The container starts as root only to hand the paths the app
# writes to the unprivileged account, then re-executes this script as that
# account; migrations and the server never run as root. Doing the handover
# here (not as a manual host step) keeps existing deployments working: their
# license files, pinned SSH host keys and host config files were all written
# by root. Only the specific paths the app manages are touched.
if [ "$(id -u)" = "0" ]; then
    own() {
        # own <path>...: chown what exists; never follow symlinks out of it.
        for p in "$@"; do
            [ -e "$p" ] && chown -hR "$APP_UID:$APP_GID" "$p"
        done
        return 0
    }
    own_file() {
        # own_file <file> <mode>: create an empty managed config file when its
        # directory exists (the daemon is installed) but the file does not.
        f="$1"; mode="$2"
        if [ ! -e "$f" ] && [ -d "$(dirname "$f")" ]; then
            install -m "$mode" /dev/null "$f"
        fi
        [ -e "$f" ] && chown -h "$APP_UID:$APP_GID" "$f"
        return 0
    }

    mkdir -p /var/lib/ngcorion/license /var/lib/ngcorion/tz /var/lib/ngcorion/backups
    own /var/lib/ngcorion /etc/ngcorion /app/traefik/certs /app/traefik/dynamic
    own_file /etc/snmp/snmpd.conf 0640
    own_file /etc/rsyslog.d/99-ngcorion.conf 0644
    own_file /etc/systemd/timesyncd.conf 0644

    export HOME=/home/ngcorion
    exec setpriv --reuid="$APP_UID" --regid="$APP_GID" --init-groups "$0" "$@"
fi

echo "[entrypoint] Running as uid $(id -u). Applying database migrations: alembic upgrade head"
alembic upgrade head
echo "[entrypoint] Migrations applied. Launching: $*"

exec "$@"
