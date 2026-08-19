"""
Shared pre-hardening backup helpers.

Every device family takes a configuration snapshot before it changes anything,
so a failed run can be rolled back. Two concerns are centralized here so each
family does not reinvent them:

1. ``save_device_backup`` — write the snapshot to ``device_backups``. The
   Backups page (GET /api/backups) reads *only* that table;
   ``hardening_actions.backup_config`` is invisible to it. Cisco/FortiGate keep
   the snapshot on both the action row and here — the file-config families
   (Linux/Apache/MongoDB) and the query families (MSSQL/Windows) create no
   action row, so ``device_backups`` is their only home.

2. ``build_file_bundle_command`` / ``bundle_header`` — turn a list of config
   file paths into a single human-readable text bundle, so an SSH family can
   snapshot everything its checks might touch in one round-trip.
"""

import logging
import shlex
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def save_device_backup(
    db: Session,
    *,
    backup: Optional[str],
    device_ip: Optional[str],
    device_type: str,
    user_id: Optional[int],
    asset_id: Optional[int],
    action_id: Optional[int] = None,
) -> Optional[int]:
    """
    Record a hardening-time config backup in ``device_backups``.

    Best-effort: a failure here must never fail the hardening run — the caller
    has already applied (or is about to apply) changes and the snapshot is a
    safety net, not a gate. Returns the new row id, or ``None`` when nothing was
    written (empty snapshot, no linked asset, or a DB error).

    ``device_backups.asset_id`` is NOT NULL, so runs without an inventory asset
    cannot be recorded here; those are logged and skipped.
    """
    if not backup:
        logger.warning("%s backup: empty snapshot for %s — no device_backups row", device_type, device_ip)
        return None
    if not asset_id:
        logger.warning(
            "%s backup: no asset linked to this session — snapshot (%d chars) not "
            "saved to Backups page (device_backups.asset_id is NOT NULL)",
            device_type, len(backup),
        )
        return None
    try:
        from app.models import Asset
        from app.models.backup import DeviceBackup

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        row = DeviceBackup(
            asset_id=asset_id,
            asset_name=asset.asset_name if asset else None,
            device_ip=device_ip,
            device_type=device_type,
            config_content=backup,
            source="hardening",
            hardening_action_id=action_id,
            created_by=user_id,
        )
        db.add(row)
        db.commit()
        logger.info(
            "%s backup: saved device_backups row id=%s (%d chars, action=%s, asset=%s)",
            device_type, row.id, len(backup), action_id, asset_id,
        )
        return row.id
    except Exception as exc:  # noqa: BLE001 - best-effort, never break hardening
        logger.warning("%s backup: failed to save device_backups row: %s", device_type, exc)
        try:
            db.rollback()
        except Exception as e:
            logger.warning(
                "[Hardening] rollback after the failed device_backups insert "
                f"also failed: {e}"
            )
        return None


def bundle_header(device_type: str, device_ip: Optional[str], label: str = "Configuration Backup") -> str:
    """Standard human-readable header prepended to a text config snapshot."""
    return (
        f"##### {device_type.upper()} {label} #####\n"
        f"# Backup taken at: {datetime.utcnow().isoformat()}Z\n"
        f"# Device: {device_ip or 'unknown'}\n"
        f"# By: Hardening Module\n"
        f"#\n"
    )


def build_file_bundle_command(paths: List[str]) -> str:
    """
    Build a single shell command that emits the contents of every existing file
    in ``paths`` (globs allowed), each delimited by markers so the bundle can be
    read back file-by-file.

    Non-existent paths and unmatched globs are silently skipped — the guard is
    ``[ -f "$f" ]``, and an unmatched glob stays a literal that fails that test.
    One round-trip snapshots the whole set. Meant to run under sudo so /etc
    files owned by root are still readable.
    """
    # `paths` are trusted, module-internal literals (config paths + globs), not
    # user input; they are placed unquoted so the remote shell expands globs.
    globs = " ".join(paths)
    return (
        "for f in " + globs + "; do "
        'if [ -f "$f" ]; then '
        'echo "##### BEGIN FILE: $f #####"; '
        'cat "$f" 2>/dev/null; '
        'echo ""; echo "##### END FILE: $f #####"; echo ""; '
        "fi; "
        "done"
    )
