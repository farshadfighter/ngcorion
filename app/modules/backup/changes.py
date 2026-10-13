"""
What changed between two configuration backups of a device, and who changed it.

compare(family, old, new) gives the difference as sections of "+" (in the new version only) and
"-" (in the old version only) lines. Cisco IOS and FortiOS are compared as configuration trees with
the restore parsers (app/modules/backup/restore/config_tree.py), which ignore what differs between
two captures of an unchanged device (timestamps, byte counts, prompts); file bundles (Linux, Apache,
MongoDB) file by file; anything else line by line.

Every new DeviceBackup is compared with the previous backup of its asset when it is saved
(_note_change, a before_flush hook, so all the places that take a backup - by hand, before a
hardening or a restore, scheduled - are covered). The change is "ngcorion" when a hardening action
or a restore NGCorion ran on the asset between the two backups, "external" otherwise.
"""
import difflib
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.models.backup import DeviceBackup
from app.modules.backup.restore import config_tree, file_bundle
from app.modules.backup.restore.config_tree import ConfigDiff, DiffLine, DiffSection

logger = logging.getLogger(__name__)

MAX_LINES_SHOWN = 4000


def _bundle_diff(old_text: str, new_text: str) -> ConfigDiff:
    old, new = file_bundle.parse_bundle(old_text), file_bundle.parse_bundle(new_text)
    diff = ConfigDiff()
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path), new.get(path)
        if a == b:
            continue
        if a is None:
            diff.sections.append(DiffSection(f"{path} (new file)", [DiffLine("+", t) for t in b.split("\n")]))
        elif b is None:
            diff.sections.append(DiffSection(f"{path} (removed)", [DiffLine("-", t) for t in a.split("\n")]))
        else:
            diff.sections.append(DiffSection(path, _unified(a.split("\n"), b.split("\n"))))
    return diff


def _unified(a: List[str], b: List[str]) -> List[DiffLine]:
    out = []
    for line in difflib.unified_diff(a, b, lineterm="", n=2):
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("@@"):
            out.append(DiffLine(" ", line))
        else:
            out.append(DiffLine(line[0] if line[0] in "+-" else " ", line[1:]))
    return out


def _text_diff(old_text: str, new_text: str) -> ConfigDiff:
    lines = _unified((old_text or "").splitlines(), (new_text or "").splitlines())
    return ConfigDiff(sections=[DiffSection("configuration", lines)] if any(l.op in "+-" for l in lines) else [])


def compare(family: Optional[str], old_text: str, new_text: str) -> ConfigDiff:
    """The difference from `old_text` to `new_text` ("+" added, "-" removed)."""
    family = (family or "").lower()
    try:
        if family == "cisco":
            return config_tree.diff_cisco(new_text, old_text)
        if family == "fortinet":
            return config_tree.diff_fortios(new_text, old_text)
        if family in ("linux", "apache", "mongodb"):
            return _bundle_diff(old_text, new_text)
    except Exception:  # noqa: BLE001 - a configuration the parser cannot read is still compared
        logger.warning("[Backup] %s configuration could not be parsed; compared line by line", family, exc_info=True)
    return _text_diff(old_text, new_text)


@dataclass
class Origin:
    kind: str                  # external | ngcorion
    ref: Optional[str] = None  # hardening:<id> | restore:<id>


def origin_of_change(db: Session, asset_id: int, since: datetime, until: datetime) -> Origin:
    """Whether NGCorion itself changed the asset between two backups: a hardening action carried out,
    or a restore applied, in that window."""
    from sqlalchemy import func
    from app.models.backup_restore import BackupRestore
    from app.models.hardening import HardeningAction
    # When the change was made: a hardening action's backup is taken after the action is created,
    # so its creation time would fall before the window.
    done = func.coalesce(HardeningAction.completed_at, HardeningAction.executed_at, HardeningAction.created_at)
    restored = func.coalesce(BackupRestore.finished_at, BackupRestore.created_at)
    with db.no_autoflush:
        h = (db.query(HardeningAction.id)
             .filter(HardeningAction.asset_id == asset_id, HardeningAction.status == "success",
                     HardeningAction.action_type != "preview", done >= since, done <= until)
             .order_by(HardeningAction.id.desc()).first())
        if h:
            return Origin("ngcorion", f"hardening:{h[0]}")
        r = (db.query(BackupRestore.id)
             .filter(BackupRestore.asset_id == asset_id, BackupRestore.status.in_(("succeeded", "reverted")),
                     restored >= since, restored <= until)
             .order_by(BackupRestore.id.desc()).first())
        if r:
            return Origin("ngcorion", f"restore:{r[0]}")
    return Origin("external")


def latest(db: Session, asset_id: int, before: Optional[datetime] = None) -> Optional[DeviceBackup]:
    q = db.query(DeviceBackup).filter(DeviceBackup.asset_id == asset_id)
    if before is not None:
        q = q.filter(DeviceBackup.created_at <= before)
    with db.no_autoflush:
        return q.order_by(DeviceBackup.created_at.desc(), DeviceBackup.id.desc()).first()


def counts(diff: ConfigDiff) -> Tuple[int, int]:
    return diff.added, diff.removed


def note_change(db: Session, backup: DeviceBackup, previous: Optional[DeviceBackup]) -> None:
    """Fill the change fields of a new backup from the previous one."""
    if backup.created_at is None:
        backup.created_at = datetime.utcnow()
    if previous is None:
        backup.changed, backup.change_origin = None, "first"
        return
    backup.previous_backup_id = previous.id
    diff = compare(backup.device_type or previous.device_type, previous.config_content, backup.config_content)
    added, removed = counts(diff)
    if not added and not removed:
        backup.changed, backup.added_lines, backup.removed_lines, backup.change_origin = False, 0, 0, "unchanged"
        return
    # the device was still as `previous` when it was last confirmed
    since = previous.confirmed_at or previous.created_at
    origin = origin_of_change(db, backup.asset_id, since, backup.created_at)
    backup.changed, backup.added_lines, backup.removed_lines = True, added, removed
    backup.change_origin, backup.change_ref = origin.kind, origin.ref


@event.listens_for(Session, "before_flush")
def _note_change(session: Session, flush_context, instances) -> None:
    """Every backup saved, wherever it is taken, is compared with the previous one of its asset."""
    for obj in list(session.new):
        if not isinstance(obj, DeviceBackup) or obj.change_origin is not None or not obj.asset_id:
            continue
        try:
            previous = latest(session, obj.asset_id, obj.created_at)
            note_change(session, obj, previous)
        except Exception:  # noqa: BLE001 - never lose a backup over its change summary
            logger.warning("[Backup] change summary failed for asset %s", obj.asset_id, exc_info=True)
