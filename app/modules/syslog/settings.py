"""
Syslog intake settings (System Configuration section "syslog_intake").

Off until a system administrator turns it on: listening opens a network port. Only messages from
addresses of assets in the inventory are kept.
"""
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.models.system_config import SystemConfigSetting

SECTION = "syslog_intake"
DEFAULTS = {
    "enabled": False,
    "udp": True,
    "tcp": True,
    "retention_days": 30,          # messages older than this are removed
    "storage_budget_gb": 5,        # and the oldest first when the table grows past this
    "store_max_severity": 7,       # keep messages at this severity or more severe (7 = everything)
    "backup_on_change": True,      # back a device up when it reports a configuration change (config_changes.py)
}
LIMITS = {"retention_days": (1, 365), "storage_budget_gb": (1, 500), "store_max_severity": (0, 7)}


def _clamp(key: str, value) -> int:
    lo, hi = LIMITS[key]
    return max(lo, min(int(value), hi))


def get_settings(db: Session) -> Dict:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    stored = (row.config_json or {}) if row else {}
    out = {}
    for key, default in DEFAULTS.items():
        value = stored.get(key, default)
        try:
            out[key] = bool(value) if isinstance(default, bool) else _clamp(key, value)
        except (TypeError, ValueError):
            out[key] = default
    return out


def save_settings(db: Session, values: Dict, user_id: Optional[int]) -> Dict:
    current = get_settings(db)
    for key, default in DEFAULTS.items():
        if key in values and values[key] is not None:
            current[key] = bool(values[key]) if isinstance(default, bool) else _clamp(key, values[key])
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = current
    row.updated_by = user_id
    db.commit()
    return get_settings(db)
