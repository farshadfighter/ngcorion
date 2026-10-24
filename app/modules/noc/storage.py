"""
How much disk the monitoring data takes, and how long the SNMP metrics are kept.

The SNMP metrics tiers (raw samples, 5-minute, hourly and daily rollups) and their storage budget were
only settable in .env; they are a System Configuration section ("noc_metrics_storage") now, with the
.env values as defaults. usage() reports what syslog messages and metrics take against their budgets,
measured on the stored rows (app/core/table_usage.py), and the disk's free space.
"""
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.core.config import settings as app_settings
from app.models.system_config import SystemConfigSetting

SECTION = "noc_metrics_storage"
LIMITS = {
    "raw_hours": (24, 720),          # raw samples: 1 to 30 days
    "days_5m": (7, 365),
    "days_1h": (30, 1095),
    "days_1d": (0, 3650),            # 0 = kept for good
    "storage_budget_gb": (1, 500),
}


def defaults() -> Dict[str, int]:
    return {
        "raw_hours": int(app_settings.NOC_METRICS_RAW_RETENTION_HOURS),
        "days_5m": int(app_settings.NOC_METRICS_5M_RETENTION_DAYS),
        "days_1h": int(app_settings.NOC_METRICS_1H_RETENTION_DAYS),
        "days_1d": int(app_settings.NOC_METRICS_1D_RETENTION_DAYS),
        "storage_budget_gb": max(1, int(round(app_settings.NOC_METRICS_STORAGE_BUDGET_GB))),
    }


def _clamp(key: str, value) -> int:
    lo, hi = LIMITS[key]
    return max(lo, min(int(value), hi))


def get_settings(db: Session) -> Dict[str, int]:
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    stored = (row.config_json or {}) if row else {}
    out = {}
    for key, default in defaults().items():
        try:
            out[key] = _clamp(key, stored.get(key, default))
        except (TypeError, ValueError):
            out[key] = _clamp(key, default)
    return out


def save_settings(db: Session, values: Dict, user_id: Optional[int]) -> Dict[str, int]:
    current = get_settings(db)
    for key in LIMITS:
        if values.get(key) is not None:
            current[key] = _clamp(key, values[key])
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION).first()
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = current
    row.updated_by = user_id
    db.commit()
    return get_settings(db)


def usage(db: Session) -> Dict:
    """What syslog messages and SNMP metrics take against their budgets, and the disk's free space."""
    from app.core.storage_guard import storage_state
    from app.modules.noc.metrics_retention import metrics_usage
    from app.modules.syslog import retention as syslog_retention
    from app.modules.syslog import settings as syslog_settings

    gb = 1024 ** 3
    syslog_used, syslog_rows = syslog_retention.usage(db)
    metrics_used, metrics_rows = metrics_usage(db)
    syslog_budget = syslog_settings.get_settings(db)["storage_budget_gb"] * gb
    metrics_budget = get_settings(db)["storage_budget_gb"] * gb
    disk = storage_state()
    free = disk.get("free")
    # What the two budgets may still claim, compared with the space left on the disk.
    room_needed = max(0, syslog_budget - syslog_used) + max(0, metrics_budget - metrics_used)
    return {
        "syslog": {"used_bytes": syslog_used, "rows": syslog_rows, "budget_bytes": syslog_budget},
        "metrics": {"used_bytes": metrics_used, "rows": metrics_rows, "budget_bytes": metrics_budget,
                    "evict_at": float(app_settings.NOC_METRICS_STORAGE_EVICT_THRESHOLD)},
        "disk": {"free_bytes": free, "path": disk.get("path")},
        "budgets_exceed_free": free is not None and room_needed > free,
    }
