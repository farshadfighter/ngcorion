"""Stored CVE database state (cve_settings): the update watermark, the
auto-update schedule and the NVD API key (encrypted at rest)."""
import json
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.core.credential_crypto import PURPOSE_CVE, decrypt, encrypt
from app.models.cve import CveSetting

WATERMARK = "nvd_watermark"        # ISO UTC: NVD changes up to here are loaded
KEV_INFO = "kev_info"              # {"version", "released"}
EPSS_DATE = "epss_date"
AUTO_UPDATE = "auto_update"        # {"enabled": bool, "time": "HH:MM"}
LAST_AUTO_RUN = "last_auto_run"    # date of the last automatic run
NVD_API_KEY = "nvd_api_key"        # encrypted
SIGNING_KEY = "signing_key"        # encrypted raw Ed25519 private key (base64)
INSTANCE_NAME = "instance_name"

_ENCRYPTED = {NVD_API_KEY, SIGNING_KEY}


def get(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(CveSetting, key)
    if row is None or row.value is None:
        return default
    if key in _ENCRYPTED:
        try:
            return decrypt(row.value, PURPOSE_CVE)
        except ValueError:
            return default
    try:
        return json.loads(row.value)
    except ValueError:
        return row.value


def put(db: Session, key: str, value: Any) -> None:
    """Stages the change; the caller commits (so a setting can be part of the
    same transaction as the data it describes)."""
    row = db.get(CveSetting, key)
    if value is None:
        if row is not None:
            db.delete(row)
        return
    stored = encrypt(value, PURPOSE_CVE) if key in _ENCRYPTED else json.dumps(value)
    if row is None:
        db.add(CveSetting(key=key, value=stored))
    else:
        row.value = stored


def auto_update(db: Session) -> dict:
    value = get(db, AUTO_UPDATE) or {}
    return {"enabled": bool(value.get("enabled", False)), "time": value.get("time") or "02:00"}


def has_api_key(db: Session) -> bool:
    return bool(get(db, NVD_API_KEY))


def api_key(db: Session) -> Optional[str]:
    return get(db, NVD_API_KEY) or None


def vulnerability_data_loaded(db: Session) -> bool:
    """NVD or a distribution's advisories: either makes findings meaningful
    (no finding then means nothing known to be vulnerable)."""
    if get(db, WATERMARK) is not None:
        return True
    from app.modules.advisories.store import loaded
    return loaded(db)
