"""
Pinned device keys: the SSH host keys and TLS certificates NGCorion pinned on its first
connection to each device (app/core/ssh_host_keys.py, app/core/tls_pins.py).

    GET    /api/system/device-keys                 every pin, with the asset it belongs to
    DELETE /api/system/device-keys/{kind}?host=&port=   forget one (kind: ssh | tls)

A device that was reinstalled or got a new certificate is refused until its old pin is removed.
On the virtual appliance there is no shell to run ``ssh-keygen -R``, so this is the way to do it.
Administrators only, and every removal is written to the audit trail with the fingerprint that
was dropped: removing a pin is how a man-in-the-middle would get in, so it must be deliberate
and traceable. The next connection pins whatever key the device then presents.
"""
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core import ssh_host_keys, tls_pins
from app.core.database import get_db
from app.core.dependencies import require_admin
from app.models import Asset, User
from app.models.security_audit_log import log_action

router = APIRouter(prefix="/api/system/device-keys", tags=["Device keys"])


class DeviceKey(BaseModel):
    kind: Literal["ssh", "tls"]
    host: str
    port: int
    key_type: Optional[str] = None      # ssh-ed25519, ecdsa-sha2-nistp256, ...; None for TLS
    fingerprint: str
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None


def _all_pins() -> List[DeviceKey]:
    pins = [DeviceKey(kind="ssh", host=h, port=p, key_type=t, fingerprint=f)
            for h, p, t, f in ssh_host_keys.get_store().entries()]
    pins += [DeviceKey(kind="tls", host=h, port=p, fingerprint=f) for h, p, f in tls_pins.entries()]
    return pins


@router.get("", response_model=List[DeviceKey])
def list_device_keys(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Every pinned key, with the asset whose address it is (when there is one)."""
    pins = _all_pins()
    hosts = {p.host for p in pins}
    assets = {a.ip_address: a for a in db.query(Asset).filter(Asset.ip_address.in_(hosts))} if hosts else {}
    for pin in pins:
        asset = assets.get(pin.host)
        if asset is not None:
            pin.asset_id, pin.asset_name = asset.id, asset.asset_name
    return pins


@router.delete("/{kind}")
def forget_device_key(
    kind: Literal["ssh", "tls"],
    request: Request,
    host: str = Query(..., min_length=1, max_length=255),
    port: int = Query(..., ge=1, le=65535),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Remove the pin of one device, so the next connection pins the key it presents then."""
    dropped = [p for p in _all_pins() if p.kind == kind and p.host == host and p.port == port]
    if not dropped:
        raise HTTPException(status_code=404, detail="No key is pinned for this device")
    removed = (ssh_host_keys.forget_host(host, port) if kind == "ssh" else tls_pins.forget(host, port))
    if not removed:
        raise HTTPException(status_code=404, detail="No key is pinned for this device")
    fingerprints = ", ".join(f"{p.key_type + ' ' if p.key_type else ''}{p.fingerprint}" for p in dropped)
    log_action(db, user_id=admin.id, username=admin.username, action="device_key.forget",
               module="system_config", ip_address=request.client.host if request.client else None,
               detail=f"{kind.upper()} {host}:{port} - removed {fingerprints}")
    return {"message": "The pinned key was removed. The next connection pins the key the device presents."}
