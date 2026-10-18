"""
API of TLS certificates (app/modules/tls), under /api/tls.

The page sits with the vulnerabilities: reading needs the CVE read permission; scanning, adding a service by
hand and turning one off need CVE write, removing one CVE delete; the settings (ports, interval, warning
period, old protocols) and the organisation's trusted certificate authorities are for administrators.
Every change is in the audit trail.
"""
import ipaddress
import re
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, UserRole
from app.models.asset import Asset
from app.models.tls import SOURCE_MANUAL, TlsEndpoint, TlsTrustedCa
from app.modules.tls import scanner
from app.modules.tls import service as S

router = APIRouter(prefix="/api/tls", tags=["TLS certificates"])

HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9-]{1,63})*\.?$")


def _role(user: User) -> str:
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def _admin(user: User) -> None:
    if _role(user) != UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Only administrators can change the TLS certificate settings")


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _log(db: Session, user: User, request: Request, action: str, detail: str, target_id: Optional[int] = None):
    from app.models.security_audit_log import log_action
    log_action(db, user_id=user.id, username=user.username, action=action, module="cve",
               target_id=target_id, ip_address=_ip(request), detail=detail)


def _host_ok(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(HOST.match(value)) and len(value) <= 253


def _state(db: Session) -> dict:
    st = S.get_state(db)
    return {"last_run": st.get("last_run"), "running": bool(st.get("running")),
            "requested": bool(st.get("requested")), "last_stats": st.get("last_stats")}


# ── reading ──────────────────────────────────────────────────────────────

@router.get("/overview")
def overview(current_user: User = Depends(require_permission("cve", "read")), db: Session = Depends(get_db)):
    """Every TLS service with its certificate, problems and level, the counts, and the scan state."""
    rows = S.evaluate(db, include_disabled=True)
    active = [r for r in rows if r["endpoint"].enabled]
    settings = S.get_settings(db)
    return {"summary": S.summary(active), "services": [S.out(r) for r in rows],
            "warn_days": settings["warn_days"], "auto_scan": settings["auto_scan"], "scan": _state(db)}


@router.get("/assets/{asset_id}")
def asset_services(asset_id: int, current_user: User = Depends(require_permission("cve", "read")),
                   db: Session = Depends(get_db)):
    if db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"services": [S.out(r) for r in S.evaluate(db, [asset_id], include_disabled=True)]}


@router.get("/services/{service_id}")
def get_service(service_id: int, current_user: User = Depends(require_permission("cve", "read")),
                db: Session = Depends(get_db)):
    ep = db.get(TlsEndpoint, service_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="TLS service not found")
    rows = [r for r in S.evaluate(db, [ep.asset_id], include_disabled=True) if r["endpoint"].id == ep.id]
    if not rows:        # its asset was deleted meanwhile
        raise HTTPException(status_code=404, detail="TLS service not found")
    return S.out(rows[0])


# ── scanning ─────────────────────────────────────────────────────────────

class ScanIn(BaseModel):
    asset_id: Optional[int] = None


@router.post("/scan")
def scan(body: ScanIn, request: Request, current_user: User = Depends(require_permission("cve", "write")),
         db: Session = Depends(get_db)):
    """One asset: scanned now (a few seconds) and its services returned. All assets: the background scan is
    asked to run within a minute."""
    if body.asset_id is not None:
        asset = db.get(Asset, body.asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        name = asset.asset_name
        stats = S.run_scan(db, asset_ids=[asset.id])
        _log(db, current_user, request, "tls.scan", f"Scanned the TLS certificates of {name}", asset.id)
        db.commit()
        return {"stats": stats, "services": [S.out(r) for r in S.evaluate(db, [asset.id], include_disabled=True)]}
    S.set_state(db, requested=True)
    _log(db, current_user, request, "tls.scan", "Asked for a scan of every TLS certificate")
    db.commit()
    return {"scan": _state(db)}


class ServiceIn(BaseModel):
    asset_id: int
    port: int = Field(..., ge=1, le=65535)
    host: Optional[str] = Field(None, max_length=253)
    server_name: Optional[str] = Field(None, max_length=253)

    @field_validator("host", "server_name")
    @classmethod
    def _name(cls, v):
        v = (v or "").strip()
        if v and not _host_ok(v):
            raise ValueError("Not a host name or address")
        return v or None


@router.post("/services", status_code=201)
def add_service(body: ServiceIn, request: Request, current_user: User = Depends(require_permission("cve", "write")),
                db: Session = Depends(get_db)):
    """A TLS service the automatic scan does not find (another port, a name of its own): read at once."""
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    host = body.host or (asset.ip_address or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="The asset has no address: enter the host")
    if db.query(TlsEndpoint).filter(TlsEndpoint.asset_id == asset.id, TlsEndpoint.host == host,
                                    TlsEndpoint.port == body.port).first():
        raise HTTPException(status_code=409, detail="This TLS service is already listed")
    ep = TlsEndpoint(asset_id=asset.id, host=host, port=body.port, server_name=body.server_name,
                     source=SOURCE_MANUAL, created_by=current_user.id, first_seen_at=datetime.utcnow())
    db.add(ep)
    db.flush()
    what, name = S.where(ep), asset.asset_name
    _log(db, current_user, request, "tls.service_add", f"Added the TLS service {what} of {name}", ep.id)
    db.commit()
    S.run_scan(db, endpoint_ids=[ep.id])
    rows = [r for r in S.evaluate(db, [asset.id], include_disabled=True) if r["endpoint"].id == ep.id]
    return S.out(rows[0])


class ServicePatch(BaseModel):
    enabled: Optional[bool] = None
    server_name: Optional[str] = Field(None, max_length=253)

    @field_validator("server_name")
    @classmethod
    def _name(cls, v):
        v = (v or "").strip()
        if v and not _host_ok(v):
            raise ValueError("Not a host name or address")
        return v


@router.patch("/services/{service_id}")
def change_service(service_id: int, body: ServicePatch, request: Request,
                   current_user: User = Depends(require_permission("cve", "write")), db: Session = Depends(get_db)):
    """Turn a service off (not scanned, no findings: e.g. it is not the organisation's) or on, or set the
    name sent and checked."""
    ep = db.get(TlsEndpoint, service_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="TLS service not found")
    asset = db.get(Asset, ep.asset_id)
    name = asset.asset_name if asset else "-"
    if body.enabled is not None and body.enabled != ep.enabled:
        ep.enabled = body.enabled
        what = S.where(ep)
        _log(db, current_user, request, "tls.service_toggle",
             f"Turned {'on' if body.enabled else 'off'} the TLS service {what} of {name}", ep.id)
    if body.server_name is not None and (body.server_name or None) != ep.server_name:
        ep.server_name = body.server_name or None
        what = S.where(ep)
        _log(db, current_user, request, "tls.service_name", f"Changed the server name of the TLS service {what} of {name}",
             ep.id)
    db.commit()
    rows = [r for r in S.evaluate(db, [ep.asset_id], include_disabled=True) if r["endpoint"].id == ep.id]
    return S.out(rows[0]) if rows else {"id": ep.id}


@router.delete("/services/{service_id}")
def delete_service(service_id: int, request: Request, current_user: User = Depends(require_permission("cve", "delete")),
                   db: Session = Depends(get_db)):
    ep = db.get(TlsEndpoint, service_id)
    if ep is None:
        raise HTTPException(status_code=404, detail="TLS service not found")
    if ep.source != SOURCE_MANUAL:
        raise HTTPException(status_code=400, detail="A service the scan found comes back with the next scan: turn it off instead")
    asset = db.get(Asset, ep.asset_id)
    what, name = S.where(ep), asset.asset_name if asset else "-"
    db.delete(ep)
    _log(db, current_user, request, "tls.service_delete", f"Removed the TLS service {what} of {name}", service_id)
    db.commit()
    return {"ok": True}


# ── settings ─────────────────────────────────────────────────────────────

class SettingsIn(BaseModel):
    warn_days: int = Field(..., ge=7, le=180)
    auto_scan: bool
    interval_hours: int = Field(..., ge=6, le=168)
    check_protocols: bool
    ports: List[int] = Field(..., min_length=1, max_length=S.MAX_PORTS)

    @field_validator("ports")
    @classmethod
    def _ports(cls, v):
        if any(p < 1 or p > 65535 for p in v):
            raise ValueError("A port is between 1 and 65535")
        return v


@router.get("/settings")
def get_settings(current_user: User = Depends(require_permission("cve", "read")), db: Session = Depends(get_db)):
    return S.get_settings(db)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, current_user: User = Depends(require_permission("cve", "read")),
                 db: Session = Depends(get_db)):
    _admin(current_user)
    saved = S.save_settings(db, body.model_dump(), current_user.id)
    ports = ", ".join(str(p) for p in saved["ports"])
    days, hours = saved["warn_days"], saved["interval_hours"]
    if saved["auto_scan"]:
        _log(db, current_user, request, "tls.settings",
             f"Automatic TLS scan every {hours} h on ports {ports}; warns {days} days before expiry")
    else:
        _log(db, current_user, request, "tls.settings",
             f"Automatic TLS scan off; ports {ports}; warns {days} days before expiry")
    db.commit()
    return saved


# ── the organisation's certificate authorities ───────────────────────────

class CaIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    pem: str = Field(..., min_length=50, max_length=20000)


def _ca_out(c: TlsTrustedCa) -> dict:
    return {"id": c.id, "name": c.name, "subject": c.subject, "fingerprint": c.fingerprint,
            "not_after": c.not_after.isoformat() if c.not_after else None,
            "created_at": c.created_at.isoformat() if c.created_at else None}


@router.get("/cas")
def list_cas(current_user: User = Depends(require_permission("cve", "read")), db: Session = Depends(get_db)):
    return [_ca_out(c) for c in db.query(TlsTrustedCa).order_by(TlsTrustedCa.name)]


@router.post("/cas", status_code=201)
def add_ca(body: CaIn, request: Request, current_user: User = Depends(require_permission("cve", "read")),
           db: Session = Depends(get_db)):
    """A certificate authority of the organisation (PEM): what it issued counts as trusted from the next scan."""
    _admin(current_user)
    try:
        ca = scanner.parse_ca(body.pem)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if db.query(TlsTrustedCa).filter(TlsTrustedCa.fingerprint == ca["fingerprint"]).first():
        raise HTTPException(status_code=409, detail="This certificate authority is already trusted")
    row = TlsTrustedCa(name=body.name.strip(), created_by=current_user.id, **ca)
    db.add(row)
    db.flush()
    name = row.name
    _log(db, current_user, request, "tls.ca_add", f"Trusted the certificate authority {name}", row.id)
    db.commit()
    return _ca_out(row)


@router.delete("/cas/{ca_id}")
def delete_ca(ca_id: int, request: Request, current_user: User = Depends(require_permission("cve", "read")),
              db: Session = Depends(get_db)):
    _admin(current_user)
    row = db.get(TlsTrustedCa, ca_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate authority not found")
    name = row.name
    db.delete(row)
    _log(db, current_user, request, "tls.ca_delete", f"No longer trusts the certificate authority {name}", ca_id)
    db.commit()
    return {"ok": True}
