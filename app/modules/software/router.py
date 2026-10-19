"""
Software inventory API.

  GET  /api/software/products              the fleet's products (asset_list read)
  GET  /api/software/products/assets       which assets run one product
  GET  /api/software/products/export       the same list as an Excel workbook
  GET  /api/software/assets                what each asset has, one line per asset
  GET  /api/software/assets/{id}           one asset's installed software
  GET  /api/software/assets/{id}/changes   what changed between its collections
  POST /api/software/assets/{id}/collect   collect now with credentials used once
                                           and never stored (asset_list write)
  GET  /api/software/maps, /suggest        admin answers for unknown products
  PUT  /api/software/maps, DELETE .../{id} (admin or manager)
"""
import logging
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin_or_manager, require_permission
from app.models import Asset, User
from app.models.security_audit_log import log_action
from app.models.software import SoftwareProductMap
from app.modules.software import export, hooks, service
from app.modules.software.service import SoftwareError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/software", tags=["Software inventory"])

_read = require_permission("asset_list", "read")
_write = require_permission("asset_list", "write")


def _fail(e: SoftwareError):
    return HTTPException(status_code=e.status, detail=str(e))


def _log(db: Session, user: User, action: str, detail: str, target_id=None, result: str = "success"):
    log_action(db, user_id=user.id, username=user.username, action=action, module="software",
               target_id=target_id, result=result, detail=detail)


def _refresh_risk(db: Session, asset_id: int) -> None:
    """New software can bring new vulnerabilities, so a new risk score."""
    try:
        from app.modules.risk.service import risk_calculation_service
        risk_calculation_service.calculate(asset_id=asset_id, db=db, trigger_type="software_collected")
    except Exception:  # noqa: BLE001 - never fail the collection over the score
        logger.exception("[software] risk recalculation for asset %s failed", asset_id)
        db.rollback()


# ── the fleet ─────────────────────────────────────────────────────────────

@router.get("/products")
def get_products(db: Session = Depends(get_db), _: User = Depends(_read)):
    return service.products(db)


@router.get("/products/assets")
def get_product_assets(key: str = Query(..., max_length=300), status: str = Query(..., max_length=12),
                       label: Optional[str] = Query(None, max_length=300),
                       db: Session = Depends(get_db), _: User = Depends(_read)):
    return service.product_assets(db, key, status, label)


@router.get("/products/export")
def export_products(lang: Literal["fa", "en"] = "en", db: Session = Depends(get_db),
                    user: User = Depends(_read)):
    """Download the software products list as Excel."""
    data = service.products(db)
    stream = export.products_workbook(data, lang)
    _log(db, user, "software.export", f"Exported {len(data['items'])} software products")
    name = f"software_{datetime.now():%Y%m%d_%H%M}.xlsx"
    return StreamingResponse(stream, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             headers={"Content-Disposition": f"attachment; filename={name}"})


# ── per asset ─────────────────────────────────────────────────────────────

@router.get("/assets")
def get_assets_overview(db: Session = Depends(get_db), _: User = Depends(_read)):
    return service.assets_overview(db)


@router.get("/assets/{asset_id}")
def get_asset_inventory(asset_id: int, db: Session = Depends(get_db), _: User = Depends(_read)):
    """The software installed on one asset, with identification and CVE counts."""
    try:
        return service.asset_inventory(db, asset_id)
    except SoftwareError as e:
        raise _fail(e)


@router.get("/assets/{asset_id}/updates")
def get_asset_updates(asset_id: int, db: Session = Depends(get_db), _: User = Depends(_read)):
    """The distribution's security updates this asset is missing."""
    from app.models import Asset
    from app.modules.advisories.service import security_updates
    if db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return security_updates(db, asset_id)


@router.get("/assets/{asset_id}/changes")
def get_asset_changes(asset_id: int, collection_id: Optional[int] = None, db: Session = Depends(get_db),
                      _: User = Depends(_read)):
    """What was installed, removed or updated on an asset, per collection."""
    if db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return service.changes(db, asset_id, collection_id)


class CollectIn(BaseModel):
    """Body of collecting now: platform and credentials, used for this request only and never stored.
    """
    platform: Literal["linux", "windows"]
    username: str = Field(..., min_length=1, max_length=200)
    password: str = Field(..., min_length=1, max_length=500)
    port: Optional[int] = Field(None, ge=1, le=65535)
    sudo_password: Optional[str] = Field(None, max_length=500)
    transport: Literal["ntlm", "kerberos", "basic", "credssp"] = "ntlm"


def _winrm_reason(text: str) -> str:
    """Why WinRM did not answer, in words the person can act on."""
    low = text.lower()
    if "refused" in low:
        return "the connection was refused (WinRM is not enabled on this port, or a firewall blocks it)"
    if "timed out" in low or "timeout" in low:
        return "no answer in time (check the address, the port and the firewall)"
    if "ssl" in low or "certificate" in low:
        return "the HTTPS certificate was not accepted (use port 5985 for HTTP, or a trusted certificate)"
    if "name or service not known" in low or "resolve" in low or "getaddrinfo" in low:
        return "the address could not be resolved"
    return " ".join(text.split())[-200:]


def _connect_error(exc: Exception, platform: str, address: str) -> HTTPException:
    """A collection problem as the reason the person can act on: credentials refused, the asset not
    answering (and why), or connected but the list could not be read. Never 401: that is the app's own
    session expiring."""
    from app.core.ssh_exceptions import SSHAuthenticationError, SSHConnectionError
    if isinstance(exc, (SSHAuthenticationError, PermissionError)):    # PermissionError: WinRM refused the login
        return HTTPException(status_code=400, detail="The username or password was not accepted")
    if isinstance(exc, SSHConnectionError):
        status = exc.http_status if exc.http_status != 401 else 400
        return HTTPException(status_code=status, detail=exc.message)
    text = str(exc)
    if "401" in text or "credentials were rejected" in text.lower():
        return HTTPException(status_code=400, detail="The username or password was not accepted")
    if platform == "windows" and isinstance(exc, ConnectionError):
        return HTTPException(status_code=502, detail=f"WinRM on {address} did not answer: {_winrm_reason(text)}")
    # The SSH and WinRM clients map every failure to connect above; anything else came after it.
    reason = " ".join(f"{type(exc).__name__}: {text}".split())[:200]
    return HTTPException(status_code=502, detail=f"Connected to {address}, but reading the software list failed: {reason}")


@router.post("/assets/{asset_id}/collect")
async def collect_now(asset_id: int, body: CollectIn, db: Session = Depends(get_db), user: User = Depends(_write)):
    """Collect an asset's installed software now over SSH or WinRM (runs in a worker thread so the
    server stays responsive).
    """
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip_address:
        raise HTTPException(status_code=400, detail="The asset has no IP address")
    try:
        if body.platform == "linux":
            col = await run_in_threadpool(hooks.collect_now_linux, db, asset, username=body.username,
                                          password=body.password, port=body.port or 22,
                                          sudo_password=body.sudo_password or None, user_id=user.id)
        else:
            col = await run_in_threadpool(hooks.collect_now_windows, db, asset, username=body.username,
                                          password=body.password, port=body.port or 5985,
                                          transport=body.transport, user_id=user.id)
    except Exception as exc:  # noqa: BLE001 - reported as the reason the person can act on
        # The exception, not the credentials: neither client puts the password in its messages.
        logger.warning("[software] collect-now on asset %s (%s, %s) failed", asset_id, body.platform,
                       asset.ip_address, exc_info=True)
        error = _connect_error(exc, body.platform, f"{asset.ip_address}:{body.port or (22 if body.platform == 'linux' else 5985)}")
        reason = error.detail[:200]
        _log(db, user, "software.collect", f"Software collection on {asset.asset_name} ({asset.ip_address}) "
                                           f"failed: {reason}", target_id=asset_id, result="failed")
        raise error
    if col is None or col.status != "ok":
        reason = (col.error if col is not None else None) or "Nothing could be collected"
        _log(db, user, "software.collect", f"Software collection on {asset.asset_name} failed: {reason[:200]}",
             target_id=asset_id, result="failed")
        raise HTTPException(status_code=422, detail=reason)
    _log(db, user, "software.collect",
         f"Collected {col.item_count} items from {asset.asset_name} ({asset.ip_address}) over {body.platform}",
         target_id=asset_id)
    _refresh_risk(db, asset_id)
    return {"collection": service._collection(col)}


# ── identifying products ──────────────────────────────────────────────────

class MapIn(BaseModel):
    """Body of identifying a product: either a CPE vendor/product or "internal" (not in NVD)."""
    match_key: str = Field(..., min_length=1, max_length=300)
    status: Literal["cpe", "internal"]
    vendor: Optional[str] = Field(None, max_length=120)
    product: Optional[str] = Field(None, max_length=160)
    label: Optional[str] = Field(None, max_length=200)


@router.get("/maps")
def get_maps(db: Session = Depends(get_db), _: User = Depends(_read)):
    return service.maps_list(db)


@router.get("/suggest")
def get_suggestions(q: str = Query(..., min_length=1, max_length=200), db: Session = Depends(get_db),
                    _: User = Depends(require_admin_or_manager)):
    return service.suggest(db, q)


@router.put("/maps")
def put_map(body: MapIn, db: Session = Depends(get_db), user: User = Depends(require_admin_or_manager)):
    """Save how a product is identified (admin or manager); findings follow on the next matching."""
    try:
        row = service.save_map(db, body.match_key, body.status, body.vendor, body.product, body.label, user.id)
    except SoftwareError as e:
        raise _fail(e)
    what = f"{row.vendor}:{row.product}" if row.status == "cpe" else "internal, not in NVD"
    _log(db, user, "software.map", f"Identified '{row.match_key}' as {what}", target_id=row.id)
    return {"id": row.id, "match_key": row.match_key, "status": row.status, "vendor": row.vendor,
            "product": row.product, "label": row.label}


@router.delete("/maps/{map_id}")
def delete_map(map_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin_or_manager)):
    """Remove an administrator's identification; the built-in catalog applies again."""
    row = db.get(SoftwareProductMap, map_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Mapping not found")
    key = row.match_key
    db.delete(row)
    db.commit()
    _log(db, user, "software.unmap", f"Removed the identification of '{key}'", target_id=map_id)
    return {"ok": True}
