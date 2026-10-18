"""
API of end of life (app/modules/eol), under /api/eol.

Reading needs the asset list read permission (the page sits with the software inventory); entering the end
of support of something on an asset needs asset list write; the catalog (update from endoflife.date,
import a file, the organisation's own products) and the warning period are for administrators. Every
change is in the audit trail.
"""
import re
from collections import defaultdict
from datetime import date, datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, UserRole
from app.models.asset import Asset
from app.models.eol import SOURCE_CUSTOM, SOURCE_IMPORT, SOURCE_ONLINE, EolAssetEntry, EolProduct
from app.modules.eol import catalog as C
from app.modules.eol import service as S

router = APIRouter(prefix="/api/eol", tags=["End of life"])

MAX_FILE = 5 * 1024 * 1024


def _role(user: User) -> str:
    return user.role.value if hasattr(user.role, "value") else str(user.role)


def _admin(user: User) -> None:
    if _role(user) != UserRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Only administrators can change the end-of-life catalog")


def _ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _log(db: Session, user: User, request: Request, action: str, detail: str, target_id: Optional[int] = None):
    from app.models.security_audit_log import log_action
    log_action(db, user_id=user.id, username=user.username, action=action, module="asset_list",
               target_id=target_id, ip_address=_ip(request), detail=detail)


def _assets(db: Session, ids) -> Dict[int, Asset]:
    ids = list(ids)
    return {a.id: a for a in db.query(Asset).filter(Asset.id.in_(ids))} if ids else {}


# ── reading ──────────────────────────────────────────────────────────────

@router.get("/overview")
def overview(current_user: User = Depends(require_permission("asset_list", "read")),
             db: Session = Depends(get_db)):
    """The fleet: how many assets are in each status, each release cycle found with its assets, and the
    names the catalog does not know."""
    comps = S.components(db)
    assets = _assets(db, {c.asset_id for c in comps})
    comps = [c for c in comps if c.asset_id in assets]
    groups: Dict[str, Dict] = {}
    unknown = defaultdict(lambda: {"assets": set(), "versions": set()})
    for c in comps:
        if c.status == "unknown":
            u = unknown[(c.name, c.product_name)]
            u["assets"].add(c.asset_id)
            if c.version:
                u["versions"].add(c.version)
            continue
        g = groups.setdefault(c.key, {"key": c.key, "product": c.product, "product_name": c.product_name or c.name,
                                      "cycle": c.cycle, "cycle_label": c.cycle_label, "title": c.title, "status": c.status,
                                      "until": c.until, "ended_on": c.ended_on, "extended_until": c.extended_until,
                                      "security_only": c.security_only, "latest": c.latest,
                                      "manual": c.origin == "manual", "assets": []})
        g["assets"].append({"id": c.asset_id, "name": assets[c.asset_id].asset_name,
                            "ip": assets[c.asset_id].ip_address, "version": c.version, "entry_id": c.entry_id})
    rows = sorted(groups.values(), key=lambda g: (S.ORDER[g["status"]], g["until"] or "9999", g["product_name"]))
    settings = S.get_settings(db)
    return {"summary": S.summary(comps), "groups": rows, "warn_days": settings["warn_days"],
            "unknown": sorted(({"name": n, "product_name": p, "assets": len(v["assets"]),
                                "versions": sorted(v["versions"])[:10]} for (n, p), v in unknown.items()),
                              key=lambda x: -x["assets"]),
            "catalog_date": C.builtin()["generated"]}


@router.get("/assets/{asset_id}")
def asset_components(asset_id: int, current_user: User = Depends(require_permission("asset_list", "read")),
                     db: Session = Depends(get_db)):
    """Every component of one asset with its end-of-life status, the worst first."""
    if db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    comps = S.by_asset(S.components(db, [asset_id])).get(asset_id, [])
    return {"status": S.worst(comps), "components": [c.out() for c in comps]}


@router.get("/catalog")
def catalog(current_user: User = Depends(require_permission("asset_list", "read")), db: Session = Depends(get_db)):
    products, _ = C.load(db)
    custom = {r.key: r.match_names or [] for r in db.query(EolProduct).filter(EolProduct.source == SOURCE_CUSTOM)}
    return {"generated": C.builtin()["generated"], "source": C.builtin()["source"],
            "products": [{"key": p["key"], "name": p["name"], "source": p["source"], "link": p.get("link"),
                          "updated_at": p.get("updated_at"), "cycles": len(p["cycles"]),
                          "match_names": custom.get(p["key"])}
                         for p in sorted(products.values(), key=lambda p: p["name"].lower())]}


@router.get("/catalog/export")
def export_catalog(current_user: User = Depends(require_permission("asset_list", "read")),
                   db: Session = Depends(get_db)):
    """The catalog as this installation uses it, in the format of the built-in file (to import elsewhere)."""
    products, _ = C.load(db)
    return {"source": "NGCorion export", "generated": date.today().isoformat(),
            "products": [{k: p.get(k) for k in ("key", "name", "link", "cycles")} for p in products.values()
                         if p["source"] != SOURCE_CUSTOM]}


@router.get("/catalog/{key}")
def catalog_product(key: str, current_user: User = Depends(require_permission("asset_list", "read")),
                    db: Session = Depends(get_db)):
    products, _ = C.load(db)
    p = products.get(key)
    if p is None:
        raise HTTPException(status_code=404, detail="Product not found")
    today, warn = datetime.utcnow().date(), S.get_settings(db)["warn_days"]
    return {"key": p["key"], "name": p["name"], "source": p["source"], "link": p.get("link"),
            "cycles": [{**c, **S.status_of(c, today, warn)} for c in p["cycles"]]}


# ── the catalog ──────────────────────────────────────────────────────────

@router.post("/catalog/update")
def update_online(request: Request, current_user: User = Depends(require_permission("asset_list", "read")),
                  db: Session = Depends(get_db)):
    """Download every built-in product again from endoflife.date (needs internet access)."""
    _admin(current_user)
    got, failed = C.fetch_online()
    if not got:
        raise HTTPException(status_code=502, detail="endoflife.date could not be reached; import a file instead")
    n = C.store(db, got, SOURCE_ONLINE, current_user.id)
    _log(db, current_user, request, "eol.catalog_update",
         f"Updated {n} products of the end-of-life catalog from endoflife.date")
    db.commit()
    return {"updated": n, "failed": failed}


@router.post("/catalog/import")
async def import_catalog(request: Request, file: UploadFile = File(...),
                         current_user: User = Depends(require_permission("asset_list", "read")),
                         db: Session = Depends(get_db)):
    """Products from a file: NGCorion's export or an endoflife.date API answer."""
    _admin(current_user)
    raw = await file.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise HTTPException(status_code=413, detail="The file is larger than 5 MB")
    try:
        products = C.parse_file(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    n = C.store(db, products, SOURCE_IMPORT, current_user.id)
    _log(db, current_user, request, "eol.catalog_import", f"Imported {n} products into the end-of-life catalog")
    db.commit()
    return {"imported": n, "skipped": len(products) - n}


@router.delete("/catalog/{key}")
def reset_product(key: str, request: Request, current_user: User = Depends(require_permission("asset_list", "read")),
                  db: Session = Depends(get_db)):
    """Forget a downloaded or imported product (the built-in one applies again) or delete one of the
    organisation's own."""
    _admin(current_user)
    row = db.query(EolProduct).filter(EolProduct.key == key).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Only a downloaded, imported or own product can be removed")
    name = row.name
    db.delete(row)
    _log(db, current_user, request, "eol.catalog_reset", f"Removed {name} from the end-of-life catalog changes")
    db.commit()
    return {"ok": True}


class CycleIn(BaseModel):
    cycle: str = Field(..., min_length=1, max_length=40)
    label: Optional[str] = Field(None, max_length=80)
    security_until: date
    extended_until: Optional[date] = None


class CustomIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    match_names: List[str] = Field(..., min_length=1, max_length=20)
    cycles: List[CycleIn] = Field(..., min_length=1, max_length=100)

    @field_validator("match_names")
    @classmethod
    def _names(cls, v):
        v = [x.strip() for x in v if x and x.strip()]
        if not v or any(len(x) > 200 for x in v):
            raise ValueError("Give the software names the product is found under")
        return v


def _custom_cycles(body: CustomIn) -> List[dict]:
    ids = [c.cycle.strip() for c in body.cycles]
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=400, detail="Two release cycles have the same name")
    return [{"cycle": c.cycle.strip(), "label": (c.label or c.cycle).strip(), "release": None, "active_until": None,
             "security_until": c.security_until.isoformat(),
             "extended_until": c.extended_until.isoformat() if c.extended_until else None,
             "lts": False, "latest": None} for c in body.cycles]


@router.post("/catalog/custom", status_code=201)
def add_custom(body: CustomIn, request: Request, current_user: User = Depends(require_permission("asset_list", "read")),
               db: Session = Depends(get_db)):
    """A product endoflife.date does not track (a firmware, an appliance), recognised by its software names."""
    _admin(current_user)
    key = "custom-" + (re.sub(r"[^a-z0-9]+", "-", body.name.lower()).strip("-")[:40] or "product")
    if db.query(EolProduct).filter(EolProduct.key == key).first() or key in {p["key"] for p in C.builtin()["products"]}:
        raise HTTPException(status_code=409, detail="A product with this name already exists")
    row = EolProduct(key=key, name=body.name.strip(), source=SOURCE_CUSTOM, match_names=body.match_names,
                     cycles=_custom_cycles(body), updated_by=current_user.id, updated_at=datetime.utcnow())
    db.add(row)
    db.flush()
    _log(db, current_user, request, "eol.custom_product", f"Added the product {row.name} to the end-of-life catalog",
         row.id)
    db.commit()
    return {"key": key}


@router.put("/catalog/custom/{key}")
def update_custom(key: str, body: CustomIn, request: Request,
                  current_user: User = Depends(require_permission("asset_list", "read")), db: Session = Depends(get_db)):
    _admin(current_user)
    row = db.query(EolProduct).filter(EolProduct.key == key, EolProduct.source == SOURCE_CUSTOM).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Product not found")
    row.name, row.match_names, row.cycles = body.name.strip(), body.match_names, _custom_cycles(body)
    row.updated_by, row.updated_at = current_user.id, datetime.utcnow()
    _log(db, current_user, request, "eol.custom_product", f"Changed the product {row.name} of the end-of-life catalog",
         row.id)
    db.commit()
    return {"ok": True}


# ── entered by hand ──────────────────────────────────────────────────────

class EntryIn(BaseModel):
    asset_id: int
    name: str = Field(..., min_length=2, max_length=200)
    version: Optional[str] = Field(None, max_length=80)
    support_until: date
    note: Optional[str] = Field(None, max_length=2000)


@router.post("/entries", status_code=201)
def add_entry(body: EntryIn, request: Request, current_user: User = Depends(require_permission("asset_list", "write")),
              db: Session = Depends(get_db)):
    """The end of support of something on an asset the inventory does not see."""
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    e = EolAssetEntry(asset_id=asset.id, name=body.name.strip(), version=(body.version or "").strip() or None,
                      support_until=body.support_until, note=(body.note or "").strip() or None,
                      created_by=current_user.id)
    db.add(e)
    db.flush()
    name, asset_name = e.name, asset.asset_name
    _log(db, current_user, request, "eol.entry_add",
         f"Entered the end of support of {name} on {asset_name}", e.id)
    db.commit()
    return {"id": e.id}


@router.delete("/entries/{entry_id}")
def delete_entry(entry_id: int, request: Request, current_user: User = Depends(require_permission("asset_list", "write")),
                 db: Session = Depends(get_db)):
    e = db.get(EolAssetEntry, entry_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Entry not found")
    asset = db.get(Asset, e.asset_id)
    name, asset_name = e.name, asset.asset_name if asset else "-"
    db.delete(e)
    _log(db, current_user, request, "eol.entry_delete",
         f"Removed the end of support of {name} on {asset_name}", entry_id)
    db.commit()
    return {"ok": True}


# ── settings ─────────────────────────────────────────────────────────────

class SettingsIn(BaseModel):
    warn_days: int = Field(..., ge=30, le=730)


@router.get("/settings")
def get_settings(current_user: User = Depends(require_permission("asset_list", "read")), db: Session = Depends(get_db)):
    return S.get_settings(db)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, current_user: User = Depends(require_permission("asset_list", "read")),
                 db: Session = Depends(get_db)):
    _admin(current_user)
    days = body.warn_days
    _log(db, current_user, request, "eol.settings", f"End of support warns {days} days ahead")
    return S.save_settings(db, {"warn_days": days}, current_user.id)

