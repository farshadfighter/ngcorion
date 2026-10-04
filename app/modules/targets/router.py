"""
GET /api/targets/catalog - what the Auditing and Hardening forms can run
against, grouped by category, with how many assets of each the inventory
holds (so the picker can show "In my inventory" first).
"""
from collections import Counter
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.core.target_catalog import CATEGORIES, MODES, targets_for
from app.models import Asset, User
from app.utils.device_classification import WINDOWS_ROLE_FAMILIES, infer_device_family, infer_device_variant

router = APIRouter(prefix="/api/targets", tags=["Targets"])


class CatalogVersion(BaseModel):
    device_type: str
    label: str
    group: Optional[str] = None
    asset_count: int


class CatalogTarget(BaseModel):
    id: str
    label: str
    description: str
    category: str
    family: str
    icon: str
    monogram: str
    connects_via: str
    device_type: Optional[str] = None
    versions: List[CatalogVersion]
    keywords: List[str]
    asset_count: int


class CatalogCategory(BaseModel):
    id: str
    label: str


class Catalog(BaseModel):
    mode: str
    categories: List[CatalogCategory]
    targets: List[CatalogTarget]


@router.get("/catalog", response_model=Catalog)
def get_catalog(
    mode: str = Query("audit", description="audit | hardening"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if mode not in MODES:
        raise HTTPException(status_code=400, detail="mode must be 'audit' or 'hardening'")
    # Same gate as the form that shows the picker (raises 403 otherwise).
    require_permission("AUDITING" if mode == "audit" else "HARDENING", "read")(current_user=current_user, db=db)

    families, variants = Counter(), Counter()
    for asset in db.query(Asset).options(joinedload(Asset.asset_type)).all():
        family = infer_device_family(asset)
        families[family] += 1
        # A domain controller (or another Windows role) is a Windows Server too.
        if family in WINDOWS_ROLE_FAMILIES:
            families["windows"] += 1
        variants[infer_device_variant(asset)] += 1

    targets = targets_for(mode)
    return Catalog(
        mode=mode,
        categories=[CatalogCategory(id=c, label=label) for c, label in CATEGORIES
                    if any(t.category == c for t in targets)],
        targets=[
            CatalogTarget(
                id=t.id, label=t.label, description=t.description, category=t.category, family=t.family,
                icon=t.icon, monogram=t.monogram, connects_via=t.connects_via, device_type=t.device_type,
                versions=[CatalogVersion(device_type=v.device_type, label=v.label, group=v.group,
                                         asset_count=variants[v.device_type]) for v in t.versions],
                keywords=list(t.keywords),
                asset_count=families[t.family],
            )
            for t in targets
        ],
    )
