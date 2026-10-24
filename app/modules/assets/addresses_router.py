"""
Other addresses of an asset: GET/POST /api/assets/{id}/addresses, DELETE /api/assets/{id}/addresses/{address_id}.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import Asset, User, log_action
from app.models.asset_address import AssetAddress
from app.modules.assets import addresses

router = APIRouter(prefix="/api/assets", tags=["Asset addresses"])


class AddressIn(BaseModel):
    """An address the asset also sends from, and what it is."""
    address: str = Field(..., min_length=2, max_length=64)
    note: Optional[str] = Field(None, max_length=120)


def _asset(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/{asset_id}/addresses")
def list_addresses(asset_id: int, _: User = Depends(require_permission("asset_list", "read")),
                   db: Session = Depends(get_db)):
    """The asset's other addresses (syslog from them is the asset's)."""
    _asset(db, asset_id)
    return [addresses.as_dict(r) for r in addresses.list_for(db, asset_id)]


@router.post("/{asset_id}/addresses")
def add_address(asset_id: int, body: AddressIn, request: Request,
                user: User = Depends(require_permission("asset_list", "write")), db: Session = Depends(get_db)):
    """Add an address the asset also sends from; syslog from it is the asset's within a minute."""
    asset = _asset(db, asset_id)
    try:
        row = addresses.add(db, asset, body.address, body.note, user.id)
    except addresses.AddressError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    address = row.address
    log_action(db, user_id=user.id, username=user.username, action="asset.address_added", module="asset_list",
               target_id=asset.id, ip_address=request.client.host if request.client else None,
               detail=f"Address {address} added to {asset.asset_name}")
    return addresses.as_dict(row)


@router.delete("/{asset_id}/addresses/{address_id}", status_code=204)
def remove_address(asset_id: int, address_id: int, request: Request,
                   user: User = Depends(require_permission("asset_list", "write")), db: Session = Depends(get_db)):
    """Remove one of the asset's other addresses."""
    asset = _asset(db, asset_id)
    row = db.query(AssetAddress).filter(AssetAddress.id == address_id, AssetAddress.asset_id == asset_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Address not found")
    address = row.address
    db.delete(row)
    db.commit()
    log_action(db, user_id=user.id, username=user.username, action="asset.address_removed", module="asset_list",
               target_id=asset.id, ip_address=request.client.host if request.client else None,
               detail=f"Address {address} removed from {asset.asset_name}")
