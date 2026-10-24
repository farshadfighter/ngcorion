"""
Other addresses of an asset (app/models/asset_address.py): listing, adding and removing them, and the
address -> asset map syslog matches senders with.
"""
import ipaddress
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import Asset
from app.models.asset_address import AssetAddress


class AddressError(ValueError):
    """An address that cannot be added, with the reason the person can act on."""


def normalize(value: Optional[str]) -> Optional[str]:
    """"10.0.0.5", " 10.0.0.5 ", "::ffff:10.0.0.5" -> "10.0.0.5"; None when not an address."""
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip().split("%")[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def as_dict(row: AssetAddress) -> Dict:
    return {"id": row.id, "asset_id": row.asset_id, "address": row.address, "note": row.note,
            "created_at": row.created_at.isoformat() if row.created_at else None}


def list_for(db: Session, asset_id: int) -> List[AssetAddress]:
    return db.query(AssetAddress).filter(AssetAddress.asset_id == asset_id).order_by(AssetAddress.id).all()


def add(db: Session, asset: Asset, address: str, note: Optional[str], user_id: Optional[int]) -> AssetAddress:
    """Add an address to the asset; refused when it is not an IP address, is the asset's own inventory
    address, or already belongs to another asset."""
    norm = normalize(address)
    if norm is None:
        raise AddressError("Enter an IPv4 or IPv6 address")
    if normalize(asset.ip_address) == norm:
        raise AddressError("This is the asset's own IP address")
    taken = db.query(AssetAddress).filter(AssetAddress.address == norm).first()
    if taken is not None:
        owner = db.get(Asset, taken.asset_id)
        raise AddressError(f"{norm} is already an address of {owner.asset_name if owner else 'another asset'}")
    for other_id, other_name, other_ip in db.query(Asset.id, Asset.asset_name, Asset.ip_address) \
            .filter(Asset.ip_address.isnot(None), Asset.id != asset.id):
        if normalize(other_ip) == norm:
            raise AddressError(f"{norm} is the IP address of {other_name}")
    row = AssetAddress(asset_id=asset.id, address=norm, note=(note or "").strip()[:120] or None, created_by=user_id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def address_map(db: Session) -> Dict[str, int]:
    """address -> asset id of every other address (the inventory addresses are mapped by the caller and win)."""
    return {address: asset_id for address, asset_id in db.query(AssetAddress.address, AssetAddress.asset_id)}
