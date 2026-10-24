"""
Asset Service - Complete CRUD operations
"""
import logging
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query
from typing import Optional
from math import ceil
from app.models import (
    AssetType, Asset, AssetOwner, AssetLocation,
    OSCatalog, VendorCatalog,
    AssetDependency, AssetSecurityStatus
)
from app.core.asset_entitlement import check_asset_capacity
from app.models.asset_zone import find_zone
from app.models.risk import RiskZone
from app.modules.assets.change_history import FIELD_META, compute_field_changes
from .schemas import AssetTypeCreate
from .hosting import requires_hosting

logger = logging.getLogger(__name__)


def _validate_zone(db: Session, name) -> None:
    """A zone typed in must be one of the network zones (Asset Requirements, Network Zones)."""
    if name and str(name).strip() and find_zone(db, name) is None:
        raise ValueError(f"{name} is not a network zone")


def _rescore(db: Session, asset_id: int, trigger: str) -> None:
    """Recalculate an asset's risk score; never fails the change that asked for it."""
    try:
        from app.modules.risk.service import risk_calculation_service
        risk_calculation_service.calculate(asset_id=asset_id, db=db, trigger_type=trigger)
    except Exception as e:  # noqa: BLE001 - the score is recalculated on the next audit anyway
        db.rollback()
        logger.warning(f"[Risk] recalculation failed for asset {asset_id}: {e}")


def _validate_hosting(db: Session, asset_type_id: Optional[int], hosted_on_asset_id: Optional[int], asset_id: Optional[int] = None) -> None:
    """Raises ValueError if `asset_type_id` needs a hosting server (a virtual
    type, or VM/Application/Database by name) but `hosted_on_asset_id` isn't
    set, if the referenced host doesn't exist, if an asset is set to host
    itself, or if a virtual asset names another virtual asset: it runs on a
    physical server."""
    asset_type = (db.query(AssetType).filter(AssetType.id == asset_type_id).first()
                  if asset_type_id is not None else None)
    if hosted_on_asset_id is not None:
        if hosted_on_asset_id == asset_id:
            raise ValueError("An asset cannot be hosted on itself")
        host = db.query(Asset).filter(Asset.id == hosted_on_asset_id).first()
        if not host:
            raise ValueError(f"Host asset with id {hosted_on_asset_id} does not exist")
        if asset_type is not None and asset_type.is_virtual:
            host_type = db.query(AssetType).filter(AssetType.id == host.asset_type_id).first()
            if host_type is not None and host_type.is_virtual:
                raise ValueError(f"A virtual asset runs on a physical server: '{host.asset_name}' is virtual")
        return

    if asset_type and requires_hosting(asset_type.type_name, asset_type.is_virtual):
        raise ValueError(
            f"Asset type '{asset_type.type_name}' must specify which server "
            f"it's hosted on (hosted_on_asset_id)"
        )


class AssetInUseError(Exception):
    """An asset could not be deleted because another record still points at it.

    Distinct from "not found" so the router can answer 409 rather than 404 or a
    bare 500 — the caller needs to know the asset is still there.
    """


class AssetService:
    """Asset Management Service with complete CRUD operations"""

    # ==========================================
    # Helper Methods
    # ==========================================

    @staticmethod
    def paginate_query(query: Query, page: int = 1, page_size: int = 50):
        """
        Paginate a SQLAlchemy query

        Args:
            query: SQLAlchemy query object
            page: Page number (1-indexed)
            page_size: Number of items per page

        Returns:
            tuple: (items, total_count, total_pages)
        """
        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 50

        total_count = query.count()
        total_pages = ceil(total_count / page_size) if total_count > 0 else 1

        items = query.offset((page - 1) * page_size).limit(page_size).all()

        return items, total_count, total_pages

    # ==========================================
    # Asset Types
    # ==========================================
    
    @staticmethod
    def get_all_asset_types(db: Session):
        """Get all asset types"""
        return db.query(AssetType).all()
    
    @staticmethod
    def get_asset_type(db: Session, type_id: int):
        """Get asset type by id"""
        return db.query(AssetType).filter(AssetType.id == type_id).first()
    
    @staticmethod
    def create_asset_type(db: Session, data: AssetTypeCreate):
        """Create new asset type"""
        asset_type = AssetType(**data.model_dump())
        db.add(asset_type)
        db.commit()
        db.refresh(asset_type)
        return asset_type
    
    @staticmethod
    def update_asset_type(db: Session, type_id: int, data: dict):
        """Update asset type"""
        asset_type = db.query(AssetType).filter(AssetType.id == type_id).first()
        if asset_type:
            for key, value in data.items():
                if hasattr(asset_type, key):
                    setattr(asset_type, key, value)
            db.commit()
            db.refresh(asset_type)
        return asset_type

    @staticmethod
    def delete_asset_type(db: Session, type_id: int):
        """Delete asset type"""
        asset_type = db.query(AssetType).filter(AssetType.id == type_id).first()
        if asset_type:
            asset_count = db.query(Asset).filter(Asset.asset_type_id == type_id).count()
            if asset_count:
                raise ValueError(
                    f"Cannot delete asset type because it is used by {asset_count} asset(s)"
                )
            db.delete(asset_type)
            db.commit()
            return True
        return False
    
    # ==========================================
    # Assets
    # ==========================================
    
    @staticmethod
    def get_user_assets(db: Session, user_id: int):
        """Get all assets for a user - sorted by asset_name"""
        return db.query(Asset).filter(Asset.user_id == user_id).order_by(Asset.asset_name).all()
    
    @staticmethod
    def get_all_assets(db: Session):
        """Get all assets (admin only) - sorted by asset_name"""
        return db.query(Asset).order_by(Asset.asset_name).all()
    
    @staticmethod
    def get_asset(db: Session, asset_id: int):
        """Get asset by id"""
        return db.query(Asset).filter(Asset.id == asset_id).first()
    
    @staticmethod
    def create_asset(db: Session, data: dict):
        """Create new asset with optional security status"""
        # Extract security_status if present
        security_status_data = data.pop('security_status', None)

        _validate_hosting(db, data.get('asset_type_id'), data.get('hosted_on_asset_id'))
        _validate_zone(db, data.get('asset_role'))
        # The license covers a number of assets; refuse past it with a clear 403.
        check_asset_capacity(db)

        # Create asset
        asset = Asset(**data)
        db.add(asset)
        db.commit()
        db.refresh(asset)

        # Create security status if provided
        if security_status_data:
            security_status_data['asset_id'] = asset.id
            security_status = AssetSecurityStatus(**security_status_data)
            db.add(security_status)
            db.commit()

        # Risk recalculation trigger (give the new asset an initial risk score)
        try:
            from app.modules.risk.service import risk_calculation_service
            risk_calculation_service.calculate(
                asset_id=asset.id,
                db=db,
                trigger_type="asset_created",
            )
        except Exception as e:
            # Never block asset creation on a risk-scoring failure.
            logger.warning(
                f"[Risk] initial risk calculation failed for new asset "
                f"{asset.id}: {e}"
            )

        return asset
    
    @staticmethod
    def update_asset(db: Session, asset_id: int, data: dict):
        """Update asset with optional security status.

        Returns (asset, field_changes) - field_changes is a per-field diff
        (see app/modules/assets/change_history.py) for the caller to record
        as this update's AssetLog entry, powering the Change History view.
        """
        # Extract security_status if present
        security_status_data = data.pop('security_status', None)

        # Validate asset_type_id if provided
        if 'asset_type_id' in data and data['asset_type_id'] is not None:
            asset_type = db.query(AssetType).filter(AssetType.id == data['asset_type_id']).first()
            if not asset_type:
                raise ValueError(f"Asset type with id {data['asset_type_id']} does not exist")

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        field_changes = []
        if asset:
            # Values as they'll be *after* this update (a None in `data` is a
            # no-op below, same as every other field on this endpoint).
            effective_type_id = data.get('asset_type_id') or asset.asset_type_id
            effective_hosted_on = data.get('hosted_on_asset_id') or asset.hosted_on_asset_id
            _validate_hosting(db, effective_type_id, effective_hosted_on, asset_id=asset.id)
            _validate_zone(db, data.get('asset_role'))

            # Snapshot pre-update values for every field this request touches,
            # so they can be diffed against the post-update values below.
            old_values = {key: getattr(asset, key, None) for key in data if key in FIELD_META}

            # Update asset fields
            for key, value in data.items():
                # `icon` and the zone are the exceptions to "None is a no-op": an
                # explicit None puts the asset back on its type's automatic icon,
                # or out of any zone.
                if value is not None or key in ('icon', 'asset_role'):
                    setattr(asset, key, value)
            db.commit()
            db.refresh(asset)

            field_changes = compute_field_changes(db, asset, old_values)
            if any(c["field"] == "asset_role" for c in field_changes):
                _rescore(db, asset.id, "profile_updated")

            # Update or create security status if provided
            if security_status_data:
                existing_security = db.query(AssetSecurityStatus).filter(
                    AssetSecurityStatus.asset_id == asset_id
                ).first()

                if existing_security:
                    # Update existing security status
                    for key, value in security_status_data.items():
                        if hasattr(existing_security, key):
                            setattr(existing_security, key, value)
                else:
                    # Create new security status
                    security_status_data['asset_id'] = asset_id
                    new_security = AssetSecurityStatus(**security_status_data)
                    db.add(new_security)

                db.commit()

        return asset, field_changes

    @staticmethod
    def delete_asset(db: Session, asset_id: int):
        """Delete an asset and everything the database cascades with it.

        Every child FK is ON DELETE CASCADE or SET NULL and the ORM side is
        passive_deletes, so Postgres does the whole job in one statement. A row
        that still references the asset through some constraint added later
        would raise IntegrityError mid-transaction and leave the session
        unusable for the audit-log write that follows, so it is rolled back and
        reported instead of surfacing as an opaque 500.
        """
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            return False
        try:
            db.delete(asset)
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise AssetInUseError(
                f"Asset {asset_id} could not be deleted because other records "
                f"still reference it."
            ) from exc
        return True
    
    # ==========================================
    # Owners
    # ==========================================
    
    @staticmethod
    def get_all_owners(db: Session):
        """Get all owners (admin only)"""
        return db.query(AssetOwner).all()
    
    @staticmethod
    def get_user_owners(db: Session, user_id: int):
        """Get owners for a specific user"""
        return db.query(AssetOwner).filter(AssetOwner.user_id == user_id).all()
    
    @staticmethod
    def get_owner(db: Session, owner_id: int):
        """Get owner by id"""
        return db.query(AssetOwner).filter(AssetOwner.id == owner_id).first()
    
    @staticmethod
    def create_owner(db: Session, data: dict, user_id: int):
        """Create asset owner"""
        owner = AssetOwner(**data, user_id=user_id)
        db.add(owner)
        db.commit()
        db.refresh(owner)
        return owner
    
    @staticmethod
    def update_owner(db: Session, owner_id: int, data: dict):
        """Update owner"""
        owner = db.query(AssetOwner).filter(AssetOwner.id == owner_id).first()
        if owner:
            for key, value in data.items():
                if value is not None and hasattr(owner, key):
                    setattr(owner, key, value)
            db.commit()
            db.refresh(owner)
        return owner
    
    @staticmethod
    def delete_owner(db: Session, owner_id: int):
        """Delete owner"""
        owner = db.query(AssetOwner).filter(AssetOwner.id == owner_id).first()
        if owner:
            db.delete(owner)
            db.commit()
            return True
        return False
    
    # ==========================================
    # Locations
    # ==========================================
    
    @staticmethod
    def get_all_locations(db: Session):
        """Get all locations (admin only)"""
        return db.query(AssetLocation).all()
    
    @staticmethod
    def get_user_locations(db: Session, user_id: int):
        """Get locations for a specific user"""
        return db.query(AssetLocation).filter(AssetLocation.user_id == user_id).all()
    
    @staticmethod
    def get_location(db: Session, location_id: int):
        """Get location by id"""
        return db.query(AssetLocation).filter(AssetLocation.id == location_id).first()
    
    @staticmethod
    def create_location(db: Session, data: dict, user_id: int):
        """Create asset location"""
        location = AssetLocation(**data, user_id=user_id)
        db.add(location)
        db.commit()
        db.refresh(location)
        return location
    
    @staticmethod
    def update_location(db: Session, location_id: int, data: dict):
        """Update location"""
        location = db.query(AssetLocation).filter(AssetLocation.id == location_id).first()
        if location:
            for key, value in data.items():
                if value is not None and hasattr(location, key):
                    setattr(location, key, value)
            db.commit()
            db.refresh(location)
        return location
    
    @staticmethod
    def delete_location(db: Session, location_id: int):
        """Delete location"""
        location = db.query(AssetLocation).filter(AssetLocation.id == location_id).first()
        if location:
            db.delete(location)
            db.commit()
            return True
        return False

    # ==========================================
    # Network Zones: the one list (risk_zones, each with the exposure score the risk score uses;
    # app/models/asset_zone.py)
    # ==========================================

    @staticmethod
    def get_all_zones(db: Session):
        """Active network zones, least exposed first."""
        return (db.query(RiskZone).filter(RiskZone.status == "active")
                .order_by(RiskZone.score, RiskZone.name).all())

    @staticmethod
    def _zone_name_free(db: Session, name: str, zone_id: Optional[int] = None) -> None:
        clash = find_zone(db, name)
        if clash is not None and clash.id != zone_id:
            raise ValueError("Zone name already exists")

    @staticmethod
    def create_zone(db: Session, data: dict, user_id: Optional[int] = None):
        """A new zone; without a score it gets the score risk gives an asset with no zone."""
        from app.modules.risk.service import risk_calculation_service
        name = (data.get("zone_name") or "").strip()
        AssetService._zone_name_free(db, name)
        score = data.get("score")
        if score is None:
            score = risk_calculation_service._load_settings(db)["unknown_zone_score"]
        zone = RiskZone(name=name, description=data.get("description"), score=score, status="active",
                        place=data.get("place") or None, created_by=user_id, updated_by=user_id)
        db.add(zone)
        db.commit()
        db.refresh(zone)
        return zone

    @staticmethod
    def update_zone(db: Session, zone_id: int, data: dict, user_id: Optional[int] = None):
        """Change a zone; returns (zone, score_changed), (None, False) when there is none. Omitted
        values stay; a new name moves to the zone's assets (app/models/asset_zone.py)."""
        row = db.query(RiskZone).filter(RiskZone.id == zone_id).first()
        if row is None:
            return None, False
        name = (data.get("zone_name") or "").strip()
        if name:
            AssetService._zone_name_free(db, name, zone_id)
            row.name = name
        if data.get("description") is not None:
            row.description = data["description"]
        if "place" in data:
            row.place = data["place"] or None          # "" or None: read from the name again
        score_changed = data.get("score") is not None and float(row.score) != float(data["score"])
        if score_changed:
            row.score = data["score"]
        row.updated_by = user_id
        db.commit()
        db.refresh(row)
        return row, score_changed

    @staticmethod
    def delete_zone(db: Session, zone_id: int):
        """Delete a zone no asset is in."""
        from app.models.risk import AssetRiskProfile
        zone = db.query(RiskZone).filter(RiskZone.id == zone_id).first()
        if zone is None:
            return False
        if db.query(AssetRiskProfile).filter(AssetRiskProfile.zone_id == zone_id).count():
            raise ValueError("Cannot delete zone with assigned assets")
        db.delete(zone)
        db.commit()
        return True
    
    # ==========================================
    # OS Catalog
    # ==========================================
    
    @staticmethod
    def get_all_os(db: Session):
        """Get all OS entries"""
        return db.query(OSCatalog).all()
    
    @staticmethod
    def create_os(db: Session, data: dict):
        """Create OS entry"""
        os_entry = OSCatalog(**data)
        db.add(os_entry)
        db.commit()
        db.refresh(os_entry)
        return os_entry
    
    @staticmethod
    def update_os(db: Session, os_id: int, data: dict):
        """Update os. Only keys present in `data` are written, so a partial
        payload leaves the other columns alone."""
        row = db.query(OSCatalog).filter(OSCatalog.id == os_id).first()
        if row:
            for key, value in data.items():
                if value is not None and hasattr(row, key):
                    setattr(row, key, value)
            db.commit()
            db.refresh(row)
        return row

    @staticmethod
    def delete_os(db: Session, os_id: int):
        """Delete OS entry"""
        os_entry = db.query(OSCatalog).filter(OSCatalog.id == os_id).first()
        if os_entry:
            db.delete(os_entry)
            db.commit()
            return True
        return False
    
    # ==========================================
    # Vendor Catalog
    # ==========================================
    
    @staticmethod
    def get_all_vendors(db: Session):
        """Get all vendors"""
        return db.query(VendorCatalog).all()
    
    @staticmethod
    def create_vendor(db: Session, data: dict):
        """Create vendor"""
        vendor = VendorCatalog(**data)
        db.add(vendor)
        db.commit()
        db.refresh(vendor)
        return vendor
    
    @staticmethod
    def update_vendor(db: Session, vendor_id: int, data: dict):
        """Update vendor. Only keys present in `data` are written, so a partial
        payload leaves the other columns alone."""
        row = db.query(VendorCatalog).filter(VendorCatalog.id == vendor_id).first()
        if row:
            for key, value in data.items():
                if value is not None and hasattr(row, key):
                    setattr(row, key, value)
            db.commit()
            db.refresh(row)
        return row

    @staticmethod
    def delete_vendor(db: Session, vendor_id: int):
        """Delete vendor"""
        vendor = db.query(VendorCatalog).filter(VendorCatalog.id == vendor_id).first()
        if vendor:
            db.delete(vendor)
            db.commit()
            return True
        return False
    
    # ==========================================
    # Dependencies
    # ==========================================
    
    @staticmethod
    def get_asset_dependencies(db: Session, asset_id: int):
        """Get dependencies for an asset"""
        return db.query(AssetDependency).filter(AssetDependency.asset_id == asset_id).all()
    
    @staticmethod
    def create_dependency(db: Session, data: dict):
        """Create dependency"""
        dep = AssetDependency(**data)
        db.add(dep)
        db.commit()
        db.refresh(dep)
        return dep
    
    @staticmethod
    def delete_dependency(db: Session, dep_id: int):
        """Delete dependency"""
        dep = db.query(AssetDependency).filter(AssetDependency.id == dep_id).first()
        if dep:
            db.delete(dep)
            db.commit()
            return True
        return False
    
    # ==========================================
    # Security Status
    # ==========================================
    
    @staticmethod
    def get_security_status(db: Session, asset_id: int):
        """Get security status for an asset"""
        return db.query(AssetSecurityStatus).filter(AssetSecurityStatus.asset_id == asset_id).first()
    
    @staticmethod
    def create_security_status(db: Session, data: dict):
        """Create security status"""
        status = AssetSecurityStatus(**data)
        db.add(status)
        db.commit()
        db.refresh(status)
        return status
    
    @staticmethod
    def update_security_status(db: Session, status_id: int, data: dict):
        """Update security status"""
        status = db.query(AssetSecurityStatus).filter(AssetSecurityStatus.id == status_id).first()
        if status:
            for key, value in data.items():
                if value is not None and hasattr(status, key):
                    setattr(status, key, value)
            db.commit()
            db.refresh(status)
        return status
    
    # ==========================================
    # Asset Views (for Asset List page)
    # ==========================================
    
    @staticmethod
    def get_assets_overview(db: Session, user_id: int = None):
        """Overview view - sorted by asset_name"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)

        # Sort by asset name instead of ID for professional appearance
        query = query.order_by(Asset.asset_name)
        return [asset.get_overview() for asset in query.all()]
    
    @staticmethod
    def get_assets_network_system(db: Session, user_id: int = None):
        """Network & System view - sorted by asset_name"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)

        # Sort by asset name instead of ID for professional appearance
        query = query.order_by(Asset.asset_name)
        return [asset.get_network_system() for asset in query.all()]
    
    @staticmethod
    def get_assets_location_ownership(db: Session, user_id: int = None):
        """Location & Ownership view - sorted by asset_name"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)

        # Sort by asset name instead of ID for professional appearance
        query = query.order_by(Asset.asset_name)
        return [asset.get_location_ownership() for asset in query.all()]
    
    @staticmethod
    def get_assets_security_audit(db: Session, user_id: int = None):
        """Security/Risk/Audit view with security status - sorted by asset_name"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)

        # Sort by asset name instead of ID for professional appearance
        query = query.order_by(Asset.asset_name)
        assets = query.all()
        result = []

        for asset in assets:
            data = asset.get_security_risk_audit()

            # Add security status fields if available
            if hasattr(asset, 'security_status') and asset.security_status:
                # Handle both list (InstrumentedList) and single object cases
                sec = asset.security_status
                if isinstance(sec, list):
                    sec = sec[0] if len(sec) > 0 else None

                if sec:
                    data.update({
                        'antivirus_installed': sec.antivirus_installed,
                        'antivirus_status': sec.antivirus_status,
                        'firewall_enabled': sec.firewall_enabled,
                        'backup_enabled': sec.backup_enabled,
                        'vulnerability_score': sec.vulnerability_score,
                        'compliance_status': sec.compliance_status,
                    })
                else:
                    # Default values if no security status exists
                    data.update({
                        'antivirus_installed': None,
                        'antivirus_status': None,
                        'firewall_enabled': None,
                        'backup_enabled': None,
                        'vulnerability_score': None,
                        'compliance_status': None,
                    })
            else:
                # Default values if no security status exists
                data.update({
                    'antivirus_installed': None,
                    'antivirus_status': None,
                    'firewall_enabled': None,
                    'backup_enabled': None,
                    'vulnerability_score': None,
                    'compliance_status': None,
                })

            result.append(data)

        return result
