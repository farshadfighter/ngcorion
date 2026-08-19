"""
Asset Service - Complete CRUD operations
"""
import logging
from sqlalchemy.orm import Session
from sqlalchemy.orm.query import Query
from typing import List, Optional
from math import ceil
from datetime import date as date_type
from app.models import (
    AssetType, Asset, AssetOwner, AssetLocation,
    NetworkZone, OSCatalog, VendorCatalog,
    AssetDependency, AssetSecurityStatus
)
from .schemas import AssetTypeCreate

logger = logging.getLogger(__name__)


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
        """Update asset with optional security status"""
        # Auto-stamp audit date on every update
        data['last_audit_date'] = date_type.today()

        # Extract security_status if present
        security_status_data = data.pop('security_status', None)

        # Validate asset_type_id if provided
        if 'asset_type_id' in data and data['asset_type_id'] is not None:
            asset_type = db.query(AssetType).filter(AssetType.id == data['asset_type_id']).first()
            if not asset_type:
                raise ValueError(f"Asset type with id {data['asset_type_id']} does not exist")

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            # Update asset fields
            for key, value in data.items():
                if value is not None:
                    setattr(asset, key, value)
            db.commit()
            db.refresh(asset)

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

        return asset
    
    @staticmethod
    def delete_asset(db: Session, asset_id: int):
        """Delete asset"""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            db.delete(asset)
            db.commit()
            return True
        return False
    
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
    # Network Zones
    # ==========================================
    
    @staticmethod
    def get_all_zones(db: Session):
        """Get all network zones"""
        return db.query(NetworkZone).all()
    
    @staticmethod
    def create_zone(db: Session, data: dict):
        """Create network zone"""
        zone = NetworkZone(**data)
        db.add(zone)
        db.commit()
        db.refresh(zone)
        return zone
    
    @staticmethod
    def delete_zone(db: Session, zone_id: int):
        """Delete network zone"""
        zone = db.query(NetworkZone).filter(NetworkZone.id == zone_id).first()
        if zone:
            db.delete(zone)
            db.commit()
            return True
        return False
    
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
