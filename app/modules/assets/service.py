"""
Asset Service - Complete CRUD operations
"""
from sqlalchemy.orm import Session
from app.models import (
    AssetType, Asset, AssetOwner, AssetLocation,
    NetworkZone, OSCatalog, VendorCatalog, 
    AssetDependency, AssetSecurityStatus
)
from .schemas import AssetTypeCreate


class AssetService:
    """Asset Management Service with complete CRUD operations"""
    
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
        asset_type = AssetType(**data.dict())
        db.add(asset_type)
        db.commit()
        db.refresh(asset_type)
        return asset_type
    
    @staticmethod
    def delete_asset_type(db: Session, type_id: int):
        """Delete asset type"""
        asset_type = db.query(AssetType).filter(AssetType.id == type_id).first()
        if asset_type:
            db.delete(asset_type)
            db.commit()
            return True
        return False
    
    # ==========================================
    # Assets
    # ==========================================
    
    @staticmethod
    def get_user_assets(db: Session, user_id: int):
        """Get all assets for a user"""
        return db.query(Asset).filter(Asset.user_id == user_id).all()
    
    @staticmethod
    def get_all_assets(db: Session):
        """Get all assets (admin only)"""
        return db.query(Asset).all()
    
    @staticmethod
    def get_asset(db: Session, asset_id: int):
        """Get asset by id"""
        return db.query(Asset).filter(Asset.id == asset_id).first()
    
    @staticmethod
    def create_asset(db: Session, data: dict):
        """Create new asset"""
        asset = Asset(**data)
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return asset
    
    @staticmethod
    def update_asset(db: Session, asset_id: int, data: dict):
        """Update asset"""
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            for key, value in data.items():
                if value is not None:
                    setattr(asset, key, value)
            db.commit()
            db.refresh(asset)
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
        """Overview view"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)
        
        return [asset.get_overview() for asset in query.all()]
    
    @staticmethod
    def get_assets_network_system(db: Session, user_id: int = None):
        """Network & System view"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)
        
        return [asset.get_network_system() for asset in query.all()]
    
    @staticmethod
    def get_assets_location_ownership(db: Session, user_id: int = None):
        """Location & Ownership view"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)
        
        return [asset.get_location_ownership() for asset in query.all()]
    
    @staticmethod
    def get_assets_security_audit(db: Session, user_id: int = None):
        """Security/Risk/Audit view"""
        query = db.query(Asset)
        if user_id:
            query = query.filter(Asset.user_id == user_id)
        
        return [asset.get_security_risk_audit() for asset in query.all()]