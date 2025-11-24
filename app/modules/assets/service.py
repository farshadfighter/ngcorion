from sqlalchemy.orm import Session
from app.models import AssetType
from .schemas import AssetTypeCreate
from app.models import Asset, AssetOwner, AssetLocation

class AssetService:
    
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
    
    # === Owner/Location ===
    
    @staticmethod
    def create_owner(db: Session, data: dict, user_id: int):
        """Create asset owner"""
        owner = AssetOwner(**data, user_id=user_id)
        db.add(owner)
        db.commit()
        db.refresh(owner)
        return owner
    
    @staticmethod
    def create_location(db: Session, data: dict, user_id: int):
        """Create asset location"""
        location = AssetLocation(**data, user_id=user_id)
        db.add(location)
        db.commit()
        db.refresh(location)
        return location
