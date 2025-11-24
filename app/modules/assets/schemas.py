from pydantic import BaseModel
from typing import Optional

from datetime import date, datetime
from app.models.enums import StatusEnum, ConfidentialityLevelEnum, RiskLevelEnum


class AssetTypeBase(BaseModel):
    type_name: str
    category: str
    description: Optional[str] = None

class AssetTypeCreate(AssetTypeBase):
    pass

class AssetTypeResponse(AssetTypeBase):
    id: int
    
    class Config:
        from_attributes = True


# Asset Schemas
class AssetBase(BaseModel):
    asset_name: str
    hostname: Optional[str] = None
    asset_type_id: int
    asset_role: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    location_id: Optional[int] = None
    owner_id: Optional[int] = None
    status: StatusEnum = StatusEnum.ACTIVE
    confidentiality_level: Optional[ConfidentialityLevelEnum] = None
    risk_level: Optional[RiskLevelEnum] = None
    last_audit_date: Optional[date] = None
    last_patch_date: Optional[date] = None
    asset_value: Optional[float] = None
    description: Optional[str] = None

class AssetCreate(AssetBase):
    user_id: int  # Admin specifies which user owns this

class AssetUpdate(BaseModel):
    asset_name: Optional[str] = None
    hostname: Optional[str] = None
    status: Optional[StatusEnum] = None
    # ... (other fields optional)

class AssetResponse(AssetBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Owner/Location Schemas
class AssetOwnerCreate(BaseModel):
    full_name: str
    department: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None

class AssetOwnerResponse(AssetOwnerCreate):
    id: int
    user_id: int
    
    class Config:
        from_attributes = True

class AssetLocationCreate(BaseModel):
    site_name: str
    rack_name: Optional[str] = None
    room: Optional[str] = None
    floor: Optional[str] = None
    network_zone: Optional[str] = None
    vlan_id: Optional[int] = None
    subnet: Optional[str] = None

class AssetLocationResponse(AssetLocationCreate):
    id: int
    user_id: int
    
    class Config:
        from_attributes = True