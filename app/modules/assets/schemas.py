from pydantic import BaseModel
from typing import Optional

from datetime import date, datetime
from app.models.enums import StatusEnum, ConfidentialityLevelEnum, RiskLevelEnum
from app.models.enums import RelationTypeEnum

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
    user_id: Optional[int] = None  # Admin specifies which user owns this

class AssetUpdate(BaseModel):
    asset_name: Optional[str] = None
    hostname: Optional[str] = None
    asset_type_id: Optional[int] = None
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
    status: Optional[StatusEnum] = None
    confidentiality_level: Optional[ConfidentialityLevelEnum] = None
    risk_level: Optional[RiskLevelEnum] = None
    last_audit_date: Optional[date] = None
    last_patch_date: Optional[date] = None
    asset_value: Optional[float] = None
    description: Optional[str] = None

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
                
# Network Zones
class NetworkZoneCreate(BaseModel):
    zone_name: str
    description: Optional[str] = None

class NetworkZoneResponse(NetworkZoneCreate):
    id: int
    
    class Config:
        from_attributes = True

# OS Catalog
class OSCatalogCreate(BaseModel):
    os_name: str
    os_version: Optional[str] = None
    os_family: Optional[str] = None

class OSCatalogResponse(OSCatalogCreate):
    id: int
    
    class Config:
        from_attributes = True

# Vendor Catalog
class VendorCatalogCreate(BaseModel):
    vendor_name: str
    vendor_type: Optional[str] = None

class VendorCatalogResponse(VendorCatalogCreate):
    id: int
    
    class Config:
        from_attributes = True

# Asset Dependencies
class AssetDependencyCreate(BaseModel):
    asset_id: int
    depends_on_id: int
    relation_type: RelationTypeEnum
    description: Optional[str] = None

class AssetDependencyResponse(AssetDependencyCreate):
    id: int
    
    class Config:
        from_attributes = True

# Asset Security Status
class AssetSecurityStatusCreate(BaseModel):
    asset_id: int
    antivirus_installed: bool = False
    antivirus_status: Optional[str] = None
    firewall_enabled: bool = False
    last_patch_date: Optional[date] = None
    backup_enabled: bool = False
    vulnerability_score: Optional[float] = None
    compliance_status: Optional[str] = None
    notes: Optional[str] = None

class AssetSecurityStatusResponse(AssetSecurityStatusCreate):
    id: int
    
    class Config:
        from_attributes = True