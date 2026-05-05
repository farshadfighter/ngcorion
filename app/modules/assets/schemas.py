from pydantic import BaseModel, field_validator, EmailStr, ConfigDict
from typing import Optional, Generic, TypeVar, List
import re

from datetime import date, datetime
from app.models.enums import StatusEnum, ConfidentialityLevelEnum, RiskLevelEnum
from app.models.enums import RelationTypeEnum

# Generic type for pagination
T = TypeVar('T')

class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response"""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int

class AssetTypeBase(BaseModel):
    type_name: str
    category: str
    description: Optional[str] = None

class AssetTypeCreate(AssetTypeBase):
    @field_validator('type_name', 'category')
    @classmethod
    def validate_strings(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError('Field must be at least 2 characters')
        return v

class AssetTypeResponse(AssetTypeBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


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

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v):
        if v is None or v == '':
            return v
        # IPv4 validation
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(pattern, v):
            raise ValueError('Invalid IP address format')
        return v

    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v):
        if v is None or v == '':
            return v
        # MAC address validation - supports multiple formats:
        # - XX:XX:XX:XX:XX:XX (colon separated)
        # - XX-XX-XX-XX-XX-XX (hyphen separated)
        # - XXXX.XXXX.XXXX (Cisco dot notation)
        # - XXXXXXXXXXXX (no separators)
        mac_patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # Colon or hyphen separated
            r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',    # Cisco dot notation
            r'^[0-9A-Fa-f]{12}$'                             # No separators (compact)
        ]
        if not any(re.match(pattern, v) for pattern in mac_patterns):
            raise ValueError('Invalid MAC address format. Supported formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXX.XXXX.XXXX, or XXXXXXXXXXXX')
        return v

    @field_validator('asset_value')
    @classmethod
    def validate_value(cls, v):
        if v is not None and v < 0:
            raise ValueError('Asset value must be positive')
        return v

    @field_validator('asset_name')
    @classmethod
    def validate_name(cls, v):
        if v is not None and len(v.strip()) < 2:
            raise ValueError('Asset name must be at least 2 characters')
        return v

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
    security_status: Optional[dict] = None

    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v):
        if v is None or v == '':
            return v
        # IPv4 validation
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(pattern, v):
            raise ValueError('Invalid IP address format')
        return v

    @field_validator('mac_address')
    @classmethod
    def validate_mac(cls, v):
        if v is None or v == '':
            return v
        # MAC address validation - supports multiple formats:
        # - XX:XX:XX:XX:XX:XX (colon separated)
        # - XX-XX-XX-XX-XX-XX (hyphen separated)
        # - XXXX.XXXX.XXXX (Cisco dot notation)
        # - XXXXXXXXXXXX (no separators)
        mac_patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # Colon or hyphen separated
            r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$',    # Cisco dot notation
            r'^[0-9A-Fa-f]{12}$'                             # No separators (compact)
        ]
        if not any(re.match(pattern, v) for pattern in mac_patterns):
            raise ValueError('Invalid MAC address format. Supported formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXX.XXXX.XXXX, or XXXXXXXXXXXX')
        return v

    @field_validator('asset_value')
    @classmethod
    def validate_value(cls, v):
        if v is not None and v < 0:
            raise ValueError('Asset value must be positive')
        return v

    @field_validator('asset_name')
    @classmethod
    def validate_name(cls, v):
        if v is not None and len(v.strip()) < 2:
            raise ValueError('Asset name must be at least 2 characters')
        return v

class AssetResponse(AssetBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

# Owner/Location Schemas
class AssetOwnerCreate(BaseModel):
    full_name: str
    department: Optional[str] = None
    role: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    #responsibility_level: Optional[str] = None

    @field_validator('full_name')
    @classmethod
    def validate_full_name(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError('Full name must be at least 2 characters')
        return v

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if v is None or v == '':
            return v
        # Basic phone validation (allows various formats)
        v = v.strip()
        if len(v) < 7:
            raise ValueError('Phone number must be at least 7 characters')
        return v


class AssetOwnerResponse(AssetOwnerCreate):
    id: int
    user_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AssetLocationCreate(BaseModel):
    site_name: str
    rack_name: Optional[str] = None
    room: Optional[str] = None
    floor: Optional[str] = None
    network_zone: Optional[str] = None
    vlan_id: Optional[int] = None
    subnet: Optional[str] = None

    @field_validator('site_name')
    @classmethod
    def validate_site_name(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError('Site name must be at least 2 characters')
        return v

    @field_validator('vlan_id')
    @classmethod
    def validate_vlan(cls, v):
        if v is not None and (v < 1 or v > 4094):
            raise ValueError('VLAN ID must be between 1 and 4094')
        return v

    @field_validator('subnet')
    @classmethod
    def validate_subnet(cls, v):
        if v is None or v == '':
            return v
        # Basic CIDR validation
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$'
        if not re.match(pattern, v):
            raise ValueError('Invalid subnet format (use CIDR notation, e.g., 192.168.1.0/24)')
        return v

class AssetLocationResponse(AssetLocationCreate):
    id: int
    user_id: int
    
    model_config = ConfigDict(from_attributes=True)
                
# Network Zones
class NetworkZoneCreate(BaseModel):
    zone_name: str

class NetworkZoneResponse(NetworkZoneCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)

# OS Catalog
class OSCatalogCreate(BaseModel):
    os_name: str

class OSCatalogResponse(OSCatalogCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)

# Vendor Catalog
class VendorCatalogCreate(BaseModel):
    vendor_name: str

class VendorCatalogResponse(VendorCatalogCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)

# Asset Dependencies
class AssetDependencyCreate(BaseModel):
    asset_id: int
    depends_on_id: int
    relation_type: RelationTypeEnum
    description: Optional[str] = None

class AssetDependencyResponse(AssetDependencyCreate):
    id: int
    
    model_config = ConfigDict(from_attributes=True)

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
    
    model_config = ConfigDict(from_attributes=True)