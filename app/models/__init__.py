from .user import User, UserRole
from .login_log import LoginLog

__all__ = ["User", "UserRole", "LoginLog"]

from app.core.database import Base

# Import ENUMs
from app.models.enums import (
    StatusEnum,
    ConfidentialityLevelEnum,
    RiskLevelEnum,
    RelationTypeEnum
)

# Import existing models
from app.models.user import User
from app.models.login_log import LoginLog

# Import asset reference tables
from app.models.asset_types import AssetType
from app.models.network_zones import NetworkZone
from app.models.os_catalog import OSCatalog
from app.models.vendor_catalog import VendorCatalog

# Import user-specific tables
from app.models.asset_owners import AssetOwner
from app.models.asset_locations import AssetLocation

# Import main asset table
from app.models.asset import Asset

# Import asset-related tables
from app.models.asset_dependencies import AssetDependency
from app.models.asset_security_status import AssetSecurityStatus


__all__ = [
    "Base",
    "StatusEnum",
    "ConfidentialityLevelEnum",
    "RiskLevelEnum",
    "RelationTypeEnum",
    "User",
    "LoginLog",
    "AssetType",
    "NetworkZone",
    "OSCatalog",
    "VendorCatalog",
    "AssetOwner",
    "AssetLocation",
    "Asset",
    "AssetDependency",
    "AssetSecurityStatus",
]
