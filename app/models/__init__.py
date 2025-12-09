"""
Models Package
Import all models so Alembic can discover them
"""

# Import Base first
from app.core.database import Base

# Import ENUMs first
from app.models.enums import (
    StatusEnum,
    ConfidentialityLevelEnum,
    RiskLevelEnum,
    RelationTypeEnum
)

# Import user models (no dependencies)
from app.models.user import User, UserRole
from app.models.login_log import LoginLog

# Import user permissions
from app.models.user_permission import UserPermission, ModuleEnum

# Import reference tables (no foreign keys to other tables)
from app.models.asset_types import AssetType
from app.models.network_zones import NetworkZone
from app.models.os_catalog import OSCatalog
from app.models.vendor_catalog import VendorCatalog
from app.models.asset_owners import AssetOwner
from app.models.asset_locations import AssetLocation

# Import main asset table (depends on reference tables above)
from app.models.asset import Asset

# Import asset-related tables (depend on Asset)
from app.models.asset_dependencies import AssetDependency
from app.models.asset_security_status import AssetSecurityStatus

# Import port and protocol models (depend on Asset)
from app.models.port import Port, Protocol

# Import discovery models (depend on User and Asset)
from app.models.discovery import (
    DiscoveryScan,
    DiscoveredHost,
    DiscoveryApplication,
    DiscoveryAuditLog
)

# Import audit models LAST (depend on User and Asset)
from app.models.audit import (
    DeviceType,
    CheckStatus,
    AuditTemplate,
    AuditCheck,
    AuditSession,
    AuditResult
)

# Export all
__all__ = [
    "Base",
    # Enums
    "StatusEnum",
    "ConfidentialityLevelEnum",
    "RiskLevelEnum",
    "RelationTypeEnum",
    # User models
    "User",
    "UserRole",
    "LoginLog",
    "UserPermission",
    "ModuleEnum",
    # Reference tables
    "AssetType",
    "NetworkZone",
    "OSCatalog",
    "VendorCatalog",
    "AssetOwner",
    "AssetLocation",
    # Asset models
    "Asset",
    "AssetDependency",
    "AssetSecurityStatus",
    # Port and Protocol models
    "Port",
    "Protocol",
    # Discovery models
    "DiscoveryScan",
    "DiscoveredHost",
    "DiscoveryApplication",
    "DiscoveryAuditLog",
    # Audit models
    "DeviceType",
    "CheckStatus",
    "AuditTemplate",
    "AuditCheck",
    "AuditSession",
    "AuditResult",
]