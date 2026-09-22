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
    RelationTypeEnum,
    SnmpVersionEnum,
    SnmpAuthProtocolEnum,
    SnmpPrivProtocolEnum,
    SyslogProtocolEnum
)

# Import user models (no dependencies)
from app.models.user import User, UserRole
from app.models.login_log import LoginLog
from app.models.password_reset_token import PasswordResetToken

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
    DiscoveryAuditLog,
    log_scan_started,
    log_scan_completed,
    log_scan_failed,
    log_discovery_applied,
    log_scan_cancelled,
    log_scan_deleted,
    log_host_applied,
    log_bulk_application_started,
    log_bulk_application_completed,
    log_discovery_preview
)

# Import audit models (depend on User and Asset)
from app.models.audit import (
    DeviceType,
    CheckStatus,
    AuditTemplate,
    AuditCheck,
    AuditSession,
    AuditResult
)

# Import module-specific audit logs
from app.models.asset_requirement_log import (
    AssetRequirementLog,
    log_requirement_import,
    log_requirement_create,
    log_requirement_update,
    log_requirement_delete
)
from app.models.asset_log import (
    AssetLog,
    log_asset_created,
    log_asset_updated,
    log_asset_deleted,
    log_asset_import
)

# Import security audit log (system-wide action tracking)
from app.models.security_audit_log import (
    AuditLog,
    log_action,
    log_user_action,
    log_asset_action,
    log_discovery_action
)

# Import hardening models LAST (depend on Audit)
from app.models.hardening import HardeningAction

# Import hardening log model and helpers
from app.models.hardening_log import (
    HardeningLog,
    log_hardening_preview,
    log_hardening_execute,
    log_batch_hardening,
    log_auto_hardening
)

# Import backup model (depends on HardeningAction and Asset)
from app.models.backup import DeviceBackup

# Import CVE model (standalone - matched against Asset at read time, no FK)
from app.models.cve import CveRecord

# Import topology models (depend on Asset and User)
from app.models.topology import TopologyLink, TopologyNodePosition

# Import NOC / SNMP monitoring models (depend on Asset and User)
from app.models.noc import AssetSnmpCredential, AssetSnmpStatus, AssetSnmpInterface
from app.models.noc_metrics import AssetMetricSample, AssetMetricRollup
from app.models.topology_log import (
    TopologyLog,
    log_topology_link_created,
    log_topology_link_updated,
    log_topology_link_deleted,
)

# Import architecture validation findings (depend on Asset and User)
from app.models.architecture_finding import ArchitectureFinding

# Import design models (depend on Asset and User)
from app.models.design import (
    ArchitectureDesign,
    ArchitectureDesignVersion,
    DesignComponent,
    DesignRelationship,
    DesignAssetMapping,
)

# Import configuration models (depend on design models and Asset)
from app.models.configuration import ConfigurationJob, ConfigurationObject

# Import deployment models (depend on configuration models, Asset and DeviceBackup)
from app.models.deployment import DeploymentJob

# Import drift models (depend on Asset, DeviceBackup and User)
from app.models.drift import DriftRun, DriftResult

# Import risk models (depend on User and Asset)
from app.models.risk import (
    RiskSetting,
    RiskZone,
    AssetRiskProfile,
    AssetOpenPort,
    AssetRiskScore,
    AssetRiskHistory,
    RiskCalculationLog
)

# Import system configuration model (depends on User)
from app.models.system_config import SystemConfigSetting, CONFIG_SECTIONS

# Import scheduled jobs (depend on Asset and User)
from app.models.scheduling import ScheduledJob, ScheduledJobRun

# Export all
__all__ = [
    "Base",
    # Enums
    "StatusEnum",
    "ConfidentialityLevelEnum",
    "RiskLevelEnum",
    "RelationTypeEnum",
    "SnmpVersionEnum",
    "SnmpAuthProtocolEnum",
    "SnmpPrivProtocolEnum",
    "SyslogProtocolEnum",
    # User models
    "User",
    "UserRole",
    "LoginLog",
    "PasswordResetToken",
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
    "log_scan_started",
    "log_scan_completed",
    "log_scan_failed",
    "log_discovery_applied",
    "log_scan_cancelled",
    "log_scan_deleted",
    "log_host_applied",
    "log_bulk_application_started",
    "log_bulk_application_completed",
    "log_discovery_preview",
    # Audit models
    "DeviceType",
    "CheckStatus",
    "AuditTemplate",
    "AuditCheck",
    "AuditSession",
    "AuditResult",
    # Hardening models
    "HardeningAction",
    "HardeningLog",
    "DeviceBackup",
    # CVE
    "CveRecord",
    # Topology models
    "TopologyLink",
    "TopologyNodePosition",
    "TopologyLog",
    "log_topology_link_created",
    "log_topology_link_updated",
    "log_topology_link_deleted",
    # NOC / SNMP monitoring
    "AssetSnmpCredential",
    "AssetSnmpStatus",
    "AssetSnmpInterface",
    # Architecture Validation
    "ArchitectureFinding",
    # Design models
    "ArchitectureDesign",
    "ArchitectureDesignVersion",
    "DesignComponent",
    "DesignRelationship",
    "DesignAssetMapping",
    # Configuration models
    "ConfigurationJob",
    "ConfigurationObject",
    # Deployment models
    "DeploymentJob",
    # Drift models
    "DriftRun",
    "DriftResult",
    # Risk models
    "RiskSetting",
    "RiskZone",
    "AssetRiskProfile",
    "AssetOpenPort",
    "AssetRiskScore",
    "AssetRiskHistory",
    "RiskCalculationLog",
    # Scheduled jobs
    "ScheduledJob",
    "ScheduledJobRun",
    # System configuration
    "SystemConfigSetting",
    "CONFIG_SECTIONS",
    # CIS benchmark results
    "log_hardening_preview",
    "log_hardening_execute",
    "log_batch_hardening",
    "log_auto_hardening",
    # Module audit logs
    "AssetRequirementLog",
    "log_requirement_import",
    "log_requirement_create",
    "log_requirement_update",
    "log_requirement_delete",
    "AssetLog",
    "log_asset_created",
    "log_asset_updated",
    "log_asset_deleted",
    "log_asset_import",
    # Security audit log
    "AuditLog",
    "log_action",
    "log_user_action",
    "log_asset_action",
    "log_discovery_action",
]
