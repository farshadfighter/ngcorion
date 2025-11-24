import enum

class StatusEnum(str, enum.Enum):
    ACTIVE = "active"
    STANDBY = "standby"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"

class ConfidentialityLevelEnum(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"

class RiskLevelEnum(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RelationTypeEnum(str, enum.Enum):
    NETWORK_LINK = "network_link"
    APP_DEPENDENCY = "app_dependency"
    BACKUP_LINK = "backup_link"
    POWER_SOURCE = "power_source"
    LOGICAL_CONNECTION = "logical_connection"