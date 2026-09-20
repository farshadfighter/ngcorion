import enum

class StatusEnum(str, enum.Enum):
    ACTIVE = "active"
    STANDBY = "standby"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"
    # Set automatically by the NOC poller for assets with an SNMP credential
    # configured (app/modules/noc/service.py), after several consecutive
    # failed polls - never set by a user directly. Assets without SNMP
    # monitoring keep their status fully manual, as before.
    INACTIVE = "inactive"

class ConfidentialityLevelEnum(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"

class RiskLevelEnum(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    CRITICAL = "critical"

class SnmpVersionEnum(str, enum.Enum):
    V2C = "v2c"
    V3 = "v3"

class SnmpAuthProtocolEnum(str, enum.Enum):
    MD5 = "MD5"
    SHA = "SHA"

class SnmpPrivProtocolEnum(str, enum.Enum):
    DES = "DES"
    AES = "AES"

class SyslogProtocolEnum(str, enum.Enum):
    UDP = "UDP"
    TCP = "TCP"

class RelationTypeEnum(str, enum.Enum):
    NETWORK_LINK = "network_link"
    APP_DEPENDENCY = "app_dependency"
    BACKUP_LINK = "backup_link"
    POWER_SOURCE = "power_source"
    LOGICAL_CONNECTION = "logical_connection"