"""
Shared enumerations of asset fields (status, confidentiality, risk level,
dependency relation types). Stored as their string values.
"""
import enum

class StatusEnum(str, enum.Enum):
    """Lifecycle status of an asset."""
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
    """How sensitive the data on an asset is; one input of its risk score."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"

class RiskLevelEnum(str, enum.Enum):
    """Risk level labels used for assets and findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    CRITICAL = "critical"

class SnmpVersionEnum(str, enum.Enum):
    """SNMP versions the NOC poller and the SNMP agent settings support."""
    V2C = "v2c"
    V3 = "v3"

class SnmpAuthProtocolEnum(str, enum.Enum):
    """SNMPv3 authentication protocols."""
    MD5 = "MD5"
    SHA = "SHA"

class SnmpPrivProtocolEnum(str, enum.Enum):
    """SNMPv3 privacy (encryption) protocols."""
    DES = "DES"
    AES = "AES"

class SyslogProtocolEnum(str, enum.Enum):
    """Transport of syslog forwarding."""
    UDP = "UDP"
    TCP = "TCP"

class RelationTypeEnum(str, enum.Enum):
    """Kinds of dependency between two assets (network link, application dependency, backup, power,
    logical).
    """
    NETWORK_LINK = "network_link"
    APP_DEPENDENCY = "app_dependency"
    BACKUP_LINK = "backup_link"
    POWER_SOURCE = "power_source"
    LOGICAL_CONNECTION = "logical_connection"