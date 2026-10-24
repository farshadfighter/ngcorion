"""Pydantic schemas for the NOC (SNMP monitoring) module."""
import ipaddress
import re
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, field_validator


class HealthNow(BaseModel):
    """Device health from the last successful poll (app/modules/noc/health.py); a measure is null when
    the device does not report it."""
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    temperature_c: Optional[float] = None


class SnmpCredentialSet(BaseModel):
    """Input for PUT /api/noc/hosts/{asset_id}/credential. Secret fields
    (community/auth_key/priv_key) are plaintext here and encrypted before
    storage - never echoed back (see SnmpCredentialInfo)."""
    version: str = "v2c"  # v2c | v3
    port: int = 161
    # Where SNMP reaches the device when not its inventory address; "" = the asset's IP address.
    poll_address: Optional[str] = None
    community: Optional[str] = None
    username: Optional[str] = None
    auth_protocol: Optional[str] = None  # MD5 | SHA
    auth_key: Optional[str] = None
    priv_protocol: Optional[str] = None  # DES | AES
    priv_key: Optional[str] = None

    @field_validator("poll_address")
    @classmethod
    def _address(cls, v):
        """An IP address or a host name; empty = the asset's IP address."""
        v = (v or "").strip()
        if not v:
            return ""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        if len(v) > 253 or not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*", v):
            raise ValueError("Enter an IP address or a host name")
        return v


class SnmpCredentialInfo(BaseModel):
    """Output - secrets are never returned, only whether one is set."""
    version: str
    port: int
    poll_address: Optional[str] = None
    has_community: bool
    username: Optional[str] = None
    auth_protocol: Optional[str] = None
    has_auth_key: bool
    priv_protocol: Optional[str] = None
    has_priv_key: bool
    updated_at: Optional[datetime] = None


class HostSummary(BaseModel):
    """A host in the NOC list: reachability, uptime and interface counts."""
    asset_id: int
    asset_name: str
    ip_address: Optional[str] = None
    asset_type_name: Optional[str] = None
    icon: str = "other"
    has_credential: bool
    reachable: Optional[bool] = None  # None = never polled
    sys_name: Optional[str] = None
    last_polled_at: Optional[datetime] = None
    error_message: Optional[str] = None
    health: HealthNow = HealthNow()
    uptime_seconds: Optional[int] = None


class FileSystemInfo(BaseModel):
    name: str
    size: int
    used: int
    percent: Optional[float] = None


class SensorInfo(BaseModel):
    name: str
    celsius: float


class RebootInfo(BaseModel):
    detected_at: datetime
    booted_at: datetime
    previous_uptime_seconds: Optional[int] = None


class InterfaceInfo(BaseModel):
    """One interface of a host with its last counters and status."""
    id: int  # AssetSnmpInterface.id - what GET /hosts/{id}/metrics?interface_id= expects, not if_index
    if_index: int
    if_descr: Optional[str] = None
    if_name: Optional[str] = None
    if_alias: Optional[str] = None
    if_type: Optional[int] = None
    if_speed: Optional[int] = None
    if_admin_status: Optional[str] = None
    if_oper_status: Optional[str] = None
    in_octets: Optional[int] = None
    out_octets: Optional[int] = None
    last_polled_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HostDetail(BaseModel):
    """A host's detail page: credential (without secrets), system information and interfaces."""
    asset_id: int
    asset_name: str
    ip_address: Optional[str] = None
    asset_type_name: Optional[str] = None
    icon: str = "other"
    credential: Optional[SnmpCredentialInfo] = None
    reachable: Optional[bool] = None
    sys_descr: Optional[str] = None
    sys_name: Optional[str] = None
    sys_contact: Optional[str] = None
    sys_location: Optional[str] = None
    sys_uptime_ticks: Optional[int] = None
    error_message: Optional[str] = None
    last_polled_at: Optional[datetime] = None
    interfaces: list[InterfaceInfo] = []
    # health: the device's own uptime (hrSystemUptime where it has one), CPU, memory, disk, temperature
    uptime_seconds: Optional[int] = None
    health: HealthNow = HealthNow()
    memory_total_bytes: Optional[int] = None
    health_source: Optional[str] = None      # host-resources | ucd | cisco | fortigate
    filesystems: list[FileSystemInfo] = []
    sensors: list[SensorInfo] = []
    booted_at: Optional[datetime] = None
    reboots: list[RebootInfo] = []           # restarts NOC noticed, newest first (last 20)


class PollNowResponse(BaseModel):
    """Result of polling one host."""
    asset_id: int
    reachable: bool
    message: str


class PollAllResponse(BaseModel):
    """How many hosts were polled."""
    polled_count: int


class MetricPoint(BaseModel):
    """One point of a metric time series. For a raw-resolution point
    avg == min == max and count == 1; for a rollup point they summarize
    every raw sample in that bucket (see app/modules/noc/metrics_retention.py)."""
    t: datetime
    avg: float
    min: float
    max: float
    count: int


class MetricSeriesResponse(BaseModel):
    """A metric's time series at the granularity chosen for the requested range."""
    metric: str
    granularity: str  # "raw" | "5m" | "1h" | "1d"
    interface_id: Optional[int] = None
    points: list[MetricPoint]
