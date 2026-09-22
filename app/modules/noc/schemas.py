"""Pydantic schemas for the NOC (SNMP monitoring) module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class SnmpCredentialSet(BaseModel):
    """Input for PUT /api/noc/hosts/{asset_id}/credential. Secret fields
    (community/auth_key/priv_key) are plaintext here and encrypted before
    storage - never echoed back (see SnmpCredentialInfo)."""
    version: str = "v2c"  # v2c | v3
    port: int = 161
    community: Optional[str] = None
    username: Optional[str] = None
    auth_protocol: Optional[str] = None  # MD5 | SHA
    auth_key: Optional[str] = None
    priv_protocol: Optional[str] = None  # DES | AES
    priv_key: Optional[str] = None


class SnmpCredentialInfo(BaseModel):
    """Output - secrets are never returned, only whether one is set."""
    version: str
    port: int
    has_community: bool
    username: Optional[str] = None
    auth_protocol: Optional[str] = None
    has_auth_key: bool
    priv_protocol: Optional[str] = None
    has_priv_key: bool
    updated_at: Optional[datetime] = None


class HostSummary(BaseModel):
    asset_id: int
    asset_name: str
    ip_address: Optional[str] = None
    asset_type_name: Optional[str] = None
    has_credential: bool
    reachable: Optional[bool] = None  # None = never polled
    sys_name: Optional[str] = None
    last_polled_at: Optional[datetime] = None
    error_message: Optional[str] = None


class InterfaceInfo(BaseModel):
    if_index: int
    if_descr: Optional[str] = None
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
    asset_id: int
    asset_name: str
    ip_address: Optional[str] = None
    asset_type_name: Optional[str] = None
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


class PollNowResponse(BaseModel):
    asset_id: int
    reachable: bool
    message: str


class PollAllResponse(BaseModel):
    polled_count: int
