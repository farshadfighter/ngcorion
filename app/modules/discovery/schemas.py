"""
NGCORION - Auto Discovery Schemas
app/modules/discovery/schemas.py
"""

from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict
from datetime import datetime
import re


class ScanRequest(BaseModel):
    """
    Request to start a network scan
    
    Example:
        {"target": "192.168.1.0/24", "scan_type": "detailed"}
    """
    target: str  # IP address or IP range
    scan_type: str = "basic"  # basic, detailed, full
    
    @field_validator('target')
    @classmethod
    def validate_target(cls, v):
        """Validate IP address or CIDR range format"""
        # Single IP: 192.168.1.1
        # CIDR: 192.168.1.0/24
        # Range: 192.168.1.1-254
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
        ip_range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$'
        
        if not (re.match(ip_pattern, v) or re.match(ip_range_pattern, v)):
            raise ValueError('Invalid IP format. Use: 192.168.1.1, 192.168.1.0/24, or 192.168.1.1-254')
        
        # Validate each octet
        parts = v.split('/')[0].split('-')[0].split('.')
        for part in parts:
            if int(part) > 255:
                raise ValueError('Invalid IP: octet cannot be > 255')
        
        return v
    
    @field_validator('scan_type')
    @classmethod
    def validate_scan_type(cls, v):
        allowed = ['basic', 'detailed', 'full']
        if v not in allowed:
            raise ValueError(f'scan_type must be one of: {allowed}')
        return v


class DiscoveredPort(BaseModel):
    """Information about a discovered port"""
    port: int
    protocol: str  # tcp, udp
    state: str  # open, closed, filtered
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None


class DiscoveredHost(BaseModel):
    """
    Information about a discovered host
    
    Maps to Asset fields:
        hostname → hostname
        ip_address → ip_address
        mac_address → mac_address
        vendor → manufacturer
        os_name → os_name
        os_version → os_version
    """
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None  # From MAC address OUI lookup
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_accuracy: Optional[int] = None  # 0-100 confidence
    ports: List[DiscoveredPort] = []
    state: str = "up"  # up, down
    
    # Asset mapping hints
    suggested_asset_type: Optional[str] = None  # server, router, switch, etc.


class ScanResponse(BaseModel):
    """Response from a network scan"""
    scan_id: str
    target: str
    scan_type: str
    status: str  # running, completed, failed
    started_at: datetime
    completed_at: Optional[datetime] = None
    hosts_up: int = 0
    hosts_total: int = 0
    hosts: List[DiscoveredHost] = []
    error: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """Status check response"""
    scan_id: str
    status: str
    progress: int = 0
    hosts_found: int = 0


class ApplyDiscoveryRequest(BaseModel):
    """
    Request to apply discovered data to an asset
    
    Example:
        {
            "asset_id": 5,
            "ip_address": "192.168.1.100",
            "fields_to_apply": ["hostname", "os_name", "mac_address"]
        }
    """
    asset_id: int
    ip_address: str  # To match discovered host
    fields_to_apply: List[str]  # Which fields to update


class ApplyDiscoveryResponse(BaseModel):
    """Response after applying discovered data"""
    asset_id: int
    updated_fields: List[str]
    skipped_fields: List[str]  # Already had data
    message: str


class AssetMatchResponse(BaseModel):
    """Response when checking if IP matches an existing asset"""
    found: bool
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    empty_fields: List[str] = []  # Fields that can be filled
    current_values: Dict[str, Optional[str]] = {}


class CreateAssetFromDiscoveryRequest(BaseModel):
    """Request to create new asset from discovered host"""
    discovered_host: DiscoveredHost
    asset_name: str  # User must provide name
    asset_type_id: int  # User must select type