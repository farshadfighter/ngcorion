"""
NGCORION - Auto Discovery Schemas
app/modules/discovery/schemas.py
"""

from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import re


class ScanRequest(BaseModel):
    """
    Request to start a network scan

    Example:
        {
            "job_name": "Production Network Scan",
            "target": "192.168.1.0/24",
            "scan_type": "well_known_ports",
            "ports": "80,443,8080",
            "protocol": "TCP"
        }
    """
    job_name: Optional[str] = None  # User-friendly name for the scan job
    target: str  # IP address, IP range, or CIDR
    scan_type: str = "well_known_ports"  # all_ports, well_known_ports, custom_ports
    ports: Optional[str] = None  # Port specification: "80,443,8080" or "1-1000" (required for custom_ports)
    protocol: str = "TCP"  # TCP, UDP, or BOTH
    
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
        allowed = ['all_ports', 'well_known_ports', 'custom_ports']
        if v not in allowed:
            raise ValueError(f'scan_type must be one of: {allowed}')
        return v

    @field_validator('protocol')
    @classmethod
    def validate_protocol(cls, v):
        allowed = ['TCP', 'UDP', 'BOTH']
        if v.upper() not in allowed:
            raise ValueError(f'protocol must be one of: {allowed}')
        return v.upper()

    @field_validator('ports')
    @classmethod
    def validate_ports(cls, v):
        if v is None:
            return v
        # Allow: "80,443,8080", "1-1000", or single port
        # Validate comma-separated or range
        if ',' in v:
            # Comma-separated: "80,443,8080"
            for port in v.split(','):
                if not port.strip().isdigit() or not (1 <= int(port.strip()) <= 65535):
                    raise ValueError(f'Invalid port: {port}')
        elif '-' in v:
            # Range: "1-1000"
            parts = v.split('-')
            if len(parts) != 2:
                raise ValueError('Port range must be in format: 1-1000')
            start, end = parts
            if not (start.isdigit() and end.isdigit()):
                raise ValueError('Port range must contain only numbers')
            if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                raise ValueError('Ports must be between 1-65535')
            if int(start) >= int(end):
                raise ValueError('Start port must be less than end port')
        else:
            # Single port
            if not v.isdigit() or not (1 <= int(v) <= 65535):
                raise ValueError('Port must be between 1-65535')
        return v


class DiscoveredPort(BaseModel):
    """Information about a discovered port"""
    port: int
    protocol: str  # tcp, udp
    state: str  # open, closed, filtered
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    ostype: Optional[str] = None  # OS type guessed from service detection (-sV)


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
    os_guessed: Optional[str] = None  # OS guessed from service detection (-sV)
    ports: List[DiscoveredPort] = []
    state: str = "up"  # up, down

    # Asset mapping hints
    suggested_asset_type: Optional[str] = None  # server, router, switch, etc.


class ScanResponse(BaseModel):
    """Response from a network scan"""
    scan_id: str
    job_name: Optional[str] = None
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

# ========================================
# Pending Approval Workflow Schemas
# ========================================

class PendingHostResponse(BaseModel):
    """Response schema for discovered host awaiting approval"""
    id: int
    scan_id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_info: Optional[str] = None
    os_accuracy: Optional[int] = None
    os_guessed: Optional[str] = None  # OS guessed from service detection (-sV)
    open_ports: List[DiscoveredPort] = []
    status: str  # pending, approved, rejected, merged
    state: Optional[str] = None  # up, down, unknown
    discovered_at: datetime
    matched_asset_id: Optional[int] = None
    highlight: bool = True  # For UI to show orange highlighting


class PendingHostsListResponse(BaseModel):
    """List of pending discovered hosts"""
    total: int
    pending: List[PendingHostResponse]


class ApproveHostRequest(BaseModel):
    """
    Request to approve a discovered host

    Actions:
    - create_new: Create new asset from discovered data
    - merge_with_existing: Update existing asset (non-destructive)
    """
    action: str  # create_new or merge_with_existing
    asset_id: Optional[int] = None  # Required if action is merge_with_existing
    asset_data: Optional[Dict[str, Any]] = None  # Asset creation data if creating new

    @field_validator('action')
    @classmethod
    def validate_action(cls, v):
        allowed = ['create_new', 'merge_with_existing']
        if v not in allowed:
            raise ValueError(f'action must be one of: {allowed}')
        return v


class ApproveHostResponse(BaseModel):
    """Response after approving a discovered host"""
    success: bool
    asset_id: int
    message: str
    fields_applied: List[str]
    action_taken: str  # created or merged


class RejectHostResponse(BaseModel):
    """Response after rejecting a discovered host"""
    success: bool
    message: str


class BulkApproveRequest(BaseModel):
    """Request to approve multiple hosts at once"""
    host_ids: List[int]
    default_asset_type_id: int
    default_location_id: Optional[int] = None
    default_owner_id: Optional[int] = None


class BulkApproveResponse(BaseModel):
    """Response after bulk approval"""
    success: bool
    approved: int
    created_assets: List[int]
    errors: List[Dict[str, Any]]


class MatchCheckResponse(BaseModel):
    """Response when checking for matching assets"""
    matches_found: bool
    matches: List[Dict[str, Any]]
    recommendation: str  # merge, create_new, or review

    
class ScanListResponse(BaseModel):
    """Response for listing scans"""
    scans: List[Dict[str, Any]]
    total: int


# ========================================
# Configuration Models
# ========================================

class ScanConfigResponse(BaseModel):
    """Available scan configuration options"""
    scan_types: List[str] = ["all_ports", "well_known_ports", "custom_ports"]
    protocols: List[str] = ["TCP", "UDP", "BOTH"]
    port_presets: Dict[str, str] = {
        "common": "80,443,22,21,25,110,143,3306,3389,8080",
        "web": "80,443,8080,8443,8000,8888",
        "database": "3306,5432,1433,1521,27017,6379"
    }


# ========================================
# Port Management Schemas
# ========================================

class PortInfo(BaseModel):
    """Information about a port"""
    port_number: int
    protocol: str  # TCP, UDP
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    state: str = "open"


class AddPortsRequest(BaseModel):
    """Request to add new ports to an asset"""
    asset_id: int
    ports: List[PortInfo]
    scan_id: Optional[str] = None  # Track which scan discovered these ports


class OverwritePortsRequest(BaseModel):
    """Request to overwrite all ports for an asset"""
    asset_id: int
    ports: List[PortInfo]
    scan_id: Optional[str] = None  # Track which scan discovered these ports


class PortManagementResponse(BaseModel):
    """Response after port management operation"""
    success: bool
    asset_id: int
    ports_added: int
    ports_removed: int
    message: str


# ========================================
# Apply Discovery with Modes
# ========================================

class ApplyDiscoveryMode(BaseModel):
    """
    Request to apply discovery results with a specific mode

    Modes:
    - overwrite: Replace all existing data with discovered data
    - merge: Keep existing data + add new discovered data (fill empty fields, add new ports)
    - create_new: Create a new asset with the discovered data
    """
    mode: str  # overwrite, merge, create_new
    host_id: int  # Discovered host ID
    asset_id: Optional[int] = None  # Required for overwrite and merge modes
    # For create_new mode
    asset_name: Optional[str] = None
    asset_type_id: Optional[int] = None
    location_id: Optional[int] = None
    owner_id: Optional[int] = None

    @field_validator('mode')
    @classmethod
    def validate_mode(cls, v):
        allowed = ['overwrite', 'merge', 'create_new']
        if v not in allowed:
            raise ValueError(f'mode must be one of: {allowed}')
        return v


class ApplyDiscoveryModeResponse(BaseModel):
    """Response after applying discovery with mode"""
    success: bool
    mode: str
    asset_id: int
    asset_name: str
    message: str
    # Details about what was applied
    fields_updated: List[str] = []
    fields_overwritten: List[str] = []
    ports_added: int = 0
    ports_removed: int = 0
    # Comparison data for confirmation UI
    before: Optional[Dict[str, Any]] = None
    after: Optional[Dict[str, Any]] = None


class DiscoveryPreviewRequest(BaseModel):
    """Request to preview what changes will be made"""
    host_id: int
    asset_id: Optional[int] = None  # If provided, shows comparison with existing asset


class DiscoveryPreviewResponse(BaseModel):
    """Preview of changes that will be made"""
    host_id: int
    discovered_data: Dict[str, Any]
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    # If asset_id provided, show comparison
    existing_data: Optional[Dict[str, Any]] = None
    # What will happen in each mode
    overwrite_changes: Optional[Dict[str, Any]] = None
    merge_changes: Optional[Dict[str, Any]] = None
    has_existing_data: bool = False
    existing_ports_count: int = 0
    discovered_ports_count: int = 0
