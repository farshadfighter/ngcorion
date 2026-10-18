"""Pydantic schemas for the Topology module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class TopologyNode(BaseModel):
    """An asset as a topology node."""
    id: int
    name: str
    hostname: Optional[str] = None
    type_name: Optional[str] = None
    icon: str = "other"            # app.core.asset_icons key
    icon_badge: Optional[str] = None
    ip_address: Optional[str] = None
    port_count: Optional[int] = None
    # The device's own physical ports from the NOC poll (IF-MIB), in ifIndex order; the canvas draws
    # these instead of its generic port catalog, so links (drawn or found over LLDP/CDP) sit on the
    # real port. None when the asset is not polled over SNMP.
    interfaces: Optional[list[str]] = None
    # None means "never dragged" - the frontend falls back to its grid layout.
    pos_x: Optional[float] = None
    pos_y: Optional[float] = None


class TopologyNodePositionUpdate(BaseModel):
    """Body of moving a node on the topology canvas."""
    pos_x: float
    pos_y: float


class TopologyLinkSummary(BaseModel):
    """A link between two assets."""
    id: int
    source_asset_id: int
    destination_asset_id: int
    source_interface: Optional[str]
    destination_interface: Optional[str]
    link_type: str
    speed_mbps: Optional[int]
    vlan: Optional[str]
    subnet: Optional[str]
    status: str
    origin: str = "manual"                   # manual | lldp | cdp (found in the devices' neighbour tables)
    last_seen_at: Optional[datetime] = None  # when the neighbour tables last showed it
    missing_since: Optional[datetime] = None  # a found link the devices stopped reporting
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class TopologyGraph(BaseModel):
    """Every asset as a node and every link, for the canvas."""
    nodes: list[TopologyNode]
    links: list[TopologyLinkSummary]


class TopologyLinkCreate(BaseModel):
    """Body of linking two assets."""
    source_asset_id: int
    destination_asset_id: int
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    link_type: str = "ethernet"
    speed_mbps: Optional[int] = None
    vlan: Optional[str] = None
    subnet: Optional[str] = None
    status: str = "active"


class TopologyLinkUpdate(BaseModel):
    """Body of changing a link; omitted fields stay as they are."""
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    link_type: Optional[str] = None
    speed_mbps: Optional[int] = None
    vlan: Optional[str] = None
    subnet: Optional[str] = None
    status: Optional[str] = None


class TopologyFinding(BaseModel):
    """One issue found by the topology validation pass."""
    code: str
    severity: str  # low | medium | high
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    message: str


class TopologyValidationResult(BaseModel):
    """Findings of the topology check (isolated nodes, single points of failure)."""
    findings: list[TopologyFinding]
    asset_count: int
    link_count: int
