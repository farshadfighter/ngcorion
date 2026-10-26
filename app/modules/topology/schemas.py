"""Pydantic schemas for the Topology module."""
from typing import Literal, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

CloudKind = Literal["internet", "mpls", "wan", "sdwan", "lte", "public_cloud", "partner"]
LinkStatus = Literal["active", "planned", "down"]


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


class TopologyCloudOut(BaseModel):
    """An external network on the canvas (app/models/topology.py, TopologyCloud)."""
    id: int
    kind: str
    label: str
    provider: Optional[str] = None
    notes: Optional[str] = None
    pos_x: Optional[float] = None
    pos_y: Optional[float] = None

    class Config:
        from_attributes = True


class TopologyCloudLinkOut(BaseModel):
    """A device's connection to an external network."""
    id: int
    cloud_id: int
    asset_id: int
    interface: Optional[str] = None
    circuit_id: Optional[str] = None
    speed_mbps: Optional[int] = None
    status: str = "active"

    class Config:
        from_attributes = True


def _one_line(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    v = v.strip()
    if "\n" in v or "\r" in v:
        raise ValueError("must be one line")
    return v or None


class TopologyCloudIn(BaseModel):
    """Body of adding or changing an external network; omitted fields stay as they are on a change."""
    kind: Optional[CloudKind] = None
    label: Optional[str] = Field(None, max_length=120)
    provider: Optional[str] = Field(None, max_length=120)
    notes: Optional[str] = Field(None, max_length=2000)
    pos_x: Optional[float] = None
    pos_y: Optional[float] = None

    @field_validator("label", "provider")
    @classmethod
    def _one_line_text(cls, v: Optional[str]) -> Optional[str]:
        return _one_line(v)


class TopologyCloudLinkIn(BaseModel):
    """Body of connecting a device to an external network, or changing that connection."""
    cloud_id: Optional[int] = None
    asset_id: Optional[int] = None
    interface: Optional[str] = Field(None, max_length=100)
    circuit_id: Optional[str] = Field(None, max_length=100)
    speed_mbps: Optional[int] = Field(None, ge=0, le=10_000_000)
    status: Optional[LinkStatus] = None

    @field_validator("interface", "circuit_id")
    @classmethod
    def _one_line_text(cls, v: Optional[str]) -> Optional[str]:
        return _one_line(v)


class TopologyGraph(BaseModel):
    """Every asset as a node and every link, and the external networks with their links, for the canvas."""
    nodes: list[TopologyNode]
    links: list[TopologyLinkSummary]
    clouds: list[TopologyCloudOut] = []
    cloud_links: list[TopologyCloudLinkOut] = []


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
