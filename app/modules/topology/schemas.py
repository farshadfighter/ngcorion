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
    ip_address: Optional[str] = None
    port_count: Optional[int] = None
    # None means "never dragged" - the frontend falls back to its grid layout.
    pos_x: Optional[float] = None
    pos_y: Optional[float] = None


class TopologyNodePositionUpdate(BaseModel):
    pos_x: float
    pos_y: float


class TopologyLinkSummary(BaseModel):
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
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class TopologyGraph(BaseModel):
    nodes: list[TopologyNode]
    links: list[TopologyLinkSummary]


class TopologyLinkCreate(BaseModel):
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
    findings: list[TopologyFinding]
    asset_count: int
    link_count: int
