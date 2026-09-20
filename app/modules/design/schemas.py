"""Pydantic schemas for the Design module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class DesignSummary(BaseModel):
    id: int
    name: str
    description: Optional[str]
    status: str
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    latest_version_number: Optional[int] = None

    class Config:
        from_attributes = True


class DesignCreate(BaseModel):
    name: str
    description: Optional[str] = None
    # Optional: populate the auto-created version 1 from a standard template
    # (see app/modules/design/templates.py) instead of leaving it empty.
    template_id: Optional[str] = None
    template_scale: str = "medium"


class DesignTemplateInfo(BaseModel):
    id: str
    name: str
    description: str
    framework: str


class DesignTemplateScale(BaseModel):
    id: str
    label: str


class DesignVersionSummary(BaseModel):
    id: int
    design_id: int
    version_number: int
    notes: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class DesignVersionCreate(BaseModel):
    notes: Optional[str] = None
    clone_from_version_id: Optional[int] = None


class ComponentSummary(BaseModel):
    id: int
    design_version_id: int
    component_type: str
    label: str
    notes: Optional[str]
    pos_x: float
    pos_y: float
    mapped_asset_id: Optional[int] = None
    mapped_asset_name: Optional[str] = None

    class Config:
        from_attributes = True


class ComponentCreate(BaseModel):
    component_type: str = "server"
    label: str
    notes: Optional[str] = None
    pos_x: float = 0
    pos_y: float = 0


class ComponentUpdate(BaseModel):
    component_type: Optional[str] = None
    label: Optional[str] = None
    notes: Optional[str] = None
    pos_x: Optional[float] = None
    pos_y: Optional[float] = None


class RelationshipSummary(BaseModel):
    id: int
    design_version_id: int
    source_component_id: int
    destination_component_id: int
    source_interface: Optional[str]
    destination_interface: Optional[str]
    link_type: str
    vlan: Optional[str]
    subnet: Optional[str]

    class Config:
        from_attributes = True


class RelationshipCreate(BaseModel):
    source_component_id: int
    destination_component_id: int
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    link_type: str = "ethernet"
    vlan: Optional[str] = None
    subnet: Optional[str] = None


class RelationshipUpdate(BaseModel):
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    link_type: Optional[str] = None
    vlan: Optional[str] = None
    subnet: Optional[str] = None


class MapAssetRequest(BaseModel):
    asset_id: int


class DesignVersionDetail(BaseModel):
    version: DesignVersionSummary
    components: list[ComponentSummary]
    relationships: list[RelationshipSummary]


class DesignDetail(BaseModel):
    design: DesignSummary
    versions: list[DesignVersionSummary]
