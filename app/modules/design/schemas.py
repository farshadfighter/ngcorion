"""Pydantic schemas for the Design module."""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class DesignSummary(BaseModel):
    """A design as the list shows it, with its newest version number."""
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
    """Body of creating a design, optionally from a standard template and scale."""
    name: str
    description: Optional[str] = None
    # Optional: populate the auto-created version 1 from a standard template
    # (see app/modules/design/templates.py) instead of leaving it empty.
    template_id: Optional[str] = None
    template_scale: str = "medium"


class DesignTemplateInfo(BaseModel):
    """A standard design template the user can start from."""
    id: str
    name: str
    description: str
    framework: str


class DesignTemplateScale(BaseModel):
    """A size a template can be laid out for (small, medium, large)."""
    id: str
    label: str


class DesignVersionSummary(BaseModel):
    """One version of a design."""
    id: int
    design_id: int
    version_number: int
    notes: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class DesignVersionCreate(BaseModel):
    """Body of adding a version: notes and, optionally, the version to copy."""
    notes: Optional[str] = None
    clone_from_version_id: Optional[int] = None


class ComponentSummary(BaseModel):
    """A component on the canvas, with the asset it is mapped to (if any)."""
    id: int
    design_version_id: int
    component_type: str
    label: str
    notes: Optional[str]
    pos_x: float
    pos_y: float
    mapped_asset_id: Optional[int] = None
    mapped_asset_name: Optional[str] = None
    mapped_asset_port_count: Optional[int] = None
    # The mapped asset's own icon/badge, so a mapped component looks exactly
    # like that asset does everywhere else.
    mapped_asset_icon: Optional[str] = None
    mapped_asset_badge: Optional[str] = None

    class Config:
        from_attributes = True


class ComponentCreate(BaseModel):
    """Body of placing a component."""
    component_type: str = "server"
    label: str
    notes: Optional[str] = None
    pos_x: float = 0
    pos_y: float = 0


class ComponentUpdate(BaseModel):
    """Body of changing a component; omitted fields stay as they are."""
    component_type: Optional[str] = None
    label: Optional[str] = None
    notes: Optional[str] = None
    pos_x: Optional[float] = None
    pos_y: Optional[float] = None


class RelationshipSummary(BaseModel):
    """A link between two components."""
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
    """Body of connecting two components."""
    source_component_id: int
    destination_component_id: int
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    link_type: str = "ethernet"
    vlan: Optional[str] = None
    subnet: Optional[str] = None


class RelationshipUpdate(BaseModel):
    """Body of changing a relationship; omitted fields stay as they are."""
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    link_type: Optional[str] = None
    vlan: Optional[str] = None
    subnet: Optional[str] = None


class MapAssetRequest(BaseModel):
    """Body of mapping a component to an asset."""
    asset_id: int


class SuggestedComponent(BaseModel):
    """A component of a suggested design, with the real asset proposed for it."""
    key: str
    component_type: str
    label: str
    pos_x: float
    pos_y: float
    zone: str
    suggested_asset_id: Optional[int] = None
    suggested_asset_name: Optional[str] = None
    suggested_asset_port_count: Optional[int] = None
    suggested_asset_icon: Optional[str] = None
    suggested_asset_badge: Optional[str] = None

    class Config:
        from_attributes = True


class SuggestedRelationship(BaseModel):
    """A link of a suggested design, by component key."""
    source_key: str
    destination_key: str
    link_type: str

    class Config:
        from_attributes = True


class DesignSuggestionResponse(BaseModel):
    """A design suggested from the asset inventory: scale, how many assets matched, components and
    links.
    """
    scale: str
    scale_label: str
    total_assets: int
    matched_assets: int
    components: list[SuggestedComponent]
    relationships: list[SuggestedRelationship]

    class Config:
        from_attributes = True


class DesignVersionDetail(BaseModel):
    """A version with everything drawn on its canvas."""
    version: DesignVersionSummary
    components: list[ComponentSummary]
    relationships: list[RelationshipSummary]


class DesignDetail(BaseModel):
    """A design with all its versions."""
    design: DesignSummary
    versions: list[DesignVersionSummary]
