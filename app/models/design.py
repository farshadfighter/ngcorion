"""
Architecture Design Models

A design is a versioned, drawable blueprint of *planned* network components
(DesignComponent) and the links between them (DesignRelationship) - unlike
Topology, whose nodes are always real Asset rows, a design component may not
map to a real asset yet. DesignAssetMapping is that optional link once a
component has been (or will be) built as a real asset.
"""
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class ArchitectureDesign(Base):
    """A named design (blueprint), holding one or more versions."""

    __tablename__ = "architecture_designs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="draft")  # draft | published
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    versions = relationship(
        "ArchitectureDesignVersion", back_populates="design",
        cascade="all, delete-orphan", passive_deletes=True,
        order_by="ArchitectureDesignVersion.version_number",
    )
    creator = relationship("User", foreign_keys=[created_by])


class ArchitectureDesignVersion(Base):
    """One immutable-once-superseded snapshot of a design's components/links."""

    __tablename__ = "architecture_design_versions"
    __table_args__ = (UniqueConstraint("design_id", "version_number", name="uq_design_version_number"),)

    id = Column(Integer, primary_key=True, index=True)
    design_id = Column(Integer, ForeignKey("architecture_designs.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    notes = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    design = relationship("ArchitectureDesign", back_populates="versions")
    components = relationship(
        "DesignComponent", back_populates="design_version",
        cascade="all, delete-orphan", passive_deletes=True,
    )
    relationships_ = relationship(
        "DesignRelationship", back_populates="design_version",
        cascade="all, delete-orphan", passive_deletes=True,
    )


class DesignComponent(Base):
    """One planned device on the design canvas."""

    __tablename__ = "design_components"

    id = Column(Integer, primary_key=True, index=True)
    design_version_id = Column(
        Integer, ForeignKey("architecture_design_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    component_type = Column(String(50), nullable=False, default="server")  # free text, matches DeviceIcon keywords
    label = Column(String(200), nullable=False)
    notes = Column(Text, nullable=True)
    pos_x = Column(Float, nullable=False, default=0)
    pos_y = Column(Float, nullable=False, default=0)

    design_version = relationship("ArchitectureDesignVersion", back_populates="components")
    asset_mapping = relationship(
        "DesignAssetMapping", back_populates="component",
        uselist=False, cascade="all, delete-orphan", passive_deletes=True,
    )


class DesignRelationship(Base):
    """A planned link between two components in the same design version."""

    __tablename__ = "design_relationships"

    id = Column(Integer, primary_key=True, index=True)
    design_version_id = Column(
        Integer, ForeignKey("architecture_design_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_component_id = Column(Integer, ForeignKey("design_components.id", ondelete="CASCADE"), nullable=False)
    destination_component_id = Column(Integer, ForeignKey("design_components.id", ondelete="CASCADE"), nullable=False)
    source_interface = Column(String(50), nullable=True)
    destination_interface = Column(String(50), nullable=True)
    link_type = Column(String(30), nullable=False, default="ethernet")
    vlan = Column(String(20), nullable=True)
    subnet = Column(String(50), nullable=True)

    design_version = relationship("ArchitectureDesignVersion", back_populates="relationships_")
    source_component = relationship("DesignComponent", foreign_keys=[source_component_id])
    destination_component = relationship("DesignComponent", foreign_keys=[destination_component_id])


class DesignAssetMapping(Base):
    """Links a planned component to the real asset that implements it."""

    __tablename__ = "design_asset_mappings"

    id = Column(Integer, primary_key=True, index=True)
    design_component_id = Column(
        Integer, ForeignKey("design_components.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    mapped_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    mapped_at = Column(DateTime, default=datetime.utcnow)

    component = relationship("DesignComponent", back_populates="asset_mapping")
    asset = relationship("Asset", foreign_keys=[asset_id])
