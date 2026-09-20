"""Design Service - designs, versions, components, relationships, asset mapping."""
from typing import Optional
from sqlalchemy.orm import Session
from app.models import (
    ArchitectureDesign,
    ArchitectureDesignVersion,
    DesignComponent,
    DesignRelationship,
    DesignAssetMapping,
)
from app.modules.design.templates import build_template


class DesignService:
    """Architecture Design Service."""

    # ==========================================
    # Designs
    # ==========================================

    @staticmethod
    def list_designs(db: Session):
        return db.query(ArchitectureDesign).order_by(ArchitectureDesign.updated_at.desc()).all()

    @staticmethod
    def get_design(db: Session, design_id: int) -> Optional[ArchitectureDesign]:
        return db.query(ArchitectureDesign).filter(ArchitectureDesign.id == design_id).first()

    @staticmethod
    def create_design(db: Session, name: str, description: Optional[str], user_id: Optional[int]) -> ArchitectureDesign:
        design = ArchitectureDesign(name=name, description=description, created_by=user_id)
        db.add(design)
        db.flush()

        version = ArchitectureDesignVersion(design_id=design.id, version_number=1, created_by=user_id)
        db.add(version)
        db.commit()
        db.refresh(design)
        return design

    @staticmethod
    def latest_version_number(db: Session, design_id: int) -> Optional[int]:
        version = (
            db.query(ArchitectureDesignVersion)
            .filter(ArchitectureDesignVersion.design_id == design_id)
            .order_by(ArchitectureDesignVersion.version_number.desc())
            .first()
        )
        return version.version_number if version else None

    # ==========================================
    # Versions
    # ==========================================

    @staticmethod
    def get_version(db: Session, version_id: int) -> Optional[ArchitectureDesignVersion]:
        return db.query(ArchitectureDesignVersion).filter(ArchitectureDesignVersion.id == version_id).first()

    @staticmethod
    def create_version(
        db: Session,
        design: ArchitectureDesign,
        notes: Optional[str],
        user_id: Optional[int],
        clone_from: Optional[ArchitectureDesignVersion] = None,
    ) -> ArchitectureDesignVersion:
        next_number = (DesignService.latest_version_number(db, design.id) or 0) + 1
        new_version = ArchitectureDesignVersion(
            design_id=design.id, version_number=next_number, notes=notes, created_by=user_id
        )
        db.add(new_version)
        db.flush()

        if clone_from is not None:
            component_id_map = {}
            for component in clone_from.components:
                clone = DesignComponent(
                    design_version_id=new_version.id,
                    component_type=component.component_type,
                    label=component.label,
                    notes=component.notes,
                    pos_x=component.pos_x,
                    pos_y=component.pos_y,
                )
                db.add(clone)
                db.flush()
                component_id_map[component.id] = clone.id
                if component.asset_mapping and component.asset_mapping.asset_id:
                    db.add(DesignAssetMapping(design_component_id=clone.id, asset_id=component.asset_mapping.asset_id))

            for relationship in clone_from.relationships_:
                db.add(
                    DesignRelationship(
                        design_version_id=new_version.id,
                        source_component_id=component_id_map[relationship.source_component_id],
                        destination_component_id=component_id_map[relationship.destination_component_id],
                        source_interface=relationship.source_interface,
                        destination_interface=relationship.destination_interface,
                        link_type=relationship.link_type,
                        vlan=relationship.vlan,
                        subnet=relationship.subnet,
                    )
                )

        db.commit()
        db.refresh(new_version)
        return new_version

    @staticmethod
    def apply_template(
        db: Session, version: ArchitectureDesignVersion, template_id: str, scale: str
    ) -> ArchitectureDesignVersion:
        """Populate a (normally just-created, empty) version from a standard
        template - see app/modules/design/templates.py. Each generated
        component/relationship is inserted exactly like a hand-drawn one; the
        template's local "_key" references are resolved to real ids as rows
        are created, then discarded."""
        component_defs, relationship_defs = build_template(template_id, scale)

        key_to_id: dict[str, int] = {}
        for comp in component_defs:
            row = DesignComponent(
                design_version_id=version.id,
                component_type=comp["component_type"],
                label=comp["label"],
                pos_x=comp["pos_x"],
                pos_y=comp["pos_y"],
            )
            db.add(row)
            db.flush()
            key_to_id[comp["_key"]] = row.id

        for rel in relationship_defs:
            db.add(
                DesignRelationship(
                    design_version_id=version.id,
                    source_component_id=key_to_id[rel["_source"]],
                    destination_component_id=key_to_id[rel["_destination"]],
                    link_type=rel["link_type"],
                )
            )

        db.commit()
        db.refresh(version)
        return version

    # ==========================================
    # Components
    # ==========================================

    @staticmethod
    def get_component(db: Session, component_id: int) -> Optional[DesignComponent]:
        return db.query(DesignComponent).filter(DesignComponent.id == component_id).first()

    @staticmethod
    def create_component(db: Session, version: ArchitectureDesignVersion, data: dict) -> DesignComponent:
        component = DesignComponent(design_version_id=version.id, **data)
        db.add(component)
        db.commit()
        db.refresh(component)
        return component

    @staticmethod
    def update_component(db: Session, component: DesignComponent, changes: dict) -> DesignComponent:
        for field, value in changes.items():
            setattr(component, field, value)
        db.commit()
        db.refresh(component)
        return component

    @staticmethod
    def delete_component(db: Session, component: DesignComponent) -> None:
        db.delete(component)
        db.commit()

    @staticmethod
    def map_component_to_asset(db: Session, component: DesignComponent, asset_id: int, user_id: Optional[int]) -> DesignAssetMapping:
        mapping = component.asset_mapping
        if mapping is None:
            mapping = DesignAssetMapping(design_component_id=component.id)
            db.add(mapping)
        mapping.asset_id = asset_id
        mapping.mapped_by = user_id
        db.commit()
        db.refresh(mapping)
        return mapping

    @staticmethod
    def unmap_component(db: Session, component: DesignComponent) -> None:
        if component.asset_mapping is not None:
            db.delete(component.asset_mapping)
            db.commit()

    # ==========================================
    # Relationships
    # ==========================================

    @staticmethod
    def get_relationship(db: Session, relationship_id: int) -> Optional[DesignRelationship]:
        return db.query(DesignRelationship).filter(DesignRelationship.id == relationship_id).first()

    @staticmethod
    def create_relationship(db: Session, version: ArchitectureDesignVersion, data: dict) -> DesignRelationship:
        relationship = DesignRelationship(design_version_id=version.id, **data)
        db.add(relationship)
        db.commit()
        db.refresh(relationship)
        return relationship

    @staticmethod
    def update_relationship(db: Session, relationship: DesignRelationship, changes: dict) -> DesignRelationship:
        for field, value in changes.items():
            setattr(relationship, field, value)
        db.commit()
        db.refresh(relationship)
        return relationship

    @staticmethod
    def delete_relationship(db: Session, relationship: DesignRelationship) -> None:
        db.delete(relationship)
        db.commit()
