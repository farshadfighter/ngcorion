"""
Design Router

CRUD for architecture designs, their versions, planned components and the
relationships between them, plus mapping a component to a real asset.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, Asset
from app.modules.design.service import DesignService
from app.modules.design.schemas import (
    DesignSummary,
    DesignCreate,
    DesignDetail,
    DesignVersionSummary,
    DesignVersionCreate,
    DesignVersionDetail,
    ComponentSummary,
    ComponentCreate,
    ComponentUpdate,
    RelationshipSummary,
    RelationshipCreate,
    RelationshipUpdate,
    MapAssetRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/design", tags=["Design"])


def _component_summary(component) -> ComponentSummary:
    mapping = component.asset_mapping
    return ComponentSummary(
        id=component.id,
        design_version_id=component.design_version_id,
        component_type=component.component_type,
        label=component.label,
        notes=component.notes,
        pos_x=component.pos_x,
        pos_y=component.pos_y,
        mapped_asset_id=mapping.asset_id if mapping else None,
        mapped_asset_name=mapping.asset.asset_name if mapping and mapping.asset else None,
    )


@router.get("/", response_model=list[DesignSummary])
def list_designs(
    current_user: User = Depends(require_permission("design_configuration", "read")),
    db: Session = Depends(get_db),
):
    designs = DesignService.list_designs(db)
    return [
        DesignSummary(
            id=d.id, name=d.name, description=d.description, status=d.status,
            created_at=d.created_at, updated_at=d.updated_at,
            latest_version_number=DesignService.latest_version_number(db, d.id),
        )
        for d in designs
    ]


@router.post("/", response_model=DesignSummary, status_code=201)
def create_design(
    request: DesignCreate,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    design = DesignService.create_design(db, request.name, request.description, current_user.id)
    return DesignSummary(
        id=design.id, name=design.name, description=design.description, status=design.status,
        created_at=design.created_at, updated_at=design.updated_at, latest_version_number=1,
    )


@router.get("/{design_id}", response_model=DesignDetail)
def get_design(
    design_id: int,
    current_user: User = Depends(require_permission("design_configuration", "read")),
    db: Session = Depends(get_db),
):
    design = DesignService.get_design(db, design_id)
    if not design:
        raise HTTPException(status_code=404, detail="Design not found")
    return DesignDetail(
        design=DesignSummary(
            id=design.id, name=design.name, description=design.description, status=design.status,
            created_at=design.created_at, updated_at=design.updated_at,
            latest_version_number=DesignService.latest_version_number(db, design.id),
        ),
        versions=design.versions,
    )


@router.post("/{design_id}/versions", response_model=DesignVersionSummary, status_code=201)
def create_version(
    design_id: int,
    request: DesignVersionCreate,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    design = DesignService.get_design(db, design_id)
    if not design:
        raise HTTPException(status_code=404, detail="Design not found")

    clone_from = None
    if request.clone_from_version_id is not None:
        clone_from = DesignService.get_version(db, request.clone_from_version_id)
        if not clone_from or clone_from.design_id != design.id:
            raise HTTPException(status_code=404, detail="Source version not found in this design")

    return DesignService.create_version(db, design, request.notes, current_user.id, clone_from)


@router.get("/versions/{version_id}", response_model=DesignVersionDetail)
def get_version_detail(
    version_id: int,
    current_user: User = Depends(require_permission("design_configuration", "read")),
    db: Session = Depends(get_db),
):
    version = DesignService.get_version(db, version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Design version not found")
    return DesignVersionDetail(
        version=version,
        components=[_component_summary(c) for c in version.components],
        relationships=version.relationships_,
    )


@router.post("/versions/{version_id}/components", response_model=ComponentSummary, status_code=201)
def create_component(
    version_id: int,
    request: ComponentCreate,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    version = DesignService.get_version(db, version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Design version not found")
    component = DesignService.create_component(db, version, request.model_dump())
    return _component_summary(component)


@router.patch("/components/{component_id}", response_model=ComponentSummary)
def update_component(
    component_id: int,
    request: ComponentUpdate,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    component = DesignService.get_component(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    changes = request.model_dump(exclude_unset=True)
    if changes:
        component = DesignService.update_component(db, component, changes)
    return _component_summary(component)


@router.delete("/components/{component_id}", status_code=204)
def delete_component(
    component_id: int,
    current_user: User = Depends(require_permission("design_configuration", "delete")),
    db: Session = Depends(get_db),
):
    component = DesignService.get_component(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    DesignService.delete_component(db, component)


@router.post("/components/{component_id}/map", response_model=ComponentSummary)
def map_component(
    component_id: int,
    request: MapAssetRequest,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    component = DesignService.get_component(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    DesignService.map_component_to_asset(db, component, request.asset_id, current_user.id)
    db.refresh(component)
    return _component_summary(component)


@router.delete("/components/{component_id}/map", status_code=204)
def unmap_component(
    component_id: int,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    component = DesignService.get_component(db, component_id)
    if not component:
        raise HTTPException(status_code=404, detail="Component not found")
    DesignService.unmap_component(db, component)


@router.post("/versions/{version_id}/relationships", response_model=RelationshipSummary, status_code=201)
def create_relationship(
    version_id: int,
    request: RelationshipCreate,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    version = DesignService.get_version(db, version_id)
    if not version:
        raise HTTPException(status_code=404, detail="Design version not found")
    if request.source_component_id == request.destination_component_id:
        raise HTTPException(status_code=400, detail="A relationship cannot connect a component to itself")
    for component_id in (request.source_component_id, request.destination_component_id):
        component = DesignService.get_component(db, component_id)
        if not component or component.design_version_id != version.id:
            raise HTTPException(status_code=404, detail=f"Component {component_id} not found in this version")
    return DesignService.create_relationship(db, version, request.model_dump())


@router.patch("/relationships/{relationship_id}", response_model=RelationshipSummary)
def update_relationship(
    relationship_id: int,
    request: RelationshipUpdate,
    current_user: User = Depends(require_permission("design_configuration", "write")),
    db: Session = Depends(get_db),
):
    relationship = DesignService.get_relationship(db, relationship_id)
    if not relationship:
        raise HTTPException(status_code=404, detail="Relationship not found")
    changes = request.model_dump(exclude_unset=True)
    if changes:
        relationship = DesignService.update_relationship(db, relationship, changes)
    return relationship


@router.delete("/relationships/{relationship_id}", status_code=204)
def delete_relationship(
    relationship_id: int,
    current_user: User = Depends(require_permission("design_configuration", "delete")),
    db: Session = Depends(get_db),
):
    relationship = DesignService.get_relationship(db, relationship_id)
    if not relationship:
        raise HTTPException(status_code=404, detail="Relationship not found")
    DesignService.delete_relationship(db, relationship)
