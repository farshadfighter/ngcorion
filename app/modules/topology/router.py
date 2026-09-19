"""
Topology Router

API endpoints for the network topology graph (assets as nodes, cabled links
between them) and a lightweight structural validation pass.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User, Asset, TopologyLink
from app.models.topology_log import (
    log_topology_link_created,
    log_topology_link_updated,
    log_topology_link_deleted,
)
from app.modules.topology.service import TopologyService
from app.modules.topology.schemas import (
    TopologyGraph,
    TopologyNode,
    TopologyNodePositionUpdate,
    TopologyLinkSummary,
    TopologyLinkCreate,
    TopologyLinkUpdate,
    TopologyValidationResult,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/topology", tags=["Topology"])


@router.get("/", response_model=TopologyGraph)
def get_topology(
    current_user: User = Depends(require_permission("topology", "read")),
    db: Session = Depends(get_db),
):
    """Full topology graph: every asset as a node, every link between them."""
    assets = TopologyService.get_nodes(db)
    links = TopologyService.get_links(db)
    positions = TopologyService.get_positions(db)

    nodes = [
        TopologyNode(
            id=a.id,
            name=a.asset_name,
            hostname=a.hostname,
            type_name=a.asset_type.type_name if a.asset_type else None,
            ip_address=a.ip_address,
            port_count=getattr(a, "port_count", None),
            pos_x=positions[a.id].pos_x if a.id in positions else None,
            pos_y=positions[a.id].pos_y if a.id in positions else None,
        )
        for a in assets
    ]

    return TopologyGraph(nodes=nodes, links=links)


@router.patch("/nodes/{asset_id}/position", status_code=204)
def save_node_position(
    asset_id: int,
    request: TopologyNodePositionUpdate,
    current_user: User = Depends(require_permission("topology", "write")),
    db: Session = Depends(get_db),
):
    """Save where a node was dragged to on the canvas."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    TopologyService.save_position(db, asset_id, request.pos_x, request.pos_y)


@router.post("/links", response_model=TopologyLinkSummary, status_code=201)
def create_link(
    request: TopologyLinkCreate,
    current_user: User = Depends(require_permission("topology", "write")),
    db: Session = Depends(get_db),
):
    """Create a link between two assets."""
    if request.source_asset_id == request.destination_asset_id:
        raise HTTPException(status_code=400, detail="A link cannot connect an asset to itself")

    source = db.query(Asset).filter(Asset.id == request.source_asset_id).first()
    if not source:
        raise HTTPException(status_code=404, detail="Source asset not found")
    destination = db.query(Asset).filter(Asset.id == request.destination_asset_id).first()
    if not destination:
        raise HTTPException(status_code=404, detail="Destination asset not found")

    link = TopologyService.create_link(db, request.model_dump(), current_user.id)
    log_topology_link_created(db, current_user.id, link.id, link.source_asset_id, link.destination_asset_id)
    return link


@router.patch("/links/{link_id}", response_model=TopologyLinkSummary)
def update_link(
    link_id: int,
    request: TopologyLinkUpdate,
    current_user: User = Depends(require_permission("topology", "write")),
    db: Session = Depends(get_db),
):
    """Update a link's metadata (interfaces, type, speed, VLAN, subnet, status)."""
    link = TopologyService.get_link(db, link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Topology link not found")

    changes = request.model_dump(exclude_unset=True)
    if not changes:
        return link

    link = TopologyService.update_link(db, link, changes)
    log_topology_link_updated(db, current_user.id, link.id, changes)
    return link


@router.delete("/links/{link_id}", status_code=204)
def delete_link(
    link_id: int,
    current_user: User = Depends(require_permission("topology", "delete")),
    db: Session = Depends(get_db),
):
    """Remove a link."""
    link = TopologyService.get_link(db, link_id)
    if not link:
        raise HTTPException(status_code=404, detail="Topology link not found")

    link_id_for_log = link.id
    TopologyService.delete_link(db, link)
    log_topology_link_deleted(db, current_user.id, link_id_for_log)


@router.post("/validate", response_model=TopologyValidationResult)
def validate_topology(
    current_user: User = Depends(require_permission("topology", "read")),
    db: Session = Depends(get_db),
):
    """Run the structural validation pass (orphan nodes, single points of failure)."""
    findings = TopologyService.validate(db)
    asset_count = db.query(Asset).count()
    link_count = db.query(TopologyLink).count()
    return TopologyValidationResult(findings=findings, asset_count=asset_count, link_count=link_count)
