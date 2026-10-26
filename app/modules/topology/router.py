"""
Topology Router

API endpoints for the network topology graph (assets as nodes, cabled links
between them) and a lightweight structural validation pass.
"""
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, Asset, TopologyLink
from app.models.topology import TopologyCloud, TopologyCloudLink
from app.models.topology_log import (
    TopologyLog,
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
    TopologyCloudIn,
    TopologyCloudOut,
    TopologyCloudLinkIn,
    TopologyCloudLinkOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/topology", tags=["Topology"])


@router.get("/", response_model=TopologyGraph)
def get_topology(
    current_user: User = Depends(require_permission("topology", "read")),
    db: Session = Depends(get_db),
):
    """Full topology graph: every asset as a node, every link between them,
    plus a dashed logical edge for each asset hosted on another (server ->
    VM/Application/Database)."""
    assets = TopologyService.get_nodes(db)
    links = list(TopologyService.get_links(db)) + TopologyService.get_hosted_edges(db)
    positions = TopologyService.get_positions(db)
    interfaces = TopologyService.get_interfaces(db)

    nodes = [
        TopologyNode(
            id=a.id,
            name=a.asset_name,
            hostname=a.hostname,
            type_name=a.asset_type.type_name if a.asset_type else None,
            icon=a.resolved_icon,
            icon_badge=a.icon_badge,
            ip_address=a.ip_address,
            port_count=getattr(a, "port_count", None),
            interfaces=interfaces.get(a.id),
            pos_x=positions[a.id].pos_x if a.id in positions else None,
            pos_y=positions[a.id].pos_y if a.id in positions else None,
        )
        for a in assets
    ]

    return TopologyGraph(nodes=nodes, links=links,
                         clouds=db.query(TopologyCloud).order_by(TopologyCloud.id).all(),
                         cloud_links=db.query(TopologyCloudLink).order_by(TopologyCloudLink.id).all())


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
    # A link found over LLDP / CDP would be drawn again at the next read; remember it was removed.
    from app.modules.noc.topology_discovery import suppress_link
    suppress_link(db, link)
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


# ── External networks (clouds): not assets, so not inventory and not licensed ──

def _cloud_log(db: Session, user: User, action: str, details: dict) -> None:
    db.add(TopologyLog(user_id=user.id, action=action, details=details, status="success"))
    db.commit()


@router.post("/clouds", response_model=TopologyCloudOut, status_code=201)
def create_cloud(request: TopologyCloudIn, current_user: User = Depends(require_permission("topology", "write")),
                 db: Session = Depends(get_db)):
    """Add an external network (the Internet, MPLS, a WAN, SD-WAN, an LTE/4G backup, a public cloud or a
    partner's network) to the canvas."""
    if not request.kind or not request.label:
        raise HTTPException(status_code=422, detail="Choose the kind of network and give it a name")
    cloud = TopologyCloud(**request.model_dump(), created_by=current_user.id)
    db.add(cloud)
    db.commit()
    db.refresh(cloud)
    _cloud_log(db, current_user, "cloud.create", {"cloud_id": cloud.id, "kind": cloud.kind, "label": cloud.label})
    return cloud


@router.patch("/clouds/{cloud_id}", response_model=TopologyCloudOut)
def update_cloud(cloud_id: int, request: TopologyCloudIn,
                 current_user: User = Depends(require_permission("topology", "write")), db: Session = Depends(get_db)):
    """Rename an external network, change its kind, provider or notes, or move it on the canvas."""
    cloud = db.get(TopologyCloud, cloud_id)
    if cloud is None:
        raise HTTPException(status_code=404, detail="External network not found")
    changes = request.model_dump(exclude_unset=True)
    if "label" in changes and not changes["label"]:
        raise HTTPException(status_code=422, detail="Choose the kind of network and give it a name")
    if "kind" in changes and not changes["kind"]:
        changes.pop("kind")
    for k, v in changes.items():
        setattr(cloud, k, v)
    db.commit()
    db.refresh(cloud)
    if set(changes) - {"pos_x", "pos_y"}:           # a drag is not worth a log line
        _cloud_log(db, current_user, "cloud.update", {"cloud_id": cloud.id, "changes": sorted(changes)})
    return cloud


@router.delete("/clouds/{cloud_id}", status_code=204)
def delete_cloud(cloud_id: int, current_user: User = Depends(require_permission("topology", "delete")),
                 db: Session = Depends(get_db)):
    """Remove an external network and its connections."""
    cloud = db.get(TopologyCloud, cloud_id)
    if cloud is None:
        raise HTTPException(status_code=404, detail="External network not found")
    details = {"cloud_id": cloud.id, "kind": cloud.kind, "label": cloud.label}
    db.query(TopologyCloudLink).filter(TopologyCloudLink.cloud_id == cloud.id).delete()
    db.delete(cloud)
    db.commit()
    _cloud_log(db, current_user, "cloud.delete", details)


@router.post("/cloud-links", response_model=TopologyCloudLinkOut, status_code=201)
def create_cloud_link(request: TopologyCloudLinkIn,
                      current_user: User = Depends(require_permission("topology", "write")),
                      db: Session = Depends(get_db)):
    """Connect a device to an external network (on an interface, with the circuit and its speed)."""
    if request.cloud_id is None or db.get(TopologyCloud, request.cloud_id) is None:
        raise HTTPException(status_code=404, detail="External network not found")
    if request.asset_id is None or db.get(Asset, request.asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    data = request.model_dump()
    data["status"] = data.get("status") or "active"
    link = TopologyCloudLink(**data, created_by=current_user.id)
    db.add(link)
    db.commit()
    db.refresh(link)
    _cloud_log(db, current_user, "cloud_link.create", {"cloud_link_id": link.id, "cloud_id": link.cloud_id,
                                                       "asset_id": link.asset_id})
    return link


@router.patch("/cloud-links/{link_id}", response_model=TopologyCloudLinkOut)
def update_cloud_link(link_id: int, request: TopologyCloudLinkIn,
                      current_user: User = Depends(require_permission("topology", "write")),
                      db: Session = Depends(get_db)):
    """Change a connection's interface, circuit, speed or status."""
    link = db.get(TopologyCloudLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    changes = {k: v for k, v in request.model_dump(exclude_unset=True).items() if k not in ("cloud_id", "asset_id")}
    if "status" in changes and not changes["status"]:
        changes.pop("status")
    for k, v in changes.items():
        setattr(link, k, v)
    db.commit()
    db.refresh(link)
    _cloud_log(db, current_user, "cloud_link.update", {"cloud_link_id": link.id, "changes": sorted(changes)})
    return link


@router.delete("/cloud-links/{link_id}", status_code=204)
def delete_cloud_link(link_id: int, current_user: User = Depends(require_permission("topology", "delete")),
                      db: Session = Depends(get_db)):
    """Disconnect a device from an external network."""
    link = db.get(TopologyCloudLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    details = {"cloud_link_id": link.id, "cloud_id": link.cloud_id, "asset_id": link.asset_id}
    db.delete(link)
    db.commit()
    _cloud_log(db, current_user, "cloud_link.delete", details)
