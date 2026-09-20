"""Topology Service - graph assembly, link CRUD, and basic validation checks."""
from collections import defaultdict
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models import Asset, TopologyLink, TopologyNodePosition
from app.modules.topology.schemas import TopologyFinding


class TopologyService:
    """Topology Management Service."""

    @staticmethod
    def get_nodes(db: Session):
        """All assets, as topology nodes."""
        return db.query(Asset).all()

    @staticmethod
    def get_links(db: Session):
        return db.query(TopologyLink).all()

    @staticmethod
    def get_hosted_edges(db: Session) -> list[dict]:
        """Dashed logical edges from a server to each VM/Application/Database
        it hosts, computed at read time from Asset.hosted_on_asset_id - never
        persisted as a TopologyLink (a real cabled link), and always
        consistent with the asset inventory with no separate sync step.

        Shaped like a TopologyLinkSummary so the frontend can treat both link
        kinds uniformly, distinguished by link_type == "hosted"; `id` is the
        hosted asset's own id negated, which can never collide with a real
        TopologyLink's positive id and has nothing in the DB to edit/delete."""
        hosted = db.query(Asset).filter(Asset.hosted_on_asset_id.isnot(None)).all()
        return [
            {
                "id": -asset.id,
                "source_asset_id": asset.hosted_on_asset_id,
                "destination_asset_id": asset.id,
                "source_interface": None,
                "destination_interface": None,
                "link_type": "hosted",
                "speed_mbps": None,
                "vlan": asset.hosted_vlan,
                "subnet": None,
                "status": "active",
                "created_at": None,
                "updated_at": None,
            }
            for asset in hosted
        ]

    @staticmethod
    def get_positions(db: Session) -> dict[int, TopologyNodePosition]:
        """asset_id -> saved position, for the assets that have been dragged
        at least once."""
        rows = db.query(TopologyNodePosition).all()
        return {row.asset_id: row for row in rows}

    @staticmethod
    def save_position(db: Session, asset_id: int, pos_x: float, pos_y: float) -> TopologyNodePosition:
        """Upsert - one row per asset, overwritten on every drag-stop."""
        row = (
            db.query(TopologyNodePosition)
            .filter(TopologyNodePosition.asset_id == asset_id)
            .first()
        )
        if row:
            row.pos_x = pos_x
            row.pos_y = pos_y
            row.updated_at = datetime.utcnow()
        else:
            row = TopologyNodePosition(asset_id=asset_id, pos_x=pos_x, pos_y=pos_y)
            db.add(row)
        db.commit()
        db.refresh(row)
        return row

    @staticmethod
    def get_link(db: Session, link_id: int) -> Optional[TopologyLink]:
        return db.query(TopologyLink).filter(TopologyLink.id == link_id).first()

    @staticmethod
    def create_link(db: Session, data: dict, user_id: Optional[int]) -> TopologyLink:
        link = TopologyLink(**data, created_by=user_id)
        db.add(link)
        db.commit()
        db.refresh(link)
        return link

    @staticmethod
    def update_link(db: Session, link: TopologyLink, changes: dict) -> TopologyLink:
        for field, value in changes.items():
            setattr(link, field, value)
        db.commit()
        db.refresh(link)
        return link

    @staticmethod
    def delete_link(db: Session, link: TopologyLink) -> None:
        db.delete(link)
        db.commit()

    # ==========================================
    # Validation
    # ==========================================

    @staticmethod
    def validate(db: Session) -> list[TopologyFinding]:
        """Lightweight structural checks over the current topology graph.

        Two checks for now: assets with no link at all (orphan nodes), and
        assets with exactly one link (single point of failure / no redundancy).
        Both are informational, not blocking - Architecture Validation covers
        richer, rule-driven checks.
        """
        assets = db.query(Asset).all()
        links = db.query(TopologyLink).filter(TopologyLink.status != "planned").all()

        degree = defaultdict(int)
        for link in links:
            degree[link.source_asset_id] += 1
            degree[link.destination_asset_id] += 1
        # A hosted-on relationship is a real connection too (to its host),
        # even though it isn't a cabled TopologyLink - without this, every
        # VM/Application/Database asset would wrongly show up as an
        # "orphan_node" the moment it's given a required host.
        for asset in assets:
            if asset.hosted_on_asset_id is not None:
                degree[asset.id] += 1
                degree[asset.hosted_on_asset_id] += 1

        findings: list[TopologyFinding] = []
        for asset in assets:
            asset_degree = degree.get(asset.id, 0)
            if asset_degree == 0:
                findings.append(
                    TopologyFinding(
                        code="orphan_node",
                        severity="low",
                        asset_id=asset.id,
                        asset_name=asset.asset_name,
                        message=f"'{asset.asset_name}' has no topology links.",
                    )
                )
            elif asset_degree == 1:
                findings.append(
                    TopologyFinding(
                        code="single_link",
                        severity="medium",
                        asset_id=asset.id,
                        asset_name=asset.asset_name,
                        message=f"'{asset.asset_name}' has only one link (no redundancy).",
                    )
                )

        return findings
