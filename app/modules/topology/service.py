"""Topology Service - graph assembly, link CRUD, and basic validation checks."""
from collections import defaultdict
from typing import Optional
from sqlalchemy.orm import Session
from app.models import Asset, TopologyLink
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
