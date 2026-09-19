"""
Architecture Finding Model

Stores the results of an Architecture Validation run: one row per rule that
matched an asset, with a workflow (open -> accepted | ignored) so a finding
doesn't have to be re-triaged on every re-run.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class ArchitectureFinding(Base):
    """One rule violation found for one asset by the Architecture Validation engine."""

    __tablename__ = "architecture_findings"

    id = Column(Integer, primary_key=True, index=True)
    rule_code = Column(String(20), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False, default="medium")  # low | medium | high
    category = Column(String(50), nullable=True)
    recommendation = Column(Text, nullable=True)

    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    asset_name = Column(String(255), nullable=True)

    status = Column(String(20), nullable=False, default="open", index=True)  # open | accepted | ignored
    ignored_reason = Column(Text, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    asset = relationship("Asset", foreign_keys=[asset_id])
    resolver = relationship("User", foreign_keys=[resolved_by])
