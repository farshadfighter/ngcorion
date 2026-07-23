"""
ORM model for ``cis_audit_results``.

Stores per-check results emitted by the self-contained CIS benchmark services
(``app/cis/services/*``). Each :class:`app.cis.base.CISResult` produced by an
audit maps to one row here, tagged with the host and service it came from.

The foreign key targets ``asset_inventory`` (the project's real asset table).
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.sql import func, text

from app.core.database import Base


class CISAuditResult(Base):
    __tablename__ = "cis_audit_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        nullable=False,
        index=True,  # -> ix_cis_audit_results_host_id
    )
    check_id = Column(String(20), nullable=False)      # e.g. "2.1"
    check_title = Column(String(255), nullable=False)
    service = Column(String(50), nullable=False)       # e.g. "mongodb"
    section = Column(String(10), nullable=False)       # e.g. "2", "3.1"
    scored = Column(Boolean, nullable=False, server_default=text("true"), default=True)
    status = Column(String(10), nullable=False)        # pass / fail / error / skipped
    current_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)
    fix_applied = Column(Boolean, nullable=False, server_default=text("false"), default=False)
    error_msg = Column(Text, nullable=True)
    audited_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    fixed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_cis_audit_results_host_service", "host_id", "service"),
        Index("ix_cis_audit_results_host_status", "host_id", "status"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host_id": self.host_id,
            "check_id": self.check_id,
            "check_title": self.check_title,
            "service": self.service,
            "section": self.section,
            "scored": self.scored,
            "status": self.status,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "fix_applied": self.fix_applied,
            "error_msg": self.error_msg,
            "audited_at": self.audited_at.isoformat() if self.audited_at else None,
            "fixed_at": self.fixed_at.isoformat() if self.fixed_at else None,
        }
