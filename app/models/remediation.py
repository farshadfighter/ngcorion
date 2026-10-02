"""
Remediation tracking and risk acceptance.

  RemediationItem   one open problem on one asset, from any module: a CVE
                    finding, a failed audit check (latest completed audit) or
                    an architecture finding. Carries the owner, the deadline
                    (from the SLA for its severity) and its workflow state:
                    open -> in_progress -> pending_verification -> resolved.
                    "resolved" is only ever set by the sync, when the source
                    no longer reports the problem; a problem that comes back
                    reopens the same row. "accepted" while an approved risk
                    acceptance covers it.
  RemediationEvent  the item's history (created, assigned, status, notes...).
  RiskAcceptance    an exception: why the problem stays, the compensating
                    control and until when. Covers one item, or one CVE /
                    audit check / architecture rule on every asset. Must be
                    approved by someone other than the requester; accepted
                    findings leave the risk score until the acceptance ends.

The sync that keeps the items in step with the modules lives in
app/modules/remediation/service.py.
"""
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.core.database import Base

SOURCES = ("cve", "audit", "arch")
SEVERITIES = ("critical", "high", "medium", "low")

ITEM_OPEN = "open"
ITEM_IN_PROGRESS = "in_progress"
ITEM_PENDING = "pending_verification"
ITEM_RESOLVED = "resolved"
ITEM_ACCEPTED = "accepted"
ITEM_STATUSES = (ITEM_OPEN, ITEM_IN_PROGRESS, ITEM_PENDING, ITEM_RESOLVED, ITEM_ACCEPTED)
# Still needing work (counted as "open" on the page and for deadlines).
ITEM_ACTIVE = (ITEM_OPEN, ITEM_IN_PROGRESS, ITEM_PENDING)

ACCEPT_PENDING = "pending"
ACCEPT_APPROVED = "approved"
ACCEPT_REJECTED = "rejected"
ACCEPT_EXPIRED = "expired"
ACCEPT_REVOKED = "revoked"
ACCEPT_STATUSES = (ACCEPT_PENDING, ACCEPT_APPROVED, ACCEPT_REJECTED, ACCEPT_EXPIRED, ACCEPT_REVOKED)

SCOPE_ITEM = "item"      # this finding only
SCOPE_REF = "ref"        # this CVE / check / rule on every asset


class RemediationItem(Base):
    __tablename__ = "remediation_items"

    id = Column(Integer, primary_key=True)
    # "cve:<asset>:<CVE id>", "audit:<asset>:<check>[:<vdom>]", "arch:<asset>:<rule>"
    key = Column(String(255), nullable=False, unique=True)
    source = Column(String(10), nullable=False, index=True)
    ref = Column(String(100), nullable=False, index=True)          # CVE id, check number, rule code
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_name = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    title = Column(Text, nullable=False)
    detail = Column(JSON, nullable=True)                            # source-specific facts for the page
    severity = Column(String(10), nullable=False, default="medium")
    kev = Column(Boolean, nullable=False, default=False)

    status = Column(String(24), nullable=False, default=ITEM_OPEN, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    due_at = Column(DateTime, nullable=True)
    due_custom = Column(Boolean, nullable=False, default=False)     # set by a person, not the SLA
    acceptance_id = Column(Integer, ForeignKey("risk_acceptances.id", ondelete="SET NULL", use_alter=True,
                                               name="fk_remediation_items_acceptance"), nullable=True)

    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    closed_reason = Column(String(40), nullable=True)               # fixed | asset_deleted | accepted_in_source
    reopened = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (Index("ix_remediation_items_status_due", "status", "due_at"),)


class RemediationEvent(Base):
    __tablename__ = "remediation_events"

    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=False, index=True)
    at = Column(DateTime, nullable=False, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kind = Column(String(30), nullable=False)
    data = Column(JSON, nullable=True)


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"

    id = Column(Integer, primary_key=True)
    scope = Column(String(10), nullable=False, default=SCOPE_ITEM)
    source = Column(String(10), nullable=False)
    ref = Column(String(100), nullable=False, index=True)
    item_id = Column(Integer, ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=True, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), nullable=True)
    title = Column(Text, nullable=False)                            # snapshot for the register
    severity = Column(String(10), nullable=False)
    kev = Column(Boolean, nullable=False, default=False)

    justification = Column(Text, nullable=False)
    compensating_control = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String(12), nullable=False, default=ACCEPT_PENDING, index=True)

    requested_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    decided_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision_note = Column(Text, nullable=True)
    ended_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ended_at = Column(DateTime, nullable=True)
