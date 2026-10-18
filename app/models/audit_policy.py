"""
Organisation policy on the audit benchmarks: which checks the organisation does not require.

A rule names a benchmark (the audit's device type, e.g. "linux") and either one check (its check
number) or a whole level (e.g. "L2"), and decides it is
  optional   recommended but not required: shown, but out of the score and of remediation;
  excluded   not applicable to this organisation: out of the score, remediation and the risk score.
It covers every asset, or the assets of one asset group. A rule only applies once someone other than
the requester has approved it, and until its expiry (when it has one).

AuditSession keeps the module's own score in raw_compliance_pct / raw_weighted_compliance_pct and
compliance_pct / weighted_compliance_pct become the score under the policy, so every page and report
that shows a score follows the policy (app/modules/audit_policy/service.py rescores sessions).
"""
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text

from app.core.database import Base

DECISIONS = ("optional", "excluded")
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_REVOKED = "revoked"
STATUS_EXPIRED = "expired"
STATUSES = (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED, STATUS_REVOKED, STATUS_EXPIRED)


class AuditPolicyRule(Base):
    """One decision of the organisation's benchmark policy (see the module docstring)."""

    __tablename__ = "audit_policy_rules"

    id = Column(Integer, primary_key=True)
    benchmark = Column(String(40), nullable=False, index=True)        # AuditSession.device_type value
    check_number = Column(String(50), nullable=True)                   # one check ...
    level = Column(String(10), nullable=True)                          # ... or a whole level (L2)
    check_title = Column(String(500), nullable=True)                   # snapshot for the list
    severity = Column(String(20), nullable=True)
    decision = Column(String(10), nullable=False)                      # optional | excluded
    group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=True)  # None: all
    reason = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    status = Column(String(10), nullable=False, default=STATUS_PENDING, index=True)
    requested_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    requested_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    decided_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    decision_note = Column(Text, nullable=True)
    ended_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    ended_at = Column(DateTime, nullable=True)
