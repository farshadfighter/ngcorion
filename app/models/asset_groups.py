"""
Tags, asset groups, credential profiles and group audit runs (app/modules/asset_groups).

- AssetTag: free labels on an asset, many per asset ("pci", "web"); stored trimmed and lower case.
- AssetGroup: a named set of assets, either "static" (members chosen by hand, AssetGroupMember) or
  "dynamic" (rules evaluated each time it is used, so a new asset that matches is in it at once).
- CredentialProfile: device sign-in details defined once by a system administrator and used by
  group runs and scheduled group audits. Write-only: the secrets are encrypted
  (credential_crypto PURPOSE_CREDENTIAL_PROFILES) and never returned; only the user name is shown.
- GroupRun / GroupRunItem: one audit (or configuration backup) of every asset of a group with one
  technology and one profile, a few assets at a time; each asset gets its normal audit session (or
  device backup) plus a line here.
"""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text,
                        UniqueConstraint)
from sqlalchemy.orm import relationship

from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AssetTag(Base):
    __tablename__ = "asset_tags"

    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), primary_key=True)
    tag = Column(String(64), primary_key=True, index=True)


class AssetGroup(Base):
    __tablename__ = "asset_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    kind = Column(String(10), nullable=False, default="dynamic")      # dynamic | static
    # dynamic: [{"field": "type", "op": "eq", "value": 3}, ...], all must hold
    rules = Column(JSON, nullable=False, default=list)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    members = relationship("AssetGroupMember", cascade="all, delete-orphan", passive_deletes=True)


class AssetGroupMember(Base):
    __tablename__ = "asset_group_members"

    group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="CASCADE"), primary_key=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="CASCADE"), primary_key=True, index=True)


class CredentialProfile(Base):
    __tablename__ = "credential_profiles"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True)
    kind = Column(String(20), nullable=False)        # ssh | winrm | mssql | sophos_api
    username = Column(String(256), nullable=False)
    # Encrypted JSON of the secret fields (password, sudo_password, enable_secret, db_password).
    secrets_encrypted = Column(Text, nullable=False)
    # Non-secret options: port, transport, verify_ssl, db_username, db_port.
    options = Column(JSON, nullable=False, default=dict)
    description = Column(Text, nullable=True)
    rotation_days = Column(Integer, nullable=False, default=90)
    secrets_changed_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)


class GroupRun(Base):
    __tablename__ = "group_runs"

    id = Column(Integer, primary_key=True)
    group_id = Column(Integer, ForeignKey("asset_groups.id", ondelete="SET NULL"), nullable=True, index=True)
    group_name = Column(String(120), nullable=False)
    # audit: the technology's audit of each asset; backup: a configuration backup of each asset
    kind = Column(String(10), nullable=False, default="audit", index=True)
    technology = Column(String(40), nullable=False)       # audit technology or device family
    audit_profile = Column(String(40), nullable=True)      # the benchmark level, e.g. L1
    credential_profile_id = Column(Integer, ForeignKey("credential_profiles.id", ondelete="SET NULL"),
                                   nullable=True)
    credential_profile_name = Column(String(120), nullable=True)
    concurrency = Column(Integer, nullable=False, default=10)
    # queued | running | stopping | stopped | done
    status = Column(String(12), nullable=False, default="queued", index=True)
    started_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_by_name = Column(String(150), nullable=True)
    scheduled_job_id = Column(Integer, ForeignKey("scheduled_jobs.id", ondelete="SET NULL"), nullable=True)
    trigger = Column(String(10), nullable=True)          # None | "syslog" (a device reported a change)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    items = relationship("GroupRunItem", cascade="all, delete-orphan", passive_deletes=True,
                         order_by="GroupRunItem.id")


class GroupRunItem(Base):
    __tablename__ = "group_run_items"
    __table_args__ = (UniqueConstraint("run_id", "asset_id", name="uq_group_run_item_asset"),)

    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("group_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("asset_inventory.id", ondelete="SET NULL"), nullable=True)
    asset_name = Column(String(255), nullable=False)
    ip_address = Column(String(64), nullable=True)
    # queued | running | done | failed | skipped | cancelled
    status = Column(String(10), nullable=False, default="queued", index=True)
    # why it failed or was skipped: auth | unreachable | license | unsupported | error | interrupted
    reason = Column(String(20), nullable=True)
    detail = Column(Text, nullable=True)
    session_id = Column(Integer, nullable=True)
    compliance = Column(Float, nullable=True)
    # backup runs: the stored backup, and first | changed | unchanged
    backup_id = Column(Integer, nullable=True)
    outcome = Column(String(12), nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    claimed = Column(Boolean, nullable=False, default=False)
