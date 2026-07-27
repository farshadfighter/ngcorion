"""
Risk & Exposure Intelligence Models

Tables backing the risk module: configurable settings/weights, network risk
zones, per-asset risk profiles (criticality + zone), observed open ports,
computed risk scores, score history, and calculation logs.

Note: asset FKs reference asset_inventory.id (the Asset model's table).
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Boolean,
    Numeric,
    JSON,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


# Configurable risk engine settings (weights, severity scores, defaults)
class RiskSetting(Base):
    __tablename__ = "risk_settings"

    id = Column(Integer, primary_key=True, index=True)
    setting_key = Column(String(100), unique=True, index=True, nullable=False)
    setting_value = Column(String(255), nullable=False)
    value_type = Column(String(20), nullable=False)  # int, float, bool, string
    description = Column(String(500), nullable=True)
    is_editable = Column(Boolean, default=True, nullable=False)
    updated_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


# Network risk zones (DMZ, Internal, Internet-facing, ...)
class RiskZone(Base):
    __tablename__ = "risk_zones"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(500), nullable=True)
    score = Column(Numeric(5, 2), nullable=False)  # 0-100 exposure score
    status = Column(String(30), default="active", nullable=False)  # active, disabled
    created_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    risk_profiles = relationship("AssetRiskProfile", back_populates="zone")


# Per-asset risk inputs: business criticality + assigned network zone
class AssetRiskProfile(Base):
    __tablename__ = "asset_risk_profiles"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    criticality_level = Column(String(30), nullable=False)  # low, medium, high, critical
    criticality_score = Column(Numeric(5, 2), nullable=False)
    zone_id = Column(
        Integer, ForeignKey("risk_zones.id", ondelete="SET NULL"), nullable=True
    )
    # True while the value is a system default, not an explicit operator choice
    criticality_is_default = Column(Boolean, default=True, nullable=False)
    zone_is_default = Column(Boolean, default=True, nullable=False)
    created_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    updated_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    asset = relationship("Asset", backref="risk_profile")
    zone = relationship("RiskZone", back_populates="risk_profiles")


# Observed open ports per asset (from discovery scans or manual entry)
class AssetOpenPort(Base):
    __tablename__ = "asset_open_ports"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    ip_address = Column(String(50), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(20), nullable=False)  # tcp, udp
    service_name = Column(String(100), nullable=True)
    severity = Column(String(20), default="medium", nullable=False)
    severity_score = Column(Integer, nullable=False)
    status = Column(String(30), default="open", nullable=False)  # open, closed
    source = Column(String(50), nullable=True)  # discovery, manual, import
    first_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_approved = Column(Boolean, default=False, nullable=False)
    is_included_in_risk = Column(Boolean, default=True, nullable=False)
    exclusion_reason = Column(String(500), nullable=True)
    updated_by = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "ip_address", "port", "protocol",
            name="uq_asset_open_ports_asset_ip_port_proto",
        ),
        Index("ix_asset_open_ports_asset_status", "asset_id", "status"),
        Index(
            "ix_asset_open_ports_asset_included", "asset_id", "is_included_in_risk"
        ),
    )

    asset = relationship("Asset", backref="open_ports")


# Latest computed risk score per asset (one row per asset, upserted)
class AssetRiskScore(Base):
    __tablename__ = "asset_risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )

    # Criticality factor
    criticality_level = Column(String(30), nullable=True)
    criticality_score = Column(Numeric(5, 2), nullable=True)
    criticality_weight = Column(Numeric(5, 2), nullable=True)
    criticality_contribution = Column(Numeric(5, 2), nullable=True)

    # Zone factor
    zone_id = Column(
        Integer, ForeignKey("risk_zones.id", ondelete="SET NULL"), nullable=True
    )
    zone_name = Column(String(100), nullable=True)
    zone_score = Column(Numeric(5, 2), nullable=True)
    zone_weight = Column(Numeric(5, 2), nullable=True)
    zone_contribution = Column(Numeric(5, 2), nullable=True)

    # Open-port factor
    open_port_raw_score = Column(Numeric(8, 2), nullable=True)
    open_port_score = Column(Numeric(5, 2), nullable=True)
    open_port_weight = Column(Numeric(5, 2), nullable=True)
    open_port_contribution = Column(Numeric(5, 2), nullable=True)

    # Audit factor
    audit_failed_weight = Column(Numeric(8, 2), nullable=True)
    audit_applicable_weight = Column(Numeric(8, 2), nullable=True)
    audit_risk_score = Column(Numeric(5, 2), nullable=True)
    audit_weight = Column(Numeric(5, 2), nullable=True)
    audit_contribution = Column(Numeric(5, 2), nullable=True)

    # Result
    final_risk_score = Column(Numeric(5, 2), nullable=True)
    risk_level = Column(String(20), nullable=True)  # low, medium, high, critical

    # Counts
    critical_findings_count = Column(Integer, default=0, nullable=False)
    high_findings_count = Column(Integer, default=0, nullable=False)
    medium_findings_count = Column(Integer, default=0, nullable=False)
    low_findings_count = Column(Integer, default=0, nullable=False)
    open_ports_count = Column(Integer, default=0, nullable=False)
    risky_ports_count = Column(Integer, default=0, nullable=False)
    resolved_by_hardening_count = Column(Integer, default=0, nullable=False)
    active_audit_findings_count = Column(Integer, default=0, nullable=False)

    # Meta
    incomplete_data = Column(Boolean, default=False, nullable=False)
    incomplete_reasons_json = Column(JSON, nullable=True)
    audit_id = Column(Integer, nullable=True)  # audit_sessions.id used as input
    calculated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_asset_risk_scores_final_desc", final_risk_score.desc()),
        Index("ix_asset_risk_scores_risk_level", "risk_level"),
    )

    asset = relationship("Asset", backref="risk_score")
    zone = relationship("RiskZone")


# Time series of computed scores per asset
class AssetRiskHistory(Base):
    __tablename__ = "asset_risk_history"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    risk_score = Column(Numeric(5, 2), nullable=False)
    risk_level = Column(String(20), nullable=False)

    criticality_score = Column(Numeric(5, 2), nullable=True)
    zone_score = Column(Numeric(5, 2), nullable=True)
    open_port_score = Column(Numeric(5, 2), nullable=True)
    audit_risk_score = Column(Numeric(5, 2), nullable=True)

    criticality_contribution = Column(Numeric(5, 2), nullable=True)
    zone_contribution = Column(Numeric(5, 2), nullable=True)
    open_port_contribution = Column(Numeric(5, 2), nullable=True)
    audit_contribution = Column(Numeric(5, 2), nullable=True)

    audit_id = Column(Integer, nullable=True)
    reason = Column(String(255), nullable=True)  # what triggered the recalculation
    calculated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index(
            "ix_asset_risk_history_asset_calculated", "asset_id", calculated_at.desc()
        ),
    )

    asset = relationship("Asset", backref="risk_history")


# Per-run calculation log for debugging/traceability
class RiskCalculationLog(Base):
    __tablename__ = "risk_calculation_logs"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(
        Integer,
        ForeignKey("asset_inventory.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    calculation_status = Column(String(30), nullable=False)  # success, failed, partial
    input_json = Column(JSON, nullable=True)
    output_json = Column(JSON, nullable=True)
    error_message = Column(String(2000), nullable=True)
    trigger_type = Column(String(50), nullable=False)  # audit, port_change, manual, ...
    trigger_reference_id = Column(Integer, nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
