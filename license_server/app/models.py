from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum as SQLEnum, Index
from sqlalchemy.sql import func
from .database import Base
import enum

class PlanType(str, enum.Enum):
    PILOT = "pilot"           # تست 1 ماهه
    BASIC1 = "basic1"         # شبکه کوچک - 15 دستگاه
    BASIC2 = "basic2"         # شبکه متوسط - 50 دستگاه
    BASIC3 = "basic3"         # شبکه بزرگ - 150 دستگاه
    ENTERPRISE = "enterprise" # نامحدود

class License(Base):
    __tablename__ = "licenses"
    
    __table_args__ = (
        Index('idx_license_key_active', 'license_key', 'is_active'),
        Index('idx_org_token_active', 'organization_token', 'is_active'),
        Index('idx_expires_at', 'expires_at'),
        Index('idx_last_heartbeat', 'last_heartbeat_at'),
    )
    
    id = Column(Integer, primary_key=True, index=True)
    license_key = Column(String, unique=True, index=True, nullable=False)
    organization_token = Column(String, unique=True, index=True, nullable=False)
    
    customer_name = Column(String, nullable=False)
    customer_email = Column(String, nullable=False)
    organization_name = Column(String, nullable=False)
    
    plan_type = Column(SQLEnum(PlanType), nullable=False)
    
    # محدودیت‌های عملیاتی
    max_assets = Column(Integer, nullable=True)  # null = unlimited
    max_discoveries = Column(Integer, nullable=True)
    max_audits = Column(Integer, nullable=True)
    max_hardens = Column(Integer, nullable=True)
    max_monitors = Column(Integer, nullable=True)
    
    # مصرف فعلی
    used_assets = Column(Integer, default=0)
    used_discoveries = Column(Integer, default=0)
    used_audits = Column(Integer, default=0)
    used_hardens = Column(Integer, default=0)
    used_monitors = Column(Integer, default=0)
    
    # VM fingerprint برای قفل شدن روی یک ماشین
    vm_fingerprint = Column(String, nullable=True)
    
    is_active = Column(Boolean, default=True)
    is_pilot_mode = Column(Boolean, default=False)  # آیا در حالت Pilot است؟
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_validated_at = Column(DateTime(timezone=True), nullable=True)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
