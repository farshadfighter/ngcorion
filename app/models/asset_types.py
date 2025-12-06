"""
Asset Types Model

این Model انواع مختلف asset ها را تعریف می‌کند.
مثل: Firewall, Router, Switch, Server و ...

این جدول مشترک بین همه کاربران است.
"""

from sqlalchemy import Column, Integer, String, Text
from app.core.database import Base


class AssetType(Base):
    """
    جدول انواع Asset
    
    این جدول لیست انواع دستگاه‌ها/نرم‌افزارها را نگه می‌دارد.
    مثلاً: Firewall, Router, Switch, Server
    
    Attributes:
        id: شناسه یکتا (خودکار)
        type_name: نام نوع asset (مثلاً: Firewall)
        category: دسته‌بندی (مثلاً: Security, Network, Infrastructure)
        description: توضیحات اختیاری
    
    مثال:
        type = AssetType(
            type_name="Firewall",
            category="Security",
            description="Network security device"
        )
    """
    
    __tablename__ = "asset_types"
    
    # ====================================
    # ستون‌ها
    # ====================================
    
    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True,
        comment="Unique identifier"
    )
    
    type_name = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        comment="نام نوع asset (مثلاً Firewall)"
    )
    
    category = Column(
        String(50),
        nullable=False,
        index=True,  # برای فیلتر کردن بر اساس دسته
        comment="دسته‌بندی (Security, Network, Infrastructure, ...)"
    )
    
    description = Column(
        Text,
        nullable=True,
        comment="توضیحات اختیاری"
    )
    
    
    # ====================================
    # متد کمکی برای نمایش
    # ====================================
    
    def __repr__(self):
        """نمایش خوانا برای debugging"""
        return f"<AssetType(id={self.id}, name='{self.type_name}', category='{self.category}')>"
    
    
    def __str__(self):
        """نمایش ساده"""
        return f"{self.type_name} ({self.category})"

