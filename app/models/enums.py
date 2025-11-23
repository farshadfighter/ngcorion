"""
ENUM Types برای Asset Management System

این فایل انواع ENUM های مورد نیاز پروژه را تعریف می‌کند.
ENUM ها فیلدهایی هستند که فقط می‌توانند مقادیر مشخصی بگیرند.

مثال: status فقط می‌تواند یکی از این مقادیر باشه:
- active
- standby
- decommissioned  
- unknown
"""

import enum


# ====================================
# 1. وضعیت Asset
# ====================================
class StatusEnum(str, enum.Enum):
    """
    وضعیت فعلی یک asset
    
    مقادیر:
    - ACTIVE: در حال استفاده
    - STANDBY: آماده استفاده (پشتیبان)
    - DECOMMISSIONED: از رده خارج شده
    - UNKNOWN: نامشخص
    """
    ACTIVE = "active"
    STANDBY = "standby"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"


# ====================================
# 2. سطح محرمانگی
# ====================================
class ConfidentialityLevelEnum(str, enum.Enum):
    """
    سطح محرمانگی داده‌های asset
    
    مقادیر:
    - PUBLIC: عمومی
    - INTERNAL: داخلی سازمان
    - CONFIDENTIAL: محرمانه
    - CRITICAL: بسیار حساس
    """
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    CRITICAL = "critical"


# ====================================
# 3. سطح ریسک
# ====================================
class RiskLevelEnum(str, enum.Enum):
    """
    سطح ریسک امنیتی asset
    
    مقادیر:
    - LOW: کم
    - MEDIUM: متوسط
    - HIGH: زیاد
    - CRITICAL: بحرانی
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ====================================
# 4. نوع رابطه (برای asset_dependencies)
# ====================================
class RelationTypeEnum(str, enum.Enum):
    """
    نوع رابطه بین دو asset
    
    مقادیر:
    - NETWORK_LINK: اتصال شبکه‌ای
    - APP_DEPENDENCY: وابستگی نرم‌افزاری
    - BACKUP_LINK: اتصال پشتیبان
    - POWER_SOURCE: منبع تغذیه
    - LOGICAL_CONNECTION: اتصال منطقی
    """
    NETWORK_LINK = "network_link"
    APP_DEPENDENCY = "app_dependency"
    BACKUP_LINK = "backup_link"
    POWER_SOURCE = "power_source"
    LOGICAL_CONNECTION = "logical_connection"


# ====================================
# توضیحات مهم:
# ====================================
"""
چرا از (str, enum.Enum) استفاده کردیم؟

1. enum.Enum: برای ساخت ENUM در Python
2. str: برای اینکه مقادیر رشته باشن (نه عدد)

مثال استفاده:
>>> status = StatusEnum.ACTIVE
>>> print(status.value)
'active'

در SQLAlchemy:
>>> Column(Enum(StatusEnum))
"""