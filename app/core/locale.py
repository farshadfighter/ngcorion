"""
Interface language.

Each user may pick a language (users.language); without one the system
default from System Configuration > Language applies, else English.
"""
from typing import Optional

from sqlalchemy.orm import Session

LANGUAGES = ("en", "fa")
FALLBACK = "en"


def default_language(db: Session) -> str:
    from app.models.system_config import SECTION_LOCALE, SystemConfigSetting
    row = db.query(SystemConfigSetting).filter(SystemConfigSetting.section == SECTION_LOCALE).first()
    lang = (row.config_json or {}).get("default_language") if row else None
    return lang if lang in LANGUAGES else FALLBACK


def user_language(db: Session, user) -> str:
    lang: Optional[str] = getattr(user, "language", None)
    return lang if lang in LANGUAGES else default_language(db)
