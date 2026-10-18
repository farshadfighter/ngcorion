"""
API keys for other systems (SIEM, CMDB, scripts) - app/modules/api_keys, checked in
app/core/api_keys.py.

Each key acts through its own service account (a User with auth_source "apikey", role "user", no usable
password): its permission rows are the key's scopes, so every permission and ownership rule of the API
applies to it unchanged, and what it does is attributed to that account in the audit trail. Only the
SHA-256 of the key's secret is stored; the secret is shown once, when the key is made or renewed.
"""
from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text

from app.core.database import Base

AUTH_SOURCE_API_KEY = "apikey"


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    key_id = Column(String(16), nullable=False, unique=True)         # public part: ngk_<key_id>_<secret>
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    secret_hash = Column(String(64), nullable=False)                 # SHA-256 of the secret, hex
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    scopes = Column(JSON, nullable=False, default=list)              # [{"module": "asset_list", "write": false}]
    allowed_ips = Column(JSON, nullable=True)                        # addresses / networks; empty: any
    expires_at = Column(DateTime, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    renewed_at = Column(DateTime, nullable=True)                     # secret replaced
    last_used_at = Column(DateTime, nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
