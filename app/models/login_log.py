from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime, timezone
from app.core.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class LoginLog(Base):
    __tablename__ = "login_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True, nullable=False)
    success = Column(Boolean, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    message = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
