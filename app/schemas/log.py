"""
Response models of the login log.
"""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class LoginLogResponse(BaseModel):
    """One login attempt as the login log lists it."""
    id: int
    username: str
    success: bool
    ip_address: Optional[str]
    user_agent: Optional[str]
    message: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True