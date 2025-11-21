from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class LoginLogResponse(BaseModel):
    id: int
    username: str
    success: bool
    ip_address: Optional[str]
    user_agent: Optional[str]
    message: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True