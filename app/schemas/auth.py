from pydantic import BaseModel

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class TokenData(BaseModel):
    """Schema برای داده‌های داخل توکن (اختیاری)"""
    username: str | None = None
    role: str | None = None