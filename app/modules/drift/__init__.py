"""
Configuration drift: live configuration compared with the last backup. Kept
for the design pipeline; its router is not mounted (no page uses it, see app/main.py).
"""
from app.modules.drift.router import router

__all__ = ["router"]
