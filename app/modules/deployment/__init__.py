"""
Deployment of configuration jobs to devices. Kept for the design pipeline;
its router is not mounted (no page uses it, see app/main.py).
"""
from app.modules.deployment.router import router

__all__ = ["router"]
