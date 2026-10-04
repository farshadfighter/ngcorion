"""
Configuration jobs generated from designs. Kept for the design pipeline;
its router is not mounted (no page uses it, see app/main.py).
"""
from app.modules.configuration.router import router

__all__ = ["router"]
