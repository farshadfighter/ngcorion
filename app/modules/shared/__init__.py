"""
Shared Module

Shared infrastructure for multi-platform hardening operations.
Contains schema-driven router and validation utilities.
"""
from . import schemas
from .hardening_router import router as hardening_router

__all__ = [
    "schemas",
    "hardening_router",
]
