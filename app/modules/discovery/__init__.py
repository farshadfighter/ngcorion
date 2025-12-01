"""
NGCORION - Auto Discovery Module
app/modules/discovery/__init__.py

Network scanning and asset discovery using nmap.

Usage:
    from app.modules.discovery import router
    app.include_router(router.router)

Requirements:
    pip install python-nmap
    apt install nmap
"""

from . import router
from . import service
from . import schemas

__all__ = ['router', 'service', 'schemas']