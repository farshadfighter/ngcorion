"""
Architecture validation: best-practice rules evaluated against the asset
inventory and topology (redundancy, exposure, segmentation).
"""
from app.modules.architecture_validation.router import router

__all__ = ["router"]
