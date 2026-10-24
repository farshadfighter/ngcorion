"""
Architecture validation: the topology checked against Cisco SAFE (segmentation
between places in the network, the edge, management, redundancy).
"""
from app.modules.architecture_validation.router import router

__all__ = ["router"]
