"""
License Middleware

Enforces license validity on all API requests.
Blocks requests to /api/* if license is invalid, except for whitelisted paths.
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.license_state import get_license_state, sync_with_storage


class LicenseMiddleware(BaseHTTPMiddleware):
    """
    Middleware that checks license validity before processing requests.
    
    Passthrough paths (no license check):
    - POST /auth/login
    - GET /health
    - GET /
    - POST /api/license/activate
    - GET /api/license/status
    - POST /api/license/offline/request, /api/license/offline/install
    
    All other /api/* paths require valid license.
    """
    
    PASSTHROUGH_PATHS = {
        "/auth/login",
        "/health",
        "/",
        "/api/license/activate",
        "/api/license/status",
        # Offline (air-gapped) activation, from the same first-run screen.
        "/api/license/offline/request",
        "/api/license/offline/install",
    }
    
    async def dispatch(self, request: Request, call_next):
        """Let the passthrough paths and everything outside /api/ through; answer every other API
        request with 403 (license required) while no valid license is known.
        """
        path = request.url.path
        
        # Allow passthrough paths
        if path in self.PASSTHROUGH_PATHS:
            return await call_next(request)
        
        # Allow non-API paths (e.g., /docs, /openapi.json)
        if not path.startswith("/api/"):
            return await call_next(request)
        
        # Check license state, after loading a change another worker process made (an
        # activation or an offline license file installed there): each worker keeps its own copy.
        sync_with_storage()
        state = get_license_state()
        if not state.valid:
            # Tell an infrastructure problem apart from a licensing problem.
            # "License server unreachable" is a 503 the operator can fix by
            # restoring connectivity; telling them to "activate a license" when
            # a perfectly good license exists just sends them down the wrong path
            # (and, worse, towards re-activating on a fingerprint that no longer
            # matches).
            if state.offline:
                return JSONResponse(
                    status_code=503,
                    content={
                        "detail": (
                            "License server is unreachable. The application is "
                            "temporarily unavailable — check network connectivity "
                            "to the license server."
                        ),
                        # The state message carries the specific cause (refused
                        # connection, HTTP 500, offline grace window expired).
                        # Without it every one of those looked identical to the
                        # operator, who then had no idea what to fix.
                        "reason": state.message,
                        "license_server_unreachable": True,
                    },
                    headers={"Retry-After": "60"},
                )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "No valid license. Please activate a license first.",
                    "reason": state.message,
                    "license_required": True
                }
            )
        
        # License is valid, proceed
        return await call_next(request)
