"""
License Middleware

Enforces license validity on all API requests.
Blocks requests to /api/* if license is invalid, except for whitelisted paths.
"""
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.license_state import get_license_state


class LicenseMiddleware(BaseHTTPMiddleware):
    """
    Middleware that checks license validity before processing requests.
    
    Passthrough paths (no license check):
    - POST /auth/login
    - GET /health
    - GET /
    - POST /api/license/activate
    - GET /api/license/status
    
    All other /api/* paths require valid license.
    """
    
    PASSTHROUGH_PATHS = {
        "/auth/login",
        "/health",
        "/",
        "/api/license/activate",
        "/api/license/status",
    }
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Allow passthrough paths
        if path in self.PASSTHROUGH_PATHS:
            return await call_next(request)
        
        # Allow non-API paths (e.g., /docs, /openapi.json)
        if not path.startswith("/api/"):
            return await call_next(request)
        
        # Check license state
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
