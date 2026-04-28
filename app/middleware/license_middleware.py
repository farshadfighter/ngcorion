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
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "No valid license. Please activate a license first.",
                    "license_required": True
                }
            )
        
        # License is valid, proceed
        return await call_next(request)
