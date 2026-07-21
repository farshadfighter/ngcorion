"""
Deprecated Routes - Backward Compatibility

Provides 307 (Temporary Redirect) responses for old API paths that
have been superseded by the new standardized API structure.

Note: /api/audit/sessions/{id} routes are NOT here — they are now
served directly by app.modules.audit.router (shared cross-family router).
"""

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

deprecated_router = APIRouter(tags=["Deprecated"])


# ========================= FORTINET AUDIT REDIRECTS =========================

@deprecated_router.post("/api/fortinet/audit/execute")
def deprecated_fortinet_audit_execute():
    """Redirect to new FortiGate audit execute endpoint."""
    return RedirectResponse(
        url="/api/audit/fortinet/execute",
        status_code=307
    )


@deprecated_router.post("/api/fortinet/vdoms/discover")
def deprecated_fortinet_vdoms_discover():
    """Redirect to new FortiGate VDOMs discover endpoint."""
    return RedirectResponse(
        url="/api/audit/fortinet/vdoms/discover",
        status_code=307
    )


@deprecated_router.get("/api/fortinet/audit/sessions")
def deprecated_fortinet_audit_sessions():
    """Redirect to new FortiGate audit sessions endpoint."""
    return RedirectResponse(
        url="/api/audit/fortinet/sessions",
        status_code=307
    )


@deprecated_router.get("/api/fortinet/audit/sessions/{session_id}")
def deprecated_fortinet_audit_session(session_id: int):
    """Redirect to new FortiGate audit session endpoint."""
    return RedirectResponse(
        url=f"/api/audit/fortinet/sessions/{session_id}",
        status_code=307
    )


@deprecated_router.get("/api/fortinet/audit/sessions/{session_id}/results")
def deprecated_fortinet_audit_session_results(session_id: int):
    """Redirect to new FortiGate audit session results endpoint."""
    return RedirectResponse(
        url=f"/api/audit/fortinet/sessions/{session_id}/results",
        status_code=307
    )


@deprecated_router.delete("/api/fortinet/audit/sessions/{session_id}")
def deprecated_delete_fortinet_audit_session(session_id: int):
    """Redirect to new FortiGate audit session delete endpoint."""
    return RedirectResponse(
        url=f"/api/audit/fortinet/sessions/{session_id}",
        status_code=307
    )


# ========================= CISCO HARDENING REDIRECTS =========================

@deprecated_router.post("/api/hardening/preview")
def deprecated_hardening_preview():
    """Redirect to new Cisco hardening preview endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/preview",
        status_code=307
    )


@deprecated_router.post("/api/hardening/execute")
def deprecated_hardening_execute():
    """Redirect to new Cisco hardening execute endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/execute",
        status_code=307
    )


@deprecated_router.get("/api/hardening/actions")
def deprecated_hardening_actions():
    """Redirect to new Cisco hardening actions endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/actions",
        status_code=307
    )


@deprecated_router.get("/api/hardening/actions/{action_id}")
def deprecated_hardening_action(action_id: int):
    """Redirect to new Cisco hardening action endpoint."""
    return RedirectResponse(
        url=f"/api/hardening/cisco/actions/{action_id}",
        status_code=307
    )


@deprecated_router.delete("/api/hardening/actions/{action_id}")
def deprecated_delete_hardening_action(action_id: int):
    """Redirect to new Cisco hardening action delete endpoint."""
    return RedirectResponse(
        url=f"/api/hardening/cisco/actions/{action_id}",
        status_code=307
    )


@deprecated_router.post("/api/hardening/auto-audit")
def deprecated_hardening_auto_audit():
    """Redirect to new Cisco hardening auto-audit endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/auto-audit",
        status_code=307
    )


@deprecated_router.post("/api/hardening/auto-fix")
def deprecated_hardening_auto_fix():
    """Redirect to new Cisco hardening auto-fix endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/auto-fix",
        status_code=307
    )


# Note: the /api/hardening/session/{id}/parameters, /auto-preview,
# /auto-harden-defaults and /batch-execute redirects were removed along with the
# per-family endpoints they pointed at. That whole flow is now served by the
# device-agnostic /api/hardening/harden-all/* endpoints, which take a different
# request shape — so a redirect would have broken any caller that followed it.
