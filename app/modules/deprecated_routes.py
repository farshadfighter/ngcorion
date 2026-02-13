"""
Deprecated Routes - Backward Compatibility

Provides 307 (Temporary Redirect) responses for old API paths.
This allows existing clients to continue working while transitioning
to the new standardized API structure.

Old Path Structure:
- /api/audit/sessions -> /api/audit/cisco/sessions
- /api/fortinet/audit/* -> /api/audit/fortinet/*
- /api/hardening/* -> /api/hardening/cisco/*

These redirects should be removed in a future version after
all clients have migrated to the new paths.
"""

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

deprecated_router = APIRouter(tags=["Deprecated"])


# ========================= CISCO AUDIT REDIRECTS =========================

@deprecated_router.get("/api/audit/sessions")
def deprecated_audit_sessions():
    """Redirect to new Cisco audit sessions endpoint."""
    return RedirectResponse(
        url="/api/audit/cisco/sessions",
        status_code=307
    )


@deprecated_router.get("/api/audit/sessions/count")
def deprecated_audit_sessions_count():
    """Redirect to new Cisco audit sessions count endpoint."""
    return RedirectResponse(
        url="/api/audit/cisco/sessions/count",
        status_code=307
    )


@deprecated_router.get("/api/audit/sessions/{session_id}")
def deprecated_audit_session(session_id: int):
    """Redirect to new Cisco audit session endpoint."""
    return RedirectResponse(
        url=f"/api/audit/cisco/sessions/{session_id}",
        status_code=307
    )


@deprecated_router.get("/api/audit/sessions/{session_id}/results")
def deprecated_audit_session_results(session_id: int):
    """Redirect to new Cisco audit session results endpoint."""
    return RedirectResponse(
        url=f"/api/audit/cisco/sessions/{session_id}/results",
        status_code=307
    )


@deprecated_router.get("/api/audit/sessions/{session_id}/cis-table")
def deprecated_audit_cis_table(session_id: int):
    """Redirect to new Cisco CIS table endpoint."""
    return RedirectResponse(
        url=f"/api/audit/cisco/sessions/{session_id}/cis-table",
        status_code=307
    )


@deprecated_router.delete("/api/audit/sessions/{session_id}")
def deprecated_delete_audit_session(session_id: int):
    """Redirect to new Cisco audit session delete endpoint."""
    return RedirectResponse(
        url=f"/api/audit/cisco/sessions/{session_id}",
        status_code=307
    )


@deprecated_router.get("/api/audit/asset/{asset_id}/history")
def deprecated_asset_audit_history(asset_id: int):
    """Redirect to new Cisco asset audit history endpoint."""
    return RedirectResponse(
        url=f"/api/audit/cisco/asset/{asset_id}/history",
        status_code=307
    )


@deprecated_router.post("/api/audit/cisco/execute")
def deprecated_cisco_execute():
    """Redirect old nested cisco/execute to new path."""
    return RedirectResponse(
        url="/api/audit/cisco/execute",
        status_code=307
    )


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


@deprecated_router.get("/api/hardening/session/{session_id}/parameters")
def deprecated_hardening_session_parameters(session_id: int):
    """Redirect to new Cisco hardening session parameters endpoint."""
    return RedirectResponse(
        url=f"/api/hardening/cisco/session/{session_id}/parameters",
        status_code=307
    )


@deprecated_router.get("/api/hardening/session/{session_id}/auto-preview")
def deprecated_hardening_session_auto_preview(session_id: int):
    """Redirect to new Cisco hardening session auto-preview endpoint."""
    return RedirectResponse(
        url=f"/api/hardening/cisco/session/{session_id}/auto-preview",
        status_code=307
    )


@deprecated_router.post("/api/hardening/auto-harden-defaults")
def deprecated_hardening_auto_harden_defaults():
    """Redirect to new Cisco hardening auto-harden-defaults endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/auto-harden-defaults",
        status_code=307
    )


@deprecated_router.post("/api/hardening/batch-execute")
def deprecated_hardening_batch_execute():
    """Redirect to new Cisco hardening batch-execute endpoint."""
    return RedirectResponse(
        url="/api/hardening/cisco/batch-execute",
        status_code=307
    )
