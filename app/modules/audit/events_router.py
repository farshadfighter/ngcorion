"""
Recent Security Events API

Read-only view over the audit_logs table that every module already writes to
through models.security_audit_log.log_action — no new tables, no writes.

The table has 60+ call sites across assets, auditing, hardening, discovery,
risk and system config, but nothing exposed it for reading: /api/logs returns
LoginLog (sign-in history) only. The main dashboard's "Recent Security Events"
panel needs the cross-module stream, hence this endpoint.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/events", tags=["Security Events"])

# Modules whose activity counts as a security event on the dashboard. Sign-in
# noise and per-user admin chatter are deliberately excluded — the panel is
# about what happened to the estate, not who logged in.
_DASHBOARD_MODULES = (
    "asset_list",
    "asset_requirement",
    "asset_auto_discovery",
    "auditing",
    "hardening",
    "risk",
    "system_config",
)

# Human labels for the dashboard, keyed by the module the action was logged
# under. Falls back to the raw action when a module is not listed.
_MODULE_LABELS = {
    "asset_list": "Asset Management",
    "asset_requirement": "Asset Management",
    "asset_auto_discovery": "Auto Discovery",
    "auditing": "Auditing",
    "hardening": "Hardening",
    "risk": "Risk Intelligence",
    "system_config": "System Configuration",
}


def _title(action: Optional[str]) -> str:
    """'asset.create' -> 'Asset Create'; used as the event's headline."""
    if not action:
        return "Activity"
    return action.replace("_", " ").replace(".", " ").strip().title()


@router.get("/recent")
def recent_security_events(
    limit: int = Query(10, ge=1, le=100),
    _current_user: User = Depends(require_permission("LOGS", "read")),
    db: Session = Depends(get_db),
):
    """Most recent cross-module activity, newest first."""
    rows = db.execute(
        text("""
            SELECT id, username, action, module, result, detail, timestamp
            FROM audit_logs
            WHERE module = ANY(:modules)
            ORDER BY timestamp DESC
            LIMIT :limit
        """),
        {"modules": list(_DASHBOARD_MODULES), "limit": limit},
    ).mappings()

    items = [
        {
            "id": row["id"],
            "module": row["module"],
            "module_label": _MODULE_LABELS.get(row["module"], row["module"]),
            "action": row["action"],
            "title": _title(row["action"]),
            "username": row["username"],
            "result": row["result"],
            "detail": row["detail"],
            "timestamp": (
                row["timestamp"].isoformat() if row["timestamp"] else None
            ),
        }
        for row in rows
    ]

    if not items:
        return {"items": [], "message": "No activity recorded yet."}
    return {"items": items}
