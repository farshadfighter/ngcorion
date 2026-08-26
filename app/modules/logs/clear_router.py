"""System Logs - clear endpoint.

The System Logs page shows a unified feed stitched together from six sources.
Its "Clear History" button had no server side at all: the frontend only emptied
its own Redux array, so the rows came back on the next refresh.

This provides the missing DELETE. It clears the five operational log tables in
one transaction and reports how many rows went from each.

The security audit trail (audit_logs) is deliberately NOT cleared:
  * it is the tamper-evidence record of privileged actions, including this one;
  * the unified feed's "Auditing" section is a filtered view over it, so wiping
    it would erase unrelated security history to tidy up a log page.
Callers that want those rows gone need a separate, explicitly-named action with
its own retention policy -- not a general "clear the log page" button.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import (
    User,
    LoginLog,
    AssetLog,
    AssetRequirementLog,
    DiscoveryAuditLog,
    HardeningLog,
    log_action,
)

router = APIRouter(prefix="/api/logs", tags=["Logs"])


# (response key, model). Order is stable so the response reads predictably.
_CLEARABLE = (
    ("login", LoginLog),
    ("asset", AssetLog),
    ("asset_requirement", AssetRequirementLog),
    ("discovery", DiscoveryAuditLog),
    ("hardening", HardeningLog),
)


@router.delete("/clear")
def clear_all_logs(
    current_user: User = Depends(require_permission("LOGS", "delete")),
    db: Session = Depends(get_db),
):
    """Delete every row from the operational log tables.

    Returns the per-table delete counts so the UI can report what it removed
    rather than optimistically claiming success.
    """
    deleted = {}
    for key, model in _CLEARABLE:
        # synchronize_session=False: nothing in this session holds these rows,
        # and it keeps the delete a single statement per table.
        deleted[key] = db.query(model).delete(synchronize_session=False)

    # log_action() commits, which flushes the pending deletes in the same
    # transaction -- so the audit entry and the deletions land together and the
    # trail cannot lose the record of this action. No further commit needed.
    log_action(
        db,
        user_id=current_user.id,
        username=current_user.username,
        action="logs.clear",
        module="logs",
        detail=f"Cleared system logs: {deleted}",
    )

    return {
        "status": "success",
        "deleted": deleted,
        "total_deleted": sum(deleted.values()),
    }
