"""
Harden All API — one plan endpoint, one execute endpoint, every device family.

    GET  /api/hardening/harden-all/session/{session_id}/plan
    POST /api/hardening/harden-all/execute
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import (
    check_quota_available,
    consume_quota_on_success,
    require_permission,
)
from app.core.ssh_exceptions import (
    SSHAlgorithmMismatchError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHConnectionTimeoutError,
    SSHHostKeyError,
    SSHNetworkError,
)
from app.models import User
from app.modules.shared.hardening_audit import log_session_execute_outcome

from . import service
from .contract import HardenAllPlan, HardenAllRequest, HardenAllResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/hardening/harden-all", tags=["Hardening - Harden All"])


@router.get("/session/{session_id}/plan", response_model=HardenAllPlan)
def get_harden_all_plan(
    session_id: int,
    current_user: User = Depends(require_permission("HARDENING", "read")),
    db: Session = Depends(get_db),
):
    """
    Everything the Harden All wizard needs for one audit session, in one call:
    which failed checks can be remediated, which cannot and why, the parameters
    to collect, the credential fields to render, and which execution options
    (backup, dry run) this device family supports.
    """
    try:
        return service.build_plan(db, session_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        logger.exception("Harden All plan failed for session %s", session_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build hardening plan: {e}",
        )


@router.post("/execute", response_model=HardenAllResult)
def execute_harden_all(
    http_request: Request,
    request: HardenAllRequest,
    current_user: User = Depends(require_permission("HARDENING", "write")),
    db: Session = Depends(get_db),
    _quota_check: None = Depends(check_quota_available("harden")),
):
    """
    Remediate every fixable failed check in the session (or the subset named by
    `result_ids`) and return one normalized result per check.

    Credentials are used for this call only and are never stored.
    """
    consume_quota = consume_quota_on_success("harden")
    # Read the id up front: current_user can expire, and touching it inside an
    # exception handler after a failed flush raises PendingRollbackError, which
    # would mask the real failure.
    user_id = current_user.id

    # Resolved up front so the audit log still names the right device family when
    # execution blows up before the plan is built.
    device_family, asset_id = service.describe_session(db, request.session_id)

    def _log(*, success: int = 0, failed: int = 0, error: str = None):
        log_session_execute_outcome(
            db,
            device_type=device_family,
            action="batch_execute",
            session_id=request.session_id,
            asset_id=asset_id,
            user_id=user_id,
            check_ids=[str(i) for i in (request.result_ids or [])],
            success_count=success,
            failed_count=failed,
            error=error,
        )

    try:
        result = service.execute_plan(db, request, user_id)

        if not result.dry_run:
            consume_quota(http_request)
            _log(success=result.successful, failed=result.failed)
        return result

    except ValueError as e:
        _log(failed=1, error=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SSHAuthenticationError as e:
        _log(failed=1, error=str(e))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=e.to_dict())
    except SSHConnectionTimeoutError as e:
        _log(failed=1, error=str(e))
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail=e.to_dict())
    except SSHNetworkError as e:
        _log(failed=1, error=str(e))
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=e.to_dict())
    except (SSHAlgorithmMismatchError, SSHHostKeyError, SSHConnectionError) as e:
        _log(failed=1, error=str(e))
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=e.to_dict())
    except Exception as e:
        logger.exception("Harden All execution failed for session %s", request.session_id)
        _log(failed=1, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hardening failed: {e}",
        )
