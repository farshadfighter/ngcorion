"""
Shared hardening-audit helpers.

These helpers exist so vendor-specific routers (cisco, fortinet, linux,
apache, mongodb, mssql, windows) all write to the same `hardening_logs`
table with consistent failure semantics. They are best-effort: a failure
in the logging path never propagates back to the caller.
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.core.database import ensure_session_usable as _ensure_session_usable
from app.models import (
    Asset,
    AuditResult,
    HardeningAction,
    log_hardening_execute,
    log_hardening_preview,
    log_batch_hardening,
    log_auto_hardening,
)

logger = logging.getLogger(__name__)


def ensure_session_usable(db: Session) -> None:
    """
    Recover the session if a failed flush left it in pending-rollback state.

    Outcome loggers run inside routers' exception handlers, typically right
    after a DB error (e.g. a value too long for a column). Without this
    rollback, the first query here raises PendingRollbackError — which used to
    replace the real error in the HTTP 500 and lose the audit-log entry.

    Re-exported from app.core.database so the audit services share the one
    implementation; kept here as a name because every hardening caller uses it.
    """
    _ensure_session_usable(db)


def _resolve_audit_result_context(db: Session, audit_result_id: Optional[int]):
    """Return (asset, session_id, check_number, check_title) for a result id."""
    asset = None
    session_id = None
    check_number = ""
    check_title = ""
    if audit_result_id is None:
        return asset, session_id, check_number, check_title
    try:
        audit_result = db.query(AuditResult).filter(AuditResult.id == audit_result_id).first()
        if audit_result:
            check_number = audit_result.check_number or ""
            check_title = audit_result.check_title or ""
            if audit_result.audit_session is not None:
                session_id = audit_result.audit_session.id
                asset = db.query(Asset).filter(
                    Asset.id == audit_result.audit_session.asset_id
                ).first()
    except Exception as e:
        logger.warning(
            "[Hardening] could not resolve the context of audit result "
            f"{audit_result_id}: {e}"
        )
    return asset, session_id, check_number, check_title


def _resolve_action_context(db: Session, action_id: Optional[int]):
    """Return (asset, session_id, check_number, check_title) for an action id."""
    asset = None
    session_id = None
    check_number = ""
    check_title = ""
    if action_id is None:
        return asset, session_id, check_number, check_title
    try:
        action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first()
        if action:
            check_number = action.check_number or ""
            check_title = action.check_title or ""
            session_id = action.audit_session_id
            if action.asset_id:
                asset = db.query(Asset).filter(Asset.id == action.asset_id).first()
    except Exception as e:
        logger.warning(f"[Hardening] could not resolve the context of action {action_id}: {e}")
    return asset, session_id, check_number, check_title


def log_preview_outcome(
    db: Session,
    *,
    device_type: str,
    audit_result_id: Optional[int],
    user_id: int,
    status_value: str,
    check_number: str = "",
    check_title: str = "",
    error: Optional[str] = None,
) -> None:
    """Best-effort hardening-preview audit log. Never raises."""
    ensure_session_usable(db)
    try:
        asset, session_id, ar_check_number, ar_check_title = _resolve_audit_result_context(
            db, audit_result_id
        )
        log_hardening_preview(
            db=db,
            user_id=user_id,
            asset_id=asset.id if asset else None,
            asset_name=asset.asset_name if asset else None,
            audit_session_id=session_id,
            device_type=device_type,
            check_number=check_number or ar_check_number,
            check_title=check_title or ar_check_title,
            status=status_value,
            error=error,
        )
    except Exception as e:
        logger.warning(
            "[Hardening] preview audit log failed for audit result "
            f"{audit_result_id}: {e}"
        )


def log_execute_outcome(
    db: Session,
    *,
    device_type: str,
    action_id: Optional[int],
    user_id: int,
    status_value: str,
    verification_passed: Optional[bool] = None,
    error: Optional[str] = None,
) -> None:
    """Best-effort hardening-execute audit log. Never raises."""
    ensure_session_usable(db)
    try:
        asset, session_id, check_number, check_title = _resolve_action_context(db, action_id)
        log_hardening_execute(
            db=db,
            user_id=user_id,
            asset_id=asset.id if asset else None,
            asset_name=asset.asset_name if asset else None,
            audit_session_id=session_id,
            device_type=device_type,
            check_number=check_number,
            check_title=check_title,
            verification_passed=verification_passed,
            status=status_value,
            error=error,
        )

        # Risk recalculation trigger
        try:
            from app.modules.risk.service import risk_calculation_service
            if verification_passed is not None and asset is not None:
                risk_calculation_service.calculate(
                    asset_id=asset.id,
                    db=db,
                    trigger_type="hardening_verified",
                    trigger_reference_id=action_id,
                )
        except Exception as exc:
            # never block the hardening flow
            logger.warning(
                "[Risk] risk recalculation after hardening execute failed for "
                f"action {action_id}: {exc}"
            )
    except Exception as e:
        logger.warning(f"[Hardening] execute audit log failed for action {action_id}: {e}")


def _resolve_asset(db: Session, asset_id: Optional[int]):
    if not asset_id:
        return None
    try:
        return db.query(Asset).filter(Asset.id == asset_id).first()
    except Exception:
        return None


def log_session_execute_outcome(
    db: Session,
    *,
    device_type: str,
    action: str,
    session_id: Optional[int],
    asset_id: Optional[int],
    user_id: int,
    check_ids: Optional[list] = None,
    success_count: int = 0,
    failed_count: int = 0,
    error: Optional[str] = None,
) -> None:
    """
    Best-effort hardening log for session-scoped operations
    (auto-harden, batch-execute, execute-single).

    Uses log_batch_hardening for batch-style actions and
    log_auto_hardening for auto-harden actions. Never raises.
    """
    ensure_session_usable(db)
    try:
        asset = _resolve_asset(db, asset_id)
        kwargs = dict(
            db=db,
            user_id=user_id,
            asset_id=asset_id,
            asset_name=asset.asset_name if asset else None,
            audit_session_id=session_id,
            device_type=device_type,
            check_ids=check_ids or [],
            success_count=success_count,
            failed_count=failed_count,
            error=error,
        )
        if action == "auto_harden":
            log_auto_hardening(**kwargs)
        else:
            log_batch_hardening(**kwargs)

        # Risk recalculation trigger
        try:
            from app.modules.risk.service import risk_calculation_service
            if asset_id:
                risk_calculation_service.calculate(
                    asset_id=asset_id,
                    db=db,
                    trigger_type="hardening_verified",
                    trigger_reference_id=session_id,
                )
        except Exception as exc:
            # never block the hardening flow
            logger.warning(
                "[Risk] risk recalculation after session hardening failed for "
                f"asset {asset_id}: {exc}"
            )
    except Exception as e:
        logger.warning(f"[Hardening] session audit log failed for audit session {session_id}: {e}")
