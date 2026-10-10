"""
The license's entitlement: how many assets NGCorion may manage.

The license (its signed answers, app/core/license_state.py) grants max_assets:
the plan's assets plus 50 per add-on pack, or None for unlimited, or the
pilot's 5 while the license server has not been reached for more than 48 hours.
Every asset in the inventory counts.

Two rules follow from it:

* No asset is added beyond the limit - by hand, by import or from discovery.
  The callers check first (check_asset_capacity) so the operator gets a clear
  message; the before_flush guard at the bottom of this module refuses any
  other path that would insert past the limit.
* While the inventory holds more assets than the license covers (after the
  offline fallback to the pilot, or a smaller plan), audits and hardening run
  only on the first max_assets assets, the oldest by id. The others stay in
  the inventory, untouched; nothing is deleted.

Nothing here talks to the license server. Without a valid license nothing is
licensed: the license middleware refuses the API, and the checks here refuse
the background paths (scheduled audits) as well.
"""
import logging
from typing import Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import event, func
from sqlalchemy.orm import Session

from app.core.license_state import get_license_state
from app.models.asset import Asset

logger = logging.getLogger(__name__)

ASSET_LIMIT_HEADERS = {"X-Asset-Limit": "true"}


class AssetLimitExceeded(HTTPException):
    """403: the license does not cover this asset, or another one."""

    def __init__(self, detail: str):
        super().__init__(status_code=403, detail=detail, headers=ASSET_LIMIT_HEADERS)

    def __str__(self) -> str:
        # Code that reports str(exc) (bulk adds, scheduled jobs) shows the reason, not "403: ...".
        return str(self.detail)


def entitlement() -> Tuple[bool, Optional[int]]:
    """(licensed, max_assets): whether a valid license is in force, and its asset limit (None =
    unlimited)."""
    state = get_license_state()
    return bool(state.valid), (state.max_assets if state.valid else 0)


def count_assets(db: Session) -> int:
    """Every asset in the inventory."""
    return int(db.query(func.count(Asset.id)).scalar() or 0)


def usage(db: Session) -> dict:
    """The numbers the license page and the asset list show. `licensed_through_id`: while the
    inventory is over the limit, the id of the last asset the license covers (assets with a higher
    id are outside it); None when every asset is covered."""
    licensed, limit = entitlement()
    used = count_assets(db)
    over = licensed and limit is not None and used > limit
    through = None
    if over:
        through = db.query(Asset.id).order_by(Asset.id).offset(max(limit - 1, 0)).limit(1).scalar() \
            if limit > 0 else 0
    return {
        "used": used,
        "max_assets": limit if licensed else 0,
        "unlimited": licensed and limit is None,
        "over_limit": over,
        "remaining": None if (licensed and limit is None) else max((limit or 0) - used, 0),
        "licensed_through_id": through,
    }


def _position(db: Session, asset_id: int) -> int:
    """1-based position of the asset among all assets, oldest (lowest id) first."""
    return int(db.query(func.count(Asset.id)).filter(Asset.id <= asset_id).scalar() or 0)


def is_asset_licensed(db: Session, asset_id: Optional[int]) -> bool:
    """Whether audits and hardening may run on this asset: a valid license, and the asset among
    the first max_assets of the inventory."""
    licensed, limit = entitlement()
    if not licensed:
        return False
    if limit is None:
        return True
    if asset_id is None:
        return False
    return _position(db, asset_id) <= limit


def require_licensed_asset(db: Session, asset_id: Optional[int]) -> None:
    """Refuse (403, X-Asset-Limit) to audit or harden an asset the license does not cover.

    Called by every audit and hardening entry point before any connection to the target is made,
    and by the scheduler before a scheduled audit. `asset_id` None (a target that is not in the
    inventory) is covered only by an unlimited license.
    """
    licensed, limit = entitlement()
    if not licensed:
        raise AssetLimitExceeded("No valid license: audits and hardening are not available.")
    if limit is None:
        return
    if asset_id is None:
        raise AssetLimitExceeded(
            "Audits and hardening run on inventory assets: add the target to the asset inventory first."
        )
    if _position(db, asset_id) > limit:
        used = count_assets(db)
        raise AssetLimitExceeded(
            f"This asset is beyond the license's limit of {limit} assets (the inventory has {used}). "
            f"Audits and hardening run on the first {limit} assets only. Extend the license with "
            f"add-on packs, or remove assets you no longer need."
        )


def check_asset_capacity(db: Session, adding: int = 1) -> None:
    """Refuse (403, X-Asset-Limit) to add `adding` assets when the license does not cover them."""
    licensed, limit = entitlement()
    if not licensed:
        raise AssetLimitExceeded("No valid license: assets cannot be added.")
    if limit is None or adding <= 0:
        return
    used = count_assets(db)
    if used + adding > limit:
        room = max(limit - used, 0)
        raise AssetLimitExceeded(
            f"The license covers {limit} assets and the inventory has {used}; "
            + (f"only {room} more can be added. " if room else "no more can be added. ")
            + "Extend the license with add-on packs (50 assets each) or remove assets you no longer need."
        )


def remaining_capacity(db: Session) -> Optional[int]:
    """How many more assets the license lets the inventory take: None = no limit, 0 = none (also
    without a valid license). For bulk adds (import, approving many discovered hosts), which add
    what fits and report the rest."""
    licensed, limit = entitlement()
    if not licensed:
        return 0
    if limit is None:
        return None
    return max(limit - count_assets(db), 0)


def capacity_message() -> str:
    """The per-item refusal a bulk add reports once the license's limit is reached."""
    _, limit = entitlement()
    return (f"not added: the license's limit of {limit} assets is reached "
            f"(extend it with add-on packs of 50 assets)")


@event.listens_for(Session, "before_flush")
def _refuse_assets_beyond_the_license(session: Session, flush_context, instances) -> None:
    """The last line: whatever code path inserts assets, the flush that would take the inventory
    past a valid license's limit fails with AssetLimitExceeded (a 403 when it reaches the API).

    Enforced only while a valid license with a finite limit is in force: without one the API is
    refused by the license middleware anyway, and maintenance tools (database restore, tests) can
    still write.
    """
    new_assets = sum(1 for obj in session.new if isinstance(obj, Asset))
    if not new_assets:
        return
    licensed, limit = entitlement()
    if not licensed or limit is None:
        return
    with session.no_autoflush:
        used = int(session.query(func.count(Asset.id)).scalar() or 0)
    if used + new_assets > limit:
        logger.warning("[License] Refused to add %d asset(s): %d of %d in use", new_assets, used, limit)
        raise AssetLimitExceeded(
            f"The license covers {limit} assets and the inventory has {used}; "
            f"{new_assets} more cannot be added. Extend the license with add-on packs "
            f"(50 assets each) or remove assets you no longer need."
        )


def asset_of_result(db: Session, result_id: Optional[int]) -> Optional[int]:
    """The asset an audit result (finding) belongs to, for the hardening endpoints that act on one."""
    from app.models.audit import AuditResult

    result = db.query(AuditResult).filter(AuditResult.id == result_id).first() if result_id else None
    return result.session.asset_id if result is not None and result.session is not None else None


def asset_of_action(db: Session, action_id: Optional[int]) -> Optional[int]:
    """The asset a hardening action targets."""
    from app.models.hardening import HardeningAction

    action = db.query(HardeningAction).filter(HardeningAction.id == action_id).first() if action_id else None
    return action.asset_id if action is not None else None
