"""
Risk scores that still carry an asset's old zone.

A score keeps the zone it was calculated with (asset_risk_scores.zone_id / zone_name), which the risk
pages, dashboards and Asset 360 show. A zone set in Asset List or Risk recalculates the asset's score
at once; a zone that changed without it - the merge of the two zone lists (migration e3b5d7f9a1c2), a
direct database edit - left the score on the old zone until someone pressed "Recalculate all". At
startup, one worker recalculates every score whose zone is not the asset's zone any more.
"""
import logging
import threading
from typing import List

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.risk import AssetRiskProfile, AssetRiskScore

logger = logging.getLogger(__name__)
_thread = None


def stale_zone_assets(db: Session) -> List[int]:
    """Assets whose score was calculated with another zone than the one they are in."""
    return [aid for (aid,) in db.query(AssetRiskScore.asset_id)
            .join(AssetRiskProfile, AssetRiskProfile.asset_id == AssetRiskScore.asset_id)
            .filter(AssetRiskScore.zone_id.is_distinct_from(AssetRiskProfile.zone_id))
            .order_by(AssetRiskScore.asset_id)]


def rescore_stale_zones(db: Session) -> int:
    from app.modules.risk.service import risk_calculation_service
    done = 0
    for asset_id in stale_zone_assets(db):
        try:
            risk_calculation_service.calculate(asset_id, db, trigger_type="profile_updated")
            done += 1
        except Exception as exc:  # noqa: BLE001 - one asset must not stop the others
            db.rollback()
            logger.warning("[Risk] zone rescore failed for asset %s: %s", asset_id, exc)
    return done


def _run() -> None:
    db = SessionLocal()
    try:
        done = rescore_stale_zones(db)
        if done:
            logger.info("[Risk] recalculated %d score(s) still on an old zone", done)
    except Exception as exc:  # noqa: BLE001 - never takes the application down
        logger.warning("[Risk] zone rescore skipped: %s", exc)
    finally:
        db.close()


def start_zone_rescore() -> None:
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_run, name="risk-zone-rescore", daemon=True)
        _thread.start()


async def stop_zone_rescore() -> None:
    """Nothing to stop: the run ends by itself."""
