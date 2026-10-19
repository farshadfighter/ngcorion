"""The dashboards' data: the main dashboard (app/modules/dashboard/overview.py), for any signed-in user,
each part filled only from the modules the user may read; the assets overview
(app/modules/dashboard/assets_overview.py), the risk overview (app/modules/dashboard/risk_overview.py) and the
hardening overview (app/modules/dashboard/hardening_overview.py)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user, require_permission
from app.models import User
from app.modules.dashboard import assets_overview as A
from app.modules.dashboard import hardening_overview as H
from app.modules.dashboard import overview as S
from app.modules.dashboard import risk_overview as R

router = APIRouter()


@router.get("/overview")
def dashboard_overview(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """What needs action, coverage, the 90-day risk and compliance trends and the riskiest assets."""
    return S.overview(db, current_user)


@router.get("/assets")
def assets_overview(current_user: User = Depends(require_permission("ASSET_LIST", "read")),
                    db: Session = Depends(get_db)):
    """The inventory: totals, missing details, coverage by the other modules, breakdowns, newest assets."""
    return A.overview(db, current_user)


@router.get("/risk")
def risk_overview(current_user: User = Depends(require_permission("RISK", "read")), db: Session = Depends(get_db)):
    """Risk totals, what builds the risk, zone by level, the 90-day trend, incomplete scores, top assets."""
    return R.overview(db, current_user)


@router.get("/hardening")
def hardening_overview(current_user: User = Depends(require_permission("HARDENING", "read")),
                       db: Session = Depends(get_db)):
    """How hardening is going, what needs a person, missing controls, impact in risk terms, reach."""
    return H.overview(db, current_user)
