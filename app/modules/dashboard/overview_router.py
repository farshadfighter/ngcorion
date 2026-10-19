"""The main dashboard's data (app/modules/dashboard/overview.py), for any signed-in user: each part is
filled only from the modules the user may read."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User
from app.modules.dashboard import overview as S

router = APIRouter()


@router.get("/overview")
def dashboard_overview(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """What needs action, coverage, the 90-day risk and compliance trends and the riskiest assets."""
    return S.overview(db, current_user)
