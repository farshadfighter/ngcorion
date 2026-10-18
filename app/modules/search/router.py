"""
API of the global search (app/modules/search/service.py), under /api/search.

Open to every signed-in user: each kind of result is filtered by the user's own read permissions inside
the search, so nobody finds what their pages would not show them.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import User
from app.modules.search import service as S

router = APIRouter(prefix="/api/search", tags=["Search"])


@router.get("")
def search(q: str = Query(..., max_length=100), limit: int = Query(5, ge=1, le=20),
           current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Results grouped by kind (assets, CVEs, unknown devices, findings, certificates, software, groups,
    users, reports), at most `limit` of each."""
    return S.search(db, current_user, q, limit)
