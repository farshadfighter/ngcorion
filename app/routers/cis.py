"""
CIS benchmark API — drives the self-contained services in ``app/cis/services``.

Endpoints (mounted under ``/api/cis``):

* ``POST /audit``                         — run a full benchmark, persist results
* ``GET  /results/{host_id}``             — latest result per check for a host
* ``GET  /results/{host_id}/section/{s}`` — same, filtered by section prefix
* ``POST /fix/{host_id}/{check_id}``      — remediate one check, update its row
* ``GET  /summary/{host_id}``             — per-service compliance rollup

Only ``mongodb`` is wired today (:class:`app.cis.services.mongodb.MongoDBBenchmark`).

Notes on how this maps onto the existing codebase:

* The asset table is ``asset_inventory`` and does **not** store SSH credentials
  (matching the apache/cisco modules, credentials are supplied per request and
  never persisted). ``POST /audit`` therefore accepts optional SSH fields in the
  body in addition to ``host_id`` / ``service`` / ``auto_fix``.
* ``MongoDBBenchmark`` exposes ``audit()`` and per-check ``_check_<id>`` methods
  (whose fix logic is gated on ``auto_fix``); there is no public ``fix()``. The
  fix endpoint dispatches to ``_check_<id>`` with ``auto_fix=True`` to remediate
  a single control without modifying the benchmark module.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Type

import paramiko
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.cis.base import CISCheck, CISResult
from app.cis.services.mongodb import MongoDBBenchmark
from app.core.database import get_db
from app.models import Asset
from app.models.cis_result import CISAuditResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cis", tags=["CIS Benchmarks"])

# Services wired into this API. Extend as more benchmark classes are added.
SUPPORTED_SERVICES: Dict[str, Type[CISCheck]] = {
    "mongodb": MongoDBBenchmark,
}

# Exceptions that mean "could not reach / authenticate to the host over SSH".
# paramiko.NoValidConnectionsError and socket errors are OSError subclasses.
SSH_ERRORS = (paramiko.SSHException, OSError, socket.timeout)

_CHECK_ID_RE = re.compile(r"^\d+(?:\.\d+)+$")


# --------------------------------------------------------------------------- #
# Request / response schemas
# --------------------------------------------------------------------------- #
class AuditRequest(BaseModel):
    host_id: int
    service: str = "mongodb"
    auto_fix: bool = False
    # SSH credentials are used only for this session and never stored, matching
    # the other audit modules. Optional so that assets which one day carry
    # credentials keep working, but at least a username must be resolvable.
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key_file: Optional[str] = None
    ssh_port: int = 22


class FixRequest(BaseModel):
    service: str = "mongodb"
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key_file: Optional[str] = None
    ssh_port: int = 22


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _get_host_or_404(db: Session, host_id: int) -> Asset:
    asset = db.query(Asset).filter(Asset.id == host_id).first()
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")
    return asset


def _resolve_service(service: str) -> Type[CISCheck]:
    cls = SUPPORTED_SERVICES.get(service)
    if cls is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported service '{service}'. Supported: {sorted(SUPPORTED_SERVICES)}",
        )
    return cls


def _build_benchmark(
    cls: Type[CISCheck],
    asset: Asset,
    *,
    ssh_username: Optional[str],
    ssh_password: Optional[str],
    ssh_key_file: Optional[str],
    ssh_port: int,
    auto_fix: bool,
) -> CISCheck:
    """Instantiate a benchmark for ``asset``, resolving connection details.

    Credentials come from the request; if the asset ever grows SSH attributes
    they are used as a fallback. Raises 400 when the host IP or username is
    unavailable.
    """
    host = getattr(asset, "ip_address", None)
    if not host:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asset has no ip_address")

    username = ssh_username or getattr(asset, "ssh_user", None)
    password = ssh_password or getattr(asset, "ssh_password", None)
    key_file = ssh_key_file or getattr(asset, "ssh_key_path", None)

    if not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ssh_username is required (not stored on the asset)",
        )

    return cls(
        host=host,
        ssh_username=username,
        ssh_password=password,
        ssh_key_file=key_file,
        ssh_port=ssh_port,
        auto_fix=auto_fix,
    )


def _run_audit(bench: CISCheck) -> List[CISResult]:
    """Connect (so SSH failures surface as exceptions) then run the full audit."""
    bench.connect()  # raises SSH_ERRORS on connection/auth failure
    try:
        return bench.audit()
    finally:
        bench.close()


def _run_single_fix(bench: CISCheck, check_id: str, title: str) -> CISResult:
    """Remediate one control by invoking its ``_check_<id>`` method (auto_fix=True)."""
    method_name = "_check_" + check_id.replace(".", "_")
    method = getattr(bench, method_name, None)
    if method is None or not callable(method):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown check '{check_id}'")
    try:
        return method(check_id, title)  # runs the check with fix logic enabled
    finally:
        bench.close()


def _persist_results(
    db: Session,
    host_id: int,
    service: str,
    results: List[CISResult],
    run_ts: datetime,
) -> None:
    rows = [
        CISAuditResult(
            host_id=host_id,
            check_id=r.id,
            check_title=r.title,
            service=service,
            section=(r.section or r.id.split(".", 1)[0]),
            scored=bool(r.scored),
            status=r.status.value,
            current_value=r.current_value,
            expected_value=r.expected_value,
            fix_applied=bool(r.fix_applied),
            error_msg=r.error_msg,
            audited_at=run_ts,
            fixed_at=run_ts if r.fix_applied else None,
        )
        for r in results
    ]
    db.add_all(rows)
    db.commit()


def _latest_per_check(rows: List[CISAuditResult]) -> List[CISAuditResult]:
    """Collapse to the newest row per (service, check_id).

    ``rows`` must already be ordered newest-first.
    """
    latest: Dict[tuple, CISAuditResult] = {}
    for row in rows:
        key = (row.service, row.check_id)
        if key not in latest:
            latest[key] = row
    return list(latest.values())


def _tally(results: List[CISResult]) -> Dict[str, int]:
    counts = {"pass": 0, "fail": 0, "error": 0, "skipped": 0}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@router.post("/audit")
async def run_audit(body: AuditRequest, db: Session = Depends(get_db)):
    asset = _get_host_or_404(db, body.host_id)
    cls = _resolve_service(body.service)
    bench = _build_benchmark(
        cls,
        asset,
        ssh_username=body.ssh_username,
        ssh_password=body.ssh_password,
        ssh_key_file=body.ssh_key_file,
        ssh_port=body.ssh_port,
        auto_fix=body.auto_fix,
    )

    try:
        results = await asyncio.to_thread(_run_audit, bench)
    except SSH_ERRORS as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH connection failed: {exc}",
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("CIS audit failed for host %s service %s", body.host_id, body.service)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error")

    run_ts = datetime.now(timezone.utc)
    try:
        _persist_results(db, body.host_id, body.service, results, run_ts)
    except Exception:
        db.rollback()
        logger.exception("failed to persist CIS results for host %s", body.host_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error")

    counts = _tally(results)
    return {
        "host_id": body.host_id,
        "service": body.service,
        "total": len(results),
        "pass": counts["pass"],
        "fail": counts["fail"],
        "error": counts["error"],
        "skipped": counts["skipped"],
        "results": [r.to_dict() for r in results],
    }


@router.get("/results/{host_id}")
def get_results(
    host_id: int,
    service: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    scored: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
):
    _get_host_or_404(db, host_id)

    query = db.query(CISAuditResult).filter(CISAuditResult.host_id == host_id)
    if service:
        query = query.filter(CISAuditResult.service == service)
    rows = query.order_by(
        CISAuditResult.audited_at.desc(), CISAuditResult.id.desc()
    ).all()

    latest = _latest_per_check(rows)
    if status_filter:
        latest = [r for r in latest if r.status == status_filter]
    if scored is not None:
        latest = [r for r in latest if r.scored == scored]

    latest.sort(key=lambda r: (r.audited_at, r.id), reverse=True)
    return [r.to_dict() for r in latest]


@router.get("/results/{host_id}/section/{section_id}")
def get_results_by_section(
    host_id: int,
    section_id: str,
    service: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    scored: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
):
    _get_host_or_404(db, host_id)

    query = db.query(CISAuditResult).filter(CISAuditResult.host_id == host_id)
    if service:
        query = query.filter(CISAuditResult.service == service)
    rows = query.order_by(
        CISAuditResult.audited_at.desc(), CISAuditResult.id.desc()
    ).all()

    latest = [r for r in _latest_per_check(rows) if (r.section or "").startswith(section_id)]
    if status_filter:
        latest = [r for r in latest if r.status == status_filter]
    if scored is not None:
        latest = [r for r in latest if r.scored == scored]

    latest.sort(key=lambda r: (r.audited_at, r.id), reverse=True)
    return [r.to_dict() for r in latest]


@router.post("/fix/{host_id}/{check_id}")
async def fix_check(
    host_id: int,
    check_id: str,
    body: FixRequest,
    db: Session = Depends(get_db),
):
    if not _CHECK_ID_RE.match(check_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid check_id")

    asset = _get_host_or_404(db, host_id)
    cls = _resolve_service(body.service)

    # The row to update must already exist (audit first, then fix). Its title is
    # what we hand to the per-check method.
    existing = (
        db.query(CISAuditResult)
        .filter(
            CISAuditResult.host_id == host_id,
            CISAuditResult.service == body.service,
            CISAuditResult.check_id == check_id,
        )
        .order_by(CISAuditResult.audited_at.desc(), CISAuditResult.id.desc())
        .first()
    )
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No audit result for check '{check_id}'; run an audit first",
        )

    bench = _build_benchmark(
        cls,
        asset,
        ssh_username=body.ssh_username,
        ssh_password=body.ssh_password,
        ssh_key_file=body.ssh_key_file,
        ssh_port=body.ssh_port,
        auto_fix=True,
    )

    try:
        result = await asyncio.to_thread(_run_single_fix, bench, check_id, existing.check_title)
    except SSH_ERRORS as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SSH connection failed: {exc}",
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("CIS fix failed for host %s check %s", host_id, check_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error")

    try:
        existing.status = result.status.value
        existing.current_value = result.current_value
        existing.expected_value = result.expected_value
        existing.error_msg = result.error_msg
        existing.fix_applied = bool(result.fix_applied)
        if result.fix_applied:
            existing.fixed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing)
    except Exception:
        db.rollback()
        logger.exception("failed to update CIS result row for host %s check %s", host_id, check_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error")

    return existing.to_dict()


@router.get("/summary/{host_id}")
def get_summary(host_id: int, db: Session = Depends(get_db)):
    _get_host_or_404(db, host_id)

    rows = (
        db.query(CISAuditResult)
        .filter(CISAuditResult.host_id == host_id)
        .order_by(CISAuditResult.audited_at.desc(), CISAuditResult.id.desc())
        .all()
    )
    latest = _latest_per_check(rows)

    services: Dict[str, dict] = {}
    for row in latest:
        svc = services.setdefault(
            row.service,
            {
                "total": 0,
                "pass": 0,
                "fail": 0,
                "error": 0,
                "skipped": 0,
                "scored_pass": 0,
                "scored_fail": 0,
                "last_audited": None,
            },
        )
        svc["total"] += 1
        if row.status in svc:
            svc[row.status] += 1
        if row.scored and row.status == "pass":
            svc["scored_pass"] += 1
        if row.scored and row.status == "fail":
            svc["scored_fail"] += 1
        ts = row.audited_at.isoformat() if row.audited_at else None
        if ts and (svc["last_audited"] is None or ts > svc["last_audited"]):
            svc["last_audited"] = ts

    return {"host_id": host_id, "services": services}
