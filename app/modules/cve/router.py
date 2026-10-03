"""
CVE API.

  /api/cve/findings, /entries, /products, /assets/{id}/software
      findings from the local database, and the products each asset runs
  /api/cve/db/...
      the database itself: status, update history, online / offline updates,
      exports, trusted package keys (changes are admin-only)
"""
import json
import logging
import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_admin, require_permission
from app.models import Asset, User
from app.models.cve import AssetSoftware, CveCpeMatch, CveEntry, CveTrustedKey, CveUpdateJob
from app.models.security_audit_log import log_action
from app.modules.cve import feeds, findings, jobs, keys, package, settings
from app.modules.cve.schemas import (
    ConnectionCheck, ConnectionResult, CveEntryDetail, DbSettingsUpdate, DbStatus, ExportRequest,
    FindingsResponse, JobOut, PackageCheck, PackageVerified, ProductSuggestion, SoftwareCreate, SoftwareOut,
    TrustedKeyCreate, TrustedKeyOut, UpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cve", tags=["CVE"])

_read = require_permission("cve", "read")
_write = require_permission("cve", "write")


def _job_out(db: Session, job: Optional[CveUpdateJob]) -> Optional[JobOut]:
    if job is None:
        return None
    name = None
    if job.requested_by:
        user = db.get(User, job.requested_by)
        name = user.username if user else None
    return JobOut(
        id=job.id, kind=job.kind, trigger=job.trigger, status=job.status, progress=job.progress,
        stats=job.stats, error=job.error, file_name=job.file_name, requested_by=job.requested_by,
        requested_by_name=name, created_at=job.created_at, started_at=job.started_at,
        finished_at=job.finished_at,
    )


def _audit(db: Session, user: User, action: str, detail: str, target_id: Optional[int] = None,
           result: str = "success"):
    log_action(db, user_id=user.id, username=user.username, action=action, module="cve",
               target_id=target_id, result=result, detail=detail)


def _refresh_risk(db: Session, asset_id: int) -> None:
    """The asset's products changed, so may its known vulnerabilities (CV)."""
    try:
        from app.modules.risk.service import risk_calculation_service
        risk_calculation_service.calculate(asset_id=asset_id, db=db, trigger_type="cve_software_changed")
    except Exception:  # noqa: BLE001 - never fail the edit over the score
        logger.exception("[CVE] risk recalculation for asset %s failed", asset_id)
        db.rollback()


def _busy(exc: jobs.JobBusy):
    return HTTPException(status_code=409, detail=str(exc))


# ── findings ─────────────────────────────────────────────────────────────

@router.get("/findings", response_model=FindingsResponse)
def get_findings(asset_id: Optional[int] = None, current_user: User = Depends(_read), db: Session = Depends(get_db)):
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    result = findings.compute(db, asset_id)
    result["database_loaded"] = settings.get(db, settings.WATERMARK) is not None
    from app.modules.advisories.store import loaded as advisories_loaded
    result["advisories_loaded"] = advisories_loaded(db)
    return result


@router.get("/entries/{cve_id}", response_model=CveEntryDetail)
def get_entry(cve_id: str, current_user: User = Depends(_read), db: Session = Depends(get_db)):
    entry = db.get(CveEntry, cve_id.upper())
    if entry is None:
        raise HTTPException(status_code=404, detail="CVE not found in the local database")
    out = CveEntryDetail.model_validate(entry)
    out.references = entry.references or []
    out.products = [
        {"vendor": m.vendor, "product": m.product, "version": m.version, "start_incl": m.start_incl,
         "start_excl": m.start_excl, "end_incl": m.end_incl, "end_excl": m.end_excl}
        for m in db.query(CveCpeMatch).filter(CveCpeMatch.cve_id == entry.cve_id).limit(200)
    ]
    return out


@router.get("/products", response_model=List[ProductSuggestion])
def suggest_products(q: str = Query(..., min_length=2, max_length=80), current_user: User = Depends(_read),
                     db: Session = Depends(get_db)):
    """Vendor/product names as NVD writes them, for adding software by hand."""
    term = q.strip().lower().replace(" ", "_")
    escaped = term.replace("%", "").replace("_", r"\_")
    like = f"%{escaped}%"
    rows = (db.query(CveCpeMatch.vendor, CveCpeMatch.product, func.count(func.distinct(CveCpeMatch.cve_id)))
            .filter((CveCpeMatch.product.ilike(like)) | (CveCpeMatch.vendor.ilike(like)))
            .group_by(CveCpeMatch.vendor, CveCpeMatch.product)
            .order_by(func.count(func.distinct(CveCpeMatch.cve_id)).desc())
            .limit(15).all())
    return [ProductSuggestion(vendor=v, product=p, cves=n) for v, p, n in rows]


@router.post("/assets/{asset_id}/software", response_model=SoftwareOut, status_code=201)
def add_software(asset_id: int, body: SoftwareCreate, current_user: User = Depends(_write),
                 db: Session = Depends(get_db)):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    row = AssetSoftware(asset_id=asset_id, vendor=body.vendor, product=body.product, version=body.version,
                        created_by=current_user.id)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="This product is already listed for the asset")
    db.refresh(row)
    _audit(db, current_user, "cve.software.add",
           f"{asset.asset_name}: {row.vendor} {row.product} {row.version}", target_id=asset_id)
    _refresh_risk(db, asset_id)
    return row


@router.delete("/assets/{asset_id}/software/{software_id}", status_code=204)
def remove_software(asset_id: int, software_id: int, current_user: User = Depends(_write),
                    db: Session = Depends(get_db)):
    row = db.get(AssetSoftware, software_id)
    if row is None or row.asset_id != asset_id:
        raise HTTPException(status_code=404, detail="Not found")
    detail = f"asset {asset_id}: {row.vendor} {row.product} {row.version}"
    db.delete(row)
    db.commit()
    _audit(db, current_user, "cve.software.remove", detail, target_id=asset_id)
    _refresh_risk(db, asset_id)


# ── database status ──────────────────────────────────────────────────────

@router.get("/db/status", response_model=DbStatus)
def db_status(current_user: User = Depends(_read), db: Session = Depends(get_db)):
    cves = db.query(func.count(CveEntry.cve_id)).scalar() or 0
    size = 0
    for table in ("cve_entries", "cve_cpe_matches"):
        size += db.execute(text("SELECT pg_total_relation_size(CAST(:t AS regclass))"), {"t": table}).scalar() or 0
    last = (db.query(CveUpdateJob).filter(CveUpdateJob.status.in_(("succeeded", "failed", "cancelled")),
                                          CveUpdateJob.kind != "export")
            .order_by(CveUpdateJob.id.desc()).first())
    return DbStatus(
        loaded=settings.get(db, settings.WATERMARK) is not None,
        cves=cves,
        with_cpe=db.query(func.count(func.distinct(CveCpeMatch.cve_id))).scalar() or 0,
        kev=db.query(func.count(CveEntry.cve_id)).filter(CveEntry.kev.is_(True)).scalar() or 0,
        epss=db.query(func.count(CveEntry.cve_id)).filter(CveEntry.epss.isnot(None)).scalar() or 0,
        watermark=feeds.iso_to_dt(settings.get(db, settings.WATERMARK)),
        kev_released=(settings.get(db, settings.KEV_INFO) or {}).get("released"),
        epss_date=settings.get(db, settings.EPSS_DATE),
        size_bytes=size,
        api_key_configured=settings.has_api_key(db),
        auto_update=settings.auto_update(db),
        bundle_available=jobs.bundle_available(),
        active_job=_job_out(db, jobs.active_job(db)),
        last_job=_job_out(db, last),
        sources={"nvd": feeds.NVD_API_URL, "kev": feeds.KEV_URL, "epss": feeds.EPSS_URL},
        is_admin=current_user.role.value == "admin",
    )


@router.get("/db/jobs", response_model=List[JobOut])
def list_jobs(limit: int = Query(30, ge=1, le=200), current_user: User = Depends(_read),
              db: Session = Depends(get_db)):
    return [_job_out(db, j) for j in db.query(CveUpdateJob).order_by(CveUpdateJob.id.desc()).limit(limit)]


@router.get("/db/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: int, current_user: User = Depends(_read), db: Session = Depends(get_db)):
    job = db.get(CveUpdateJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_out(db, job)


@router.post("/db/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(job_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    job = db.get(CveUpdateJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if not jobs.request_cancel(db, job):
        raise HTTPException(status_code=409, detail="The job has already finished")
    _audit(db, current_user, "cve.cancel", f"job {job.id} ({job.kind})", target_id=job.id)
    db.refresh(job)
    return _job_out(db, job)


# ── settings / online ────────────────────────────────────────────────────

@router.put("/db/settings", response_model=DbStatus)
def update_settings(body: DbSettingsUpdate, current_user: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    changes = []
    if body.clear_api_key:
        settings.put(db, settings.NVD_API_KEY, None)
        changes.append("NVD API key removed")
    elif body.nvd_api_key:
        key = body.nvd_api_key.strip()
        if not all(c.isalnum() or c == "-" for c in key):
            raise HTTPException(status_code=422, detail="The NVD API key has an unexpected format")
        settings.put(db, settings.NVD_API_KEY, key)
        changes.append("NVD API key set")
    if body.auto_update_enabled is not None or body.auto_update_time is not None:
        cfg = settings.auto_update(db)
        if body.auto_update_enabled is not None:
            cfg["enabled"] = body.auto_update_enabled
        if body.auto_update_time is not None:
            cfg["time"] = body.auto_update_time
        settings.put(db, settings.AUTO_UPDATE, cfg)
        changes.append(f"automatic update {'on at ' + cfg['time'] if cfg['enabled'] else 'off'}")
    db.commit()
    if changes:
        _audit(db, current_user, "cve.settings", "; ".join(changes))
    return db_status(current_user, db)


@router.post("/db/test-connection", response_model=ConnectionResult)
def test_connection(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    checks = []
    try:
        jobs.make_client(settings.api_key(db)).ping()
        detail = "Reachable" + (" with the API key" if settings.has_api_key(db) else " (no API key - slower updates)")
        checks.append(ConnectionCheck(name="NVD", ok=True, detail=detail))
    except feeds.FeedError as exc:
        checks.append(ConnectionCheck(name="NVD", ok=False, detail=str(exc)))
    for name, fetch in (("CISA KEV", feeds.fetch_kev), ("EPSS", feeds.fetch_epss)):
        try:
            data = fetch()
            n = len(data.get("items") or data.get("rows") or [])
            checks.append(ConnectionCheck(name=name, ok=True, detail=f"Reachable ({n:,} entries)"))
        except feeds.FeedError as exc:
            checks.append(ConnectionCheck(name=name, ok=False, detail=str(exc)))
    return ConnectionResult(ok=all(c.ok for c in checks), checks=checks)


@router.post("/db/update", response_model=JobOut, status_code=202)
def start_update(body: UpdateRequest = UpdateRequest(), current_user: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    try:
        job = jobs.create_job(db, "full" if body.full else "online", current_user.id)
    except jobs.JobBusy as exc:
        raise _busy(exc)
    jobs.start_online(job, body.full)
    return _job_out(db, job)


@router.post("/db/bundle/load", response_model=JobOut, status_code=202)
def load_bundle(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    path = jobs.bundle_path()
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="No CVE database snapshot is installed with this release")
    try:
        job = jobs.create_job(db, "bundle", current_user.id, file_name=os.path.basename(path))
    except jobs.JobBusy as exc:
        raise _busy(exc)
    jobs.start_import(job, path, remove_after=False)
    return _job_out(db, job)


# ── offline packages ─────────────────────────────────────────────────────

def _verified(token: Optional[str], file_name: str, size: int, v: package.Verified) -> PackageVerified:
    return PackageVerified(
        token=token if v.importable else None, file_name=file_name, size=size, importable=v.importable,
        signer=v.signer or None, manifest=v.manifest if v.signer else None,
        checks=[PackageCheck(name=c.name, status=c.status, detail=c.detail) for c in v.checks],
    )


@router.post("/db/packages", response_model=PackageVerified)
async def upload_package(request: Request, file_name: str = Query("package.ngcve", max_length=255),
                         current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Upload (the raw file as the request body) and check a package.
    Nothing is imported until it is confirmed.

    The body is streamed rather than declared as a form upload, so the admin
    check runs before any of it is read, and the size limit holds while it
    arrives - a multipart body would be spooled whole first."""
    name = os.path.basename(file_name)[:200] or "package.ngcve"
    limit = package.MAX_PACKAGE_BYTES
    too_big = f"The file is larger than the {limit // (1024 * 1024)} MB package limit."
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=too_big)
    token, path = jobs.new_upload()
    size = 0
    try:
        with open(path, "wb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise package.PackageError(too_big)
                out.write(chunk)
        verified = await run_in_threadpool(package.verify, db, path)
    except package.PackageError as exc:
        if os.path.exists(path):
            os.remove(path)
        _audit(db, current_user, "cve.package.check", f"{name}: {exc}", result="failed")
        raise HTTPException(status_code=413 if str(exc) == too_big else 422, detail=str(exc))
    except BaseException:
        if os.path.exists(path):
            os.remove(path)
        raise
    if not verified.importable:
        os.remove(path)
        failed = next(c for c in verified.checks if c.status == "fail")
        _audit(db, current_user, "cve.package.check", f"{name}: {failed.detail}", result="failed")
    else:
        with open(path + ".json", "w") as meta:
            json.dump({"file_name": name}, meta)
    return _verified(token, name, size, verified)


@router.post("/db/packages/{token}/import", response_model=JobOut, status_code=202)
def import_package(token: str, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        path = jobs.upload_path(token)
    except package.PackageError:
        raise HTTPException(status_code=404, detail="Upload not found - upload the package again")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Upload not found - upload the package again")
    name = os.path.basename(path)
    try:
        with open(path + ".json") as meta:
            name = json.load(meta).get("file_name") or name
        os.remove(path + ".json")
    except (OSError, ValueError):
        pass
    try:
        job = jobs.create_job(db, "offline", current_user.id, file_name=name)
    except jobs.JobBusy as exc:
        raise _busy(exc)
    jobs.start_import(job, path)
    return _job_out(db, job)


@router.post("/db/export", response_model=JobOut, status_code=202)
def start_export(body: ExportRequest, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if settings.get(db, settings.WATERMARK) is None:
        raise HTTPException(status_code=409, detail="The CVE database has not been loaded yet")
    if body.kind == "delta" and body.since is None:
        raise HTTPException(status_code=422, detail="A partial package needs a start date")
    since = body.since.replace(tzinfo=None) if body.since else None
    try:
        job = jobs.create_job(db, "export", current_user.id)
    except jobs.JobBusy as exc:
        raise _busy(exc)
    jobs.start_export(job, body.kind, since if body.kind == "delta" else None)
    return _job_out(db, job)


@router.get("/db/export/{job_id}/file")
def download_export(job_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    job = db.get(CveUpdateJob, job_id)
    path = jobs.export_file(job) if job else None
    if path is None:
        raise HTTPException(status_code=404, detail="The package is no longer available - export it again")
    return FileResponse(path, media_type="application/octet-stream", filename=os.path.basename(path))


# ── trusted keys ─────────────────────────────────────────────────────────

@router.get("/db/keys", response_model=List[TrustedKeyOut])
def list_keys(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return keys.trusted(db)


@router.post("/db/keys", response_model=TrustedKeyOut, status_code=201)
def add_key(body: TrustedKeyCreate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    public = body.public_key.strip()
    try:
        keys.load_public(public)
    except keys.KeyError_ as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    fp = keys.fingerprint(public)
    if any(k["fingerprint"] == fp for k in keys.trusted(db)):
        raise HTTPException(status_code=409, detail="This key is already trusted")
    row = CveTrustedKey(name=body.name.strip(), public_key=public, fingerprint=fp, created_by=current_user.id)
    db.add(row)
    db.commit()
    db.refresh(row)
    _audit(db, current_user, "cve.key.add", f"{row.name} ({fp[:16]})", target_id=row.id)
    return TrustedKeyOut(id=row.id, name=row.name, public_key=row.public_key, fingerprint=fp, builtin=False)


@router.delete("/db/keys/{key_id}", status_code=204)
def remove_key(key_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(CveTrustedKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Key not found")
    detail = f"{row.name} ({row.fingerprint[:16]})"
    db.delete(row)
    db.commit()
    _audit(db, current_user, "cve.key.remove", detail, target_id=key_id)


# ── distribution advisories (app/modules/advisories) ─────────────────────

class AdvisorySettings(BaseModel):
    auto: Optional[bool] = None
    releases: Optional[List[str]] = Field(None, max_length=50)


@router.get("/advisories")
def advisories_status(current_user: User = Depends(_read), db: Session = Depends(get_db)):
    from app.modules.advisories.service import status
    out = status(db)
    out["job"] = _job_out(db, jobs.active_job(db))
    out["is_admin"] = current_user.role.value == "admin"
    return out


@router.put("/advisories/settings")
def advisories_settings(body: AdvisorySettings, current_user: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    from app.modules.advisories.service import set_settings
    try:
        changes = set_settings(db, body.auto, body.releases)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if changes:
        _audit(db, current_user, "cve.advisories.settings", "; ".join(changes))
    return advisories_status(current_user, db)


@router.post("/advisories/update", response_model=JobOut, status_code=202)
def advisories_update(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        job = jobs.create_job(db, "advisories", current_user.id)
    except jobs.JobBusy as exc:
        raise _busy(exc)
    jobs.start_advisories(job)
    return _job_out(db, job)


@router.post("/advisories/import", response_model=JobOut, status_code=202)
async def advisories_import(request: Request, file_name: str = Query("all.zip", max_length=255),
                            current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """An OSV archive (all.zip of Ubuntu, Debian, Red Hat, Rocky Linux or
    AlmaLinux from osv-vulnerabilities.storage.googleapis.com), streamed as
    the request body. It is not signed: administrators only, and its SHA-256
    goes into the audit log."""
    from app.modules.advisories import osv
    name = os.path.basename(file_name)[:200] or "all.zip"
    limit = osv.MAX_ZIP_BYTES
    too_big = f"The file is larger than the {limit // (1024 * 1024)} MB limit."
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(status_code=413, detail=too_big)
    token, path = jobs.new_upload()
    path = path[:-len(package.EXTENSION)] + ".zip"
    size = 0
    try:
        with open(path, "wb") as out:
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=too_big)
                out.write(chunk)
        if size < 22 or open(path, "rb").read(2) != b"PK":
            raise HTTPException(status_code=422, detail="Not an OSV archive (not a ZIP file).")
        job = jobs.create_job(db, "adv_import", current_user.id, file_name=name)
    except jobs.JobBusy as exc:
        os.remove(path)
        raise _busy(exc)
    except BaseException:
        if os.path.exists(path):
            os.remove(path)
        raise
    _audit(db, current_user, "cve.advisories.import", f"{name} ({size:,} bytes) queued as job {job.id}",
           target_id=job.id)
    jobs.start_adv_import(job, path)
    return _job_out(db, job)


@router.delete("/advisories/releases/{release}", status_code=204)
def advisories_remove(release: str, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    from app.modules.advisories.service import remove_release
    if jobs.active_job(db) is not None:
        raise HTTPException(status_code=409, detail="Wait for the running database job to finish.")
    if not remove_release(db, release):
        raise HTTPException(status_code=409, detail="An asset runs this release; it cannot be removed.")
    _audit(db, current_user, "cve.advisories.remove", release)
