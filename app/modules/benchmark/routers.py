"""
Audit and hardening routers for a benchmark module.

The endpoints, bodies and responses are the Windows module's:

    POST   /api/audit/{key}/execute
    GET    /api/audit/{key}/sessions            (+ /count, /{id}, /{id}/results)
    GET    /api/audit/{key}/asset/{asset_id}/history
    DELETE /api/audit/{key}/sessions/{id}

    POST   /api/hardening/{key}/preview
    POST   /api/hardening/{key}/execute-single
    GET    /api/hardening/{key}/supported-checks
    GET    /api/hardening/{key}/check/{check_id}/template

so the existing forms, result views, Fix and Harden All work unchanged.
"""

import copy
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, create_model
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import (
    assert_session_access,
    check_quota_available,
    consume_quota_on_success,
    owner_scope,
    require_permission,
)
from app.core.hardening_param_security import ParameterSecurityError
from app.models import Asset, AuditSession, User, log_action
from app.modules.shared.hardening_audit import log_session_execute_outcome

from .audit_service import BenchmarkAuditService
from .connectors import get_connector
from .hardening_service import BenchmarkHardeningService
from .spec import ModuleSpec

logger = logging.getLogger(__name__)


class BenchmarkSessionResponse(BaseModel):
    session_id: int
    job_name: Optional[str] = None
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    target_ip: str
    device_type: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    compliance: dict
    connection_error: Optional[str] = None


class BenchmarkResultResponse(BaseModel):
    id: int
    check_number: Optional[str] = None
    check_title: Optional[str] = None
    severity: Optional[str] = None
    level: Optional[str] = None
    status: str
    evidence_snippet: Optional[str] = None
    checked_at: Optional[str] = None


class PreviewRequest(BaseModel):
    check_id: str = Field(..., max_length=100)
    parameters: Optional[Dict[str, str]] = None


def _model_name(spec: ModuleSpec, suffix: str) -> str:
    return "".join(p.capitalize() for p in spec.key.split("_")) + suffix


def _credentials(body: BaseModel, spec: ModuleSpec) -> Dict[str, Any]:
    names = get_connector(spec.connector).request_fields.keys()
    return {n: getattr(body, n) for n in names}


def build_audit_router(spec: ModuleSpec) -> APIRouter:
    service = BenchmarkAuditService(spec)
    connector = get_connector(spec.connector)

    AuditRequest = create_model(
        _model_name(spec, "AuditRequest"),
        asset_id=(int, Field(..., description=f"Asset ID of the {spec.label} target")),
        profile=(str, Field("FULL", pattern="^(L1|FULL)$")),
        job_name=(Optional[str], Field(None, max_length=200)),
        **copy.deepcopy(connector.request_fields),
    )

    router = APIRouter(prefix=f"/api/audit/{spec.key}", tags=spec.tags_audit or [f"Audit - {spec.label}"])

    def _log(db, user_id, target_id, result, detail):
        log_action(db=db, user_id=user_id, action="execute_audit", module=spec.log_module,
                   target_id=target_id, result=result, detail=detail)

    @router.post("/execute", response_model=BenchmarkSessionResponse,
                 dependencies=[Depends(check_quota_available("audit"))],
                 summary=f"Run a {spec.label} audit ({spec.benchmark})")
    def execute(body: AuditRequest, request: Request,  # type: ignore[valid-type]
                current_user: User = Depends(require_permission("AUDITING", "write")),
                db: Session = Depends(get_db)):
        consume_quota = consume_quota_on_success("audit")
        user_id = current_user.id
        asset = db.query(Asset).filter(Asset.id == body.asset_id).first()
        where = f"Asset ID: {body.asset_id}, Name: {asset.asset_name if asset else None}, " \
                f"IP: {asset.ip_address if asset else None}"
        try:
            session = service.execute(db, body.asset_id, user_id, _credentials(body, spec),
                                      profile=body.profile, job_name=body.job_name)
        except ValueError as exc:
            _log(db, user_id, body.asset_id, "failed", f"{where}. Error: {exc}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        except PermissionError as exc:
            _log(db, user_id, body.asset_id, "failed", f"{where}. Error: {exc}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={
                "error_type": "authentication_error",
                "message": "Authentication failed — check the username and password."})
        except ConnectionError as exc:
            _log(db, user_id, body.asset_id, "failed", f"{where}. Error: {exc}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
                "error_type": "connection_error",
                "message": "Could not connect to the device — check the host, port, and network."})
        except Exception as exc:  # noqa: BLE001
            _log(db, user_id, body.asset_id, "failed", f"{where}. Error: {exc}")
            logger.exception("%s audit execution failed", spec.label)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Audit execution failed. See the server logs for details.")

        summary = service.summary(db, session.id)
        _log(db, user_id, session.id, "success",
             f"{where}, Profile: {body.profile}, Compliance: {session.compliance_pct}%")
        consume_quota(request)
        return summary

    @router.get("/sessions", response_model=List[BenchmarkSessionResponse])
    def list_sessions(limit: int = Query(50, ge=1), offset: int = Query(0, ge=0),
                      current_user: User = Depends(require_permission("AUDITING", "read")),
                      db: Session = Depends(get_db)):
        sessions = service.list_sessions(db, min(limit, 100), offset, owner_id=owner_scope(current_user))
        return [s for s in (service.summary(db, x.id) for x in sessions) if s]

    @router.get("/sessions/count")
    def count(current_user: User = Depends(require_permission("AUDITING", "read")),
              db: Session = Depends(get_db)):
        return {"total": service.count(db, owner_id=owner_scope(current_user))}

    def _own_session(db, session_id, current_user) -> AuditSession:
        session = service.get_session(db, session_id)
        if not session or session.device_type != spec.device_type:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"Audit session {session_id} not found")
        assert_session_access(session, current_user)
        return session

    @router.get("/sessions/{session_id}", response_model=BenchmarkSessionResponse)
    def get_session(session_id: int, current_user: User = Depends(require_permission("AUDITING", "read")),
                    db: Session = Depends(get_db)):
        _own_session(db, session_id, current_user)
        return service.summary(db, session_id)

    @router.get("/sessions/{session_id}/results", response_model=List[BenchmarkResultResponse])
    def get_results(session_id: int, current_user: User = Depends(require_permission("AUDITING", "read")),
                    db: Session = Depends(get_db)):
        _own_session(db, session_id, current_user)
        return [{
            "id": r.id, "check_number": r.check_number, "check_title": r.check_title,
            "severity": r.severity, "level": r.level or "L1", "status": r.status.value,
            "evidence_snippet": r.evidence_snippet,
            "checked_at": r.checked_at.isoformat() if r.checked_at else None,
        } for r in service.get_results(db, session_id)]

    @router.get("/asset/{asset_id}/history", response_model=List[BenchmarkSessionResponse])
    def asset_history(asset_id: int, limit: int = Query(10, ge=1, le=100),
                      current_user: User = Depends(require_permission("AUDITING", "read")),
                      db: Session = Depends(get_db)):
        if not db.query(Asset).filter(Asset.id == asset_id).first():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset {asset_id} not found")
        sessions = service.asset_history(db, asset_id, limit, owner_id=owner_scope(current_user))
        return [s for s in (service.summary(db, x.id) for x in sessions) if s]

    @router.delete("/sessions/{session_id}")
    def delete_session(session_id: int, current_user: User = Depends(require_permission("AUDITING", "write")),
                       db: Session = Depends(get_db)):
        session = _own_session(db, session_id, current_user)
        user_id, asset_id, ip = current_user.id, session.asset_id, session.target_ip
        service.delete(db, session_id)
        log_action(db=db, user_id=user_id, action="delete_audit_session", module=spec.log_module,
                   target_id=session_id, result="success",
                   detail=f"Deleted session for Asset ID: {asset_id}, IP: {ip}")
        return {"message": f"Audit session {session_id} deleted successfully"}

    return router


def build_hardening_router(spec: ModuleSpec) -> APIRouter:
    service = BenchmarkHardeningService(spec)
    connector = get_connector(spec.connector)
    ts = spec.templates

    SingleFixRequest = create_model(
        _model_name(spec, "SingleFixRequest"),
        asset_id=(int, Field(...)),
        session_id=(Optional[int], Field(None, description="Audit session whose result is updated on success")),
        check_id=(str, Field(..., max_length=100)),
        parameters=(Dict[str, str], Field(default_factory=dict)),
        **copy.deepcopy(connector.request_fields),
    )

    router = APIRouter(prefix=f"/api/hardening/{spec.key}",
                       tags=spec.tags_hardening or [f"Hardening - {spec.label}"])

    def _param_info(check_id):
        return [{
            "name": p.name, "type": p.input_type, "label": p.label, "description": p.description,
            "required": p.required and p.default is None, "default": p.default, "options": p.options,
            "min_value": p.min_value, "max_value": p.max_value,
        } for p in ts.params_for(check_id)]

    @router.post("/preview")
    def preview(body: PreviewRequest, current_user: User = Depends(require_permission("HARDENING", "read"))):
        template = ts.get(body.check_id)
        if not template:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"No hardening template found for check {body.check_id}")
        if template.manual_only:
            # The UI shows this as "manual remediation required" with the text
            # below, so it carries the guidance, not just the refusal.
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Check {body.check_id} requires manual remediation: {template.description}")
        try:
            commands = ts.statements(body.check_id, body.parameters or {})
        except ParameterSecurityError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        params = ts.params_for(body.check_id)
        warnings = []
        if template.warning:
            warnings.append(template.warning)
        if template.requires_restart:
            warnings.append("Requires a restart after execution")
        return {
            "check_id": body.check_id,
            "check_title": template.description,
            "commands": commands,
            "required_parameters": [p.name for p in params if p.required and p.default is None],
            "optional_parameters": [p.name for p in params if not (p.required and p.default is None)],
            "parameter_defaults": ts.defaults(body.check_id),
            "warnings": warnings,
            "auto_fixable": ts.auto_fixable(body.check_id),
        }

    @router.post("/execute-single", dependencies=[Depends(check_quota_available("harden"))])
    def execute_single(http_request: Request, body: SingleFixRequest,  # type: ignore[valid-type]
                       current_user: User = Depends(require_permission("HARDENING", "write")),
                       db: Session = Depends(get_db)):
        consume_quota = consume_quota_on_success("harden")
        user_id = current_user.id
        if body.session_id is not None:
            session = db.query(AuditSession).filter(AuditSession.id == body.session_id).first()
            assert_session_access(session, current_user)
            if session.device_type != spec.device_type:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"Session {body.session_id} is not a {spec.label} audit session")

        def _log(success, failed, error=None):
            log_session_execute_outcome(db, device_type=spec.key, action="execute_single", session_id=None,
                                        asset_id=body.asset_id, user_id=user_id, check_ids=[body.check_id],
                                        success_count=success, failed_count=failed, error=error)
        try:
            result = service.execute_single(db, body.asset_id, _credentials(body, spec), body.check_id,
                                            body.parameters, session_id=body.session_id)
        except ValueError as exc:
            _log(0, 1, str(exc))
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        except PermissionError as exc:
            _log(0, 1, str(exc))
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={
                "error_type": "authentication_error",
                "message": "Authentication failed — check the username and password."})
        except ConnectionError as exc:
            _log(0, 1, str(exc))
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail={
                "error_type": "connection_error",
                "message": "Could not connect to the device — check the host, port, and network."})
        except Exception as exc:  # noqa: BLE001
            _log(0, 1, str(exc))
            logger.exception("%s single fix failed", spec.label)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Single fix failed. See the server logs for details.")
        consume_quota(http_request)
        ok = result.get("success") is True
        _log(1 if ok else 0, 0 if ok else 1, result.get("error_message"))
        return result

    @router.get("/supported-checks")
    def supported_checks(current_user: User = Depends(require_permission("HARDENING", "read"))):
        return service.supported_checks()

    @router.get("/check/{check_id}/template")
    def check_template(check_id: str, current_user: User = Depends(require_permission("HARDENING", "read"))):
        template = ts.get(check_id)
        if not template:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail=f"No hardening template found for check {check_id}")
        return {
            "check_id": check_id,
            "description": template.description,
            "statements": template.statements,
            "verify_statements": template.verify_statements,
            "requires_restart": template.requires_restart,
            "manual_only": template.manual_only,
            "warning": template.warning,
            "auto_fixable": ts.auto_fixable(check_id),
            "parameters": _param_info(check_id),
            "defaults": ts.defaults(check_id),
        }

    return router
