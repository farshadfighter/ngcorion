"""
System Configuration API Router

Six sections — time, SNMP, syslog, SMS, SMTP and TLS certificate — applied to
the local host this API runs on.

All routes require JWT authentication. Access is governed by the SYSTEM_CONFIG
module permission, matching the codebase-wide require_permission(module, type)
pattern:
  GET (view) endpoints          -> SYSTEM_CONFIG read
  PUT / POST / DELETE endpoints -> SYSTEM_CONFIG write
Admins bypass permission checks as everywhere else.

Persistence order for the applied sections (time/snmp/syslog) is
save-then-apply: the operator's input is committed first, then pushed to the
host. Since the backend container has no systemd, the apply step is best-effort
— whatever could not be done here comes back as
``{"success": true, "warning": "Config saved. …"}`` with HTTP 200, never a 500
that would hide the fact that the settings were stored. The audit log still
records those as result=failed.
"""
import logging
from typing import Any, Dict, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.models import User, log_action
from app.models.system_config import (
    SECTION_SMS,
    SECTION_SMTP,
    SECTION_SNMP,
    SECTION_SYSLOG,
    SECTION_TIME,
    SystemConfigSetting,
)

from .schemas import (
    SmsConfig,
    SmsTestRequest,
    SmtpConfig,
    SmtpTestRequest,
    SnmpConfig,
    SyslogConfig,
    TimeConfig,
)
from . import service
from .service import SystemConfigError

logger = logging.getLogger(__name__)

router = APIRouter()

MODULE = "system_config"


# ======================================================================
# Helpers
# ======================================================================

def _load(db: Session, section: str) -> Dict[str, Any]:
    """Stored payload for a section ({} when never configured)."""
    row = (
        db.query(SystemConfigSetting)
        .filter(SystemConfigSetting.section == section)
        .first()
    )
    return dict(row.config_json or {}) if row else {}


def _save(
    db: Session, section: str, payload: Dict[str, Any], user: User
) -> SystemConfigSetting:
    """Upsert the single row for this section."""
    row = (
        db.query(SystemConfigSetting)
        .filter(SystemConfigSetting.section == section)
        .first()
    )
    if row is None:
        row = SystemConfigSetting(section=section)
        db.add(row)
    row.config_json = payload
    row.updated_by = user.id
    db.commit()
    db.refresh(row)
    return row


def _log(
    db: Session,
    user_id: Optional[int],
    username: Optional[str],
    action: str,
    detail: str,
    result: str = "success",
) -> None:
    log_action(
        db, user_id=user_id, username=username,
        action=action, module=MODULE, detail=detail, result=result,
    )


def _updated_at(db: Session, section: str) -> Optional[str]:
    row = (
        db.query(SystemConfigSetting)
        .filter(SystemConfigSetting.section == section)
        .first()
    )
    return row.updated_at.isoformat() if row and row.updated_at else None


def _persist_and_apply(
    db: Session,
    user: User,
    section: str,
    payload: Dict[str, Any],
    apply_fn,
) -> Optional[str]:
    """Save the section, then apply it to the host (see module docstring).

    Returns None when the host accepted everything, or a single warning string
    describing what still has to be done by hand. A host that can't be
    reconfigured from here is not a request failure: the settings are stored, so
    the caller gets 200 with the warning rather than a 500 that hides the save.
    """
    user_id, username = user.id, user.username
    _save(db, section, payload, user)

    action = f"system_config.{section}.update"
    warnings = apply_fn(payload) or []
    if not warnings:
        _log(db, user_id, username, action,
             detail=f"Applied {section} configuration")
        return None

    warning = "Config saved. " + " ".join(warnings)
    # result=failed keeps the audit trail honest even though the API returns 200.
    _log(db, user_id, username, action,
         detail=f"Saved with warnings: {' '.join(warnings)}", result="failed")
    return warning


# ======================================================================
# 1. Time
# ======================================================================

@router.get("/time")
def get_time_config(
    _current_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
    db: Session = Depends(get_db),
):
    """Stored time settings plus the host's live clock state."""
    return {
        "config": _load(db, SECTION_TIME) or None,
        "server_time": service.system_time_status(),
        "updated_at": _updated_at(db, SECTION_TIME),
    }


@router.put("/time")
def update_time_config(
    data: TimeConfig,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Save the time settings and apply them with timedatectl/timesyncd."""
    payload = data.model_dump(mode="json")
    warning = _persist_and_apply(db, current_user, SECTION_TIME, payload,
                                 service.apply_time_config)
    return {
        "success": True,
        "warning": warning,
        "config": payload,
        "server_time": service.system_time_status(),
        "updated_at": _updated_at(db, SECTION_TIME),
    }


# ======================================================================
# 2. SNMP
# ======================================================================

@router.get("/snmp")
def get_snmp_config(
    _current_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
    db: Session = Depends(get_db),
):
    """SNMP settings with the v3 passwords masked."""
    stored = _load(db, SECTION_SNMP)
    return {
        "config": service.mask_snmp(stored) if stored else None,
        "updated_at": _updated_at(db, SECTION_SNMP),
    }


@router.put("/snmp")
def update_snmp_config(
    data: SnmpConfig,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Save the SNMP settings, rewrite snmpd.conf and restart snmpd.

    Passwords echoed back as the mask keep their stored value, so a client that
    re-submits a masked GET never overwrites a real password with asterisks.
    """
    stored = _load(db, SECTION_SNMP)
    payload = data.model_dump(mode="json")
    payload["v3_auth_password"] = service.unmask(
        payload.get("v3_auth_password"), stored.get("v3_auth_password")
    )
    payload["v3_priv_password"] = service.unmask(
        payload.get("v3_priv_password"), stored.get("v3_priv_password")
    )
    if payload["version"] == "v3" and not (
        payload.get("v3_auth_password") and payload.get("v3_priv_password")
    ):
        raise HTTPException(
            status_code=400,
            detail="v3_auth_password and v3_priv_password are required for SNMP v3",
        )

    warning = _persist_and_apply(db, current_user, SECTION_SNMP, payload,
                                 service.apply_snmp_config)
    return {
        "success": True,
        "warning": warning,
        "config": service.mask_snmp(payload),
        "updated_at": _updated_at(db, SECTION_SNMP),
    }


# ======================================================================
# 3. Syslog
# ======================================================================

@router.get("/syslog")
def get_syslog_config(
    _current_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
    db: Session = Depends(get_db),
):
    return {
        "config": _load(db, SECTION_SYSLOG) or None,
        "updated_at": _updated_at(db, SECTION_SYSLOG),
    }


@router.put("/syslog")
def update_syslog_config(
    data: SyslogConfig,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Save the syslog settings, write the rsyslog drop-in and restart rsyslog."""
    payload = data.model_dump(mode="json")
    warning = _persist_and_apply(db, current_user, SECTION_SYSLOG, payload,
                                 service.apply_syslog_config)
    return {
        "success": True,
        "warning": warning,
        "config": payload,
        "updated_at": _updated_at(db, SECTION_SYSLOG),
    }


# ======================================================================
# 4. SMS
# ======================================================================

@router.get("/sms")
def get_sms_config(
    _current_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
    db: Session = Depends(get_db),
):
    """SMS settings with the API key and password masked."""
    stored = _load(db, SECTION_SMS)
    return {
        "config": service.mask_sms(stored) if stored else None,
        "updated_at": _updated_at(db, SECTION_SMS),
    }


@router.put("/sms")
def update_sms_config(
    data: SmsConfig,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Save the SMS settings (no host-level change to apply)."""
    user_id, username = current_user.id, current_user.username
    stored = _load(db, SECTION_SMS)
    payload = data.model_dump(mode="json")
    payload["api_key"] = service.unmask(payload.get("api_key"), stored.get("api_key"))
    payload["password"] = service.unmask(
        payload.get("password"), stored.get("password")
    )
    # Echoing the mask back for a secret that was never stored unmasks to None,
    # which would then be written over a field the schema declares as required
    # (and later fail at send time with an unhelpful error). Reject it here, the
    # way the SNMP route already does for its v3 passwords.
    if not payload.get("api_key"):
        raise HTTPException(
            status_code=400,
            detail="api_key is required; no stored value to keep",
        )

    _save(db, SECTION_SMS, payload, current_user)
    _log(db, user_id, username, "system_config.sms.update",
         detail=f"Updated SMS settings (provider={payload.get('provider')})")
    return {
        "success": True,
        "warning": None,  # nothing to apply on the host
        "config": service.mask_sms(payload),
        "updated_at": _updated_at(db, SECTION_SMS),
    }


@router.post("/sms/test")
def test_sms(
    data: SmsTestRequest,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Send a test SMS with the stored credentials."""
    user_id, username = current_user.id, current_user.username
    stored = _load(db, SECTION_SMS)
    if not stored:
        raise HTTPException(
            status_code=400, detail="SMS is not configured yet"
        )

    result = service.send_test_sms(stored, data.phone)
    _log(db, user_id, username, "system_config.sms.test",
         detail=f"Test SMS to {data.phone}: {result['message']}",
         result="success" if result["success"] else "failed")
    return result


# ======================================================================
# 5. SMTP
# ======================================================================

@router.get("/smtp")
def get_smtp_config(
    _current_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
    db: Session = Depends(get_db),
):
    """SMTP settings with the password masked."""
    stored = _load(db, SECTION_SMTP)
    return {
        "config": service.mask_smtp(stored) if stored else None,
        "updated_at": _updated_at(db, SECTION_SMTP),
    }


@router.put("/smtp")
def update_smtp_config(
    data: SmtpConfig,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Save the SMTP settings (no host-level change to apply)."""
    user_id, username = current_user.id, current_user.username
    stored = _load(db, SECTION_SMTP)
    payload = data.model_dump(mode="json")
    payload["password"] = service.unmask(
        payload.get("password"), stored.get("password")
    )
    if payload.get("password") is None:
        # See the SMS route: the mask can only stand in for a secret that
        # actually exists. (An empty string is a legitimate SMTP password for a
        # relay that does not authenticate, so only None is rejected.)
        raise HTTPException(
            status_code=400,
            detail="password is required; no stored value to keep",
        )

    _save(db, SECTION_SMTP, payload, current_user)
    _log(db, user_id, username, "system_config.smtp.update",
         detail=f"Updated SMTP settings (host={payload.get('host')}:{payload.get('port')})")
    return {
        "success": True,
        "warning": None,  # nothing to apply on the host
        "config": service.mask_smtp(payload),
        "updated_at": _updated_at(db, SECTION_SMTP),
    }


@router.post("/smtp/test")
def test_smtp(
    data: SmtpTestRequest,
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Send a test email with the stored settings."""
    user_id, username = current_user.id, current_user.username
    stored = _load(db, SECTION_SMTP)
    if not stored:
        raise HTTPException(status_code=400, detail="SMTP is not configured yet")

    result = service.send_test_email(stored, str(data.to))
    _log(db, user_id, username, "system_config.smtp.test",
         detail=f"Test email to {data.to}: {result['message']}",
         result="success" if result["success"] else "failed")
    return result


# ======================================================================
# 6. Certificate (no DB row — files live in /etc/ngcorion/certs)
# ======================================================================

@router.get("/certificate")
def get_certificate(
    _current_user: User = Depends(require_permission("SYSTEM_CONFIG", "read")),
):
    """Metadata of the installed TLS certificate, read from the file itself."""
    try:
        return service.get_certificate_info()
    except SystemConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/certificate/upload")
async def upload_certificate(
    cert_file: Optional[UploadFile] = File(
        None, description="PEM/DER certificate (.cer or .crt)"
    ),
    key_file: Optional[UploadFile] = File(
        None, description="Matching private key (PEM), optional"
    ),
    pfx_file: Optional[UploadFile] = File(
        None, description="PKCS#12 bundle (.pfx) — alternative to cert_file"
    ),
    pfx_password: Optional[str] = Form(None),
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Install a TLS certificate from either a cert(+key) pair or a PFX bundle,
    then hand it to Traefik through the shared ./traefik/certs mount."""
    user_id, username = current_user.id, current_user.username

    if pfx_file is not None and cert_file is not None:
        raise HTTPException(
            status_code=400,
            detail="Upload either cert_file (+ key_file) or pfx_file, not both",
        )
    if pfx_file is None and cert_file is None:
        raise HTTPException(
            status_code=400, detail="cert_file or pfx_file is required"
        )

    try:
        if pfx_file is not None:
            cert_pem, key_pem = service.extract_pfx(
                await pfx_file.read(), pfx_password
            )
            source = pfx_file.filename or "bundle.pfx"
        else:
            cert_pem = service.normalize_certificate(await cert_file.read())
            key_pem = (
                service.validate_private_key(await key_file.read())
                if key_file is not None else None
            )
            source = cert_file.filename or "certificate"

        service.save_certificate(cert_pem, key_pem)
        info = service.get_certificate_info()
    except SystemConfigError as exc:
        _log(db, user_id, username, "system_config.certificate.upload",
             detail=f"Upload failed: {exc}", result="failed")
        raise HTTPException(status_code=500, detail=str(exc))

    publish_result = service.publish_certificate_to_proxy()
    _log(db, user_id, username, "system_config.certificate.upload",
         detail=(
             f"Installed certificate from '{source}' "
             f"(issued_to={info.get('issued_to')}, expires_at={info.get('expires_at')}); "
             f"traefik: {publish_result['message']}"
         ),
         result="success" if publish_result["published"] else "failed")

    return {
        "success": True,
        "message": publish_result["message"],
        "certificate": info,
        "traefik": publish_result,
    }


@router.delete("/certificate")
def remove_certificate(
    current_user: User = Depends(require_permission("SYSTEM_CONFIG", "write")),
    db: Session = Depends(get_db),
):
    """Delete the installed certificate and key from disk."""
    user_id, username = current_user.id, current_user.username
    try:
        removed = service.delete_certificate()
    except SystemConfigError as exc:
        _log(db, user_id, username, "system_config.certificate.delete",
             detail=f"Delete failed: {exc}", result="failed")
        raise HTTPException(status_code=500, detail=str(exc))

    if not removed:
        raise HTTPException(status_code=404, detail="No certificate installed")

    _log(db, user_id, username, "system_config.certificate.delete",
         detail="Removed the installed certificate and key")
    # The copy published to traefik/certs is deliberately left in place:
    # removing it would leave Traefik with no certificate at all and break
    # HTTPS for everyone, including this UI.
    return {
        "success": True,
        "message": (
            "Certificate removed. The copy Traefik is serving from "
            "traefik/certs was left in place so HTTPS keeps working; replace it "
            "by uploading a new certificate."
        ),
    }
