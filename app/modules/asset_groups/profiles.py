"""
Credential profiles: device sign-in details a system administrator defines once, for group runs and
scheduled group audits.

A profile is write-only. Its secrets (password, sudo password, enable secret, database password)
are encrypted with their own key (credential_crypto PURPOSE_CREDENTIAL_PROFILES) and no API ever
returns them; an edit with a secret left empty keeps the stored one. Who may define them: system
administrators. Who may use one in a run or schedule: anyone with read permission on the
"credential_profiles" module (and, as for any audit, write permission on auditing).

Kinds, and the audit technologies each signs in to:

  ssh         cisco, fortinet, linux, apache, mongodb, docker, kubernetes, mysql, esxi, nginx
  winrm       windows, active_directory, dns_server, dhcp_server, iis
  mssql       mssql
  sophos_api  sophos

params_for() turns a profile into the keyword arguments of the technology's normal audit, the same
ones a person types into the audit form.
"""
import inspect
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.core.credential_crypto import PURPOSE_CREDENTIAL_PROFILES, decrypt, encrypt
from app.models.asset_groups import CredentialProfile

SECRET_FIELDS = ("password", "sudo_password", "enable_secret", "db_password")

KINDS: Dict[str, Dict] = {
    "ssh": {"secrets": SECRET_FIELDS, "options": {"port": 22, "db_username": None, "db_port": None}},
    "winrm": {"secrets": ("password",), "options": {"port": 5985, "transport": "ntlm", "verify_ssl": None}},
    "mssql": {"secrets": ("password",), "options": {"port": 1433}},
    "sophos_api": {"secrets": ("password",), "options": {"port": 4444}},
}
TRANSPORTS = ("ntlm", "kerberos", "credssp", "basic")

TECH_KIND = {
    **{t: "ssh" for t in ("cisco", "fortinet", "linux", "apache", "mongodb", "docker", "kubernetes",
                          "mysql", "esxi", "nginx")},
    **{t: "winrm" for t in ("windows", "active_directory", "dns_server", "dhcp_server", "iis")},
    "mssql": "mssql",
    "sophos": "sophos_api",
}

# The core audit services (app/modules/scheduling/audit_dispatch.py) take exactly their own keyword
# arguments; benchmark modules pick their connector's fields and ignore the rest.
_CORE = {
    "cisco": ("app.modules.cisco.audit.service", "AuditService", "execute_cisco_audit"),
    "fortinet": ("app.modules.fortinet.audit.service", "FortinetAuditService", "execute_fortinet_audit"),
    "linux": ("app.modules.linux.audit.service", "LinuxAuditService", "execute_linux_audit"),
    "apache": ("app.modules.apache.audit.service", "ApacheAuditService", "execute_apache_audit"),
    "mongodb": ("app.modules.mongodb.audit.service", "MongoDBSHAuditService", "execute_mongodb_audit"),
    "mssql": ("app.modules.mssql.audit.service", "MSSQLAuditService", "execute_mssql_audit"),
    "windows": ("app.modules.windows.audit.service", "WindowsAuditService", "execute_windows_audit"),
}


class ProfileError(ValueError):
    pass


def kind_for(technology: str) -> Optional[str]:
    return TECH_KIND.get(technology)


def _accepted(technology: str) -> Optional[set]:
    if technology not in _CORE:
        return None
    import importlib
    mod, cls, fn = _CORE[technology]
    func = getattr(getattr(importlib.import_module(mod), cls), fn)
    return set(inspect.signature(func).parameters) - {"db", "asset_id", "user_id"}


def _options(kind: str, given: Dict) -> Dict:
    out = {}
    for key, default in KINDS[kind]["options"].items():
        value = given.get(key, default)
        if value in ("", None):
            value = default
        if key in ("port", "db_port") and value is not None:
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ProfileError("A port is a number from 1 to 65535")
            if not 1 <= value <= 65535:
                raise ProfileError("A port is a number from 1 to 65535")
        if key == "transport" and value not in TRANSPORTS:
            raise ProfileError("Unknown WinRM transport")
        if key == "verify_ssl" and value is not None:
            value = bool(value)
        if key == "db_username" and value is not None:
            value = str(value).strip()[:256] or None
        out[key] = value
    return out


def secrets_of(profile: CredentialProfile) -> Dict[str, str]:
    return json.loads(decrypt(profile.secrets_encrypted, PURPOSE_CREDENTIAL_PROFILES))


def set_secrets(profile: CredentialProfile, kind: str, given: Dict, keep: Optional[Dict] = None) -> bool:
    """Store the secrets: an empty value keeps the stored one. True when any secret changed."""
    current = dict(keep or {})
    changed = False
    for field in KINDS[kind]["secrets"]:
        value = given.get(field)
        if value:
            if current.get(field) != value:
                changed = True
            current[field] = value
    current = {k: v for k, v in current.items() if k in KINDS[kind]["secrets"] and v}
    if not current.get("password"):
        raise ProfileError("Enter the password")
    profile.secrets_encrypted = encrypt(json.dumps(current), PURPOSE_CREDENTIAL_PROFILES)
    return changed


def public(profile: CredentialProfile, now: Optional[datetime] = None) -> Dict:
    """What the API shows of a profile: never a secret, only which secrets are set."""
    now = now or datetime.now(timezone.utc)
    changed = profile.secrets_changed_at
    if changed is not None and changed.tzinfo is None:
        changed = changed.replace(tzinfo=timezone.utc)
    age_days = (now - changed).days if changed else None
    try:
        has = sorted(secrets_of(profile))
    except Exception:  # noqa: BLE001 - a key change makes old secrets unreadable; show the profile anyway
        has = []
    return {
        "id": profile.id, "name": profile.name, "kind": profile.kind, "username": profile.username,
        "options": profile.options or {}, "description": profile.description,
        "secrets_set": has, "rotation_days": profile.rotation_days,
        "secrets_changed_at": profile.secrets_changed_at, "age_days": age_days,
        "rotation_due": bool(profile.rotation_days and age_days is not None and age_days >= profile.rotation_days),
        "last_used_at": profile.last_used_at, "created_at": profile.created_at,
    }


def create(db: Session, data: Dict, user_id: Optional[int]) -> CredentialProfile:
    kind = data["kind"]
    if kind not in KINDS:
        raise ProfileError("Unknown profile kind")
    p = CredentialProfile(name=data["name"].strip(), kind=kind, username=data["username"].strip(),
                          options=_options(kind, data.get("options") or {}),
                          description=(data.get("description") or "").strip() or None,
                          rotation_days=data.get("rotation_days", 90), created_by=user_id,
                          secrets_changed_at=datetime.now(timezone.utc))
    set_secrets(p, kind, data.get("secrets") or {})
    db.add(p)
    return p


def update(db: Session, p: CredentialProfile, data: Dict) -> bool:
    """Apply an edit; True when a secret (or the user name) changed, which restarts the rotation age."""
    if data.get("name") is not None:
        p.name = data["name"].strip()
    if data.get("description") is not None:
        p.description = data["description"].strip() or None
    if data.get("rotation_days") is not None:
        p.rotation_days = data["rotation_days"]
    if data.get("options") is not None:
        p.options = _options(p.kind, data["options"])
    renamed = data.get("username") is not None and data["username"].strip() != p.username
    if renamed:
        p.username = data["username"].strip()
    changed = set_secrets(p, p.kind, data.get("secrets") or {}, keep=secrets_of(p)) or renamed
    if changed:
        p.secrets_changed_at = datetime.now(timezone.utc)
    return changed


def params_for(technology: str, profile: CredentialProfile, audit_profile: Optional[str] = None,
               job_name: Optional[str] = None) -> Dict:
    """The audit's keyword arguments for `technology`, signing in with `profile`."""
    kind = kind_for(technology)
    if kind is None:
        raise ProfileError("This technology cannot be audited with a credential profile")
    if profile.kind != kind:
        raise ProfileError("The credential profile is of a different kind than the technology needs")
    s, o, user = secrets_of(profile), profile.options or {}, profile.username
    if kind == "ssh":
        p = {"ssh_username": user, "ssh_password": s.get("password"), "ssh_port": o.get("port") or 22,
             "sudo_password": s.get("sudo_password"), "ssh_secret": s.get("enable_secret")}
        db_user, db_pw, db_port = o.get("db_username"), s.get("db_password"), o.get("db_port")
        if technology == "mongodb":
            p.update(mongo_username=db_user, mongo_password=db_pw, mongo_port=db_port)
        if technology == "mysql":
            p.update(mysql_username=db_user or "root", mysql_password=db_pw, mysql_port=db_port or 3306)
    elif kind == "winrm":
        p = {"windows_username": user, "windows_password": s.get("password"), "winrm_port": o.get("port") or 5985,
             "transport": o.get("transport") or "ntlm", "verify_ssl": o.get("verify_ssl")}
    elif kind == "mssql":
        p = {"mssql_username": user, "mssql_password": s.get("password"), "mssql_port": o.get("port") or 1433}
    else:
        p = {"sophos_username": user, "sophos_password": s.get("password"), "sophos_port": o.get("port") or 4444}
    p.update(profile=audit_profile, job_name=job_name)
    p = {k: v for k, v in p.items() if v is not None}
    accepted = _accepted(technology)
    if accepted is not None:
        p = {k: v for k, v in p.items() if k in accepted}
    return p


def mark_used(db: Session, profile_id: int) -> None:
    db.query(CredentialProfile).filter(CredentialProfile.id == profile_id) \
        .update({"last_used_at": datetime.now(timezone.utc)}, synchronize_session=False)


def rotation_due(db: Session, now: Optional[datetime] = None):
    """Profiles whose secrets are older than their rotation period."""
    now = now or datetime.now(timezone.utc)
    out = []
    for p in db.query(CredentialProfile).filter(CredentialProfile.rotation_days > 0):
        changed = p.secrets_changed_at
        if changed.tzinfo is None:
            changed = changed.replace(tzinfo=timezone.utc)
        if now - changed >= timedelta(days=p.rotation_days):
            out.append(p)
    return out


# ── test sign-in on one asset ────────────────────────────────────────────────

def test_sign_in(profile: CredentialProfile, ip: str) -> None:
    """Connect to `ip` and sign in with the profile; nothing is run on the device beyond what the
    sign-in itself needs. Raises PermissionError when the sign-in is refused, ConnectionError when the
    device cannot be reached."""
    s, o = secrets_of(profile), profile.options or {}
    if profile.kind == "ssh":
        # Only the sign-in: network devices (Cisco, FortiGate) have no sudo to try.
        from app.core.ssh_exceptions import SSHAuthenticationError, SSHConnectionError
        from app.modules.linux.common.fast_ssh_runner import HardeningSSHRunner
        runner = HardeningSSHRunner(ip=ip, username=profile.username, password=s.get("password"),
                                    port=int(o.get("port") or 22), max_retries=1)
        try:
            runner.connect()
        except SSHAuthenticationError as exc:
            raise PermissionError(str(exc)) from exc
        except SSHConnectionError as exc:
            raise ConnectionError(str(exc)) from exc
        runner.disconnect()
        return
    if profile.kind == "mssql":
        from app.modules.mssql.audit.mssql_client import MSSQLClient
        try:
            with MSSQLClient(ip, profile.username, s.get("password"), port=int(o.get("port") or 1433),
                             timeout=10, max_retries=1):
                return
        except PermissionError:
            raise
        except Exception as exc:  # noqa: BLE001 - driver errors carry no secret, but keep the type only
            raise ConnectionError(type(exc).__name__) from exc
    from app.modules.benchmark.connectors import get_connector
    tech = {"winrm": "windows", "sophos_api": "sophos"}[profile.kind]
    with get_connector(profile.kind).open(ip, params_for(tech, profile)):
        return
