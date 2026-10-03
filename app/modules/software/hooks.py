"""
Software collection inside audits, and on demand.

Audits call collect_* while their connection is open and save_* once the
audit is done. Neither may fail an audit: errors are logged and recorded as
a failed collection, and the audit carries on.
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.modules.software import collect, store

logger = logging.getLogger(__name__)


# ── Linux ─────────────────────────────────────────────────────────────────

def collect_linux(ssh_client, distro_id: str) -> dict:
    """Run the package commands on an open LinuxSSHClient."""
    family = collect.linux_family(distro_id)
    try:
        cmds = [{"cmd": cmd, "sudo": False, "key": key, "timeout": timeout}
                for key, cmd, timeout in collect.LINUX_COMMANDS[family]]
        outputs = ssh_client.collect_audit_data(cmds)
        errors = [k for k, v in outputs.items() if isinstance(v, str) and v.startswith("<<ERROR")]
        main = "deb_packages" if family == "debian" else "rpm_packages"
        if main in errors or not (outputs.get(main) or "").strip():
            return {"family": family, "error": "The package list could not be read"}
        return {"family": family, "outputs": outputs}
    except Exception as exc:
        logger.warning("[software] Linux collection failed: %s", type(exc).__name__)
        return {"family": family, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}


def save_linux(db: Session, asset_id: int, raw: Optional[dict], *, audit_session_id=None, user_id=None,
               trigger="audit"):
    if not raw:
        return None
    try:
        if raw.get("error"):
            return store.save(db, asset_id, "linux", None, trigger=trigger, audit_session_id=audit_session_id,
                              user_id=user_id, error=raw["error"])
        items = collect.parse_linux(raw["family"], raw["outputs"])
        if not items:
            return store.save(db, asset_id, "linux", None, trigger=trigger, audit_session_id=audit_session_id,
                              user_id=user_id, error="No installed package was found in the output")
        return store.save(db, asset_id, "linux", items, trigger=trigger, audit_session_id=audit_session_id,
                          user_id=user_id)
    except Exception:
        logger.exception("[software] saving the Linux inventory of asset %s failed", asset_id)
        db.rollback()
        return None


# ── Windows ───────────────────────────────────────────────────────────────

def collect_windows(client) -> dict:
    """Run the inventory script on an open WindowsWinRMClient."""
    try:
        output = client._run_ps(collect.WINDOWS_SCRIPT)
        if output.startswith("PS_ERROR") or output == "(no output)":
            return {"error": output[:300]}
        return {"output": output}
    except Exception as exc:
        logger.warning("[software] Windows collection failed: %s", type(exc).__name__)
        return {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}


def save_windows(db: Session, asset_id: int, raw: Optional[dict], *, audit_session_id=None, user_id=None,
                 trigger="audit"):
    if not raw:
        return None
    try:
        if raw.get("error"):
            return store.save(db, asset_id, "windows", None, trigger=trigger, audit_session_id=audit_session_id,
                              user_id=user_id, error=raw["error"])
        items = collect.parse_windows(raw["output"])
        return store.save(db, asset_id, "windows", items or None, trigger=trigger,
                          audit_session_id=audit_session_id, user_id=user_id,
                          error=None if items else "No installed program was found in the output")
    except Exception:
        logger.exception("[software] saving the Windows inventory of asset %s failed", asset_id)
        db.rollback()
        return None


# ── one version a service or device reports about itself ──────────────────

def save_single(db: Session, asset_id: Optional[int], collector: str, item: Optional[dict], *,
                audit_session_id=None, user_id=None):
    """Apache / MongoDB / SQL Server / Cisco / Fortinet audits. Nothing is
    recorded when the version could not be read - the previous one stays."""
    if not asset_id or not item:
        return None
    try:
        col = store.save(db, asset_id, collector, [item], audit_session_id=audit_session_id, user_id=user_id)
        if item.get("kind") == "firmware":
            store.record_firmware(db, asset_id, item, user_id)
        return col
    except Exception:
        logger.exception("[software] saving the %s version of asset %s failed", collector, asset_id)
        db.rollback()
        return None


# ── on demand ─────────────────────────────────────────────────────────────

def collect_now_linux(db: Session, asset, *, username: str, password: str, port: int = 22,
                      sudo_password: Optional[str] = None, user_id=None):
    """Connect, read the package list, save. Credentials are used once."""
    from app.modules.linux.common.ssh_client import LinuxSSHClient
    client = LinuxSSHClient(ip=asset.ip_address, username=username, password=password,
                            sudo_password=sudo_password, port=port, max_retries=1)
    client.connect()
    try:
        distro = client.detect_distro()
        raw = collect_linux(client, distro.get("id", "ubuntu"))
    finally:
        client.disconnect()
    return save_linux(db, asset.id, raw, user_id=user_id, trigger="manual")


def collect_now_windows(db: Session, asset, *, username: str, password: str, port: int = 5985,
                        transport: str = "ntlm", user_id=None):
    from app.core.config import settings
    from app.modules.windows.audit.winrm_client import WindowsWinRMClient
    with WindowsWinRMClient(ip=asset.ip_address, username=username, password=password, port=port,
                            transport=transport, verify_ssl=settings.WINRM_VERIFY_SSL) as client:
        raw = collect_windows(client)
    return save_windows(db, asset.id, raw, user_id=user_id, trigger="manual")
