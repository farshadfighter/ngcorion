"""
Hardening for benchmark modules: run a check's template over the module's
connection, verify it, and flip the audit row to PASS only when verification
printed PASS.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.hardening_param_security import ParameterSecurityError
from app.models import Asset, AuditResult, AuditSession
from app.models.audit import CheckStatus
from app.modules.windows.hardening.service import _recompute_session_stats

from .connectors import get_connector
from .spec import ModuleSpec
from .templates import PLACEHOLDER_RE

logger = logging.getLogger(__name__)


def run_template(spec: ModuleSpec, conn, check_id: str, parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute one check's fix on an open connection. Never raises."""
    ts = spec.templates
    result: Dict[str, Any] = {
        "check_id": check_id, "success": False, "statements_executed": [], "statement_outputs": {},
        "verification_result": None, "error_message": None, "requires_restart": False, "manual_only": False,
    }
    template = ts.get(check_id)
    if not template:
        result["error_message"] = f"No hardening template found for {check_id}"
        return result
    result["requires_restart"] = template.requires_restart
    result["manual_only"] = template.manual_only
    if template.manual_only:
        result["error_message"] = f"Check {check_id} requires manual remediation: {template.description}"
        return result

    missing = ts.missing(check_id, parameters)
    if missing:
        result["error_message"] = f"Missing required parameter(s): {', '.join(missing)}"
        return result

    try:
        statements = ts.statements(check_id, parameters)
        verify = ts.verify_statements(check_id, parameters)
    except ParameterSecurityError as exc:
        result["error_message"] = str(exc)
        return result

    leftover = sorted({m for s in statements + verify for m in PLACEHOLDER_RE.findall(s)})
    if leftover:
        result["error_message"] = f"Missing required parameter(s): {', '.join(leftover)}"
        return result

    errors = []
    for stmt in statements:
        try:
            out = conn.execute(stmt)
            result["statements_executed"].append(stmt)
            result["statement_outputs"][stmt[:100]] = out
        except Exception as exc:  # noqa: BLE001
            result["statement_outputs"][stmt[:100]] = f"ERROR: {str(exc)[:200]}"
            errors.append(str(exc)[:200])
            logger.error("[%s] %s failed: %s", spec.key, check_id, exc)
            # Later statements build on earlier ones; stop at the first failure.
            break

    if verify:
        outputs = []
        for vstmt in verify:
            try:
                outputs.append(conn.execute(vstmt))
            except Exception as exc:  # noqa: BLE001
                outputs.append(f"ERROR: {str(exc)[:200]}")
        result["verification_result"] = "\n".join(outputs)
        text = result["verification_result"]
        if "FAIL" in text:
            result["success"] = False
        elif "PASS" in text:
            result["success"] = True
        else:
            result["error_message"] = "Verification produced no PASS/FAIL signal — fix not confirmed"
    else:
        result["success"] = not errors

    if errors and not result["success"]:
        result["error_message"] = "; ".join(errors[:3])
    return result


class BenchmarkHardeningService:
    def __init__(self, spec: ModuleSpec):
        self.spec = spec

    def _asset(self, db: Session, asset_id: int) -> Asset:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if not asset:
            raise ValueError(f"Asset {asset_id} not found")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address configured")
        return asset

    def _check_session(self, db: Session, session_id: int) -> AuditSession:
        session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")
        if session.device_type != self.spec.device_type:
            raise ValueError(f"Session {session_id} is not a {self.spec.label} audit session")
        return session

    @staticmethod
    def _mark_passed(db: Session, session_id: int, results: List[Dict[str, Any]]) -> None:
        changed = False
        for r in results:
            if not r.get("success"):
                continue
            row = (db.query(AuditResult)
                   .filter(AuditResult.session_id == session_id, AuditResult.check_number == r.get("check_id"))
                   .first())
            if row:
                row.status = CheckStatus.PASS
                row.evidence_snippet = r.get("verification_result") or ""
                changed = True
        if changed:
            _recompute_session_stats(db, session_id)
        db.commit()

    def batch_execute_selected(self, db: Session, session_id: int, asset_id: int, credentials: Dict[str, Any],
                               checks: List[Dict[str, Any]], create_backup: bool = False,
                               user_id: Optional[int] = None) -> Dict[str, Any]:
        spec = self.spec
        self._check_session(db, session_id)
        asset = self._asset(db, asset_id)
        results, backup_content, backup_error = [], None, None
        with get_connector(spec.connector).open(asset.ip_address, credentials) as conn:
            if create_backup and spec.backup:
                try:
                    backup_content = spec.backup(conn)
                except Exception as exc:  # noqa: BLE001
                    backup_error = str(exc)[:300]
                    logger.error("[%s] pre-hardening backup failed on %s: %s", spec.key, asset.ip_address, exc)
            for check in checks:
                results.append(run_template(spec, conn, check.get("check_id", ""), check.get("parameters") or {}))
                time.sleep(0.1)

        out: Dict[str, Any] = {
            "total": len(checks),
            "successful": sum(1 for r in results if r["success"]),
            "failed": sum(1 for r in results if not r["success"]),
            "results": results,
        }
        if create_backup:
            if backup_content:
                from app.modules.shared.hardening_backup import save_device_backup
                save_device_backup(db, backup=backup_content, device_ip=asset.ip_address,
                                   device_type=spec.backup_device_type or spec.key,
                                   user_id=user_id, asset_id=asset_id)
                out["backup_created"] = True
            else:
                out["backup_created"] = False
                out["backup_error"] = backup_error or (
                    "No backup content captured" if spec.backup else f"{spec.label} has no configuration backup")
        self._mark_passed(db, session_id, results)
        out.update(session_id=session_id, asset_id=asset_id, target_ip=asset.ip_address,
                   executed_at=datetime.now(timezone.utc).isoformat())
        return out

    def execute_single(self, db: Session, asset_id: int, credentials: Dict[str, Any], check_id: str,
                       parameters: Optional[Dict[str, Any]] = None,
                       session_id: Optional[int] = None) -> Dict[str, Any]:
        spec = self.spec
        asset = self._asset(db, asset_id)
        with get_connector(spec.connector).open(asset.ip_address, credentials) as conn:
            result = run_template(spec, conn, check_id, parameters)
        if session_id is not None:
            self._mark_passed(db, session_id, [result])
        result.update(asset_id=asset_id, target_ip=asset.ip_address,
                      executed_at=datetime.now(timezone.utc).isoformat())
        return result

    def supported_checks(self) -> Dict[str, Any]:
        ts = self.spec.templates
        checks = []
        for cid in ts.supported():
            t = ts.get(cid)
            checks.append({
                "check_id": cid, "description": t.description, "auto_fixable": ts.auto_fixable(cid),
                "manual_only": t.manual_only, "requires_restart": t.requires_restart,
                "default_parameters": ts.defaults(cid), "warning": t.warning,
            })
        return {"total_supported": len(checks), "checks": checks}
