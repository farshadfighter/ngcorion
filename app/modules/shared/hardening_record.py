"""
The hardening_actions rows of fixes run by the family services.

Cisco and FortiGate write a HardeningAction for every fix as they run it. The
Linux, Windows, SQL Server, Apache and MongoDB services and the benchmark
modules only set the audit finding to PASS, so nothing read by the risk
score ("fixed by hardening", fixes found), the hardening overview or the
Asset 360 timeline knew a fix had run. They now record each one here, from
the per-check results their executors return.
"""
import json
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, Mapping, Optional

from sqlalchemy.orm import Session

from app.core.secret_redaction import redact_commands, redact_text
from app.models import AuditResult, HardeningAction

logger = logging.getLogger(__name__)


def record_fix_results(db: Session, *, session_id: Optional[int], asset_id: Optional[int],
                       user_id: Optional[int], results: Iterable[Dict[str, Any]],
                       parameters: Optional[Mapping[str, Optional[Mapping[str, Any]]]] = None) -> int:
    """One "execute" HardeningAction per fix that ran, linked to its finding in the audit session.

    `results` are the executors' per-check dicts (check_id, success, commands_executed or
    statements_executed, their outputs, verification_result, error_message); `parameters` maps a
    check to the values it ran with, so secrets among them are redacted. A fix is verified only
    when its executor ran a verification; one that changed nothing (manual only) is not recorded.
    Best-effort: returns how many rows were written and never raises.
    """
    if not (session_id and asset_id and user_id):
        return 0
    results = [r for r in results if isinstance(r, dict) and r.get("check_id") and not r.get("manual_only")]
    if not results:
        return 0
    try:
        findings = {
            row.check_number: row for row in db.query(AuditResult).filter(
                AuditResult.session_id == session_id,
                AuditResult.check_number.in_({r["check_id"] for r in results}))
        }
        now = datetime.utcnow()
        written = 0
        for r in results:
            finding = findings.get(r["check_id"])
            if finding is None:
                continue
            params = (parameters or {}).get(r["check_id"]) or {}
            commands = r.get("commands_executed") or r.get("statements_executed") or []
            outputs = r.get("command_outputs") or r.get("statement_outputs") or {}
            output = "\n".join(f"$ {cmd}\n{out}" for cmd, out in outputs.items()) if isinstance(outputs, dict) \
                else str(outputs)
            ok = bool(r.get("success"))
            verified = r.get("verification_result")
            db.add(HardeningAction(
                audit_result_id=finding.id, user_id=user_id, asset_id=asset_id, audit_session_id=session_id,
                check_number=str(r["check_id"])[:50],
                check_title=str(r.get("check_title") or finding.check_title or r["check_id"])[:500],
                action_type="execute", status="success" if ok else "failed",
                commands_json=json.dumps(redact_commands(commands, params)),
                output=redact_text(output, params) or None,
                verification_passed=ok if verified else None,
                verification_evidence=redact_text(str(verified), params) if verified else None,
                error_message=None if ok else (redact_text(str(r.get("error_message") or ""), params) or None),
                credentials_provided=True, executed_at=now, completed_at=now,
            ))
            written += 1
        db.commit()
        return written
    except Exception:  # noqa: BLE001 - the record never fails the hardening that already ran
        logger.exception("[Hardening] recording the fixes of audit session %s failed", session_id)
        db.rollback()
        return 0
