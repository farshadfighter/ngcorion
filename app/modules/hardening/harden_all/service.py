"""
Harden All service — plan building and unified execution.

Two entry points:

    build_plan(db, session_id)      -> HardenAllPlan
    execute_plan(db, request, user) -> HardenAllResult

Both work purely in the unified contract; every family-specific detail lives in
families.py.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import Asset, AuditResult, AuditSession
from app.models.audit import CheckStatus

from .contract import (
    CheckOutcome,
    HardenAllPlan,
    HardenAllRequest,
    HardenAllResult,
    PlanCheck,
    PlanParameter,
    SkippedCheck,
)
from .families import ExecutionContext, FamilySpec, counts_from_raw, get_family

logger = logging.getLogger(__name__)


# ============================================================
# Shared loading
# ============================================================

def _load_session(db: Session, session_id: int) -> Tuple[AuditSession, Optional[Asset], FamilySpec]:
    session = db.query(AuditSession).filter(AuditSession.id == session_id).first()
    if not session:
        raise ValueError(f"Audit session {session_id} not found")

    spec = get_family(session.device_type)
    asset = (
        db.query(Asset).filter(Asset.id == session.asset_id).first()
        if session.asset_id else None
    )
    return session, asset, spec


def describe_session(db: Session, session_id: int) -> Tuple[str, Optional[int]]:
    """(device_family, asset_id) for audit logging. Never raises."""
    try:
        session, _asset, spec = _load_session(db, session_id)
        return spec.key, session.asset_id
    except Exception:
        return "unknown", None


def _failed_results(db: Session, session_id: int) -> List[AuditResult]:
    return (
        db.query(AuditResult)
        .filter(
            AuditResult.session_id == session_id,
            AuditResult.status == CheckStatus.FAIL,
        )
        .order_by(AuditResult.check_number)
        .all()
    )


def _row_vdom(row: AuditResult) -> Optional[str]:
    return getattr(row, "vdom", None)


def _classify(spec: FamilySpec, check_numbers: List[str]) -> Tuple[List[str], Dict[str, bool]]:
    """Split check numbers into (fixable, {check_number: needs_params}).

    A check is fixable when it has a remediation template AND the family's own
    categorizer does not report it as unsupported. Both conditions matter: some
    families gate on the template catalog, others on the parameter map.
    """
    templated = [cn for cn in dict.fromkeys(check_numbers) if spec.has_template(cn)]
    categorized = spec.categorize(templated) or {}
    unsupported = set(categorized.get("not_supported") or [])
    needs_params = set(categorized.get("needs_params") or [])

    fixable = [cn for cn in templated if cn not in unsupported]
    return fixable, {cn: cn in needs_params for cn in fixable}


def _plan_parameters(spec: FamilySpec, fixable: List[str]) -> List[PlanParameter]:
    aggregated = spec.aggregate(fixable) or {}
    params: List[PlanParameter] = []
    for name, meta in aggregated.items():
        meta = meta or {}
        params.append(PlanParameter(
            name=name,
            label=meta.get("label"),
            description=meta.get("description"),
            type=meta.get("type") or "text",
            required=bool(meta.get("required")),
            default=_as_str(meta.get("default")),
            placeholder=meta.get("placeholder"),
            options=meta.get("options"),
            min_value=meta.get("min_value"),
            max_value=meta.get("max_value"),
            validation=meta.get("validation"),
            checks=list(meta.get("checks") or []),
        ))
    params.sort(key=lambda p: (not p.required, p.name))
    return params


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


# ============================================================
# Plan
# ============================================================

def build_plan(db: Session, session_id: int) -> HardenAllPlan:
    session, asset, spec = _load_session(db, session_id)
    rows = _failed_results(db, session_id)

    fixable_numbers, needs_params_map = _classify(spec, [r.check_number for r in rows])
    fixable_set = set(fixable_numbers)
    parameters = _plan_parameters(spec, fixable_numbers)

    # check_number -> parameter names, so the UI can show which checks a field feeds
    # and so execution can hand each check only the parameters it actually uses.
    params_by_check: Dict[str, List[str]] = {}
    for param in parameters:
        for check_number in param.checks:
            params_by_check.setdefault(check_number, []).append(param.name)

    # One entry per AuditResult row, never per check number: a multi-VDOM
    # FortiGate reports the same check once per VDOM and each row is remediated
    # separately. Collapsing by check number silently fixed only one VDOM.
    fixable: List[PlanCheck] = []
    skipped: List[SkippedCheck] = []
    for row in rows:
        if row.check_number in fixable_set:
            fixable.append(PlanCheck(
                result_id=row.id,
                check_number=row.check_number,
                check_title=row.check_title,
                severity=_as_str(row.severity),
                level=_as_str(row.level),
                vdom=_row_vdom(row),
                needs_params=needs_params_map.get(row.check_number, False),
                parameters=params_by_check.get(row.check_number, []),
            ))
        else:
            skipped.append(SkippedCheck(
                result_id=row.id,
                check_number=row.check_number,
                check_title=row.check_title,
                vdom=_row_vdom(row),
            ))

    return HardenAllPlan(
        session_id=session_id,
        asset_id=session.asset_id,
        asset_name=asset.asset_name if asset else None,
        target_ip=session.target_ip,
        device_family=spec.key,
        device_label=spec.label,
        sub_device_type=session.sub_device_type,
        total_failed=len(rows),
        fixable=fixable,
        skipped=skipped,
        parameters=parameters,
        credential_fields=list(spec.credential_fields),
        capabilities=spec.capabilities,
    )


# ============================================================
# Execute
# ============================================================

def _validate(plan: HardenAllPlan, request: HardenAllRequest) -> None:
    missing_creds = [
        f.label for f in plan.credential_fields
        if f.required and not (request.credentials.get(f.name) or "").strip()
    ]
    if missing_creds:
        raise ValueError(f"Missing required credentials: {', '.join(missing_creds)}")

    missing_params = [
        p.label or p.name for p in plan.parameters
        if p.required and not (request.parameters.get(p.name) or "").strip()
    ]
    if missing_params:
        raise ValueError(f"Missing required parameters: {', '.join(missing_params)}")


def _selected_checks(plan: HardenAllPlan, request: HardenAllRequest) -> List[PlanCheck]:
    if not request.result_ids:
        return list(plan.fixable)

    wanted = set(request.result_ids)
    selected = [c for c in plan.fixable if c.result_id in wanted]
    unknown = wanted - {c.result_id for c in selected}
    if unknown:
        raise ValueError(
            "These checks are not fixable in this session: "
            + ", ".join(str(i) for i in sorted(unknown))
        )
    return selected


def _per_check_payload(selected: List[PlanCheck], values: Dict[str, str]) -> List[Dict[str, Any]]:
    """checks[] payload for the families that execute by check number.

    Each check receives only the parameters it declares, and only those the user
    actually filled in — blank values are dropped so the template's own default
    wins instead of rendering an empty string into a command.
    """
    payload: List[Dict[str, Any]] = []
    seen = set()
    for check in selected:
        if check.check_number in seen:
            continue
        seen.add(check.check_number)
        params = {
            name: values[name].strip()
            for name in check.parameters
            if (values.get(name) or "").strip()
        }
        payload.append({"check_id": check.check_number, "parameters": params})
    return payload


def _reattach_result_ids(rows: List[Dict[str, Any]], selected: List[PlanCheck]) -> List[CheckOutcome]:
    """Map family result rows back onto the plan's AuditResult ids.

    Families that execute by check number return one row per check, so a
    multi-VDOM check number maps to several plan entries; the row's own vdom
    disambiguates when the family reports it.
    """
    by_key: Dict[Tuple[str, Optional[str]], List[PlanCheck]] = {}
    by_number: Dict[str, List[PlanCheck]] = {}
    for check in selected:
        by_key.setdefault((check.check_number, check.vdom), []).append(check)
        by_number.setdefault(check.check_number, []).append(check)

    outcomes: List[CheckOutcome] = []
    for row in rows:
        number = row.get("check_number") or ""
        vdom = row.get("vdom")
        candidates = by_key.get((number, vdom)) or by_number.get(number) or []
        match = candidates.pop(0) if candidates else None
        outcomes.append(CheckOutcome(
            result_id=match.result_id if match else None,
            check_number=number,
            check_title=row.get("check_title") or (match.check_title if match else None),
            vdom=vdom or (match.vdom if match else None),
            status=row.get("status") or "failed",
            detail=row.get("detail"),
            commands=row.get("commands") or [],
        ))
    return outcomes


def execute_plan(
    db: Session,
    request: HardenAllRequest,
    user_id: int,
) -> HardenAllResult:
    session, asset, spec = _load_session(db, request.session_id)
    plan = build_plan(db, request.session_id)

    _validate(plan, request)

    if request.dry_run and not spec.capabilities.dry_run:
        raise ValueError(f"{spec.label} hardening does not support dry runs")

    selected = _selected_checks(plan, request)
    if not selected:
        raise ValueError("No fixable failed checks in this session")

    # The by-check-number families execute against an asset record, not the
    # session's target IP, so a missing asset is a hard error for them.
    if spec.key not in ("cisco", "fortinet"):
        if not asset:
            raise ValueError("This audit session is not linked to an asset")
        if not asset.ip_address:
            raise ValueError(f"Asset '{asset.asset_name}' has no IP address")

    ctx = ExecutionContext(
        db=db,
        session=session,
        asset=asset,
        user_id=user_id,
        credentials=request.credentials,
        result_ids=[c.result_id for c in selected],
        parameters={k: v.strip() for k, v in request.parameters.items() if (v or "").strip()},
        checks=_per_check_payload(selected, request.parameters),
        create_backup=request.create_backup and spec.capabilities.backup,
        dry_run=request.dry_run,
    )

    logger.info(
        "Harden All: family=%s session=%s checks=%d dry_run=%s backup=%s",
        spec.key, session.id, len(selected), ctx.dry_run, ctx.create_backup,
    )

    raw = spec.execute(ctx) or {}
    outcomes = _reattach_result_ids(spec.normalize_rows(raw), selected)

    # Counts are recomputed from the normalized rows rather than trusted from the
    # family payload, so the summary can never disagree with the list below it.
    successful = sum(1 for o in outcomes if o.status == "success")
    failed = sum(1 for o in outcomes if o.status == "failed")
    skipped = sum(1 for o in outcomes if o.status == "skipped")

    # A check that the family never reported back is a silent no-op — surface it
    # as failed rather than letting it vanish from the totals.
    reported = {o.result_id for o in outcomes if o.result_id is not None}
    for check in selected:
        if check.result_id not in reported:
            outcomes.append(CheckOutcome(
                result_id=check.result_id,
                check_number=check.check_number,
                check_title=check.check_title,
                vdom=check.vdom,
                status="failed",
                detail="The device returned no result for this check",
            ))
            failed += 1

    if not outcomes and raw:
        # Family returned counts but no rows (older auto-harden style payloads).
        counts = counts_from_raw(raw)
        successful, failed, skipped = counts["successful"], counts["failed"], counts["skipped"]

    return HardenAllResult(
        session_id=session.id,
        device_family=spec.key,
        dry_run=bool(request.dry_run),
        total=len(selected),
        successful=successful,
        failed=failed,
        skipped=skipped,
        results=outcomes,
        executed_at=datetime.now(timezone.utc).isoformat(),
    )
