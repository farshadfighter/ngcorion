"""
An asset's last audit and last hardening dates, kept by NGCorion instead of typed in.

When an audit session of an asset is saved as completed, the asset's last_audit_date moves to that day;
when a hardening change on it is saved as successful (not a preview), last_hardening_date does. This
runs for every audit and hardening family, whatever module saves the row. Dates only move forward: a
later date set by hand (an audit done outside NGCorion) is kept.
"""
from datetime import date, datetime

from sqlalchemy import event
from sqlalchemy.orm import Session


def _day(value) -> date:
    if isinstance(value, datetime):
        return value.date()
    return value if isinstance(value, date) else datetime.utcnow().date()


def _advance(session: Session, asset_id: int, field: str, day: date) -> None:
    from app.models.asset import Asset
    asset = session.get(Asset, asset_id)
    if asset is not None and (getattr(asset, field) is None or getattr(asset, field) < day):
        setattr(asset, field, day)


@event.listens_for(Session, "before_flush")
def _keep_asset_dates(session: Session, flush_context, instances) -> None:
    from app.models.audit import AuditSession
    from app.models.hardening import HardeningAction
    for obj in list(session.new) + list(session.dirty):
        if isinstance(obj, AuditSession):
            if obj.status == "completed" and obj.asset_id:
                _advance(session, obj.asset_id, "last_audit_date", _day(obj.completed_at or obj.started_at))
        elif isinstance(obj, HardeningAction):
            if obj.status == "success" and obj.action_type != "preview" and obj.asset_id:
                _advance(session, obj.asset_id, "last_hardening_date", _day(obj.completed_at or obj.executed_at))
