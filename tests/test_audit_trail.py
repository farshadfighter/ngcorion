"""
The audit trail review API (app/modules/audit_trail.py): server-side search, filters and paging
over audit_logs and login_logs, CSV export protected against formula injection, and the export
itself recorded in the trail.
"""
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import text

from app.core.database import SessionLocal
from app.models import LoginLog
from app.models.security_audit_log import AuditLog
from app.modules import audit_trail

READER = SimpleNamespace(id=None, username="trail-reviewer")
REQUEST = SimpleNamespace(client=SimpleNamespace(host="192.0.2.30"))


@pytest.fixture
def db():
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def tag():
    """A unique user name per test: audit_logs is append-only, rows of earlier runs stay."""
    return f"trail-{uuid.uuid4().hex[:10]}"


def _events(**kw):
    base = dict(q=None, module=None, action=None, result=None, username=None, ip=None,
                date_from=None, date_to=None)
    base.update(kw)
    return base


def _seed(db, tag):
    now = datetime.now(timezone.utc)
    rows = [
        AuditLog(username=tag, action="user.create", module="user_management", result="success",
                 ip_address="10.0.0.5", detail="Created user 'bob'", timestamp=now),
        AuditLog(username=tag, action="role.change", module="user_management", result="success",
                 ip_address="10.0.0.5", detail="Changed role to 'admin'", timestamp=now - timedelta(days=3)),
        AuditLog(username=tag, action="auth.password_change", module="auth", result="failed",
                 ip_address="10.0.0.9", detail='=HYPERLINK("http://x","y")', timestamp=now),
    ]
    db.add_all(rows)
    db.commit()


@patch.object(audit_trail, "local_timezone", return_value=None)  # no time zone set: days in UTC
def test_filters_and_search(_tz, db, tag):
    _seed(db, tag)
    page = audit_trail.list_events(filters=_events(username=tag), page=1, page_size=50, db=db, _user=READER)
    assert page.total == 3 and page.items[0].timestamp >= page.items[-1].timestamp
    assert audit_trail.list_events(filters=_events(username=tag, module="auth"), page=1, page_size=50,
                                   db=db, _user=READER).total == 1
    assert audit_trail.list_events(filters=_events(username=tag, result="failed"), page=1, page_size=50,
                                   db=db, _user=READER).total == 1
    assert audit_trail.list_events(filters=_events(username=tag, q="bob"), page=1, page_size=50,
                                   db=db, _user=READER).total == 1
    assert audit_trail.list_events(filters=_events(username=tag, ip="10.0.0.9"), page=1, page_size=50,
                                   db=db, _user=READER).total == 1
    today = datetime.now(timezone.utc).date()
    assert audit_trail.list_events(filters=_events(username=tag, date_from=today - timedelta(days=1)),
                                   page=1, page_size=50, db=db, _user=READER).total == 2
    assert audit_trail.list_events(filters=_events(username=tag, date_to=today - timedelta(days=2)),
                                   page=1, page_size=50, db=db, _user=READER).total == 1


@patch.object(audit_trail, "local_timezone", return_value=None)
def test_search_looks_in_each_field_but_not_across_them(_tz, db, tag):
    _seed(db, tag)

    def found(text):
        return audit_trail.list_events(filters=_events(username=tag, q=text), page=1, page_size=50,
                                       db=db, _user=READER).total

    assert found("PASSWORD_CH") == 1          # action, any case
    assert found("user_manage") == 2          # module (the _ is literal, not a wildcard)
    assert found(tag[-6:]) == 3               # user name
    assert found("role to 'adm") == 1         # detail
    assert found("user.create\n" + tag) == 0  # never across two fields


def test_search_uses_the_trigram_index(db):
    # alembic c3e5f7a9b1d4 builds ix_audit_logs_search_trgm on SEARCH_TEXT; if the two drift apart the
    # planner silently goes back to reading every row (about 1.5 s at a million events).
    if not db.execute(text("SELECT 1 FROM pg_indexes WHERE indexname = 'ix_audit_logs_search_trgm'")).scalar():
        pytest.skip("pg_trgm not available in this database: the migration skipped the index")
    query = audit_trail._events(db, **_events(q="load-01234"))
    sql = str(query.statement.compile(dialect=db.bind.dialect, compile_kwargs={"literal_binds": True}))
    db.execute(text("SET LOCAL enable_seqscan = off"))
    plan = "\n".join(r[0] for r in db.execute(text("EXPLAIN " + sql)))
    db.rollback()
    assert "ix_audit_logs_search_trgm" in plan, plan


def test_days_are_the_configured_time_zone(db, tag):
    # 00:30 on 2026-10-11 in Tehran (UTC+3:30) is still 2026-10-10 in UTC
    db.add(AuditLog(username=tag, action="user.create", module="user_management", result="success",
                    timestamp=datetime(2026, 10, 10, 21, 0, tzinfo=timezone.utc)))
    db.commit()

    def count(day):
        return audit_trail.list_events(filters=_events(username=tag, date_from=day, date_to=day), page=1,
                                       page_size=50, db=db, _user=READER).total

    with patch.object(audit_trail, "local_timezone", return_value=ZoneInfo("Asia/Tehran")):
        assert count(date(2026, 10, 11)) == 1 and count(date(2026, 10, 10)) == 0
    with patch.object(audit_trail, "local_timezone", return_value=None):
        assert count(date(2026, 10, 10)) == 1 and count(date(2026, 10, 11)) == 0


def test_like_wildcards_are_literal(db, tag):
    _seed(db, tag)
    assert audit_trail.list_events(filters=_events(username=tag, q="%"), page=1, page_size=50,
                                   db=db, _user=READER).total == 0


def test_paging(db, tag):
    _seed(db, tag)
    first = audit_trail.list_events(filters=_events(username=tag), page=1, page_size=2, db=db, _user=READER)
    second = audit_trail.list_events(filters=_events(username=tag), page=2, page_size=2, db=db, _user=READER)
    assert (first.total, len(first.items), len(second.items)) == (3, 2, 1)
    assert not {e.id for e in first.items} & {e.id for e in second.items}


def test_facets_list_what_is_present(db, tag):
    _seed(db, tag)
    facets = audit_trail.event_facets(db=db, _user=READER)
    assert {"auth", "user_management"} <= set(facets.modules)
    assert {"user.create", "role.change"} <= set(facets.actions)
    assert {"success", "failed"} <= set(facets.results)


def test_export_is_formula_safe_and_recorded(db, tag):
    _seed(db, tag)
    response = audit_trail.export_events(REQUEST, filters=_events(username=tag), db=db, user=READER)
    body = response.body.decode("utf-8")
    assert "attachment" in response.headers["content-disposition"]
    assert body.startswith("\ufeffid,time_utc,user,")
    assert "'=HYPERLINK" in body and ',"=HYPERLINK' not in body and ",=HYPERLINK" not in body
    assert len(body.strip().splitlines()) == 4          # header + 3 rows
    record = (db.query(AuditLog).filter(AuditLog.action == "audit_trail.export",
                                        AuditLog.username == READER.username)
              .order_by(AuditLog.id.desc()).first())
    assert record is not None and record.ip_address == "192.0.2.30"
    assert record.detail.startswith("Exported 3 security events; filters: ") and tag in record.detail


def test_logins(db, tag):
    now = datetime.now(timezone.utc)
    db.add_all([LoginLog(username=tag, success=False, ip_address="10.1.1.1", timestamp=now),
                LoginLog(username=tag, success=True, ip_address="10.1.1.1", timestamp=now)])
    db.commit()
    filters = dict(username=tag, success=None, ip=None, date_from=None, date_to=None)
    assert audit_trail.list_logins(filters=filters, page=1, page_size=50, db=db, _user=READER).total == 2
    failed = audit_trail.list_logins(filters={**filters, "success": False}, page=1, page_size=50,
                                     db=db, _user=READER)
    assert failed.total == 1 and failed.items[0].success is False


def test_routes_need_the_log_permission():
    for route in audit_trail.router.routes:
        names = [getattr(d.call, "__name__", "") for d in route.dependant.dependencies]
        assert any("permission" in n or "checker" in n for n in names) or \
            any(d.call is audit_trail._reader for d in route.dependant.dependencies), route.path
