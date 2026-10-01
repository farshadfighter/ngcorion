"""Health endpoints: the public liveness check and the admin detail."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import Session

from app.core.database import engine
from app.core.singleton import SingletonTask
from app.models.user import User, UserRole
from app.modules import system_health


@pytest.fixture
def db():
    connection = engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


def test_public_health_reports_the_database():
    res = system_health.health()
    body = json.loads(res.body)
    assert res.status_code == 200 and body["status"] == "ok" and body["database"] == "ok"
    assert set(body) == {"status", "version", "database"}        # nothing internal


def test_public_health_is_503_without_the_database(monkeypatch):
    class Broken:
        def execute(self, *a):
            raise RuntimeError("down")

        def close(self):
            pass
    monkeypatch.setattr(system_health, "SessionLocal", lambda: Broken())
    res = system_health.health()
    assert res.status_code == 503 and json.loads(res.body)["database"] == "unreachable"


def _request(singletons=()):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(singletons=list(singletons))))


def test_detail_lists_every_check(db):
    admin = User(username="health_admin", hashed_password="x", role=UserRole.ADMIN)
    out = system_health.health_detail(_request(), admin, db)
    names = [c["name"] for c in out["checks"]]
    for expected in ("database", "migrations", "task:job-scheduler", "task:noc-poller",
                     "task:noc-metrics-retention", "task:cve-auto-update", "scheduled_jobs",
                     "cve_database", "license", "disk_data"):
        assert expected in names
    checks = {c["name"]: c for c in out["checks"]}
    assert checks["migrations"]["status"] == "ok", checks["migrations"]
    # No worker runs the background tasks in a test process.
    assert checks["task:job-scheduler"]["status"] == "error" and out["status"] == "error"


def test_detail_sees_a_running_background_task(db):
    admin = User(username="health_admin2", hashed_password="x", role=UserRole.ADMIN)

    async def scenario():
        async def stop():
            pass
        task = SingletonTask("job-scheduler", lambda: None, stop, retry_seconds=0.05)
        task.start()
        await asyncio.sleep(0.3)
        try:
            out = await asyncio.to_thread(system_health.health_detail, _request([task]), admin, db)
        finally:
            await task.stop()
        return {c["name"]: c for c in out["checks"]}["task:job-scheduler"]

    check = asyncio.run(scenario())
    assert check["status"] == "ok" and "this worker" in check["detail"]
