"""
Background work runs once, however many uvicorn workers there are:
the advisory-lock leader (app/core/singleton.py), claiming of due scheduled
jobs, and job ownership by process.
"""
import asyncio
import os
from datetime import datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.core import singleton
from app.core.database import engine
from app.models.scheduling import ScheduledJob
from app.models.user import User
from app.modules.scheduling.service import SchedulingService


class TestLeader:
    def test_only_one_holder_runs_the_task_and_another_takes_over(self):
        """Two SingletonTasks of one name stand in for two worker processes:
        each holds its own database connection, as separate processes do."""
        started = []

        async def scenario():
            stopped = []

            def make(tag):
                async def stop():
                    stopped.append(tag)
                return singleton.SingletonTask("test-single-run", lambda: started.append(tag), stop,
                                               retry_seconds=0.05)
            a, b = make("a"), make("b")
            a.start()
            b.start()
            await asyncio.sleep(0.4)
            assert len(started) == 1                      # exactly one runs it
            leader, follower = (a, b) if started[0] == "a" else (b, a)
            await leader.stop()                           # that "process" exits
            await asyncio.sleep(0.4)
            assert len(started) == 2 and started[1] != started[0]   # the other takes over
            await follower.stop()
            assert set(stopped) == {"a", "b"}

        asyncio.run(scenario())

    def test_lock_keys_are_stable_and_distinct(self):
        assert singleton.lock_key("job-scheduler") == singleton.lock_key("job-scheduler")
        assert singleton.lock_key("job-scheduler") != singleton.lock_key("noc-poller")


class TestRunnerTag:
    def test_alive_only_for_a_live_process_of_this_server(self):
        assert singleton.runner_is_alive(singleton.runner_tag())
        assert not singleton.runner_is_alive(None)
        assert not singleton.runner_is_alive(f"another-server:1:1|{os.getpid()}")   # an earlier run
        assert not singleton.runner_is_alive(f"{singleton.INSTANCE_ID}|999999999")   # a worker that died


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


def _job(db, recurrence="daily", due=True):
    user = User(username=f"single_run_{os.getpid()}_{id(db)}_{recurrence}", hashed_password="x")
    db.add(user)
    db.flush()
    job = ScheduledJob(job_name="nightly audit", job_type="discovery", technology=None, asset_id=None,
                       params_encrypted="x", recurrence=recurrence, hour=2, minute=0, day_of_week=None,
                       enabled=True, created_by=user.id,
                       next_run_at=datetime.utcnow() - timedelta(minutes=1 if due else -60))
    db.add(job)
    db.flush()
    return job


class TestSchedulerClaim:
    def test_a_due_job_is_claimed_once(self, db):
        job = _job(db)
        old_next = job.next_run_at
        now = datetime.utcnow()
        assert job.id in SchedulingService.claim_due_jobs(db, now)
        assert job.id not in SchedulingService.claim_due_jobs(db, now)   # another worker, same moment
        db.refresh(job)
        assert job.next_run_at > now > old_next and job.enabled

    def test_a_one_off_job_is_disabled_when_claimed(self, db):
        job = _job(db, recurrence="once")
        assert job.id in SchedulingService.claim_due_jobs(db, datetime.utcnow())
        db.refresh(job)
        assert job.enabled is False
        assert job.id not in SchedulingService.claim_due_jobs(db, datetime.utcnow())

    def test_jobs_not_due_are_left(self, db):
        job = _job(db, due=False)
        assert job.id not in SchedulingService.claim_due_jobs(db, datetime.utcnow())
