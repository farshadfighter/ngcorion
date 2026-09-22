"""
Pure next_run_at computation for a ScheduledJob's recurrence - kept apart
from the scheduler loop / service so it is trivially unit-testable without a
database.
"""
from datetime import datetime, timedelta
from typing import Optional


def compute_next_run_at(
    recurrence: str,
    hour: Optional[int],
    minute: int,
    day_of_week: Optional[int],
    now: datetime,
) -> datetime:
    """The next datetime (strictly after `now`) this job should fire.

    - hourly: the next top-of-`minute` past `now`, every hour.
    - daily / once: the next `hour:minute` past `now` (today if not yet
      passed, otherwise tomorrow). "once" jobs use this only to compute
      their single run time; the scheduler disables them after firing
      instead of computing a further next_run_at.
    - weekly: the next `day_of_week` at `hour:minute` past `now`.
    """
    if recurrence == "hourly":
        candidate = now.replace(minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(hours=1)
        return candidate

    if recurrence in ("daily", "once"):
        h = hour if hour is not None else 0
        candidate = now.replace(hour=h, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    if recurrence == "weekly":
        h = hour if hour is not None else 0
        dow = day_of_week if day_of_week is not None else 0
        candidate = now.replace(hour=h, minute=minute, second=0, microsecond=0)
        days_ahead = (dow - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate

    raise ValueError(f"Unknown recurrence: {recurrence!r}")
