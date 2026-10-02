"""
Report periods. A preset ("previous_month", "last_30_days", ...) is resolved
when the report is built, in the system time zone and in the calendar of the
report language: "previous month" is Shahrivar for a Persian report and
September for an English one built on the same day.

The comparison period is the previous calendar unit for calendar presets,
and a window of the same length just before for rolling ones.
"""
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Optional, Tuple

from app.modules.reports import calendar as cal

PRESETS = ("last_7_days", "last_30_days", "previous_month", "previous_quarter", "year_to_date", "custom")


class PeriodError(ValueError):
    pass


@dataclass
class Period:
    start: datetime          # UTC, naive, inclusive
    end: datetime            # UTC, naive, exclusive
    first_day: date          # local, inclusive
    last_day: date           # local, inclusive
    label: str

    @property
    def days(self) -> float:
        return (self.end - self.start).total_seconds() / 86400


def _to_utc(d: date, tz) -> datetime:
    local = datetime.combine(d, time.min)
    if tz is None:
        return local
    return local.replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)


def local_now(now_utc: datetime, tz) -> datetime:
    if tz is None:
        return now_utc
    return now_utc.replace(tzinfo=timezone.utc).astimezone(tz).replace(tzinfo=None)


def _label(first: date, last: date, lang: str, tr) -> str:
    if first == cal.month_start(first, lang) and last + timedelta(days=1) == cal.month_start(first, lang, 1):
        return cal.month_label(first, lang)
    return tr("{start} to {end}", start=cal.fmt_date(first, lang), end=cal.fmt_date(last, lang))


def _make(first: date, end_excl: date, tz, lang, tr, end_utc: Optional[datetime] = None) -> Period:
    return Period(start=_to_utc(first, tz), end=end_utc or _to_utc(end_excl, tz), first_day=first,
                  last_day=end_excl - timedelta(days=1), label=_label(first, end_excl - timedelta(days=1), lang, tr))


def resolve(preset: str, lang: str, tr, tz, now_utc: datetime, date_from: Optional[date] = None,
            date_to: Optional[date] = None) -> Tuple[Period, Period]:
    """(period, previous period) for a preset."""
    today = local_now(now_utc, tz).date()
    if preset == "last_7_days" or preset == "last_30_days":
        n = 7 if preset == "last_7_days" else 30
        first = today - timedelta(days=n - 1)
        cur = _make(first, today + timedelta(days=1), tz, lang, tr, end_utc=now_utc)
        prev = _make(first - timedelta(days=n), first, tz, lang, tr)
        return cur, prev
    if preset == "previous_month":
        this = cal.month_start(today, lang)
        first = cal.month_start(today, lang, -1)
        return (_make(first, this, tz, lang, tr),
                _make(cal.month_start(today, lang, -2), first, tz, lang, tr))
    if preset == "previous_quarter":
        this = cal.quarter_start(today, lang)
        first = cal.quarter_start(today, lang, -1)
        return (_make(first, this, tz, lang, tr),
                _make(cal.quarter_start(today, lang, -2), first, tz, lang, tr))
    if preset == "year_to_date":
        first = cal.year_start(today, lang)
        cur = _make(first, today + timedelta(days=1), tz, lang, tr, end_utc=now_utc)
        prev_first = cal.year_start(first - timedelta(days=1), lang)
        span = (today - first).days + 1
        return cur, _make(prev_first, prev_first + timedelta(days=span), tz, lang, tr)
    if preset == "custom":
        if not date_from or not date_to:
            raise PeriodError("Choose the start and end of the period")
        if date_to < date_from:
            raise PeriodError("The period ends before it starts")
        if date_from > today:
            raise PeriodError("The period starts in the future")
        last = min(date_to, today)
        span = (last - date_from).days + 1
        end_utc = now_utc if last == today else None
        cur = _make(date_from, last + timedelta(days=1), tz, lang, tr, end_utc=end_utc)
        return cur, _make(date_from - timedelta(days=span), date_from, tz, lang, tr)
    raise PeriodError("Unknown period")
