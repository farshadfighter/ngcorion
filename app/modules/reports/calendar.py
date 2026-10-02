"""
Dates in the report language: Solar Hijri with Persian digits for Persian,
Gregorian for English. Also the calendar arithmetic the periods and schedules
need (month and quarter starts in either calendar).

The Solar Hijri conversion is the arithmetic one used by most libraries
(valid well beyond the years this product will see).
"""
from datetime import date, datetime, timedelta
from typing import Optional, Tuple

FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
FA_MONTHS = ("فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
             "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند")
EN_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
EN_MONTHS_LONG = ("January", "February", "March", "April", "May", "June", "July", "August", "September",
                  "October", "November", "December")
FA_WEEKDAYS = ("دوشنبه", "سه‌شنبه", "چهارشنبه", "پنجشنبه", "جمعه", "شنبه", "یکشنبه")


def fa_digits(value) -> str:
    return str(value).translate(FA_DIGITS)


# ── Solar Hijri ⇄ Gregorian ──────────────────────────────────────────────

def to_jalali(d: date) -> Tuple[int, int, int]:
    gy, gm, gd = d.year, d.month, d.day
    g_d_m = (0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)
    gy2 = gy + 1 if gm > 2 else gy
    days = (355666 + 365 * gy + (gy2 + 3) // 4 - (gy2 + 99) // 100 + (gy2 + 399) // 400 + gd + g_d_m[gm - 1])
    jy = -1595 + 33 * (days // 12053)
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm, jd = 1 + days // 31, 1 + days % 31
    else:
        jm, jd = 7 + (days - 186) // 30, 1 + (days - 186) % 30
    return jy, jm, jd


def from_jalali(jy: int, jm: int, jd: int) -> date:
    jy += 1595
    days = -355668 + 365 * jy + (jy // 33) * 8 + ((jy % 33) + 3) // 4 + jd
    days += (jm - 1) * 31 if jm < 7 else (jm - 7) * 30 + 186
    gy = 400 * (days // 146097)
    days %= 146097
    if days > 36524:
        days -= 1
        gy += 100 * (days // 36524)
        days %= 36524
        if days >= 365:
            days += 1
    gy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        gy += (days - 1) // 365
        days = (days - 1) % 365
    gd = days + 1
    leap = (gy % 4 == 0 and gy % 100 != 0) or gy % 400 == 0
    month_days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    gm = 0
    while gm < 12 and gd > month_days[gm]:
        gd -= month_days[gm]
        gm += 1
    return date(gy, gm + 1, gd)


# ── calendar arithmetic in the report language ───────────────────────────

def month_start(d: date, lang: str, offset: int = 0) -> date:
    """First day of the month containing d, moved by `offset` months."""
    if lang == "fa":
        y, m, _ = to_jalali(d)
        m0 = (m - 1) + offset
        return from_jalali(y + m0 // 12, m0 % 12 + 1, 1)
    m0 = (d.month - 1) + offset
    return date(d.year + m0 // 12, m0 % 12 + 1, 1)


def quarter_start(d: date, lang: str, offset: int = 0) -> date:
    if lang == "fa":
        y, m, _ = to_jalali(d)
        q0 = ((m - 1) // 3) * 3 + offset * 3
        return from_jalali(y + q0 // 12, q0 % 12 + 1, 1)
    q0 = ((d.month - 1) // 3) * 3 + offset * 3
    return date(d.year + q0 // 12, q0 % 12 + 1, 1)


def year_start(d: date, lang: str) -> date:
    if lang == "fa":
        return from_jalali(to_jalali(d)[0], 1, 1)
    return date(d.year, 1, 1)


def with_day(first_of_month: date, day: int, lang: str) -> date:
    """The given day (1-28) of the month that starts at first_of_month."""
    return first_of_month + timedelta(days=max(1, min(28, day)) - 1)


# ── formatting ───────────────────────────────────────────────────────────

def fmt_date(d: Optional[date], lang: str, long: bool = False) -> str:
    if d is None:
        return "—"
    if isinstance(d, datetime):
        d = d.date()
    if lang == "fa":
        y, m, dd = to_jalali(d)
        return fa_digits(f"{dd} {FA_MONTHS[m - 1]} {y}")
    return f"{(EN_MONTHS_LONG if long else EN_MONTHS)[d.month - 1]} {d.day}, {d.year}"


def fmt_short(d: Optional[date], lang: str) -> str:
    """Day and month only: "۵ مهر" / "Oct 5"."""
    if d is None:
        return "—"
    if isinstance(d, datetime):
        d = d.date()
    if lang == "fa":
        _, m, dd = to_jalali(d)
        return fa_digits(f"{dd} {FA_MONTHS[m - 1]}")
    return f"{EN_MONTHS[d.month - 1]} {d.day}"


def fmt_datetime(dt: Optional[datetime], lang: str) -> str:
    if dt is None:
        return "—"
    text = f"{fmt_date(dt.date(), lang)}، {dt:%H:%M}" if lang == "fa" else f"{fmt_date(dt.date(), lang)}, {dt:%H:%M}"
    return fa_digits(text) if lang == "fa" else text


def month_label(d: date, lang: str) -> str:
    """"شهریور ۱۴۰۵" / "September 2026" for the month that starts at d."""
    if lang == "fa":
        y, m, _ = to_jalali(d)
        return fa_digits(f"{FA_MONTHS[m - 1]} {y}")
    return f"{EN_MONTHS_LONG[d.month - 1]} {d.year}"


def year_of(d: date, lang: str) -> int:
    return to_jalali(d)[0] if lang == "fa" else d.year
