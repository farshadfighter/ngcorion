"""
Parsing one syslog message (the bytes of one UDP datagram or one TCP frame).

Accepted forms:
- RFC 5424: "<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG".
- BSD / RFC 3164 as devices really send it: "<PRI>Oct 13 10:00:00 host tag[pid]: text", Cisco IOS
  ("<189>45: *Oct 13 10:00:00.123: %SYS-5-CONFIG_I: Configured from console by admin"), an ISO
  timestamp instead of the BSD one.
- FortiOS key=value logs ("<189>date=2026-10-13 time=10:00:00 devname=\"FGT\" ... msg=\"...\"").
Anything else is kept whole as the message (severity "notice", the RFC 3164 default).

The input comes from the network unauthenticated: everything is decoded leniently, control
characters are removed, lengths are capped, and nothing here raises on bad input.
"""
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

MAX_MESSAGE = 8192
MAX_HOSTNAME = 255
MAX_APP = 128

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_PRI = re.compile(r"^<(\d{1,3})>")
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
# "Oct 13 10:00:00", "Oct  3 10:00:00.123", "*Oct 13 10:00:00.123 UTC" (Cisco: * or . = clock not synced)
_BSD_TIME = re.compile(r"^[*.]?([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?: [A-Z]{2,5})?:? ")
_ISO_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?) ")
_CISCO_SEQ = re.compile(r"^\d{1,10}: ")
# Cisco "logging origin-id hostname": "router1: *Oct 13 10:00:00 ..."
_CISCO_HOST = re.compile(r"^([\w.-]{1,255}): (?=[*.]?[A-Z][a-z]{2} +\d)")
_TAG = re.compile(r"^([\w./%@-]{1,64})(?:\[[\w.-]{0,32}\])?: ?")
_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')


@dataclass
class Parsed:
    facility: Optional[int]
    severity: int
    device_time: Optional[datetime]
    hostname: Optional[str]
    app_name: Optional[str]
    message: str


def _clean(text: str, limit: int) -> str:
    return _CONTROL.sub("", text).strip()[:limit]


def _opt(text: Optional[str], limit: int) -> Optional[str]:
    if text is None or text == "-":
        return None
    text = _clean(text, limit)
    return text or None


def _iso(value: str) -> Optional[datetime]:
    """An RFC 3339 time as naive UTC (a time without an offset is kept as sent)."""
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        # fromisoformat before 3.11 does not take more than 6 fraction digits
        m = re.match(r"^(.*?\.\d{6})\d*(.*)$", value)
        if not m:
            return None
        try:
            dt = datetime.fromisoformat((m.group(1) + m.group(2)).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _bsd(m: "re.Match", now: datetime) -> Optional[datetime]:
    """A BSD time has no year: this year, or last year when that would put it more than a day ahead."""
    try:
        dt = datetime(now.year, _MONTHS[m.group(1)], int(m.group(2)),
                      int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except (KeyError, ValueError):
        return None
    if dt - now > timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt


def _structured_data_end(text: str) -> int:
    """Where the STRUCTURED-DATA of an RFC 5424 message ends ("-" or one or more [..] elements, in
    which "]" can be escaped)."""
    if text.startswith("-"):
        return 1
    i, n = 0, len(text)
    while i < n and text[i] == "[":
        i += 1
        while i < n and text[i] != "]":
            i += 2 if text[i] == "\\" else 1
        i += 1
    return min(i, n)


def _rfc5424(rest: str) -> Optional[Tuple[Optional[datetime], Optional[str], Optional[str], str]]:
    parts = rest.split(" ", 6)
    if len(parts) < 6 or not parts[0].isdigit():
        return None
    _version, ts, host, app, _procid, _msgid = parts[:6]
    tail = parts[6] if len(parts) > 6 else ""
    end = _structured_data_end(tail)
    msg = tail[end:]
    if msg.startswith(" "):
        msg = msg[1:]
    if msg.startswith("﻿"):
        msg = msg[1:]
    return (None if ts == "-" else _iso(ts)), _opt(host, MAX_HOSTNAME), _opt(app, MAX_APP), msg


# FortiOS fields shown elsewhere (time, device, severity, event name) or as the message itself
_FORTI_SHOWN = {"date", "time", "eventtime", "tz", "devname", "type", "subtype", "level", "logdesc", "msg"}


def _fortios(rest: str) -> Optional[Tuple[Optional[datetime], Optional[str], Optional[str], str]]:
    if not rest.startswith(("date=", "logver=", "eventtime=", "itime=", "timestamp=")) or "devname=" not in rest:
        return None
    pairs = _KV.findall(rest[:MAX_MESSAGE])
    kv = {k: v[1:-1] if v.startswith('"') and v.endswith('"') else v for k, v in pairs}
    when = None
    if kv.get("date") and kv.get("time"):
        when = _iso(f"{kv['date']}T{kv['time']}")
    # the event name ("Admin login failed") like a Cisco mnemonic; its text first, then the other fields
    event = kv.get("logdesc") or "/".join(x for x in (kv.get("type"), kv.get("subtype")) if x) or "fortigate"
    others = " ".join(f"{k}={v}" for k, v in pairs if k not in _FORTI_SHOWN)
    text = kv.get("msg") or kv.get("logdesc") or ""
    message = f"{text} · {others}" if text and others else (text or others or rest)
    return when, _opt(kv.get("devname"), MAX_HOSTNAME), _opt(event, MAX_APP), message


def _bsd_form(rest: str, now: datetime) -> Tuple[Optional[datetime], Optional[str], Optional[str], str]:
    when, host = None, None
    rest = _CISCO_SEQ.sub("", rest, count=1)
    h = _CISCO_HOST.match(rest)
    if h:
        host, rest = h.group(1), rest[h.end():]
    m = _BSD_TIME.match(rest)
    if m:
        when, rest = _bsd(m, now), rest[m.end():]
    else:
        m = _ISO_TIME.match(rest)
        if m:
            when, rest = _iso(m.group(1)), rest[m.end():]
    if when is not None and host is None:
        # "host tag: text" - the first word is the host name unless it is already the tag
        first, _, after = rest.partition(" ")
        if first and after and not first.endswith(":") and "[" not in first and not _TAG.match(rest):
            host, rest = first, after
    app = None
    t = _TAG.match(rest)
    if t:
        app, rest = t.group(1), rest[t.end():]
    return when, _opt(host, MAX_HOSTNAME), _opt(app, MAX_APP), rest


def parse(raw: bytes, now: Optional[datetime] = None) -> Parsed:
    """Parse one message; never raises."""
    now = now or datetime.utcnow()
    text = raw.decode("utf-8", errors="replace").rstrip("\r\n\x00 ")
    facility, severity, rest = None, 5, text
    m = _PRI.match(text)
    if m and int(m.group(1)) <= 191:
        pri = int(m.group(1))
        facility, severity, rest = pri >> 3, pri & 7, text[m.end():]
    parsed = None
    try:
        parsed = _rfc5424(rest) if m else None
        parsed = parsed or _fortios(rest) or _bsd_form(rest, now)
    except Exception:  # noqa: BLE001 - a message that defeats the parser is still kept
        parsed = None
    if parsed is None:
        parsed = (None, None, None, rest)
    when, host, app, msg = parsed
    message = _clean(msg, MAX_MESSAGE) or _clean(rest, MAX_MESSAGE) or "(empty)"
    return Parsed(facility=facility, severity=severity, device_time=when, hostname=host, app_name=app,
                  message=message)
