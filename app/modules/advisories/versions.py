"""
Package version order, exactly as the package managers decide it.

A distribution's fixed version ("1:8.9p1-3ubuntu0.10", "0:115.6.0-1.el8_9")
is compared with the installed one by the rules of dpkg or rpm themselves;
the generic comparison in app/modules/cve/versions.py is close but not
exact ("~" sorts before everything in both, "^" only in rpm, the epoch
decides first, Debian's revision is compared after the upstream version).

compare(kind, a, b) -> -1 / 0 / 1, kind "deb" or "rpm".
"""
import re
from typing import Tuple

# ── dpkg (lib/dpkg/version.c) ──────────────────────────────────────────────


def _deb_split(v: str) -> Tuple[int, str, str]:
    v = (v or "").strip()
    epoch = 0
    if ":" in v:
        e, rest = v.split(":", 1)
        if e.isdigit():
            epoch, v = int(e), rest
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def _deb_order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i]) if i < len(a) else 0
            bc = _deb_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def deb_compare(a: str, b: str) -> int:
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# ── rpm (rpmio/rpmvercmp.c) ────────────────────────────────────────────────

def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        # "~" sorts before anything, even the end of the version
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        # "^" sorts after the end of the version but before anything else
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < len(a) and j < len(b)):
            break
        si, sj = i, j
        if a[i].isdigit():
            while i < len(a) and a[i].isascii() and a[i].isdigit():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isdigit():
                j += 1
            isnum = True
        else:
            while i < len(a) and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isalpha():
                j += 1
            isnum = False
        sa, sb = a[si:i], b[sj:j]
        if not sb:                       # segments of different kinds: a number is newer
            return 1 if isnum else -1
        if isnum:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


_EVR = re.compile(r"^(?:(\d+):)?(.*?)(?:-([^-]*))?$")


def _rpm_split(v: str) -> Tuple[int, str, str]:
    m = _EVR.match((v or "").strip())
    epoch, version, release = m.group(1), m.group(2), m.group(3)
    return int(epoch or 0), version or "", release or ""


def rpm_compare(a: str, b: str) -> int:
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = rpmvercmp(va, vb)
    if c:
        return c
    if not ra or not rb:                 # a version without release matches any release
        return 0
    return rpmvercmp(ra, rb)


def compare(kind: str, a: str, b: str) -> int:
    return deb_compare(a, b) if kind == "deb" else rpm_compare(a, b)
