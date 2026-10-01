"""
Version comparison for CPE ranges.

Vendor versions are not semver: FortiOS "7.2.8", IOS XE "17.9.4a", Windows
builds "10.0.20348.2527", Debian/Ubuntu packages "1:8.9p1-3ubuntu0.10",
IOS trains "15.2(4)M3". Versions are split into number and letter runs and
compared element by element:

    pre-release word (alpha, beta, rc, ...)  <  end of version  <  number  <  letter

so 1.0rc1 < 1.0 < 1.0.1, and 17.9.4 < 17.9.4a. A Debian epoch ("1:") is
ignored. Trailing ".0" elements do not make versions different (9 == 9.0).
"""
import re
from typing import List, Optional, Tuple

_TOKENS = re.compile(r"\d+|[a-z]+")
_PRE_RELEASE = {"dev", "alpha", "beta", "pre", "preview", "rc"}
_END = (1, "")
_ZERO = (2, 0)


def _key(version: str) -> List[Tuple[int, object]]:
    v = re.sub(r"^\d+:", "", version.strip().lower())
    out = []
    for tok in _TOKENS.findall(v):
        if tok.isdigit():
            out.append((2, int(tok)))
        elif tok in _PRE_RELEASE:
            out.append((0, tok))
        else:
            out.append((3, tok))
    return out


def compare(a: str, b: str) -> int:
    """-1, 0 or 1."""
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    ka += [_END] * (n - len(ka))
    kb += [_END] * (n - len(kb))
    for x, y in zip(ka, kb):
        if {x, y} == {_END, _ZERO}:   # a missing element counts as 0: 9 == 9.0
            continue
        if x != y:
            # Same kind compares by value; different kinds by kind.
            return -1 if x < y else 1
    return 0


def is_known(version: Optional[str]) -> bool:
    return bool(version) and version not in ("*", "-") and bool(_TOKENS.search(version.lower()))


def matches(version: Optional[str], *, exact: Optional[str] = None, start_incl: Optional[str] = None,
            start_excl: Optional[str] = None, end_incl: Optional[str] = None,
            end_excl: Optional[str] = None) -> bool:
    """Whether `version` falls in a CPE criterion: an exact version, or a range.

    A criterion with no version and no range ("*") covers every version.
    An asset whose version is unknown never matches a versioned criterion -
    a finding we cannot back up is worse than none."""
    has_range = any((start_incl, start_excl, end_incl, end_excl))
    if is_known(exact):
        return is_known(version) and compare(version, exact) == 0
    if not has_range:
        return True
    if not is_known(version):
        return False
    if start_incl and compare(version, start_incl) < 0:
        return False
    if start_excl and compare(version, start_excl) <= 0:
        return False
    if end_incl and compare(version, end_incl) > 0:
        return False
    if end_excl and compare(version, end_excl) >= 0:
        return False
    return True
