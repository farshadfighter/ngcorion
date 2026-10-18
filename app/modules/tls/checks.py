"""
What is wrong with the certificate a TLS service presented (app/models/tls.py TlsEndpoint), judged when
read so that it follows today's date and the warning period without a new scan.

  expired          past its end date                                  high
  not_yet_valid    before its start date (a wrong clock, or too early) medium
  untrusted        self-signed, or issued by an authority neither the public list nor the organisation's
                   own trusted CAs contain                            medium
  weak_key         RSA or DSA under 2048 bits, EC under 224           medium
  weak_signature   signed with MD5 or SHA-1                           medium
  old_protocol     the service still accepts TLS 1.0 or 1.1           medium
  name_mismatch    the certificate does not name the asset's host name (checked only when a name is known:
                   the asset's host name or the name entered with the service)   low
  expiring         ends within the warning period (default 30 days)   warning only: an alert, no finding

The level of a service: critical when expired, warning with any other problem, ok without.
"""
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional

SEVERITY = {"expired": "high", "not_yet_valid": "medium", "untrusted": "medium", "weak_key": "medium",
            "weak_signature": "medium", "old_protocol": "medium", "name_mismatch": "low"}
WEAK_SIGNATURES = {"md5", "sha1"}
MIN_BITS = {"RSA": 2048, "DSA": 2048, "EC": 224}
PROTOCOLS = {"TLSv1": "TLS 1.0", "TLSv1.1": "TLS 1.1"}
ORDER = {"critical": 0, "warning": 1, "ok": 2, "unknown": 3}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def name_ok(cert_names: Iterable[str], host: str, wanted: Iterable[Optional[str]]) -> Optional[bool]:
    """Whether the certificate is for this service: the address connected to is one of its names, or a host
    name known for it matches one (wildcards one label deep; a short name matches the first label of a
    full one). None when only an address is known and the certificate does not name it."""
    names = [n.lower() for n in cert_names or []]
    if host and host.lower() in names:
        return True
    wanted = {w.strip().lower().rstrip(".") for w in wanted if w and w.strip() and not _is_ip(w.strip())}
    if not wanted:
        return None
    for w in wanted:
        for n in names:
            if n == w:
                return True
            if n.startswith("*.") and w.endswith(n[1:]) and w.count(".") == n.count("."):
                return True
            if "." not in w and n.split(".")[0] == w:
                return True
    return False


def problems(ep, now: datetime, warn_days: int, host_names: Iterable[Optional[str]] = ()) -> List[Dict]:
    """The problems of one service's certificate (an empty list when there is no certificate yet)."""
    if not ep.fingerprint or ep.not_after is None:
        return []
    out = []
    if ep.not_after <= now:
        out.append({"code": "expired", "date": ep.not_after.date().isoformat()})
    elif ep.not_after <= now + timedelta(days=warn_days):
        out.append({"code": "expiring", "date": ep.not_after.date().isoformat(),
                    "days": max(0, (ep.not_after - now).days)})
    if ep.not_before is not None and ep.not_before > now:
        out.append({"code": "not_yet_valid", "date": ep.not_before.date().isoformat()})
    if ep.trusted is False:
        out.append({"code": "untrusted", "self_signed": bool(ep.self_signed), "reason": ep.trust_error})
    minimum = MIN_BITS.get(ep.key_type or "")
    if minimum and ep.key_bits and ep.key_bits < minimum:
        out.append({"code": "weak_key", "key": f"{ep.key_type} {ep.key_bits}"})
    if (ep.signature or "").lower() in WEAK_SIGNATURES:
        out.append({"code": "weak_signature", "algorithm": "SHA-1" if ep.signature.lower() == "sha1" else "MD5"})
    if ep.old_protocols:
        out.append({"code": "old_protocol", "protocols": [PROTOCOLS.get(p, p) for p in ep.old_protocols]})
    ok = name_ok(ep.names, ep.host, [ep.server_name, *host_names])
    if ok is False:
        out.append({"code": "name_mismatch"})
    for p in out:
        p["severity"] = SEVERITY.get(p["code"], "info")
    return out


def level(ep, found: List[Dict]) -> str:
    if not ep.fingerprint:
        return "unknown"
    codes = {p["code"] for p in found}
    if "expired" in codes:
        return "critical"
    return "warning" if codes else "ok"
