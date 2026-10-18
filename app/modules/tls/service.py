"""
TLS certificates of the services the assets run: which ports are scanned, the scan itself, and the
judgement read by the page, the alerts, the remediation tracker, the risk score and the report.

What is scanned: every asset that is not decommissioned and has an address, on the usual TLS ports
(settings "ports") and on the open TCP ports discovery recorded for it whose service looks like TLS (https,
ssl/..., ldaps, imaps ...); a port becomes a service (TlsEndpoint) once it answers a TLS handshake. Services
added by hand are scanned too, on their address and with their server name. An automatic service that has
not answered for 30 days is dropped; one turned off is neither scanned nor judged.

The scan runs once per interval (default 24 h, app/modules/tls/worker.py) and on request; it only does TLS
handshakes (app/modules/tls/scanner.py).
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.enums import StatusEnum
from app.models.risk import AssetOpenPort
from app.models.system_config import SystemConfigSetting
from app.models.tls import SOURCE_AUTO, TlsEndpoint, TlsTrustedCa
from app.modules.tls import checks
from app.modules.tls import scanner

logger = logging.getLogger(__name__)

SECTION = "tls"
STATE_SECTION = "tls_state"
DEFAULT_PORTS = [443, 465, 636, 993, 995, 3269, 5986, 8443, 9443, 10443]
DEFAULTS = {"warn_days": 30, "auto_scan": True, "interval_hours": 24, "check_protocols": True,
            "ports": DEFAULT_PORTS}
LIMITS = {"warn_days": (7, 180), "interval_hours": (6, 168)}
MAX_PORTS = 40
WORKERS = 16
DROP_AFTER_DAYS = 30
TLS_SERVICE = re.compile(r"https|ssl|tls|ldaps|imaps|pop3s|smtps|ftps|wss", re.I)
HOSTNAME = re.compile(r"^(?=.*[a-z])[a-z0-9-]+(\.[a-z0-9-]+)*$", re.I)
# risk score (factor CV, app/modules/risk/service.py) of the worst problem of an asset's services
RISK_SCORE = {"high": 60.0, "medium": 30.0, "low": 10.0}


# ── settings ─────────────────────────────────────────────────────────────

def _row(db: Session, section: str) -> Optional[SystemConfigSetting]:
    return db.query(SystemConfigSetting).filter(SystemConfigSetting.section == section).first()


def clean_ports(values) -> List[int]:
    out = []
    for v in values or []:
        try:
            p = int(v)
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535 and p not in out:
            out.append(p)
    return sorted(out)[:MAX_PORTS]


def get_settings(db: Session) -> Dict:
    row = _row(db, SECTION)
    stored = (row.config_json or {}) if row else {}
    out = {}
    for key, default in DEFAULTS.items():
        value = stored.get(key, default)
        if key in LIMITS:
            lo, hi = LIMITS[key]
            try:
                value = max(lo, min(int(value), hi))
            except (TypeError, ValueError):
                value = default
        elif key == "ports":
            value = clean_ports(value) if isinstance(value, list) else list(default)
        else:
            value = bool(value)
        out[key] = value
    return out


def save_settings(db: Session, values: Dict, user_id: Optional[int]) -> Dict:
    current = get_settings(db)
    current.update({k: v for k, v in values.items() if k in DEFAULTS and v is not None})
    if "ports" in values:
        current["ports"] = clean_ports(current["ports"])
    row = _row(db, SECTION)
    if row is None:
        row = SystemConfigSetting(section=SECTION)
        db.add(row)
    row.config_json = current
    row.updated_by = user_id
    db.commit()
    return get_settings(db)


def get_state(db: Session) -> Dict:
    row = _row(db, STATE_SECTION)
    return dict(row.config_json or {}) if row else {}


def set_state(db: Session, **values) -> None:
    row = _row(db, STATE_SECTION)
    if row is None:
        row = SystemConfigSetting(section=STATE_SECTION, config_json={})
        db.add(row)
    row.config_json = {**(row.config_json or {}), **values}
    db.commit()


# ── what is scanned ──────────────────────────────────────────────────────

def trusted_cadata(db: Session) -> Optional[str]:
    pems = [r.pem for r in db.query(TlsTrustedCa.pem)]
    return "\n".join(pems) if pems else None


def server_name_of(asset: Asset, ep: Optional[TlsEndpoint] = None) -> Optional[str]:
    """The name sent in the handshake (SNI): the one entered with the service, else the asset's host name
    when it is a DNS name."""
    if ep is not None and ep.server_name:
        return ep.server_name
    name = (asset.hostname or "").strip()
    return name if name and HOSTNAME.match(name) else None


def candidate_ports(db: Session, assets: List[Asset], ports: Iterable[int]) -> Dict[int, set]:
    base = set(ports)
    out = {a.id: set(base) for a in assets}
    if not out:
        return out
    q = (db.query(AssetOpenPort.asset_id, AssetOpenPort.port, AssetOpenPort.service_name)
         .filter(AssetOpenPort.asset_id.in_(list(out)), AssetOpenPort.status == "open",
                 AssetOpenPort.protocol == "tcp"))
    for asset_id, port, service in q:
        if port in base or (service and TLS_SERVICE.search(service)):
            out[asset_id].add(port)
    return out


def _scannable(db: Session, asset_ids: Optional[Iterable[int]] = None) -> List[Asset]:
    q = db.query(Asset).filter(Asset.status != StatusEnum.DECOMMISSIONED)
    if asset_ids is not None:
        q = q.filter(Asset.id.in_(list(asset_ids) or [-1]))
    return q.all()


# ── the scan ─────────────────────────────────────────────────────────────

def _store(ep: TlsEndpoint, p: scanner.Probe, now: datetime) -> None:
    d = scanner.describe(p.chain[0])
    if ep.fingerprint and ep.fingerprint != d["fingerprint"]:
        ep.cert_changed_at = now
    for key in ("subject", "issuer", "names", "serial", "fingerprint", "not_before", "not_after", "key_type",
                "key_bits", "signature"):
        setattr(ep, key, d[key])
    ep.trusted = p.trusted
    ep.self_signed = bool(p.self_signed or (d["self_issued"] and not p.trusted))
    ep.trust_error = p.trust_error
    ep.protocol = p.protocol
    ep.old_protocols = p.old_protocols
    ep.chain = scanner.chain_summary(p.chain)
    ep.status, ep.error, ep.last_ok_at = "read", None, now


def run_scan(db: Session, asset_ids: Optional[Iterable[int]] = None, endpoint_ids: Optional[Iterable[int]] = None,
             now: Optional[datetime] = None, probe: Optional[Callable] = None, workers: int = WORKERS) -> Dict:
    """Scan the assets (all, or these) or only these services; returns counts. Commits."""
    now = now or datetime.utcnow()
    probe = probe or scanner.probe
    settings = get_settings(db)
    cadata = trusted_cadata(db)
    if endpoint_ids is not None:
        eps = db.query(TlsEndpoint).filter(TlsEndpoint.id.in_(list(endpoint_ids) or [-1])).all()
        assets = {a.id: a for a in _scannable(db, {e.asset_id for e in eps})}
        jobs = [(e.asset_id, e.host, e.port, e) for e in eps if e.asset_id in assets]
    else:
        assets = {a.id: a for a in _scannable(db, asset_ids)}
        existing = {}
        for e in db.query(TlsEndpoint).filter(TlsEndpoint.asset_id.in_(list(assets) or [-1])):
            existing[(e.asset_id, e.host, e.port)] = e
        jobs, seen = [], set()
        ports = candidate_ports(db, [a for a in assets.values() if a.ip_address], settings["ports"])
        for asset_id, plist in ports.items():
            host = assets[asset_id].ip_address.strip()
            for port in sorted(plist):
                key = (asset_id, host, port)
                seen.add(key)
                e = existing.get(key)
                if e is None or e.enabled:
                    jobs.append((asset_id, host, port, e))
        for key, e in existing.items():
            if key not in seen and e.enabled:
                jobs.append((e.asset_id, e.host, e.port, e))

    def run(job):
        asset_id, host, port, e = job
        try:
            return job, probe(host, port, server_name=server_name_of(assets[asset_id], e), cadata=cadata,
                              check_protocols=settings["check_protocols"]), None
        except scanner.ProbeError as err:
            return job, None, err
        except Exception as err:        # a bug must not stop the other services
            logger.exception("[tls] %s:%s", host, port)
            return job, None, scanner.ProbeError("no_tls", str(err)[:300])

    stats = {"probed": len(jobs), "read": 0, "new": 0, "failed": 0, "dropped": 0}
    if jobs:
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs)))) as pool:
            results = list(pool.map(run, jobs))
    else:
        results = []
    for (asset_id, host, port, e), result, err in results:
        if result is not None:
            if e is None:
                e = TlsEndpoint(asset_id=asset_id, host=host, port=port, source=SOURCE_AUTO, first_seen_at=now)
                db.add(e)
                stats["new"] += 1
            try:
                _store(e, result, now)
            except ValueError as bad:       # a certificate cryptography cannot read
                e.status, e.error = "no_tls", f"Unreadable certificate: {bad}"[:300]
            e.last_scan_at = now
            stats["read"] += 1
        elif e is not None:
            e.status, e.error, e.last_scan_at = err.kind, str(err)[:300], now
            stats["failed"] += 1
            last = e.last_ok_at or e.first_seen_at
            if e.source == SOURCE_AUTO and last and last < now - timedelta(days=DROP_AFTER_DAYS):
                db.delete(e)
                stats["dropped"] += 1
    db.commit()
    return stats


def due(db: Session, now: Optional[datetime] = None) -> bool:
    """Whether the automatic scan should run now: asked for, or the interval has passed."""
    now = now or datetime.utcnow()
    state = get_state(db)
    if state.get("requested"):
        return True
    settings = get_settings(db)
    if not settings["auto_scan"]:
        return False
    last = state.get("last_run")
    try:
        return last is None or datetime.fromisoformat(last) <= now - timedelta(hours=settings["interval_hours"])
    except ValueError:
        return True


# ── the judgement ────────────────────────────────────────────────────────

def evaluate(db: Session, asset_ids: Optional[Iterable[int]] = None, now: Optional[datetime] = None,
             include_disabled: bool = False) -> List[Dict]:
    """Every service with its problems and level (ordered: worst first, then by the end date)."""
    now = now or datetime.utcnow()
    warn_days = get_settings(db)["warn_days"]
    q = db.query(TlsEndpoint)
    if asset_ids is not None:
        q = q.filter(TlsEndpoint.asset_id.in_(list(asset_ids) or [-1]))
    if not include_disabled:
        q = q.filter(TlsEndpoint.enabled.is_(True))
    eps = q.all()
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_({e.asset_id for e in eps} or {-1}))}
    out = []
    for e in eps:
        asset = assets.get(e.asset_id)
        if asset is None:
            continue
        found = checks.problems(e, now, warn_days, [asset.hostname]) if e.enabled else []
        out.append({"endpoint": e, "asset": asset, "problems": found, "level": checks.level(e, found)
                    if e.enabled else "unknown"})
    out.sort(key=lambda r: (checks.ORDER[r["level"]], r["endpoint"].not_after or datetime.max,
                            r["asset"].asset_name or "", r["endpoint"].port))
    return out


def where(ep: TlsEndpoint) -> str:
    return f"{ep.server_name or ep.host}:{ep.port}"


def problem_title(ep: TlsEndpoint, p: Dict) -> Optional[str]:
    """The sentence of a remediation item or report line for one problem (None: not a finding)."""
    w, code = where(ep), p["code"]
    if code == "expired":
        return f"The certificate of {w} expired on {p['date']}"
    if code == "not_yet_valid":
        return f"The certificate of {w} is not valid before {p['date']}"
    if code == "untrusted":
        return (f"The certificate of {w} is self-signed" if p.get("self_signed")
                else f"The certificate of {w} is issued by an untrusted authority")
    if code == "weak_key":
        return f"The certificate of {w} has a weak key ({p['key']})"
    if code == "weak_signature":
        return f"The certificate of {w} is signed with {p['algorithm']}"
    if code == "old_protocol":
        return f"{w} still accepts {', '.join(p['protocols'])}"
    if code == "name_mismatch":
        return f"The certificate of {w} does not name the host"
    return None


def out(row: Dict) -> Dict:
    e, a = row["endpoint"], row["asset"]
    iso = lambda d: d.isoformat() if d else None   # noqa: E731
    return {
        "id": e.id, "asset_id": a.id, "asset_name": a.asset_name, "asset_ip": a.ip_address,
        "host": e.host, "port": e.port, "server_name": e.server_name, "where": where(e), "source": e.source,
        "enabled": e.enabled, "status": e.status, "error": e.error, "level": row["level"],
        "problems": row["problems"], "last_scan_at": iso(e.last_scan_at), "last_ok_at": iso(e.last_ok_at),
        "subject": e.subject, "issuer": e.issuer, "names": e.names or [], "serial": e.serial,
        "fingerprint": e.fingerprint, "not_before": iso(e.not_before), "not_after": iso(e.not_after),
        "key_type": e.key_type, "key_bits": e.key_bits, "signature": e.signature, "self_signed": e.self_signed,
        "trusted": e.trusted, "trust_error": e.trust_error, "protocol": e.protocol,
        "old_protocols": e.old_protocols, "chain": e.chain or [], "cert_changed_at": iso(e.cert_changed_at),
    }


def summary(rows: List[Dict], now: Optional[datetime] = None) -> Dict:
    now = now or datetime.utcnow()
    levels = {k: 0 for k in checks.ORDER}
    problems: Dict[str, int] = {}
    in_30 = in_90 = 0
    for r in rows:
        levels[r["level"]] += 1
        for p in r["problems"]:
            problems[p["code"]] = problems.get(p["code"], 0) + 1
        na = r["endpoint"].not_after
        if na and now < na <= now + timedelta(days=30):
            in_30 += 1
        if na and now < na <= now + timedelta(days=90):
            in_90 += 1
    return {"services": len(rows), "levels": levels, "problems": problems, "expiring_30": in_30,
            "expiring_90": in_90, "assets": len({r["asset"].id for r in rows})}
