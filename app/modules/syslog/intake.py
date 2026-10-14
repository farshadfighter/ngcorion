"""
What happens to each received message, apart from the sockets (app/modules/syslog/listener.py):

1. The sending address must be the IP address of an asset in the inventory; anything else is
   dropped and only counted per address (it shows as "not in the inventory" on the Syslog page).
2. Each address may send RATE_PER_SECOND messages a second on average (bursts up to BURST); more is
   dropped and counted.
3. A message reporting a configuration change (config_changes.detect) is recorded as a
   ConfigChangeEvent whatever its severity; config_changes.process() backs the device up.
4. Messages less severe than the configured level are not kept.
5. Accepted messages wait in a bounded queue and are written to the database in batches
   (drain(), called about once a second); when the database cannot keep up and the queue is full,
   the newest are dropped and counted in the listener status.

The asset address map is reloaded every ASSET_REFRESH_SECONDS, so a new asset is accepted within a
minute.
"""
import ipaddress
import logging
import time
from collections import deque
from datetime import datetime
from typing import Deque, Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.syslog import ConfigChangeEvent, SyslogMessage, SyslogSource
from app.modules.syslog.config_changes import MAX_EVENTS_PER_DRAIN, detect
from app.modules.syslog.parser import parse

logger = logging.getLogger(__name__)

RATE_PER_SECOND = 200
BURST = 2000
QUEUE_MAX = 50000
DRAIN_BATCH = 5000
ASSET_REFRESH_SECONDS = 60
MAX_UNKNOWN_PER_DRAIN = 1000      # new addresses outside the inventory recorded per batch


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """"10.0.0.5", " 10.0.0.5 ", "::ffff:10.0.0.5" -> "10.0.0.5"; None when not an address."""
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip().split("%")[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


class _Bucket:
    __slots__ = ("tokens", "at")

    def __init__(self, now: float):
        self.tokens, self.at = float(BURST), now

    def take(self, now: float) -> bool:
        self.tokens = min(BURST, self.tokens + (now - self.at) * RATE_PER_SECOND)
        self.at = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class Intake:
    def __init__(self, store_max_severity: int = 7):
        self.store_max_severity = store_max_severity
        self.assets: Dict[str, int] = {}
        self.assets_loaded_at = 0.0
        self.queue: Deque[dict] = deque()
        self.queue_dropped = 0
        self.changes: List[dict] = []       # configuration changes reported, written with the next drain
        self._buckets: Dict[str, _Bucket] = {}
        # address -> [asset_id, received, dropped, last_seen, hostname] since the last drain
        self._sources: Dict[str, list] = {}
        self._unknown = 0

    # -- assets -------------------------------------------------------------------------------
    def load_assets(self, db: Session) -> None:
        from app.models import Asset
        mapping: Dict[str, int] = {}
        for asset_id, ip in db.query(Asset.id, Asset.ip_address).filter(Asset.ip_address.isnot(None)) \
                .order_by(Asset.id.desc()):
            norm = normalize_ip(ip)
            if norm:
                mapping[norm] = asset_id          # the oldest asset wins when two share an address
        self.assets = mapping
        self.assets_loaded_at = time.monotonic()

    def assets_stale(self) -> bool:
        return time.monotonic() - self.assets_loaded_at > ASSET_REFRESH_SECONDS

    def known(self, ip: str) -> Optional[int]:
        return self.assets.get(ip)

    # -- receiving ----------------------------------------------------------------------------
    def _source(self, ip: str, asset_id: Optional[int], now: datetime) -> Optional[list]:
        s = self._sources.get(ip)
        if s is None:
            if asset_id is None:
                if self._unknown >= MAX_UNKNOWN_PER_DRAIN:
                    return None
                self._unknown += 1
            s = self._sources[ip] = [asset_id, 0, 0, now, None]
        s[3] = now
        return s

    def drop(self, ip: str, now: Optional[datetime] = None) -> None:
        """Count a message (or TCP connection) refused from `ip`."""
        ip = normalize_ip(ip) or ip
        s = self._source(ip, self.known(ip), now or datetime.utcnow())
        if s is not None:
            s[2] += 1

    def accept(self, raw: bytes, source_ip: str, protocol: str, now: Optional[datetime] = None) -> bool:
        """Take one message; True when it was queued to be stored."""
        now = now or datetime.utcnow()
        ip = normalize_ip(source_ip) or source_ip
        asset_id = self.known(ip)
        if asset_id is None:
            self.drop(ip, now)
            return False
        mono = time.monotonic()
        bucket = self._buckets.get(ip)
        if bucket is None:
            bucket = self._buckets[ip] = _Bucket(mono)
        if not bucket.take(mono):
            self.drop(ip, now)
            return False
        p = parse(raw, now)
        if (b"CONFIG_I" in raw or b"logid=" in raw) and len(self.changes) < MAX_EVENTS_PER_DRAIN:
            change = detect(raw.decode("utf-8", "replace"))
            if change is not None:
                self.changes.append({"asset_id": asset_id, "received_at": now, "message": change.message,
                                     "changed_by": change.by, "changed_from": change.source,
                                     "status": "pending"})
        if p.severity > self.store_max_severity:
            return False
        if len(self.queue) >= QUEUE_MAX:
            self.queue_dropped += 1
            return False
        self.queue.append({"asset_id": asset_id, "received_at": now, "source_ip": ip, "protocol": protocol,
                           "facility": p.facility, "severity": p.severity, "device_time": p.device_time,
                           "hostname": p.hostname, "app_name": p.app_name, "message": p.message})
        s = self._source(ip, asset_id, now)
        s[1] += 1
        if p.hostname:
            s[4] = p.hostname
        return True

    # -- storing ------------------------------------------------------------------------------
    def _take_sources(self) -> List[Tuple[str, list]]:
        out, self._sources, self._unknown = list(self._sources.items()), {}, 0
        # forget rate state of addresses that have been quiet (keeps the dict small)
        if len(self._buckets) > 10000:
            self._buckets.clear()
        return out

    def drain(self, db: Session) -> int:
        """Write queued messages (up to DRAIN_BATCH) and the per-address counters; returns how many
        messages were written."""
        rows = []
        while self.queue and len(rows) < DRAIN_BATCH:
            rows.append(self.queue.popleft())
        sources = self._take_sources() if not self.queue else []
        changes, self.changes = self.changes, []
        try:
            if rows:
                db.execute(pg_insert(SyslogMessage.__table__), rows)
            if changes:
                db.execute(pg_insert(ConfigChangeEvent.__table__), changes)
            for ip, (asset_id, received, dropped, last_seen, hostname) in sources:
                stmt = pg_insert(SyslogSource.__table__).values(
                    source_ip=ip, asset_id=asset_id, first_seen=last_seen, last_seen=last_seen,
                    received=received, dropped=dropped, last_hostname=hostname)
                t = SyslogSource.__table__
                db.execute(stmt.on_conflict_do_update(index_elements=[t.c.source_ip], set_={
                    "asset_id": stmt.excluded.asset_id,
                    "last_seen": func.greatest(t.c.last_seen, stmt.excluded.last_seen),
                    "received": t.c.received + stmt.excluded.received,
                    "dropped": t.c.dropped + stmt.excluded.dropped,
                    "last_hostname": func.coalesce(stmt.excluded.last_hostname, t.c.last_hostname),
                }))
            db.commit()
        except Exception:
            db.rollback()
            # put the messages back once; the next drain retries
            for r in reversed(rows):
                if len(self.queue) < QUEUE_MAX:
                    self.queue.appendleft(r)
                else:
                    self.queue_dropped += 1
            self.changes = (changes + self.changes)[:MAX_EVENTS_PER_DRAIN]
            for ip, s in sources:
                if ip not in self._sources:
                    self._sources[ip] = s
                    self._unknown += s[0] is None
            raise
        return len(rows)
