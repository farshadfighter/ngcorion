"""
The syslog listener: UDP and TCP on SYSLOG_PORT (5514 in the container; docker-compose publishes the
host's port 514 to it), in the one worker that holds the "syslog-intake" lock (app/core/singleton.py).

Every second the queued messages are written (app/modules/syslog/intake.py); every 15 seconds the
settings are read again, so turning the intake on or off, or a protocol, in System Configuration
takes effect without a restart; every 5 seconds the status row is written for the API and alerts; every 10 seconds configuration
changes devices reported are turned into backups (config_changes.py);
every hour old messages are removed (retention.py).

TCP: one message per line (RFC 6587 non-transparent framing) or "LENGTH MESSAGE" (octet counting,
RFC 5425/6587). A connection from an address outside the inventory is closed at once. At most
MAX_CONNECTIONS connections, MAX_CONNECTIONS_PER_ADDRESS per address, closed after IDLE_SECONDS
without data; a frame longer than MAX_FRAME closes the connection.
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, Optional

from app.core.config import settings as app_settings
from app.core.database import SessionLocal
from app.modules.syslog import config_changes, retention
from app.modules.syslog import settings as syslog_settings
from app.modules.syslog.intake import Intake, normalize_ip

logger = logging.getLogger(__name__)

MAX_FRAME = 16384
MAX_CONNECTIONS = 500
MAX_CONNECTIONS_PER_ADDRESS = 10
IDLE_SECONDS = 600
SETTINGS_EVERY = 15
STATUS_EVERY = 5
CHANGES_EVERY = 10          # reported configuration changes -> backups (config_changes.process)
PRUNE_EVERY = 3600
TICK = 1.0                  # seconds between rounds of the loop


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, owner: "SyslogListener"):
        self.owner = owner

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            self.owner.intake.accept(data[:MAX_FRAME], addr[0], "udp")
        except Exception:  # noqa: BLE001 - one bad datagram must not stop the listener
            logger.debug("[Syslog] datagram from %s not taken", addr[0], exc_info=True)


class SyslogListener:
    def __init__(self, port: Optional[int] = None, bind: Optional[str] = None):
        self.port = port if port is not None else app_settings.SYSLOG_PORT
        self.bind = bind or app_settings.SYSLOG_BIND_ADDRESS
        self.intake = Intake()
        self.cfg: Dict = dict(syslog_settings.DEFAULTS)
        self._udp_transport: Optional[asyncio.DatagramTransport] = None
        self._tcp_server: Optional[asyncio.AbstractServer] = None
        self._connections: Dict[str, int] = {}
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self.error: Optional[str] = None
        self.started_at: Optional[datetime] = None

    # -- sockets ------------------------------------------------------------------------------
    @property
    def listening_udp(self) -> bool:
        return self._udp_transport is not None

    @property
    def listening_tcp(self) -> bool:
        return self._tcp_server is not None

    async def _open(self) -> None:
        want_udp = self.cfg["enabled"] and self.cfg["udp"]
        want_tcp = self.cfg["enabled"] and self.cfg["tcp"]
        errors = []
        loop = asyncio.get_running_loop()
        if want_udp and self._udp_transport is None:
            try:
                self._udp_transport, _ = await loop.create_datagram_endpoint(
                    lambda: _Udp(self), local_addr=(self.bind, self.port))
                logger.info("[Syslog] listening on UDP %s:%s", self.bind, self.port)
            except OSError as e:
                errors.append(f"UDP port {self.port}: {e.strerror or e}")
        elif not want_udp and self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
            logger.info("[Syslog] UDP listener closed")
        if want_tcp and self._tcp_server is None:
            try:
                self._tcp_server = await asyncio.start_server(self._tcp, self.bind, self.port, limit=MAX_FRAME + 64)
                logger.info("[Syslog] listening on TCP %s:%s", self.bind, self.port)
            except OSError as e:
                errors.append(f"TCP port {self.port}: {e.strerror or e}")
        elif not want_tcp and self._tcp_server is not None:
            self._tcp_server.close()
            self._tcp_server = None
            logger.info("[Syslog] TCP listener closed")
        if errors:
            if self.error != "; ".join(errors):
                logger.error("[Syslog] cannot listen: %s", "; ".join(errors))
            self.error = "; ".join(errors)
        else:
            self.error = None

    async def _close(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            try:
                await asyncio.wait_for(self._tcp_server.wait_closed(), timeout=2)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass
            self._tcp_server = None

    async def _tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = normalize_ip(peer[0] if peer else None) or "?"
        if (self.intake.known(ip) is None or sum(self._connections.values()) >= MAX_CONNECTIONS
                or self._connections.get(ip, 0) >= MAX_CONNECTIONS_PER_ADDRESS):
            self.intake.drop(ip)
            writer.close()
            return
        self._connections[ip] = self._connections.get(ip, 0) + 1
        try:
            while not self._stop.is_set():
                frame = await asyncio.wait_for(self._read_frame(reader), timeout=IDLE_SECONDS)
                if frame is None:
                    break
                if frame.strip():
                    self.intake.accept(frame, ip, "tcp")
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError,
                ConnectionError):
            pass
        except Exception:  # noqa: BLE001
            logger.debug("[Syslog] TCP connection from %s ended", ip, exc_info=True)
        finally:
            self._connections[ip] -= 1
            if not self._connections[ip]:
                del self._connections[ip]
            writer.close()

    @staticmethod
    async def _read_frame(reader: asyncio.StreamReader) -> Optional[bytes]:
        first = await reader.read(1)
        if not first:
            return None
        if first.isdigit():
            # octet counting: "123 <34>1 ..."
            head = first + await reader.readuntil(b" ")
            length = int(head[:-1])
            if length > MAX_FRAME:
                raise ValueError("frame too long")
            return await reader.readexactly(length)
        line = first + await reader.readuntil(b"\n") if first != b"\n" else b""
        return line

    # -- loop ---------------------------------------------------------------------------------
    def _db(self, fn):
        db = SessionLocal()
        try:
            return fn(db)
        finally:
            db.close()

    def _write_status(self, db) -> None:
        from app.models.syslog import SyslogStatus
        row = db.get(SyslogStatus, 1)
        if row is None:
            row = SyslogStatus(id=1)
            db.add(row)
        row.enabled, row.udp, row.tcp = bool(self.cfg["enabled"]), self.listening_udp, self.listening_tcp
        row.port, row.error = self.port, self.error
        row.started_at, row.updated_at = self.started_at, datetime.utcnow()
        row.queue_dropped = self.intake.queue_dropped
        db.commit()

    def _changes(self, db):
        return config_changes.process(db, bool(self.cfg.get("backup_on_change", True)))

    async def _reload(self) -> None:
        try:
            self.cfg = await asyncio.to_thread(self._db, syslog_settings.get_settings)
            self.intake.store_max_severity = self.cfg["store_max_severity"]
            if self.cfg["enabled"] and self.intake.assets_stale():
                await asyncio.to_thread(self._db, self.intake.load_assets)
        except Exception:  # noqa: BLE001 - the database may be briefly away; keep the current state
            logger.warning("[Syslog] could not read the settings", exc_info=True)
        await self._open()

    async def _main(self) -> None:
        loop = asyncio.get_running_loop()
        last = {"settings": -1e9, "status": -1e9, "changes": -1e9, "prune": loop.time()}
        while not self._stop.is_set():
            now = loop.time()
            if now - last["settings"] >= SETTINGS_EVERY:
                last["settings"] = now
                await self._reload()
            if self.intake.queue or self.intake._sources or self.intake.changes:
                try:
                    while self.intake.queue or self.intake._sources or self.intake.changes:
                        await asyncio.to_thread(self._db, self.intake.drain)
                        if not self.intake.queue:
                            break
                except Exception:  # noqa: BLE001
                    logger.warning("[Syslog] could not store messages; retrying", exc_info=True)
            if now - last["changes"] >= CHANGES_EVERY:
                last["changes"] = now
                try:
                    done = await asyncio.to_thread(self._db, self._changes)
                    if done["started"] or done["no_schedule"]:
                        logger.info("[Syslog] reported configuration changes: %s", done)
                except Exception:  # noqa: BLE001
                    logger.warning("[Syslog] reported configuration changes not processed", exc_info=True)
            if now - last["status"] >= STATUS_EVERY:
                last["status"] = now
                try:
                    await asyncio.to_thread(self._db, self._write_status)
                except Exception:  # noqa: BLE001
                    logger.debug("[Syslog] status not written", exc_info=True)
            if now - last["prune"] >= PRUNE_EVERY:
                last["prune"] = now
                try:
                    removed = await asyncio.to_thread(self._db, retention.prune)
                    if any(removed.values()):
                        logger.info("[Syslog] retention: %s", removed)
                except Exception:  # noqa: BLE001
                    logger.warning("[Syslog] retention failed", exc_info=True)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=TICK)
            except asyncio.TimeoutError:
                pass

    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self.started_at = datetime.utcnow()
        self._task = asyncio.create_task(self._main(), name="syslog-intake")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._task, timeout=5)
        except asyncio.TimeoutError:
            self._task.cancel()
        self._task = None
        await self._close()
        try:
            if self.intake.queue:
                await asyncio.to_thread(self._db, self.intake.drain)
            await asyncio.to_thread(self._db, self._write_status)
        except Exception:  # noqa: BLE001
            logger.debug("[Syslog] final write skipped", exc_info=True)


_listener: Optional[SyslogListener] = None


def start_syslog_intake() -> None:
    """Start the listener loop (once per process); it binds only while the intake is turned on."""
    global _listener
    if _listener is None:
        _listener = SyslogListener()
    _listener.start()


async def stop_syslog_intake() -> None:
    if _listener is not None:
        await _listener.stop()
