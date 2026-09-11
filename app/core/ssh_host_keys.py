"""
SSH host-key verification for every managed-device connection.

Background
----------
All five SSH clients in this product used to accept whatever host key a device
presented: the paramiko hardening runner set ``AutoAddPolicy()`` explicitly, and
the four netmiko clients inherited netmiko's default (also ``AutoAddPolicy()``
whenever ``ssh_strict`` is left at ``False``). An on-path attacker could
therefore transparently intercept any audit/hardening session, harvest the
device administrator credentials the session sends, and tamper with the
remediation commands in transit.

This module centralises host-key trust so every client enforces the same policy
against the same store.

Trust model
-----------
``tofu`` (default, trust on first use)
    The first time a host is seen its key is pinned to the known-hosts store and
    a WARNING is logged with the key fingerprint so an operator can verify it
    out of band. Every later connection must present that same key; a changed
    key is rejected. This is the least disruptive mode: hosts that already work
    today keep working, while the persistent-MITM and device-swap cases become
    detectable and blockable.

``strict``
    Nothing is pinned automatically. A host must already be in the store or the
    connection is refused. Use this once the fleet's keys have been provisioned
    (see docs/SSH_HOST_KEY_VERIFICATION.md).

There is deliberately **no** "disabled"/"insecure" mode: a legitimately changed
key is resolved by removing that host's entry from the store (the standard
``ssh-keygen -R`` workflow, or :func:`forget_host`), which is auditable, scoped
to one host, and cannot be left switched on globally by accident.

How each client enforces it
---------------------------
paramiko clients (``HardeningSSHRunner`` — Linux/Apache/MongoDB hardening)
    Get :class:`VerifyingHostKeyPolicy` and an intentionally *empty* in-client
    key store, so paramiko routes **every** connection through the policy and
    this module performs the unknown/match/mismatch decision itself. No extra
    network round trip, and the raised errors are precisely typed.

netmiko clients (Linux/Apache audit, Cisco, FortiGate, MongoDB audit)
    netmiko owns its ``paramiko.SSHClient`` and only exposes the
    ``ssh_strict``/``alt_key_file`` knobs, so enforcement is split in two:
    :func:`ensure_host_key_trusted` runs first (it only touches the network when
    the host is *unknown*, to learn the key for pinning), then
    :func:`netmiko_host_key_kwargs` makes netmiko's own paramiko layer verify
    against the same file with ``RejectPolicy``. A mismatch surfaces from inside
    netmiko wrapped in ``NetmikoAuthenticationException``, which
    :func:`classify_netmiko_auth_failure` turns back into a precise host-key
    error instead of a misleading "authentication failed".
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import socket
import threading
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple

import paramiko

from app.core.config import settings
from app.core.ssh_exceptions import (
    SSHConnectionError,
    SSHHostKeyError,
    map_ssh_exception,
)

try:  # POSIX only; the product ships on Linux/Docker.
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

SSH_DEFAULT_PORT = 22

#: Where the store lives when SSH_KNOWN_HOSTS_FILE is not set. The first path
#: whose parent directory exists and is writable wins. ``/etc/ngcorion`` is the
#: app's config directory and is bind-mounted into the container in
#: docker-compose.yml, so pinned keys survive container recreation there.
_DEFAULT_STORE_CANDIDATES = (
    Path("/etc/ngcorion/known_hosts"),
    Path("~/.ngcorion/known_hosts"),
)


class HostKeyPolicyMode(str, Enum):
    """Supported values of ``SSH_HOST_KEY_POLICY``."""

    TOFU = "tofu"
    STRICT = "strict"


class SSHHostKeyUnknownError(SSHHostKeyError):
    """
    The device is not in the known-hosts store and the policy will not pin it.

    Only raised in ``strict`` mode. Subclasses :class:`SSHHostKeyError`, so the
    routers that already handle host-key failures keep working unchanged.
    """

    error_type: str = "host_key_unknown"

    def __init__(self, device_ip: str, fingerprint: Optional[str] = None,
                 original_error: Optional[Exception] = None):
        detail = f" (offered {fingerprint})" if fingerprint else ""
        super().__init__(
            device_ip=device_ip,
            original_error=original_error,
            message=(
                f"Host key for {device_ip} is not trusted{detail}. "
                f"SSH_HOST_KEY_POLICY=strict refuses unknown hosts."
            ),
        )
        self.fingerprint = fingerprint
        self.suggestions = [
            "Verify the device's host key fingerprint out of band",
            "Add the verified key to the known-hosts store "
            f"({resolve_store_path()})",
            "Or set SSH_HOST_KEY_POLICY=tofu to pin keys on first connection",
        ]


class SSHHostKeyMismatchError(SSHHostKeyError):
    """
    The device presented a different host key than the one pinned for it.

    This is the man-in-the-middle / device-replaced signal: it is always a hard
    failure, in every policy mode.
    """

    error_type: str = "host_key_mismatch"

    def __init__(self, device_ip: str, expected: Optional[str] = None,
                 got: Optional[str] = None, original_error: Optional[Exception] = None):
        detail = ""
        if expected and got:
            detail = f" Expected {expected}, got {got}."
        super().__init__(
            device_ip=device_ip,
            original_error=original_error,
            message=(
                f"Host key verification FAILED for {device_ip}: the device "
                f"presented a key that does not match the pinned one.{detail}"
            ),
        )
        self.expected_fingerprint = expected
        self.got_fingerprint = got
        self.suggestions = [
            "Someone may be intercepting this connection — do not enter "
            "credentials until this is explained",
            "If the device was legitimately reinstalled or replaced, verify the "
            "new fingerprint out of band, then remove its entry from "
            f"{resolve_store_path()} (ssh-keygen -R) and reconnect",
            "Check for ARP/DNS spoofing or an unexpected jump host on the path",
        ]



def key_fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH-style ``SHA256:...`` fingerprint, for logs and operator checks."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def host_key_entry_name(host: str, port: int = SSH_DEFAULT_PORT) -> str:
    """
    Known-hosts entry name for a host/port.

    Mirrors paramiko's own convention exactly (``host`` on port 22,
    ``[host]:port`` otherwise) so entries this module writes are the entries
    netmiko's paramiko layer looks up, and so the file stays compatible with
    OpenSSH tooling such as ``ssh-keygen -R``.
    """
    if int(port) == SSH_DEFAULT_PORT:
        return host
    return f"[{host}]:{port}"


def split_entry_name(name: str, default_port: int = SSH_DEFAULT_PORT) -> Tuple[str, int]:
    """
    Inverse of :func:`host_key_entry_name`.

    paramiko hands its missing-host-key policy the *already formatted*
    ``server_hostkey_name`` — ``[10.0.0.1]:2222`` for a non-default port — so the
    policy must unpack it again before re-deriving an entry name, or the entry
    would be double-bracketed (``[[10.0.0.1]:2222]:2222``) and never match what
    the netmiko path looks up.
    """
    if name.startswith("["):
        host, sep, port = name[1:].rpartition("]:")
        if sep and host and port.isdigit():
            return host, int(port)
    return name, int(default_port)


def resolve_store_path() -> Path:
    """
    Absolute path of the known-hosts store.

    ``SSH_KNOWN_HOSTS_FILE`` wins when set. Otherwise the first default
    candidate whose directory exists (or can be created) and is writable is
    used, so a Docker deployment lands on the persistent ``/etc/ngcorion`` mount
    while a bare-metal/dev run falls back to ``~/.ngcorion`` without any manual
    configuration.
    """
    configured = (settings.SSH_KNOWN_HOSTS_FILE or "").strip()
    if configured:
        return Path(configured).expanduser()

    # Deliberately side-effect free: the directory is created lazily by
    # KnownHostsStore on the first write, so merely resolving the path (which
    # happens on every connection) never touches the filesystem.
    for candidate in _DEFAULT_STORE_CANDIDATES:
        path = candidate.expanduser()
        parent = path.parent
        if parent.is_dir():
            if os.access(parent, os.W_OK):
                return path
            continue
        # Parent missing — usable only if we could create it.
        if os.access(parent.parent, os.W_OK):
            return path

    # Nothing writable: fall back to the last candidate and let the write fail
    # loudly rather than silently skipping verification.
    return _DEFAULT_STORE_CANDIDATES[-1].expanduser()


def policy_mode() -> HostKeyPolicyMode:
    """Current ``SSH_HOST_KEY_POLICY``; unknown values fail closed to strict."""
    raw = (settings.SSH_HOST_KEY_POLICY or "").strip().lower()
    try:
        return HostKeyPolicyMode(raw)
    except ValueError:
        logger.error(
            "[SSH] SSH_HOST_KEY_POLICY=%r is not a valid policy (expected one "
            "of %s). Falling back to 'strict' — unknown hosts will be refused.",
            raw, [m.value for m in HostKeyPolicyMode],
        )
        return HostKeyPolicyMode.STRICT



class VerificationResult(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNKNOWN = "unknown"


class KnownHostsStore:
    """
    File-backed known-hosts store in standard OpenSSH format.

    Every read and every read-modify-write happens under both a process-local
    lock and an ``flock`` on the file, because production runs uvicorn with
    ``--workers 4``: without the file lock two workers pinning different hosts
    at the same moment would clobber each other's entry.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()


    def _load_unlocked(self) -> paramiko.HostKeys:
        keys = paramiko.HostKeys()
        if self.path.exists():
            try:
                keys.load(str(self.path))
            except Exception as exc:  # noqa: BLE001 - corrupt file must not
                # silently disable verification: an unreadable store is treated
                # as empty, which in strict mode refuses everything and in tofu
                # mode re-pins loudly.
                logger.error(
                    "[SSH] known-hosts store %s could not be parsed (%s: %s). "
                    "Treating it as empty — verify the file.",
                    self.path, type(exc).__name__, exc,
                )
        return keys

    def _flock(self, fh, exclusive: bool) -> None:
        if fcntl is None:  # pragma: no cover - non-POSIX
            return
        fcntl.flock(fh, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)



    def lookup(self, host: str, port: int = SSH_DEFAULT_PORT):
        """Return the stored keys for a host, or ``None`` when unknown."""
        with self._lock:
            keys = self._load_unlocked()
            return keys.lookup(host_key_entry_name(host, port))

    def verify(self, host: str, port: int, key: paramiko.PKey) -> VerificationResult:
        """Compare a presented key against what is pinned for this host."""
        entry = self.lookup(host, port)
        if not entry:
            return VerificationResult.UNKNOWN
        stored = entry.get(key.get_name())
        if stored is None:
            # We know this host but have no key of the offered type. Accepting
            # would let an attacker downgrade to a type we never pinned.
            return VerificationResult.MISMATCH
        return (
            VerificationResult.MATCH
            if stored.asbytes() == key.asbytes()
            else VerificationResult.MISMATCH
        )

    def expected_fingerprints(self, host: str, port: int = SSH_DEFAULT_PORT) -> str:
        """Human-readable summary of what is pinned, for error messages."""
        entry = self.lookup(host, port)
        if not entry:
            return ""
        return ", ".join(
            f"{name} {key_fingerprint(pkey)}" for name, pkey in entry.items()
        )

    def add(self, host: str, port: int, key: paramiko.PKey) -> None:
        """
        Pin a key, atomically and without clobbering concurrent writers.

        The file is re-read inside the lock so an entry another worker added a
        moment ago survives.
        """
        entry_name = host_key_entry_name(host, port)
        with self._lock:
            self._ensure_parent()
            # Hold an exclusive flock across the whole read-modify-write.
            lock_path = self.path.with_name(self.path.name + ".lock")
            with open(lock_path, "a+") as lock_fh:
                self._flock(lock_fh, exclusive=True)
                try:
                    keys = self._load_unlocked()
                    keys.add(entry_name, key.get_name(), key)
                    self._atomic_save(keys)
                finally:
                    if fcntl is not None:  # pragma: no branch
                        fcntl.flock(lock_fh, fcntl.LOCK_UN)

    def forget(self, host: str, port: int = SSH_DEFAULT_PORT) -> bool:
        """
        Drop every key pinned for a host. Returns True when something was
        removed. This is the supported remediation for a device that was
        legitimately reinstalled or replaced.
        """
        entry_name = host_key_entry_name(host, port)
        with self._lock:
            if not self.path.exists():
                return False
            self._ensure_parent()
            lock_path = self.path.with_name(self.path.name + ".lock")
            with open(lock_path, "a+") as lock_fh:
                self._flock(lock_fh, exclusive=True)
                try:
                    keys = self._load_unlocked()
                    if entry_name not in keys:
                        return False
                    # HostKeys has no public delete; rebuild without the entry.
                    remaining = paramiko.HostKeys()
                    for hostname in list(keys.keys()):
                        if hostname == entry_name:
                            continue
                        for keytype, pkey in keys[hostname].items():
                            remaining.add(hostname, keytype, pkey)
                    self._atomic_save(remaining)
                    logger.warning(
                        "[SSH] Removed pinned host key(s) for %s from %s",
                        entry_name, self.path,
                    )
                    return True
                finally:
                    if fcntl is not None:  # pragma: no branch
                        fcntl.flock(lock_fh, fcntl.LOCK_UN)

    def _atomic_save(self, keys: paramiko.HostKeys) -> None:
        tmp = self.path.with_name(self.path.name + f".tmp.{os.getpid()}")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as fh:
                for hostname in keys.keys():
                    for keytype, key in keys[hostname].items():
                        fh.write(f"{hostname} {keytype} {key.get_base64()}\n")
                fh.flush()
                os.fsync(fh.fileno())
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(str(tmp), str(self.path))
        os.chmod(self.path, 0o600)


_store_lock = threading.Lock()
_store: Optional[KnownHostsStore] = None
_store_path: Optional[Path] = None


def get_store() -> KnownHostsStore:
    """Process-wide store singleton, rebuilt if the configured path changes."""
    global _store, _store_path
    path = resolve_store_path()
    with _store_lock:
        if _store is None or _store_path != path:
            _store = KnownHostsStore(path)
            _store_path = path
            logger.info("[SSH] Host-key store: %s (policy=%s)",
                        path, policy_mode().value)
        return _store


def reset_store_cache() -> None:
    """Drop the cached store. For tests that repoint SSH_KNOWN_HOSTS_FILE."""
    global _store, _store_path
    with _store_lock:
        _store = None
        _store_path = None


def forget_host(host: str, port: int = SSH_DEFAULT_PORT) -> bool:
    """Remove a host's pinned key(s). See :meth:`KnownHostsStore.forget`."""
    return get_store().forget(host, port)



def evaluate_host_key(host: str, port: int, key: paramiko.PKey) -> None:
    """
    Apply the configured policy to a presented key.

    Returns normally when the connection may proceed (key matched, or was
    pinned just now under ``tofu``). Raises :class:`SSHHostKeyMismatchError` or
    :class:`SSHHostKeyUnknownError` otherwise.
    """
    store = get_store()
    result = store.verify(host, port, key)
    fingerprint = key_fingerprint(key)

    if result is VerificationResult.MATCH:
        logger.debug("[SSH] Host key verified for %s:%s (%s)", host, port, fingerprint)
        return

    if result is VerificationResult.MISMATCH:
        expected = store.expected_fingerprints(host, port)
        logger.error(
            "[SSH] HOST KEY MISMATCH for %s:%s — offered %s %s, pinned %s. "
            "Refusing the connection.",
            host, port, key.get_name(), fingerprint, expected or "(none)",
        )
        raise SSHHostKeyMismatchError(host, expected=expected or None, got=fingerprint)

    # Unknown host.
    if policy_mode() is HostKeyPolicyMode.STRICT:
        logger.error(
            "[SSH] Host %s:%s is not in the known-hosts store and "
            "SSH_HOST_KEY_POLICY=strict. Offered %s %s. Refusing the connection.",
            host, port, key.get_name(), fingerprint,
        )
        raise SSHHostKeyUnknownError(host, fingerprint=fingerprint)

    store.add(host, port, key)
    logger.warning(
        "[SSH] TRUST ON FIRST USE: pinned %s host key for %s:%s (%s). "
        "Verify this fingerprint out of band; every later connection must "
        "present the same key or it will be refused.",
        key.get_name(), host, port, fingerprint,
    )



class VerifyingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    paramiko policy that applies :func:`evaluate_host_key`.

    Used with an SSHClient that has **no** keys loaded, so paramiko delegates
    every connection here instead of only unknown ones. That keeps all three
    outcomes (match / mismatch / unknown) in one place with precise exceptions,
    and means a mismatch is reported as a mismatch rather than as paramiko's
    generic ``BadHostKeyException``.
    """

    def __init__(self, port: int = SSH_DEFAULT_PORT):
        self.port = port

    def missing_host_key(self, client, hostname, key):  # noqa: D102 - paramiko API
        # `hostname` arrives as paramiko's server_hostkey_name, which is already
        # "[host]:port" when the port is not 22 — unpack it so the entry name is
        # derived once, consistently with the netmiko path.
        host, port = split_entry_name(hostname, self.port)
        evaluate_host_key(host, port, key)



def netmiko_host_key_kwargs() -> dict:
    """
    ConnectHandler kwargs that make netmiko's own paramiko layer verify against
    this module's store.

    ``ssh_strict=True`` swaps netmiko's default ``AutoAddPolicy`` for
    ``RejectPolicy``, and ``alt_host_keys``/``alt_key_file`` point it at our
    store. ``system_host_keys=False`` keeps the ambient ``~/.ssh/known_hosts``
    of whatever user the container runs as out of the trust decision.
    """
    return {
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": str(resolve_store_path()),
    }


def _fetch_remote_host_key(host: str, port: int, timeout: float) -> paramiko.PKey:
    """
    Learn a host's key with a KEX-only handshake — no credentials are sent.

    Used solely to pin a *previously unknown* host, so it costs one extra
    handshake on first contact and nothing afterwards.
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
    finally:
        try:
            transport.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("[SSH] closing probe transport to %s failed: %s", host, exc)
    if key is None:  # pragma: no cover - paramiko always sets one on success
        raise SSHHostKeyUnknownError(host)
    return key


def ensure_host_key_trusted(host: str, port: int = SSH_DEFAULT_PORT,
                            timeout: float = 15.0) -> None:
    """
    Pre-flight for the netmiko clients.

    * Host already pinned → returns immediately, no network traffic; netmiko's
      own ``RejectPolicy`` + store then does the real verification.
    * Host unknown, ``tofu`` → one KEX-only probe learns and pins the key.
    * Host unknown, ``strict`` → refuses before any credential is sent.

    A failed probe never degrades into "trusted": it is re-raised through
    :func:`map_ssh_exception` so an unreachable device reports the real network
    or timeout error (rather than a confusing trust error) while still refusing
    to connect unverified.
    """
    if get_store().lookup(host, port):
        return

    if policy_mode() is HostKeyPolicyMode.STRICT:
        logger.error(
            "[SSH] Host %s:%s is not in the known-hosts store and "
            "SSH_HOST_KEY_POLICY=strict. Refusing before authentication.",
            host, port,
        )
        raise SSHHostKeyUnknownError(host)

    try:
        key = _fetch_remote_host_key(host, port, timeout)
    except SSHConnectionError:
        raise
    except Exception as exc:  # noqa: BLE001 - mapped below
        logger.warning(
            "[SSH] Could not read the host key of %s:%s (%s: %s). The "
            "connection is refused rather than trusted blindly.",
            host, port, type(exc).__name__, exc,
        )
        # Report the true cause (unreachable / timed out / refused) instead of
        # a trust error the operator cannot act on.
        raise map_ssh_exception(exc, host)

    evaluate_host_key(host, port, key)


_HOST_KEY_ERROR_MARKERS = (
    "host key",
    "known_hosts",
    "hostkey",
)


def looks_like_host_key_failure(error: Exception) -> bool:
    """
    True when a netmiko/paramiko error is really a host-key failure.

    netmiko wraps every ``paramiko.SSHException`` — including
    ``BadHostKeyException`` and ``RejectPolicy``'s "not found in known_hosts" —
    into ``NetmikoAuthenticationException``, so without this check a MITM would
    be reported to the operator as "wrong password".
    """
    return any(marker in str(error).lower() for marker in _HOST_KEY_ERROR_MARKERS)


def classify_netmiko_auth_failure(error: Exception, host: str) -> Exception:
    """
    Turn a ``NetmikoAuthenticationException`` into the right exception type.

    Returns an :class:`SSHHostKeyMismatchError` when the wrapped cause is a
    host-key problem, otherwise ``None`` so the caller keeps its existing
    authentication-error behaviour.
    """
    if looks_like_host_key_failure(error):
        store = get_store()
        logger.error(
            "[SSH] Host key verification failed for %s (reported by netmiko as "
            "an authentication failure): %s", host, error,
        )
        return SSHHostKeyMismatchError(
            host,
            expected=store.expected_fingerprints(host) or None,
            original_error=error,
        )
    return None
