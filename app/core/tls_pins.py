"""
TLS certificate pinning for managed devices reached over HTTPS with
self-signed certificates (Sophos Firewall's web admin / XML API).

Same trust model as app/core/ssh_host_keys.py and the same setting,
SSH_HOST_KEY_POLICY: "tofu" pins the SHA-256 fingerprint of the certificate a
device presents on first contact (logged so it can be checked out of band)
and refuses any other certificate afterwards; "strict" refuses devices that
are not pinned yet. A legitimately replaced certificate is resolved by
removing that device's pin (forget()).

The pin is checked on the TLS connection before anything - credentials
included - is sent over it. Pins live in a JSON file next to the SSH
known-hosts store (SSL_PINS_FILE overrides).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import threading
from pathlib import Path
from typing import Dict, Optional

from app.core.ssh_host_keys import HostKeyPolicyMode, policy_mode, resolve_store_path

logger = logging.getLogger(__name__)
_lock = threading.Lock()


class TLSPinError(ConnectionError):
    """A device's TLS certificate could not be trusted; nothing was sent to it."""
    pass


class TLSPinUnknownError(TLSPinError):
    """No certificate is pinned for the device and the policy (strict) does not pin on first use."""
    pass


class TLSPinMismatchError(TLSPinError):
    """The device presented a certificate other than the pinned one (possible interception, or the
    device was reinstalled).
    """
    pass


def store_path() -> Path:
    """Where the TLS pins are kept: SSL_PINS_FILE, or tls_pins.json next to the SSH known-hosts store.
    """
    configured = os.environ.get("SSL_PINS_FILE", "").strip()
    if configured:
        return Path(configured).expanduser()
    return resolve_store_path().with_name("tls_pins.json")


def _key(host: str, port: int) -> str:
    return f"[{host}]:{int(port)}"


def _load() -> Dict[str, str]:
    path = store_path()
    try:
        return json.loads(path.read_text()) if path.exists() else {}
    except (OSError, ValueError):
        logger.error("[TLS] the pin store %s is unreadable; refusing to trust any device", path)
        raise TLSPinError(f"TLS pin store {path} is unreadable")


def _save(pins: Dict[str, str]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(pins, indent=2, sort_keys=True))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def fingerprint(der: bytes) -> str:
    return "SHA256:" + hashlib.sha256(der).hexdigest()


def pinned(host: str, port: int) -> Optional[str]:
    return _load().get(_key(host, port))


def forget(host: str, port: int) -> bool:
    """Remove the pinned certificate of host:port (after a legitimate reinstall); True if there was
    one.
    """
    with _lock:
        pins = _load()
        if pins.pop(_key(host, port), None) is None:
            return False
        _save(pins)
        return True


def check(host: str, port: int, der: bytes) -> None:
    """Accept (and on first use pin) a certificate, or raise."""
    seen = fingerprint(der)
    with _lock:
        pins = _load()
        known = pins.get(_key(host, port))
        if known == seen:
            return
        if known is not None:
            raise TLSPinMismatchError(
                f"The TLS certificate of {host}:{port} changed (pinned {known}, presented {seen}). "
                "If the device's certificate was replaced on purpose, remove its pin and connect again.")
        if policy_mode() == HostKeyPolicyMode.STRICT:
            raise TLSPinUnknownError(f"{host}:{port} is not pinned (presented {seen}); pin it first")
        pins[_key(host, port)] = seen
        _save(pins)
    logger.warning("[TLS] pinned %s:%s on first use: %s - verify this fingerprint on the device", host, port, seen)


def unverified_context() -> ssl.SSLContext:
    """Encryption without CA validation; the pin check replaces it."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
