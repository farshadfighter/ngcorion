"""
Checking an API key presented as "Authorization: Bearer ngk_<key id>_<secret>" (app/models/api_key.py).

A key is accepted when its id exists, the SHA-256 of the secret matches (compared in constant time), it is
neither revoked nor expired, its service account is active, and - when the key names addresses - the
request comes from one of them. The answer is then that service account, and the request goes on like any
other: the license check, the permission of each route and every ownership rule still apply. Two-step
sign-in, password age and session idle time are about people and do not apply to a key.

Any failure answers 401 "Invalid API key" without saying which check failed, except an expired key (so its
owner knows to renew it) and an address the key does not allow (403).
"""
import hashlib
import hmac
import ipaddress
import secrets
import string
from datetime import datetime, timedelta
from typing import Iterable, List, Optional, Tuple

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

PREFIX = "ngk_"
KEY_ID_LENGTH = 10
SECRET_BYTES = 32
TOUCH_SECONDS = 60          # last use is written at most once a minute per key and address
_ALPHABET = string.ascii_lowercase + string.digits


def is_api_key(token: str) -> bool:
    return bool(token) and token.startswith(PREFIX)


def new_secret() -> Tuple[str, str]:
    """A new key id and secret; the token is ngk_<key id>_<secret>."""
    key_id = "".join(secrets.choice(_ALPHABET) for _ in range(KEY_ID_LENGTH))
    return key_id, secrets.token_urlsafe(SECRET_BYTES)


def token_of(key_id: str, secret: str) -> str:
    return f"{PREFIX}{key_id}_{secret}"


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def parse(token: str) -> Optional[Tuple[str, str]]:
    if not is_api_key(token):
        return None
    key_id, sep, secret = token[len(PREFIX):].partition("_")
    if not sep or len(key_id) != KEY_ID_LENGTH or not secret or len(secret) > 200:
        return None
    return key_id, secret


def clean_networks(values: Iterable[str]) -> List[str]:
    """Addresses or networks a key may be used from, normalised ("10.0.0.0/24"); ValueError if one is not."""
    out = []
    for v in values or []:
        v = (v or "").strip()
        if not v:
            continue
        net = ipaddress.ip_network(v, strict=False)
        text = str(net.network_address) if net.num_addresses == 1 else str(net)
        if text not in out:
            out.append(text)
    return out


def ip_allowed(ip: Optional[str], allowed: Optional[List[str]]) -> bool:
    if not allowed:
        return True
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in allowed)


def _invalid(detail: str = "Invalid API key", code: int = status.HTTP_401_UNAUTHORIZED):
    return HTTPException(status_code=code, detail=detail, headers={"WWW-Authenticate": "Bearer"}
                         if code == status.HTTP_401_UNAUTHORIZED else None)


def authenticate(db: Session, token: str, request: Optional[Request], now: Optional[datetime] = None):
    """The service account of a valid key; HTTPException otherwise."""
    from app.models import User
    from app.models.api_key import AUTH_SOURCE_API_KEY, ApiKey
    parts = parse(token)
    if parts is None:
        raise _invalid()
    key_id, secret = parts
    key = db.query(ApiKey).filter(ApiKey.key_id == key_id).first()
    # compare even when the id is unknown, so the time taken does not tell whether it exists
    expected = key.secret_hash if key is not None else "0" * 64
    if not hmac.compare_digest(expected, hash_secret(secret)) or key is None or key.revoked_at is not None:
        raise _invalid()
    now = now or datetime.utcnow()
    if key.expires_at <= now:
        raise _invalid("API key has expired")
    user = db.get(User, key.user_id)
    if user is None or not user.is_active or user.auth_source != AUTH_SOURCE_API_KEY:
        raise _invalid()
    ip = request.client.host if request is not None and request.client else None
    if not ip_allowed(ip, key.allowed_ips):
        raise _invalid("This API key is not allowed from this address", status.HTTP_403_FORBIDDEN)
    if (key.last_used_at is None or key.last_used_ip != ip
            or key.last_used_at < now - timedelta(seconds=TOUCH_SECONDS)):
        key.last_used_at, key.last_used_ip = now, ip
        db.commit()
    return user
