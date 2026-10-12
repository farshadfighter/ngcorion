"""
Time-based one-time passwords (RFC 6238, HOTP of RFC 4226 underneath), as authenticator apps
(Google Authenticator, Microsoft Authenticator, FreeOTP) generate them: HMAC-SHA1, 6 digits,
30-second steps. Written out here instead of taken from a package: it is a few lines, and the
tests check it against the RFC's own test vectors.

Also the one-time recovery codes: shown to the user once, stored only as a salted PBKDF2 hash (not
keyed by SECRET_KEY, so they keep working after a backup is restored on a server with another key).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional
from urllib.parse import quote

DIGITS = 6
STEP_SECONDS = 30
# Steps accepted either side of now: one step covers a phone clock up to 30 s off.
DRIFT_STEPS = 1
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I: read off paper


def new_secret() -> str:
    """A random 160-bit secret in base32 (what the QR code and the manual-entry key carry)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    cleaned = secret_b32.replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    """RFC 4226: the code for one counter value."""
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def step_at(when: Optional[float] = None) -> int:
    return int((time.time() if when is None else when) // STEP_SECONDS)


def code_at(secret_b32: str, when: Optional[float] = None) -> str:
    return hotp(_key(secret_b32), step_at(when))


def verify(secret_b32: str, code: str, last_used_step: Optional[int] = None,
           when: Optional[float] = None) -> Optional[int]:
    """The step the code belongs to when it is valid now (within DRIFT_STEPS) and newer than
    `last_used_step` (a code is never accepted twice); None otherwise."""
    code = (code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    key = _key(secret_b32)
    now = step_at(when)
    for step in range(now - DRIFT_STEPS, now + DRIFT_STEPS + 1):
        if last_used_step is not None and step <= last_used_step:
            continue
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "NGCorion") -> str:
    """The otpauth:// URI an authenticator app reads from the QR code."""
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP_SECONDS}"


def new_recovery_codes(count: int = 8) -> List[str]:
    """Codes such as "7KQ2-M9XD" (40 bits each)."""
    out = []
    for _ in range(count):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(8))
        out.append(f"{raw[:4]}-{raw[4:]}")
    return out


_PBKDF2_ROUNDS = 120_000


def _normal(code: str) -> str:
    return (code or "").strip().upper().replace(" ", "").replace("-", "")


def hash_recovery_code(code: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", _normal(code).encode(), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2${_PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def recovery_code_matches(code: str, stored: str) -> bool:
    try:
        _, rounds, salt, digest = stored.split("$")
        mine = hashlib.pbkdf2_hmac("sha256", _normal(code).encode(), bytes.fromhex(salt), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(mine.hex(), digest)
