"""
Encryption for credentials at rest, used by scheduled (unattended) jobs.

Every interactive device-I/O path in this app (SSH, WinRM audits, discovery)
enters credentials fresh per request and never stores them. A scheduled job
runs with nobody in the loop to type a password, so its params - which may
include real device credentials - are stored Fernet-encrypted instead of in
the clear. The Fernet key is derived from the app's own SECRET_KEY (already
a required, protected secret - see app/core/config.py) via SHA-256, so there
is no second secret to provision or rotate separately.

Same construction as app/core/snmp_crypto.py (NOC module) - kept as its own
copy here since that module isn't merged yet; safe to unify later.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _cipher() -> Fernet:
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_json(payload: str) -> str:
    """Encrypt a JSON string for storage."""
    return _cipher().encrypt(payload.encode()).decode()


def decrypt_json(ciphertext: str) -> str:
    """Decrypt a value previously returned by encrypt_json.

    Raises ValueError (not the cryptography-library-specific InvalidToken)
    so callers don't need to import cryptography themselves - e.g. after
    SECRET_KEY changes, or the stored value was corrupted.
    """
    try:
        return _cipher().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Could not decrypt stored job params - SECRET_KEY may have changed") from exc
