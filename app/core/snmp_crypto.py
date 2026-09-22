"""
Encryption for SNMP credentials at rest.

Unlike every other device-I/O path in this app (SSH, WinRM - credentials
entered fresh per request, never stored), background SNMP polling needs the
community string / SNMPv3 keys available without a user in the loop, so they
are stored Fernet-encrypted rather than in the clear. The Fernet key is
derived from the app's own SECRET_KEY (already a required, protected secret -
see app/core/config.py) via SHA-256, so there is no second secret to
provision or rotate separately.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _cipher() -> Fernet:
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret (community string, SNMPv3 key) for storage."""
    return _cipher().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a value previously returned by encrypt_secret.

    Raises ValueError (not the cryptography-library-specific InvalidToken)
    so callers don't need to import cryptography themselves - e.g. after
    SECRET_KEY changes, or the stored value was corrupted.
    """
    try:
        return _cipher().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Could not decrypt stored SNMP secret - SECRET_KEY may have changed") from exc
