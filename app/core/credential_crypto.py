"""
Encryption for secrets at rest (scheduled-job credentials, NOC SNMP secrets,
System Configuration passwords/API keys).

Keys are derived from SECRET_KEY - already a required, protected secret, see
app/core/config.py - so there is no second secret to provision. Each purpose
gets its own key via HKDF with a distinct `info` label: SECRET_KEY itself
signs every JWT, and using one raw key for both HMAC signing and several
encryption domains (the previous bare SHA-256 derivation) meant a weakness or
leak in one use carried straight into all the others.

Values written before the switch were encrypted under that legacy SHA-256 key.
It stays in the decryption set only (MultiFernet encrypts with the first key),
so existing rows keep opening and are re-encrypted under the purpose key the
next time they are saved.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

PURPOSE_SCHEDULED_JOBS = "scheduled-job-params"
PURPOSE_NOC_SNMP = "noc-snmp-credentials"
PURPOSE_SYSTEM_CONFIG = "system-config-secrets"


def _fernet_key(raw: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(raw))


def _cipher(purpose: str) -> MultiFernet:
    secret = settings.SECRET_KEY.encode()
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"ngcorion-credential-crypto",
        info=f"ngcorion:{purpose}".encode(),
    ).derive(secret)
    legacy = hashlib.sha256(secret).digest()
    return MultiFernet([_fernet_key(derived), _fernet_key(legacy)])


def encrypt(plaintext: str, purpose: str) -> str:
    return _cipher(purpose).encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str, purpose: str) -> str:
    """Raises ValueError (e.g. SECRET_KEY changed, or corrupted value)."""
    try:
        return _cipher(purpose).decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Could not decrypt stored secret - SECRET_KEY may have changed") from exc


def encrypt_json(payload: str) -> str:
    """Encrypt a scheduled job's JSON params for storage."""
    return encrypt(payload, PURPOSE_SCHEDULED_JOBS)


def decrypt_json(ciphertext: str) -> str:
    return decrypt(ciphertext, PURPOSE_SCHEDULED_JOBS)
