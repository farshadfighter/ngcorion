"""
Package signing keys (Ed25519).

Every instance has its own key pair, created on first use; its private key
is stored encrypted (settings.SIGNING_KEY). Packages it exports are signed
with it. A package is imported only when it is signed by a trusted key:
  * this instance's own key,
  * the release key given in CVE_RELEASE_PUBLIC_KEY (signs the database
    snapshot shipped with a release),
  * keys an admin added (e.g. the HQ instance whose packages are carried to
    an air-gapped site).
"""
import base64
import hashlib
import os
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from sqlalchemy.orm import Session

from app.models.cve import CveTrustedKey
from app.modules.cve import settings


class KeyError_(ValueError):
    pass


def fingerprint(public_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(public_b64)).hexdigest()


def load_public(public_b64: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(public_b64, validate=True)
        if len(raw) != 32:
            raise ValueError
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise KeyError_("Not a valid Ed25519 public key (expected 32 bytes, base64)") from exc


def _private(db: Session) -> Ed25519PrivateKey:
    stored = settings.get(db, settings.SIGNING_KEY)
    if stored:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(stored))
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    settings.put(db, settings.SIGNING_KEY, base64.b64encode(raw).decode())
    db.commit()
    return key


def instance_public(db: Session) -> str:
    pub = _private(db).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def sign(db: Session, data: bytes) -> str:
    return base64.b64encode(_private(db).sign(data)).decode()


def trusted(db: Session) -> List[Dict]:
    """[{name, public_key, fingerprint, builtin}] - built-ins first."""
    out = []
    own = instance_public(db)
    out.append({"id": None, "name": "This NGCorion", "public_key": own, "fingerprint": fingerprint(own), "builtin": True})
    release = os.getenv("CVE_RELEASE_PUBLIC_KEY", "").strip()
    if release:
        try:
            load_public(release)
            out.append({"id": None, "name": "NGCorion release", "public_key": release,
                        "fingerprint": fingerprint(release), "builtin": True})
        except KeyError_:
            pass
    for k in db.query(CveTrustedKey).order_by(CveTrustedKey.created_at).all():
        out.append({"id": k.id, "name": k.name, "public_key": k.public_key, "fingerprint": k.fingerprint,
                    "builtin": False})
    return out


def verify(db: Session, data: bytes, signature_b64: str, key_fingerprint: str) -> Optional[str]:
    """The name of the trusted key that signed `data`, or None."""
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return None
    for k in trusted(db):
        if k["fingerprint"] != key_fingerprint:
            continue
        try:
            load_public(k["public_key"]).verify(signature, data)
            return k["name"]
        except (InvalidSignature, KeyError_):
            return None
    return None
