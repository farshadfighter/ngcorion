"""The built-in license signing keys are well formed and their ids match (app/core/license_keys.py).

A typo in a pasted key would only show up in the field, as every license being refused with
"unknown key" or "malformed": catch it here instead.
"""
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.license_keys import LICENSE_SERVER_URL, TRUSTED_LICENSE_KEYS


def test_release_has_a_signing_key():
    assert TRUSTED_LICENSE_KEYS, "no key built in: this build would refuse every license"


def test_every_key_is_ed25519_and_its_id_matches():
    for kid, encoded in TRUSTED_LICENSE_KEYS.items():
        raw = base64.b64decode(encoded, validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
        # The license server's key id: the first 16 hex digits of SHA-256 over the raw public key.
        assert kid == hashlib.sha256(raw).hexdigest()[:16], kid


def test_license_server_is_fixed():
    assert LICENSE_SERVER_URL == "https://lic.ngcorion.com"
