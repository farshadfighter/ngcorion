"""Shared helpers for the signed-licensing tests: a throw-away license server key, a token
maker that signs exactly like the license server does, and a fixture that makes NGCorion
trust that key (and only that key) for the duration of a test.
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import license_keys

TEST_KEY = Ed25519PrivateKey.generate()
TEST_PUBLIC = base64.b64encode(TEST_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
TEST_KID = "testkid000000001"

OTHER_KEY = Ed25519PrivateKey.generate()      # a key NGCorion does not trust

LICENSE_KEY = "TEST-LICE-NSEK-EY01"
FINGERPRINT = "f" * 64


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(key=TEST_KEY, kid=TEST_KID, **overrides) -> str:
    """A token as the license server builds it (claims overridable)."""
    claims = {
        "v": 1, "kid": kid, "typ": "validate", "lic": LICENSE_KEY, "fp": FINGERPRINT,
        "valid": True, "msg": "license is valid", "nonce": None, "iat": int(time.time()),
        "plan": "NGC-BUS-250-1Y", "plan_name": "NGCorion Business", "pilot": False,
        "limits": {"max_assets": 350, "addon_packs": 2},
        "exp": int(time.time()) + 86400 * 300,
    }
    claims.update(overrides)
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    return f"{b64url(payload)}.{b64url(key.sign(payload))}"


@pytest.fixture
def trusted_test_key(monkeypatch):
    """Trust the test key only (the real built-in list is replaced for the test)."""
    monkeypatch.setattr(license_keys, "TRUSTED_LICENSE_KEYS", {TEST_KID: TEST_PUBLIC})
    return TEST_KID
