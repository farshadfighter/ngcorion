"""
Verification of the license server's signed answers.

The license server signs every answer (activate, validate, heartbeat) and every offline license
file (typ "offline")
with its Ed25519 private key; the token is

    base64url(claims JSON) "." base64url(signature over those exact bytes)

(license server: app/utils/license_token.py). This module accepts a token only
when all of these hold:

* its key id is one of TRUSTED_LICENSE_KEYS and the signature verifies;
* it is a token version this code understands and of the expected type;
* it is about this installation's license key and this machine's fingerprint;
* for a live answer, it echoes the nonce sent with the request, so an answer
  recorded earlier cannot be replayed.

Anything else raises LicenseTokenError. Callers treat that as a rejection, not
an outage: an answer that is not genuinely from the license server must never
unlock the product, and must not be mistaken for a network blip that the
offline grace window would cover.
"""
import base64
import json
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core import license_keys

TOKEN_VERSION = 1


class LicenseTokenError(Exception):
    """A licensing answer is missing, unsigned, forged, or not about this installation."""


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _public_key(kid: str) -> Ed25519PublicKey:
    encoded = license_keys.TRUSTED_LICENSE_KEYS.get(kid)
    if not encoded:
        if not license_keys.TRUSTED_LICENSE_KEYS:
            raise LicenseTokenError(
                "This NGCorion build has no license signing key built in "
                "(app/core/license_keys.py), so no license answer can be trusted."
            )
        raise LicenseTokenError(f"The answer is signed with an unknown key ({kid[:16]!r}).")
    try:
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded))
    except ValueError as exc:
        raise LicenseTokenError(f"Built-in license key {kid!r} is malformed.") from exc


def verify_token(
    token: Optional[str],
    *,
    license_key: str,
    vm_fingerprint: str,
    typ: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a signed answer and return its claims; LicenseTokenError when it must not be trusted.

    `nonce` is checked when given (live answers); cached tokens are verified without it.
    """
    if not token or not isinstance(token, str) or token.count(".") != 1:
        raise LicenseTokenError(
            "The license server's answer is not signed: something other than the NGCorion license "
            "server answered (a proxy, a filter, or an outdated license server)."
        )
    body, signature = token.split(".")
    try:
        payload = _b64decode(body)
        sig = _b64decode(signature)
        claims = json.loads(payload)
    except (ValueError, TypeError) as exc:
        raise LicenseTokenError("The license server's answer is malformed.") from exc
    if not isinstance(claims, dict):
        raise LicenseTokenError("The license server's answer is malformed.")

    key = _public_key(str(claims.get("kid") or ""))
    try:
        key.verify(sig, payload)
    except InvalidSignature as exc:
        raise LicenseTokenError("The license answer's signature is not valid.") from exc

    if claims.get("v") != TOKEN_VERSION:
        raise LicenseTokenError(f"Unsupported license token version {claims.get('v')!r}.")
    if typ is not None and claims.get("typ") != typ:
        raise LicenseTokenError(f"Expected a {typ!r} answer, got {claims.get('typ')!r}.")
    if claims.get("lic") != license_key:
        raise LicenseTokenError("The license answer is about a different license key.")
    if claims.get("fp") != vm_fingerprint:
        raise LicenseTokenError("The license answer is for a different machine.")
    if nonce is not None and claims.get("nonce") != nonce:
        raise LicenseTokenError("The license answer does not match this request (replayed answer?).")
    if not isinstance(claims.get("iat"), int):
        raise LicenseTokenError("The license answer has no issue time.")
    return claims


def claims_to_state(claims: Dict[str, Any], token: str) -> Dict[str, Any]:
    """The license state (as license_state.set_license_state expects it) that a verified token
    describes. Only signed values are used; nothing from the unsigned part of the response.
    """
    return {
        "valid": bool(claims.get("valid")),
        "message": str(claims.get("msg") or ""),
        "plan_code": claims.get("plan"),
        "plan_name": claims.get("plan_name"),
        "is_pilot_mode": bool(claims.get("pilot")),
        # {"max_assets": N or None, "addon_packs": k} (license_state._max_assets)
        "limits": claims.get("limits"),
        "expires_at": claims.get("exp"),
        "issued_at": claims.get("iat"),
        # An offline (air-gapped) license file: valid without contact until offline_until.
        "offline_license": claims.get("typ") == "offline",
        "offline_until": claims.get("offline_until"),
        "signed_token": token,
    }
