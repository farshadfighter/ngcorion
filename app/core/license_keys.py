"""
Public keys of the NGCorion license server, by key id.

NGCorion acts only on licensing answers signed by one of these keys (see
app/core/license_token.py). They are public halves - safe to publish - and are
deliberately part of the code, not configuration: a key that could be set in
.env or the environment could be replaced by anyone running the product, which
would bring back the "point the app at a fake license server" bypass.

Getting the key: on the license server run
    python scripts/generate_signing_key.py
and copy the printed `"<kid>": "<public key>",` line here (the private key it
prints stays on the license server). `GET /api/signing-key` on the license
server shows the key it currently signs with.

Rotating: add the new key next to the old one, release, switch the license
server to the new private key, then remove the old key in a later release.

While this is empty no license can be validated: every answer is refused with
a message saying no signing key is built in.
"""
from typing import Dict

TRUSTED_LICENSE_KEYS: Dict[str, str] = {
}
