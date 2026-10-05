"""
License Client for Main App

Communicates with the license server to activate, validate, and consume license quotas.
Stores license data encrypted in ~/.license using SecureStorage.

Every answer is trusted only through its signed token (app/core/license_token.py):
the methods below return the state the verified token describes and never the
unsigned fields next to it, so a server that is not the NGCorion license server
cannot unlock the product. The machine fingerprint is computed on this machine
(app/core/machine_fingerprint.py), never asked from the server.
"""
import requests
import hmac
import hashlib
import ipaddress
import json
import logging
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.config import settings
from app.core.license_token import LicenseTokenError, claims_to_state, verify_token
from app.core.machine_fingerprint import compute_fingerprint

logger = logging.getLogger(__name__)

# HTTP status codes that mean "the license server failed", never "this license
# is not valid". The server returns licensing verdicts as HTTP 200 with
# `valid: false` (see license_server/app/routers/licenses.py), so a 5xx or a 429
# is always an infrastructure problem and must be treated like an outage —
# not like a revoked license.
SERVER_SIDE_ERROR_STATUSES = (429, 500, 502, 503, 504)


class LicenseServerUnreachable(Exception):
    """
    Raised when the license server did not give a usable answer:
    no answer at all (DNS failure, refused connection, timeout), or a 5xx/429
    that is the server failing rather than a licensing decision.

    Callers use this to tell "the license infrastructure is down" apart from
    "this license is not valid", which must be handled very differently: the
    first is a temporary problem that the offline grace window covers, the
    second is a real licensing state that must lock the product down.
    """


class LicenseServerError(LicenseServerUnreachable):
    """
    The license server answered, but with a server-side failure (5xx / 429).

    Deliberately a subclass of LicenseServerUnreachable: every caller that
    already treats "cannot reach the license server" as a temporary outage must
    treat a 500 the same way. Before this existed, a single 500 from the license
    server flipped the in-memory state to invalid and 403-ed every request in
    the product until a later validation happened to succeed.
    """

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class LicenseNotActivated(Exception):
    """
    No license has been activated on this machine yet (nothing in local
    storage). A licensing state, not an error condition to retry: the operator
    has to activate a key.
    """


class LicenseRejected(Exception):
    """
    The license server explicitly rejected this license (HTTP 400).

    This is a verdict, not a failure: the server looked the license up and said
    no — expired, revoked, unknown key, or a VM fingerprint that no longer
    matches. Unlike an outage it must take effect immediately, so callers
    invalidate the local state on the spot instead of coasting on the offline
    grace window.

    `detail` carries the license server's own explanation, which is what the
    operator actually needs to see.
    """

    def __init__(self, detail: str, status_code: Optional[int] = 400):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


class LicenseAnswerUntrusted(LicenseRejected):
    """
    The license server answered, but the answer is not signed by a trusted key,
    is not about this license or this machine, or does not match the request
    (see app/core/license_token.py).

    A rejection, not an outage: such an answer must never unlock anything, and
    the offline grace window - meant for an unreachable server - must not cover
    a server that answers with something we cannot trust.
    """

    def __init__(self, detail: str):
        super().__init__(f"Untrusted license answer: {detail}", status_code=None)


class SecureStorage:
    """Encrypted storage for license data"""

    def __init__(self, storage_dir: str = "~/.license"):
        self.storage_dir = Path(storage_dir).expanduser()
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            # Raised while the app is starting up. A bare PermissionError from
            # mkdir tells the operator nothing about which directory or why.
            raise RuntimeError(
                f"License storage directory {self.storage_dir} could not be "
                f"created ({exc}). Set LICENSE_STORAGE_DIR to a path the "
                f"application user can write to."
            ) from exc

        self.license_file = self.storage_dir / ".license.dat"
        self.key_file = self.storage_dir / ".license.key"
        # Last validated license state, cached so a restart during a license
        # server outage resumes inside the offline grace window.
        self.state_file = self.storage_dir / ".state.dat"

        self._ensure_key()

    def _ensure_key(self):
        """Generate or load encryption key"""
        if not self.key_file.exists():
            key = Fernet.generate_key()
            # Create the file 0600 up front instead of chmod-ing after the
            # write: the previous version left the key world-readable for the
            # window between write_bytes() and chmod().
            self._write_private(self.key_file, key)

    @staticmethod
    def _write_private(path: Path, payload: bytes) -> None:
        """Write bytes to a file that is 0600 from the moment it exists."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        os.chmod(path, 0o600)

    def _get_cipher(self) -> Fernet:
        """Get Fernet cipher instance"""
        key = self.key_file.read_bytes()
        return Fernet(key)

    def save_license(self, license_data: dict):
        """Encrypt and save license data"""
        cipher = self._get_cipher()
        json_data = json.dumps(license_data)
        encrypted = cipher.encrypt(json_data.encode())
        self._write_private(self.license_file, encrypted)

    def load_license(self) -> Optional[dict]:
        """
        Load and decrypt license data.

        Returns None when nothing is stored. A *corrupt* or undecryptable file
        also returns None (there is nothing usable to return), but it is logged
        loudly: silently reporting "not activated" for a license that is only
        unreadable sends the operator off re-activating a key on a machine whose
        fingerprint may no longer match.
        """
        if not self.license_file.exists():
            return None

        try:
            cipher = self._get_cipher()
            encrypted = self.license_file.read_bytes()
            decrypted = cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception as exc:
            logger.error(
                "[License] Stored license at %s exists but could not be read "
                "(%s: %s). The app will behave as if no license were activated. "
                "If %s was replaced or lost, the license must be re-activated.",
                self.license_file, type(exc).__name__, exc, self.key_file,
            )
            return None

    def save_state(self, state: dict) -> None:
        """Encrypt and cache the last validated license state."""
        cipher = self._get_cipher()
        encrypted = cipher.encrypt(json.dumps(state).encode())
        self._write_private(self.state_file, encrypted)

    def load_state(self) -> Optional[dict]:
        """Load the cached license state, or None if absent/unreadable."""
        if not self.state_file.exists():
            return None
        try:
            cipher = self._get_cipher()
            decrypted = cipher.decrypt(self.state_file.read_bytes())
            return json.loads(decrypted.decode())
        except Exception as exc:
            logger.warning(
                "[License] Cached license state at %s could not be read "
                "(%s: %s); starting without it.",
                self.state_file, type(exc).__name__, exc,
            )
            return None

    def delete_license(self):
        """Remove license files"""
        for path in (self.license_file, self.key_file, self.state_file):
            try:
                if path.exists():
                    path.unlink()
            except OSError as exc:
                logger.error("[License] Could not remove %s: %s", path, exc)


def generate_signature(data: dict, secret: str, timestamp: str) -> str:
    """Generate HMAC-SHA256 signature for request data"""
    payload = json.dumps(data, sort_keys=True)
    message = f"{payload}:{timestamp}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


class LicenseClient:
    """Client SDK for license server interaction"""

    def __init__(
        self,
        server_url: str,
        storage_dir: str = "~/.license",
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        retries: Optional[int] = None,
        ca_bundle: Optional[str] = None,
    ):
        self.server_url = self._require_https(server_url.rstrip('/'))
        self.storage = SecureStorage(storage_dir)
        self._fingerprint: Optional[str] = None
        self.timeout = (
            connect_timeout if connect_timeout is not None else settings.LICENSE_CONNECT_TIMEOUT,
            read_timeout if read_timeout is not None else settings.LICENSE_READ_TIMEOUT,
        )
        self.retries = retries if retries is not None else settings.LICENSE_HTTP_RETRIES
        # Two sessions with deliberately different retry policies — see
        # _build_session(). `session` is the conservative one used for calls
        # that change state on the server; `idempotent_session` also retries
        # read timeouts and 5xx, for calls that are safe to repeat.
        self.session = self._build_session(self.retries, idempotent=False)
        self.idempotent_session = self._build_session(self.retries, idempotent=True)

        # The license server (lic.ngcorion.com) has a publicly trusted
        # certificate, verified with requests' normal CA bundle. `ca_bundle` is
        # for tests against a local server with its own certificate; there is
        # no setting for it, and never a way to switch verification off.
        self.ca_bundle = self._resolve_ca_bundle(ca_bundle or "")
        if self.ca_bundle:
            self.session.verify = self.ca_bundle
            self.idempotent_session.verify = self.ca_bundle

    @staticmethod
    def _require_https(url: str) -> str:
        """Refuse a plain-HTTP license server unless it is on this host.

        The answers are signed, so HTTP could not unlock the product, but the
        requests carry the license key and organization token, which must not
        cross the network in clear text.
        """
        parsed = urlparse(url)
        if parsed.scheme == "https":
            return url
        host = (parsed.hostname or "").strip("[]")
        loopback = host == "localhost"
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        if parsed.scheme == "http" and loopback:
            return url
        raise RuntimeError(
            f"The license server must be reached over https:// (got {url!r}): the license key "
            f"and organization token are sent with every request."
        )

    @property
    def machine_fingerprint(self) -> str:
        """This machine's fingerprint, computed once per process."""
        if self._fingerprint is None:
            self._fingerprint = compute_fingerprint(self.storage.storage_dir)
        return self._fingerprint

    @staticmethod
    def _nonce() -> str:
        return secrets.token_hex(16)

    def _verified(self, payload: dict, *, license_key: str, typ: str, nonce: str) -> dict:
        """Claims of the signed token in a response; LicenseAnswerUntrusted when it does not verify."""
        token = payload.get("signed_token")
        try:
            claims = verify_token(token, license_key=license_key, vm_fingerprint=self.machine_fingerprint,
                                  typ=typ, nonce=nonce)
        except LicenseTokenError as exc:
            raise LicenseAnswerUntrusted(str(exc)) from exc
        return claims, token

    def verify_cached_token(self, token: Optional[str]) -> dict:
        """The state a previously stored token describes, if it still verifies for this license and
        machine (used to restore the offline-grace state at startup); LicenseTokenError otherwise.
        """
        license_data = self.get_license_data()
        if not license_data:
            raise LicenseTokenError("No license is activated on this machine.")
        claims = verify_token(token, license_key=license_data["license_key"],
                              vm_fingerprint=self.machine_fingerprint)
        return claims_to_state(claims, token)

    @staticmethod
    def _resolve_ca_bundle(configured: str) -> Optional[str]:
        """
        Validate a CA bundle path given to the client and return an absolute path, or None.

        A missing or mistyped path is fatal on purpose. Left to requests, a bad
        bundle surfaces as an OSError from deep inside the first TLS handshake,
        which this module would classify as LicenseServerUnreachable — i.e. it
        would look exactly like a license server outage, coast for the 48h
        offline grace window, and only then fail the product closed. Refusing to
        start with a clear message is much easier to diagnose.
        """
        path = (configured or "").strip()
        if not path:
            return None

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            raise RuntimeError(
                f"The license server CA bundle {resolved} is not a readable file."
            )
        return str(resolved)

    @staticmethod
    def _build_session(attempts: int, idempotent: bool) -> requests.Session:
        """
        Build a requests Session that retries transport failures.

        Two policies, because the calls are not equally safe to repeat:

        * idempotent=False (activate, consume): only *connection* failures are
          retried. A read timeout on POST is never retried —
          /api/licenses/consume has already decremented the quota server-side by
          the time a read times out, so retrying would charge the customer twice
          for one audit.
        * idempotent=True (fingerprint, validate, heartbeat): read timeouts and
          server-side error statuses are retried too. These calls only read or
          refresh a timestamp, so repeating one is free — and not retrying them
          meant a single slow response left the app running on a stale state
          until the next hourly heartbeat.
        """
        retry_total = max(attempts - 1, 0)
        retry = Retry(
            total=retry_total,
            connect=retry_total,
            read=retry_total if idempotent else 0,
            status=retry_total,
            status_forcelist=SERVER_SIDE_ERROR_STATUSES,
            allowed_methods=(
                frozenset(["GET", "POST"]) if idempotent else frozenset(["GET"])
            ),
            backoff_factor=0.5,
            raise_on_status=False,
        )
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _request(
        self, method: str, path: str, idempotent: bool = False, **kwargs
    ) -> requests.Response:
        """
        Perform one license-server call with the configured timeout/retries.

        Failure classification, which every caller depends on:

        * connection-level problems -> LicenseServerUnreachable, so callers
          never have to inspect requests' exception tree;
        * 5xx/429 -> LicenseServerError (a LicenseServerUnreachable), because
          the license server reports licensing verdicts as HTTP 200 with
          `valid: false`. A 500 is the server being broken, and treating it as
          "your license is invalid" locked the whole product out on a transient
          server fault;
        * 4xx -> requests.HTTPError, unchanged: those carry a real answer from
          the server (e.g. quota exhausted on /consume).
        """
        url = f"{self.server_url}{path}"
        session = self.idempotent_session if idempotent else self.session
        try:
            response = session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.exceptions.RequestException as exc:
            raise LicenseServerUnreachable(
                f"License server at {self.server_url} is unreachable: {exc}"
            ) from exc

        if response.status_code in SERVER_SIDE_ERROR_STATUSES or (
            response.status_code >= 500
        ):
            raise LicenseServerError(
                f"License server at {self.server_url} returned HTTP "
                f"{response.status_code} for {method} {path}. This is a license "
                f"server failure, not a licensing decision.",
                status_code=response.status_code,
            )

        response.raise_for_status()
        return response

    def _json(self, response: requests.Response) -> dict:
        """
        Parse a license-server response body.

        A 200 whose body is not JSON (a proxy interstitial, a captive portal, a
        truncated response) is a broken answer, not a licensing verdict, so it
        is reported as LicenseServerError. Parsing it inline used to raise a raw
        JSONDecodeError, which the state layer then recorded as "license
        validation failed" and locked the app out.
        """
        try:
            payload = response.json()
        except ValueError as exc:
            raise LicenseServerError(
                f"License server at {self.server_url} returned a non-JSON "
                f"response (HTTP {response.status_code}): {exc}. A proxy or "
                f"filter between this server and the license server may be "
                f"answering instead of it.",
                status_code=response.status_code,
            ) from exc
        if not isinstance(payload, dict):
            raise LicenseServerError(
                f"License server at {self.server_url} returned an unexpected "
                f"payload type ({type(payload).__name__}); expected a JSON object.",
                status_code=response.status_code,
            )
        return payload

    def activate(self, license_key: str) -> dict:
        """Activate a license key on this machine and store it.

        The license server binds the key to this machine's fingerprint (one
        machine per license). Returns the state of the verified answer plus
        the organization token. A refusal is requests.HTTPError (400) as
        before; an answer that does not verify is LicenseAnswerUntrusted and
        nothing is stored.
        """
        vm_fingerprint = self.machine_fingerprint
        nonce = self._nonce()
        data = {"license_key": license_key, "vm_fingerprint": vm_fingerprint, "nonce": nonce}

        response = self._request("POST", "/api/licenses/activate", json=data)
        result = self._json(response)
        claims, token = self._verified(result, license_key=license_key, typ="activate", nonce=nonce)
        if not claims.get("valid"):
            raise LicenseAnswerUntrusted("the activation answer does not confirm the license")
        organization_token = result.get("organization_token")
        if not organization_token:
            raise LicenseServerError("The activation answer has no organization token.",
                                     status_code=response.status_code)

        license_data = {
            "license_key": license_key,
            "organization_token": organization_token,
            "vm_fingerprint": vm_fingerprint,
            "plan_type": claims.get("plan"),
            "activated_at": datetime.utcnow().isoformat()
        }
        self.storage.save_license(license_data)

        return dict(claims_to_state(claims, token), organization_token=organization_token)

    def _bound_license_data(self) -> dict:
        """The stored license, re-activated first if it was bound to another fingerprint.

        Installations activated by releases before signed licensing stored the
        license SERVER's fingerprint. Re-activating sends this machine's real
        one; the license server lets such a license move once. A license bound
        to a different real machine is refused (LicenseRejected).
        """
        license_data = self.get_license_data()
        if not license_data:
            raise LicenseNotActivated(
                "No license is activated on this machine. Activate a license key "
                "via POST /api/license/activate first."
            )
        if license_data.get("vm_fingerprint") == self.machine_fingerprint:
            return license_data

        logger.warning("[License] The stored license was bound to another fingerprint; re-activating it "
                       "for this machine.")
        try:
            self.activate(license_data["license_key"])
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            raise LicenseRejected(
                self._error_detail(exc.response, "The license could not be moved to this machine"),
                status_code=status,
            ) from exc
        return self.get_license_data()

    def get_license_data(self) -> Optional[dict]:
        """Load license data from storage"""
        return self.storage.load_license()
    
    def _sign_request(self, data: dict, org_token: str) -> tuple:
        """Generate signature and timestamp for request"""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        signature = generate_signature(data, org_token, timestamp)
        return signature, timestamp
    
    def validate(self) -> dict:
        """Validate the license with the server; the state of the verified answer (which may say
        valid=False - a signed "no" is still an answer).
        """
        license_data = self._bound_license_data()
        nonce = self._nonce()
        request_data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": license_data["vm_fingerprint"]
        }

        signature, timestamp = self._sign_request(
            request_data,
            license_data["organization_token"]
        )

        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp
        }

        response = self._request(
            "POST", "/api/licenses/validate",
            json=dict(request_data, nonce=nonce), headers=headers, idempotent=True,
        )

        claims, token = self._verified(self._json(response), license_key=license_data["license_key"],
                                       typ="validate", nonce=nonce)
        return claims_to_state(claims, token)

    def heartbeat(self) -> dict:
        """Send the hourly heartbeat. Returns success, message, should_downgrade and the verified
        state, all taken from the signed answer.
        """
        license_data = self._bound_license_data()
        nonce = self._nonce()
        data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": license_data["vm_fingerprint"],
            "nonce": nonce,
        }

        try:
            response = self._request(
                "POST", "/api/licenses/heartbeat", json=data, idempotent=True
            )
        except requests.HTTPError as exc:
            # The heartbeat endpoint answers 400 for every rejection it makes
            # (expired, revoked, unknown key, fingerprint mismatch) — see
            # license_server/app/routers/licenses.py. That is a decision about
            # this license, not a transport or server failure, so it is raised
            # as a distinct type the heartbeat loop acts on immediately.
            status = exc.response.status_code if exc.response is not None else None
            if status == 400:
                raise LicenseRejected(
                    self._error_detail(exc.response, "License rejected by the license server"),
                    status_code=status,
                ) from exc
            raise

        claims, token = self._verified(self._json(response), license_key=license_data["license_key"],
                                       typ="heartbeat", nonce=nonce)
        return {
            "success": True,
            "message": str(claims.get("msg") or ""),
            "should_downgrade": bool(claims.get("down")),
            "state": claims_to_state(claims, token),
        }

    @staticmethod
    def _error_detail(response: Optional[requests.Response], fallback: str) -> str:
        """Pull the license server's own message out of an error response."""
        if response is None:
            return fallback
        try:
            payload = response.json()
            if isinstance(payload, dict) and payload.get("detail"):
                return str(payload["detail"])
        except ValueError:
            pass
        body = (response.text or "").strip()
        return body[:200] if body else fallback
    
    def consume(self, operation_type: str, count: int = 1) -> dict:
        """Use quota on the license server. Returns the verified state after the consumption; the
        signed answer must name this operation and count, or it does not count (LicenseAnswerUntrusted).
        """
        license_data = self._bound_license_data()
        nonce = self._nonce()

        request_data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": license_data["vm_fingerprint"],
            "operation_type": operation_type,
            "count": count
        }
        
        signature, timestamp = self._sign_request(
            request_data,
            license_data["organization_token"]
        )
        
        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp
        }
        
        response = self._request(
            "POST", "/api/licenses/consume", json=dict(request_data, nonce=nonce), headers=headers
        )

        claims, token = self._verified(self._json(response), license_key=license_data["license_key"],
                                       typ="consume", nonce=nonce)
        if not claims.get("valid") or claims.get("op") != operation_type or claims.get("count") != count:
            raise LicenseAnswerUntrusted("the consume answer does not confirm this operation")
        return claims_to_state(claims, token)

    def deactivate(self):
        """Remove local license data"""
        self.storage.delete_license()
