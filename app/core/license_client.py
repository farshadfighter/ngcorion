"""
License Client for Main App

Communicates with the license server to activate, validate, and consume license quotas.
Stores license data encrypted in ~/.license using SecureStorage.
"""
import requests
import hmac
import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.config import settings

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

    def __init__(self, detail: str, status_code: int = 400):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


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
    ):
        self.server_url = server_url.rstrip('/')
        self.storage = SecureStorage(storage_dir)
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
                f"response (HTTP {response.status_code}): {exc}. Check that "
                f"LICENSE_SERVER_URL points at the license server itself and "
                f"not at a proxy or another service.",
                status_code=response.status_code,
            ) from exc
        if not isinstance(payload, dict):
            raise LicenseServerError(
                f"License server at {self.server_url} returned an unexpected "
                f"payload type ({type(payload).__name__}); expected a JSON object.",
                status_code=response.status_code,
            )
        return payload

    def get_fingerprint(self) -> str:
        """Get VM fingerprint from license server"""
        response = self._request("GET", "/api/fingerprint", idempotent=True)
        payload = self._json(response)
        fingerprint = payload.get("fingerprint")
        if not fingerprint:
            raise LicenseServerError(
                "License server response did not contain a fingerprint.",
                status_code=response.status_code,
            )
        return fingerprint
    
    def activate(self, license_key: str) -> dict:
        """Activate license with the server"""
        # Get fingerprint from license server
        vm_fingerprint = self.get_fingerprint()
        
        data = {
            "license_key": license_key,
            "vm_fingerprint": vm_fingerprint
        }

        response = self._request("POST", "/api/licenses/activate", json=data)

        result = self._json(response)
        
        # Save license data locally
        license_data = {
            "license_key": license_key,
            "organization_token": result.get("organization_token"),
            "vm_fingerprint": vm_fingerprint,
            "plan_type": result.get("plan_type"),
            "activated_at": datetime.utcnow().isoformat()
        }
        self.storage.save_license(license_data)
        
        return result
    
    def get_license_data(self) -> Optional[dict]:
        """Load license data from storage"""
        return self.storage.load_license()
    
    def _sign_request(self, data: dict, org_token: str) -> tuple:
        """Generate signature and timestamp for request"""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        signature = generate_signature(data, org_token, timestamp)
        return signature, timestamp
    
    def validate(self) -> dict:
        """Validate license with the server"""
        license_data = self.get_license_data()
        if not license_data:
            raise LicenseNotActivated(
                "No license is activated on this machine. Activate a license key "
                "via POST /api/license/activate first."
            )
        
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
            json=request_data, headers=headers, idempotent=True,
        )

        return self._json(response)

    def heartbeat(self) -> dict:
        """Send heartbeat to server"""
        license_data = self.get_license_data()
        if not license_data:
            raise LicenseNotActivated(
                "No license is activated on this machine. Activate a license key "
                "via POST /api/license/activate first."
            )
        
        data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": license_data["vm_fingerprint"]
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

        return self._json(response)

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
        """Consume operation quota"""
        license_data = self.get_license_data()
        if not license_data:
            raise LicenseNotActivated(
                "No license is activated on this machine. Activate a license key "
                "via POST /api/license/activate first."
            )
        
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
            "POST", "/api/licenses/consume", json=request_data, headers=headers
        )

        return self._json(response)

    def deactivate(self):
        """Remove local license data"""
        self.storage.delete_license()
