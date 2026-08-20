"""
License Client for Main App

Communicates with the license server to activate, validate, and consume license quotas.
Stores license data encrypted in ~/.license using SecureStorage.
"""
import requests
import hmac
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from app.core.config import settings


class LicenseServerUnreachable(Exception):
    """
    Raised when the license server could not be reached at all
    (DNS failure, refused connection, timeout) — as opposed to the server
    answering with a licensing decision.

    Callers use this to tell "the network is down" apart from "this license is
    not valid", which must be handled very differently: the first is a
    temporary infrastructure problem, the second is a real licensing state.
    """


class SecureStorage:
    """Encrypted storage for license data"""
    
    def __init__(self, storage_dir: str = "~/.license"):
        self.storage_dir = Path(storage_dir).expanduser()
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.license_file = self.storage_dir / ".license.dat"
        self.key_file = self.storage_dir / ".license.key"
        
        self._ensure_key()
    
    def _ensure_key(self):
        """Generate or load encryption key"""
        if not self.key_file.exists():
            key = Fernet.generate_key()
            self.key_file.write_bytes(key)
            os.chmod(self.key_file, 0o600)
    
    def _get_cipher(self) -> Fernet:
        """Get Fernet cipher instance"""
        key = self.key_file.read_bytes()
        return Fernet(key)
    
    def save_license(self, license_data: dict):
        """Encrypt and save license data"""
        cipher = self._get_cipher()
        json_data = json.dumps(license_data)
        encrypted = cipher.encrypt(json_data.encode())
        self.license_file.write_bytes(encrypted)
        os.chmod(self.license_file, 0o600)
    
    def load_license(self) -> Optional[dict]:
        """Load and decrypt license data"""
        if not self.license_file.exists():
            return None
        
        try:
            cipher = self._get_cipher()
            encrypted = self.license_file.read_bytes()
            decrypted = cipher.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except Exception:
            return None
    
    def delete_license(self):
        """Remove license files"""
        if self.license_file.exists():
            self.license_file.unlink()
        if self.key_file.exists():
            self.key_file.unlink()


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
        self.session = self._build_session(self.retries)

    @staticmethod
    def _build_session(attempts: int) -> requests.Session:
        """
        Build a requests Session that retries transport failures.

        Only *connection* failures are retried (`connect=`), plus retryable
        status codes on GET. Read timeouts on POST are deliberately NOT retried:
        /api/licenses/consume already decremented the quota server-side by the
        time a read times out, so retrying would charge the customer twice for
        one audit.
        """
        retry_total = max(attempts - 1, 0)
        retry = Retry(
            total=retry_total,
            connect=retry_total,
            read=0,
            status=retry_total,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET"]),  # status/read retries: GET only
            backoff_factor=0.5,
            raise_on_status=False,
        )
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """
        Perform one license-server call with the configured timeout/retries.

        Connection-level problems are re-raised as LicenseServerUnreachable so
        callers never have to inspect requests' exception tree; HTTP error
        responses keep raising requests.HTTPError, since those carry a real
        answer from the server.
        """
        url = f"{self.server_url}{path}"
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.exceptions.RequestException as exc:
            raise LicenseServerUnreachable(
                f"License server at {self.server_url} is unreachable: {exc}"
            ) from exc
        response.raise_for_status()
        return response

    def get_fingerprint(self) -> str:
        """Get VM fingerprint from license server"""
        response = self._request("GET", "/api/fingerprint")
        return response.json()["fingerprint"]
    
    def activate(self, license_key: str) -> dict:
        """Activate license with the server"""
        # Get fingerprint from license server
        vm_fingerprint = self.get_fingerprint()
        
        data = {
            "license_key": license_key,
            "vm_fingerprint": vm_fingerprint
        }

        response = self._request("POST", "/api/licenses/activate", json=data)

        result = response.json()
        
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
            raise Exception("License not activated. Please activate first.")
        
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
            "POST", "/api/licenses/validate", json=request_data, headers=headers
        )

        return response.json()

    def heartbeat(self) -> dict:
        """Send heartbeat to server"""
        license_data = self.get_license_data()
        if not license_data:
            raise Exception("License not activated. Please activate first.")
        
        data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": license_data["vm_fingerprint"]
        }

        response = self._request("POST", "/api/licenses/heartbeat", json=data)

        return response.json()
    
    def consume(self, operation_type: str, count: int = 1) -> dict:
        """Consume operation quota"""
        license_data = self.get_license_data()
        if not license_data:
            raise Exception("License not activated. Please activate first.")
        
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

        return response.json()

    def deactivate(self):
        """Remove local license data"""
        self.storage.delete_license()
