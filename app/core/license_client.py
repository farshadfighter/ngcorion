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
    
    def __init__(self, server_url: str, storage_dir: str = "~/.license"):
        self.server_url = server_url.rstrip('/')
        self.storage = SecureStorage(storage_dir)
    
    def get_fingerprint(self) -> str:
        """Get VM fingerprint from license server"""
        url = f"{self.server_url}/api/fingerprint"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()["fingerprint"]
    
    def activate(self, license_key: str) -> dict:
        """Activate license with the server"""
        # Get fingerprint from license server
        vm_fingerprint = self.get_fingerprint()
        
        url = f"{self.server_url}/api/licenses/activate"
        data = {
            "license_key": license_key,
            "vm_fingerprint": vm_fingerprint
        }
        
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()
        
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
        
        url = f"{self.server_url}/api/licenses/validate"
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
        
        response = requests.post(url, json=request_data, headers=headers, timeout=10)
        response.raise_for_status()
        
        return response.json()
    
    def heartbeat(self) -> dict:
        """Send heartbeat to server"""
        license_data = self.get_license_data()
        if not license_data:
            raise Exception("License not activated. Please activate first.")
        
        url = f"{self.server_url}/api/licenses/heartbeat"
        data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": license_data["vm_fingerprint"]
        }
        
        response = requests.post(url, json=data, timeout=10)
        response.raise_for_status()
        
        return response.json()
    
    def consume(self, operation_type: str, count: int = 1) -> dict:
        """Consume operation quota"""
        license_data = self.get_license_data()
        if not license_data:
            raise Exception("License not activated. Please activate first.")
        
        url = f"{self.server_url}/api/licenses/consume"
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
        
        response = requests.post(url, json=request_data, headers=headers, timeout=10)
        response.raise_for_status()
        
        return response.json()
    
    def deactivate(self):
        """Remove local license data"""
        self.storage.delete_license()
