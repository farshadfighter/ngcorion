import requests
import sys
import os
from datetime import datetime
from typing import Optional

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.utils.fingerprint import get_vm_fingerprint
from app.utils.signing import generate_signature
from .storage import SecureStorage

class LicenseClient:
    """Client SDK for license server interaction"""
    
    def __init__(self, server_url: str, storage_dir: str = "~/.license"):
        self.server_url = server_url.rstrip('/')
        self.storage = SecureStorage(storage_dir)
        self.vm_fingerprint = get_vm_fingerprint()
    
    def activate(self, license_key: str) -> dict:
        """Activate license with the server"""
        url = f"{self.server_url}/api/licenses/activate"
        data = {
            "license_key": license_key,
            "vm_fingerprint": self.vm_fingerprint
        }
        
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        result = response.json()
        
        # Save license data locally
        license_data = {
            "license_key": license_key,
            "organization_token": result.get("organization_token"),
            "vm_fingerprint": self.vm_fingerprint,
            "plan_type": result.get("plan_type"),
            "activated_at": datetime.utcnow().isoformat()
        }
        self.storage.save_license(license_data)
        
        return result
    
    def _get_license_data(self) -> dict:
        """Load license data from storage"""
        license_data = self.storage.load_license()
        if not license_data:
            raise Exception("License not activated. Please activate first.")
        return license_data
    
    def _sign_request(self, data: dict, org_token: str) -> tuple:
        """Generate signature and timestamp for request"""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        signature = generate_signature(data, org_token, timestamp)
        return signature, timestamp
    
    def validate(self) -> dict:
        """Validate license with the server"""
        license_data = self._get_license_data()
        
        url = f"{self.server_url}/api/licenses/validate"
        request_data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": self.vm_fingerprint
        }
        
        signature, timestamp = self._sign_request(
            request_data,
            license_data["organization_token"]
        )
        
        headers = {
            "X-Signature": signature,
            "X-Timestamp": timestamp
        }
        
        response = requests.post(url, json=request_data, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    def heartbeat(self) -> dict:
        """Send heartbeat to server"""
        license_data = self._get_license_data()
        
        url = f"{self.server_url}/api/licenses/heartbeat"
        data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": self.vm_fingerprint
        }
        
        response = requests.post(url, json=data)
        response.raise_for_status()
        
        return response.json()
    
    def consume(self, operation_type: str, count: int = 1) -> dict:
        """Consume operation quota"""
        license_data = self._get_license_data()
        
        url = f"{self.server_url}/api/licenses/consume"
        request_data = {
            "license_key": license_data["license_key"],
            "organization_token": license_data["organization_token"],
            "vm_fingerprint": self.vm_fingerprint,
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
        
        response = requests.post(url, json=request_data, headers=headers)
        response.raise_for_status()
        
        return response.json()
    
    def deactivate(self):
        """Remove local license data"""
        self.storage.delete_license()
