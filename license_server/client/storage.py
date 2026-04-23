import os
import json
from pathlib import Path
from cryptography.fernet import Fernet
from typing import Optional

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
            # Set restrictive permissions (owner read/write only)
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
