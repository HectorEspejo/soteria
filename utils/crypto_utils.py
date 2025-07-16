import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger(__name__)

class CryptoUtils:
    def __init__(self, key_file: str = '/etc/soteria/.key'):
        self.key_file = key_file
        self.cipher = self._get_or_create_cipher()
    
    def _get_or_create_cipher(self) -> Fernet:
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            with open(self.key_file, 'wb') as f:
                f.write(key)
            os.chmod(self.key_file, 0o600)
            logger.info(f"Created new encryption key at {self.key_file}")
        
        return Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt a string and return base64 encoded result"""
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt base64 encoded encrypted data"""
        try:
            encrypted = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise
    
    @staticmethod
    def hash_data(data: str) -> str:
        """Generate SHA256 hash of data"""
        import hashlib
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def anonymize_ip(ip: str, keep_network: bool = True) -> str:
        """Anonymize IP address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return "invalid_ip"
        
        if keep_network:
            # Keep first two octets
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        else:
            # Full anonymization
            return "xxx.xxx.xxx.xxx"
    
    @staticmethod
    def mask_sensitive_data(data: dict, sensitive_keys: list = None) -> dict:
        """Mask sensitive data in dictionary"""
        if sensitive_keys is None:
            sensitive_keys = ['password', 'api_key', 'token', 'secret', 'credential']
        
        masked_data = data.copy()
        
        def mask_value(value):
            if isinstance(value, str) and len(value) > 4:
                return value[:2] + '*' * (len(value) - 4) + value[-2:]
            return '***'
        
        def mask_dict(d):
            for key, value in d.items():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    d[key] = mask_value(value)
                elif isinstance(value, dict):
                    mask_dict(value)
        
        mask_dict(masked_data)
        return masked_data