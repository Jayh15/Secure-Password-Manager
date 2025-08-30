import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

class CryptoUtils:
    def __init__(self):
        self.backend = default_backend()
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def generate_salt(self) -> bytes:
        """Generate a random 16-byte salt"""
        return os.urandom(16)
    
    def encrypt_data(self, plaintext: str, key: bytes) -> dict:
        """Encrypt data using AES-256-CBC with random IV"""
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'iv': base64.b64encode(iv).decode(),
            'salt': base64.b64encode(self.generate_salt()).decode()
        }
    
    def decrypt_data(self, encrypted_data: dict, key: bytes) -> str:
        """Decrypt data using AES-256-CBC"""
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode()
    
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password"""
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
        return ''.join(secrets.choice(characters) for _ in range(length))
    
    def verify_master_password(self, stored_data: dict, password: str) -> bool:
        """Verify if the provided password matches the master password"""
        try:
            salt = base64.b64decode(stored_data['salt'])
            derived_key = self.derive_key(password, salt)
            
            # Try to decrypt a small piece of data to verify the password
            test_data = stored_data.get('test_data')
            if test_data:
                self.decrypt_data(test_data, derived_key)
                return True
        except:
            return False
        return False
