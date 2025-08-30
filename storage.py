import json
import os
import base64
from pathlib import Path
from typing import Dict, List, Optional
from crypto_utils import CryptoUtils

class PasswordStorage:
    def __init__(self, data_file: str = "passwords.encrypted"):
        self.data_file = data_file
        self.crypto = CryptoUtils()
        self.ensure_data_file()
    
    def ensure_data_file(self):
        """Ensure the data file exists with proper structure"""
        if not os.path.exists(self.data_file):
            # Create empty encrypted data structure
            empty_data = {
                'version': '1.0',
                'entries': [],
                'salt': base64.b64encode(self.crypto.generate_salt()).decode(),
                'test_data': None
            }
            with open(self.data_file, 'w') as f:
                json.dump(empty_data, f)
    
    def initialize_master_password(self, master_password: str) -> bool:
        """Initialize the master password for the vault"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            salt = base64.b64decode(data['salt'])
            derived_key = self.crypto.derive_key(master_password, salt)
            
            # Create test data to verify password later
            test_plaintext = "master_password_verification"
            test_encrypted = self.crypto.encrypt_data(test_plaintext, derived_key)
            
            data['test_data'] = test_encrypted
            data['initialized'] = True
            
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
            
            return True
        except Exception as e:
            print(f"Error initializing master password: {e}")
            return False
    
    def verify_master_password(self, master_password: str) -> bool:
        """Verify the master password"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            if not data.get('test_data'):
                return False
                
            salt = base64.b64decode(data['salt'])
            derived_key = self.crypto.derive_key(master_password, salt)
            
            # Try to decrypt test data
            decrypted = self.crypto.decrypt_data(data['test_data'], derived_key)
            return decrypted == "master_password_verification"
        except:
            return False
    
    def add_password(self, master_password: str, service: str, username: str, password: str, notes: str = "") -> bool:
        """Add a new password entry"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            salt = base64.b64decode(data['salt'])
            derived_key = self.crypto.derive_key(master_password, salt)
            
            # Encrypt the password entry
            entry_data = {
                'service': service,
                'username': username,
                'password': password,
                'notes': notes,
                'timestamp': os.path.getctime(self.data_file)
            }
            
            encrypted_entry = self.crypto.encrypt_data(json.dumps(entry_data), derived_key)
            
            # Add to entries
            data['entries'].append(encrypted_entry)
            
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
            
            return True
        except Exception as e:
            print(f"Error adding password: {e}")
            return False
    
    def get_passwords(self, master_password: str) -> List[Dict]:
        """Get all decrypted password entries"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            salt = base64.b64decode(data['salt'])
            derived_key = self.crypto.derive_key(master_password, salt)
            
            decrypted_entries = []
            for encrypted_entry in data.get('entries', []):
                try:
                    decrypted_json = self.crypto.decrypt_data(encrypted_entry, derived_key)
                    entry_data = json.loads(decrypted_json)
                    decrypted_entries.append(entry_data)
                except:
                    # Skip corrupted entries
                    continue
            
            return decrypted_entries
        except Exception as e:
            print(f"Error retrieving passwords: {e}")
            return []
    
    def search_passwords(self, master_password: str, search_term: str) -> List[Dict]:
        """Search password entries by service or username"""
        entries = self.get_passwords(master_password)
        return [
            entry for entry in entries
            if search_term.lower() in entry['service'].lower() or 
               search_term.lower() in entry['username'].lower()
        ]
    
    def delete_password(self, master_password: str, service: str, username: str) -> bool:
        """Delete a password entry"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            
            salt = base64.b64decode(data['salt'])
            derived_key = self.crypto.derive_key(master_password, salt)
            
            # Find and remove the entry
            entries_to_keep = []
            for encrypted_entry in data.get('entries', []):
                try:
                    decrypted_json = self.crypto.decrypt_data(encrypted_entry, derived_key)
                    entry_data = json.loads(decrypted_json)
                    if not (entry_data['service'] == service and entry_data['username'] == username):
                        entries_to_keep.append(encrypted_entry)
                except:
                    # Keep corrupted entries (they might be recoverable)
                    entries_to_keep.append(encrypted_entry)
            
            data['entries'] = entries_to_keep
            
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
            
            return True
        except Exception as e:
            print(f"Error deleting password: {e}")
            return False
    
    def is_initialized(self) -> bool:
        """Check if the vault is initialized with a master password"""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
            return data.get('initialized', False) and data.get('test_data') is not None
        except:
            return False
