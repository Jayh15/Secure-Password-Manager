# Secure-Password-Manager
A command-line password manager with AES-256 encryption and master password protection.


# Secure Password Manager

A command-line password manager with AES-256 encryption and master password protection.

## Features
- AES-256 encryption for all stored passwords
- Master password protection with PBKDF2 key derivation
- Secure storage of encrypted credentials
- Add, retrieve, update, and delete password entries
- Search functionality
- Secure password generation

## Security Features
- Salted PBKDF2 key derivation (100,000 iterations)
- AES-256-GCM encryption mode
- Authentication tags for data integrity
- Secure memory handling
- No plaintext password storage

## Usage
```bash
python password_manager.py
```

## File Structure
- `password_manager.py` - Main application
- `crypto_utils.py` - Encryption/decryption functions
- `storage.py` - Data storage and retrieval
- `requirements.txt` - Dependencies
