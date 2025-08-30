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




AES-256 is a strong symmetric-key encryption standard using a 256-bit key to encrypt data blocks over 14 rounds, making it virtually unbreakable by brute force and suitable for securing sensitive information in various applications, including government, commercial, and personal data. Master password protection involves creating a single, very strong password to secure a digital vault or other sensitive digital information, such as a password manager, browser, or encrypted file.
