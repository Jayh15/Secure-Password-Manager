#!/usr/bin/env python3
"""
Secure Password Manager with AES Encryption
A command-line password vault that securely stores your passwords.
"""

import getpass
import sys
from storage import PasswordStorage
from crypto_utils import CryptoUtils

class PasswordManager:
    def __init__(self):
        self.storage = PasswordStorage()
        self.crypto = CryptoUtils()
    
    def display_menu(self):
        """Display the main menu"""
        print("\n" + "="*50)
        print("        SECURE PASSWORD MANAGER")
        print("="*50)
        print("1. Add Password")
        print("2. View Passwords")
        print("3. Search Passwords")
        print("4. Delete Password")
        print("5. Generate Secure Password")
        print("6. Change Master Password")
        print("7. Exit")
        print("="*50)
    
    def initialize_vault(self):
        """Initialize the password vault with a master password"""
        print("\n=== Initialize Password Vault ===")
        print("This is your first time using the password manager.")
        print("Please set a strong master password.")
        print("This password will be used to encrypt all your stored passwords.")
        print("Make sure to remember it - it cannot be recovered!")
        
        while True:
            master_password = getpass.getpass("Enter master password: ")
            confirm_password = getpass.getpass("Confirm master password: ")
            
            if master_password != confirm_password:
                print("Passwords do not match! Please try again.")
                continue
            
            if len(master_password) < 8:
                print("Master password must be at least 8 characters long.")
                continue
            
            if self.storage.initialize_master_password(master_password):
                print("✓ Master password set successfully!")
                print("✓ Password vault initialized!")
                return master_password
            else:
                print("Error initializing vault. Please try again.")
                return None
    
    def authenticate(self):
        """Authenticate user with master password"""
        if not self.storage.is_initialized():
            return self.initialize_vault()
        
        attempts = 3
        while attempts > 0:
            master_password = getpass.getpass("Enter master password: ")
            
            if self.storage.verify_master_password(master_password):
                return master_password
            
            attempts -= 1
            if attempts > 0:
                print(f"Invalid password. {attempts} attempts remaining.")
            else:
                print("Too many failed attempts. Exiting...")
                sys.exit(1)
        
        return None
    
    def add_password(self, master_password: str):
        """Add a new password entry"""
        print("\n=== Add New Password ===")
        
        service = input("Service/Website: ").strip()
        username = input("Username/Email: ").strip()
        
        print("\nPassword options:")
        print("1. Enter password manually")
        print("2. Generate secure password")
        choice = input("Choose option (1-2): ").strip()
        
        if choice == "2":
            length = input("Password length (default 16): ").strip()
            try:
                length = int(length) if length else 16
                password = self.crypto.generate_secure_password(length)
                print(f"Generated password: {password}")
            except ValueError:
                print("Invalid length. Using default 16 characters.")
                password = self.crypto.generate_secure_password()
                print(f"Generated password: {password}")
        else:
            password = getpass.getpass("Password: ")
        
        notes = input("Notes (optional): ").strip()
        
        if not service or not username or not password:
            print("Service, username, and password are required!")
            return
        
        if self.storage.add_password(master_password, service, username, password, notes):
            print("✓ Password added successfully!")
        else:
            print("Error adding password.")
    
    def view_passwords(self, master_password: str):
        """View all stored passwords"""
        print("\n=== Stored Passwords ===")
        
        entries = self.storage.get_passwords(master_password)
        
        if not entries:
            print("No passwords stored yet.")
            return
        
        for i, entry in enumerate(entries, 1):
            print(f"\n{i}. {entry['service']}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {'*' * len(entry['password'])}")
            if entry['notes']:
                print(f"   Notes: {entry['notes']}")
        
        print(f"\nTotal entries: {len(entries)}")
    
    def search_passwords(self, master_password: str):
        """Search for passwords"""
        print("\n=== Search Passwords ===")
        
        search_term = input("Enter service name or username to search: ").strip()
        if not search_term:
            print("Search term cannot be empty!")
            return
        
        results = self.storage.search_passwords(master_password, search_term)
        
        if not results:
            print("No matching entries found.")
            return
        
        print(f"\nFound {len(results)} matching entries:")
        for i, entry in enumerate(results, 1):
            print(f"\n{i}. {entry['service']}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {'*' * len(entry['password'])}")
            if entry['notes']:
                print(f"   Notes: {entry['notes']}")
    
    def delete_password(self, master_password: str):
        """Delete a password entry"""
        print("\n=== Delete Password ===")
        
        service = input("Service name: ").strip()
        username = input("Username: ").strip()
        
        if not service or not username:
            print("Service and username are required!")
            return
        
        confirm = input(f"Are you sure you want to delete the password for {service} ({username})? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Deletion cancelled.")
            return
        
        if self.storage.delete_password(master_password, service, username):
            print("✓ Password deleted successfully!")
        else:
            print("Error deleting password. Entry may not exist.")
    
    def generate_password(self):
        """Generate a secure password"""
        print("\n=== Generate Secure Password ===")
        
        try:
            length = input("Password length (default 16): ").strip()
            length = int(length) if length else 16
            
            if length < 8:
                print("Password length must be at least 8 characters.")
                return
            
            password = self.crypto.generate_secure_password(length)
            print(f"\nGenerated password: {password}")
            print("Copy this password to your clipboard and use it immediately.")
            
        except ValueError:
            print("Invalid length. Please enter a number.")
    
    def run(self):
        """Main application loop"""
        print("Welcome to Secure Password Manager!")
        
        # Authenticate user
        master_password = self.authenticate()
        if not master_password:
            print("Authentication failed. Exiting...")
            return
        
        while True:
            self.display_menu()
            choice = input("Enter your choice (1-7): ").strip()
            
            if choice == "1":
                self.add_password(master_password)
            elif choice == "2":
                self.view_passwords(master_password)
            elif choice == "3":
                self.search_passwords(master_password)
            elif choice == "4":
                self.delete_password(master_password)
            elif choice == "5":
                self.generate_password()
            elif choice == "6":
                print("Change master password functionality not implemented yet.")
                print("This feature requires re-encrypting all stored passwords.")
            elif choice == "7":
                print("Goodbye! Your passwords are secure.")
                break
            else:
                print("Invalid choice. Please try again.")
            
            input("\nPress Enter to continue...")

def main():
    """Main function"""
    try:
        manager = PasswordManager()
        manager.run()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
