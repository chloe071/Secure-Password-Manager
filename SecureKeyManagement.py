from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open('vault.key', 'wb') as keyfile:
    keyfile.write(key)
print("Store this file securely and restrict file permissions!")

import os

def load_key():
    """Load the secret key from an environment variable or a file."""
    key = os.environ.get("VAULT_KEY")
    if key:
        return key.encode() #from env variable
    
    try:
        with open("vault.key", "rb") as keyfile:
            return keyfile.read()
    except FileNotFoundError:
        raise RuntimeError("Encryption key not found! Set VAULT_KEY env var or provide vault.key file.")