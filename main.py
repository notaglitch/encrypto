from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

def main():
    pass

def encrypt():
    pass

def decrypt():
    pass

def generate_key(password: str) -> bytes:
    password_bytes = password.encode()
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = kdf.derive(password_bytes)
    return key, salt

if __name__ == "__main__":
    main()
