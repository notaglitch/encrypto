from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from cryptography.exceptions import InvalidKey

def main():
    password = input("Enter encryption password: ")
    
    while True:
        print("\n=== File Encryption Tool ===")
        print("This tool can encrypt/decrypt any type of file")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")
        
        if choice == '3':
            break
            
        input_file = input("Enter input file path (any file type): ")
        if not os.path.exists(input_file):
            print(f"Error: File '{input_file}' not found.")
            continue
            
        output_file = input("Enter output file path (press Enter for default): ").strip()
        
        if not output_file:
            base_name = os.path.basename(input_file)
            if choice == '1':
                original_ext = os.path.splitext(base_name)[1]
                output_file = f"{os.path.splitext(base_name)[0]}{original_ext}.encrypted"
            else:
                output_file = base_name.replace('.encrypted', '')
                if output_file == base_name:
                    output_file = os.path.splitext(base_name)[0] + '_decrypted' + os.path.splitext(base_name)[1]
        
        try:
            if choice == '1':
                key, salt = generate_key(password)
                encrypt(key, input_file, output_file)
                print(f"File encrypted successfully! Output: {output_file}")
                print(f"Salt: {salt.hex()}")
                with open(output_file + '.salt', 'wb') as f:
                    f.write(salt)
                    
            elif choice == '2':
                try:
                    with open(input_file + '.salt', 'rb') as f:
                        salt = f.read()
                    key, _ = generate_key(password, salt)
                    decrypt(key, input_file, output_file)
                    print(f"File decrypted successfully! Output: {output_file}")
                except FileNotFoundError:
                    print("Error: Salt file not found. Cannot decrypt without the original salt.")
            
        except ValueError as e:
            print(f"Error: {str(e)}")
        except Exception as e:
            print(f"Error: An unexpected error occurred - {str(e)}")

def encrypt(key: bytes, input_file: str, output_file: str) -> None:
    iv = os.urandom(16)
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    padding_length = 16 - (len(plaintext) % 16)
    padded_data = plaintext + (bytes([padding_length]) * padding_length)
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

def decrypt(key: bytes, input_file: str, output_file: str) -> None:
    try:
        with open(input_file, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        padding_length = padded_plaintext[-1]
        if padding_length > 16 or padding_length < 1:
            raise ValueError("Invalid padding")
        
        padding = padded_plaintext[-padding_length:]
        if not all(p == padding_length for p in padding):
            raise ValueError("Invalid padding")
            
        plaintext = padded_plaintext[:-padding_length]
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
            
    except (ValueError, IndexError) as e:
        if os.path.exists(output_file):
            os.remove(output_file)
        raise ValueError("Decryption failed - incorrect password or corrupted file")

def generate_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    password_bytes = password.encode()
    if salt is None:
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
