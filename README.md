# File Encryption Tool

A simple command-line tool for encrypting and decrypting files using AES-256 encryption with CBC mode and PBKDF2 key derivation.

# Test Password: "hello123"

## Features

- AES-256 encryption in CBC mode
- PBKDF2 key derivation with SHA-256 and 100,000 iterations
- Secure random IV and salt generation
- PKCS7 padding
- Password-based encryption
- Separate salt file storage for decryption
- Supports all file types including:
  - Text files (.txt, .md, .json, etc.)
  - Binary files (.exe, .dll, etc.) 
  - Image files (.jpg, .png, .gif, etc.)
  - Document files (.pdf, .doc, .docx, etc.)
  - Archive files (.zip, .rar, etc.)
  - And any other file format

## Usage

1. Run the script:

```bash
python main.py
```

2. Choose the operation you want to perform:

- Enter `1` to encrypt a file
- Enter `2` to decrypt a file

3. Follow the prompts to provide the necessary information:

- Enter the path to the file you want to encrypt or decrypt
- Enter the encryption password
- Enter the output file path (press Enter for default)

4. The tool will then encrypt or decrypt the file and display the result.

## Notes

- The tool uses a salt file to store the encryption key. This salt file is required for decryption.
- The tool will overwrite the original file with the encrypted or decrypted version.
- The tool uses PKCS7 padding to handle files of any size.
- The tool uses a secure random IV for each encryption operation.
