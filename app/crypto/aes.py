"""
================================================================================
Assignment #2 - Secure Chat System
Information Security (CS-3002)
FAST-NUCES, Fall 2025
================================================================================

Student Information:
    Name: Umer Farooq
    Roll No: 22I-0891
    Section: CS-7D
    Instructor: Urooj Ghani

================================================================================
File: app/crypto/aes.py
Purpose: AES-128 encryption and decryption with PKCS#7 padding
================================================================================

Description:
    This module provides AES-128 encryption and decryption functionality using
    the cryptography library. It implements:
    - AES-128 block cipher encryption (ECB mode)
    - PKCS#7 padding for message alignment
    - Base64 encoding for ciphertext transmission

Key Features:
    - Uses 16-byte (128-bit) keys derived from Diffie-Hellman exchange
    - Implements PKCS#7 padding for variable-length messages
    - Provides encryption and decryption functions

Links to Other Files:
    - app/crypto/dh.py: Receives session key K from DH key derivation
    - app/client.py: Used for encrypting client messages
    - app/server.py: Used for decrypting client messages and encrypting responses
    - app/common/utils.py: Uses base64 encoding/decoding utilities

Input:
    - Plaintext message (bytes)
    - 16-byte AES key (from DH key derivation)

Output:
    - Encrypted ciphertext (base64-encoded string)
    - Decrypted plaintext (bytes)

Result:
    - Provides confidentiality for all chat messages
    - Ensures messages are encrypted before transmission
    - Enables secure message exchange between client and server

================================================================================
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from app.common.utils import b64e, b64d


def encrypt_aes128(plaintext: bytes, key: bytes) -> str:
    """
    Encrypts plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: Plaintext message to encrypt (bytes)
        key: 16-byte AES key (128 bits)
        
    Returns:
        str: Base64-encoded ciphertext
        
    Raises:
        ValueError: If key length is not 16 bytes
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Create encryptor
    encryptor = cipher.encryptor()
    
    # Apply PKCS#7 padding (block size = 16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64-encoded ciphertext
    return b64e(ciphertext)


def decrypt_aes128(ciphertext: str, key: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-128 in ECB mode and removes PKCS#7 padding.
    
    Args:
        ciphertext: Base64-encoded ciphertext string
        key: 16-byte AES key (128 bits)
        
    Returns:
        bytes: Decrypted plaintext
        
    Raises:
        ValueError: If key length is not 16 bytes or decryption fails
    """
    if len(key) != 16:
        raise ValueError(f"AES-128 requires 16-byte key, got {len(key)} bytes")
    
    # Decode base64 ciphertext
    ciphertext_bytes = b64d(ciphertext)
    
    # Create AES cipher in ECB mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    
    # Create decryptor
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext)
    plaintext += unpadder.finalize()
    
    return plaintext
