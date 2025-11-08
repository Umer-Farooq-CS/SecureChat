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

"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
raise NotImplementedError("students: implement AES helpers")
