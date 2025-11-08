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
File: app/crypto/sign.py
Purpose: RSA signature generation and verification
================================================================================

Description:
    This module provides RSA digital signature functionality using:
    - RSA PKCS#1 v1.5 signature scheme
    - SHA-256 hashing algorithm
    - Signature generation with private key
    - Signature verification with public key (from certificate)

Key Features:
    - Generates RSA signatures over SHA-256 hashes
    - Verifies signatures using sender's certificate
    - Provides message authenticity and integrity
    - Enables non-repudiation

Links to Other Files:
    - app/client.py: Signs client messages before sending
    - app/server.py: Signs server messages and verifies client signatures
    - app/crypto/pki.py: Extracts public key from certificate for verification
    - app/common/utils.py: Uses SHA-256 hashing for message digests
    - app/storage/transcript.py: Signs transcript hash for SessionReceipt

Input:
    - Message data (bytes) or hash (SHA-256 digest)
    - Private key (for signing)
    - Public key or certificate (for verification)

Output:
    - Digital signature (base64-encoded string)
    - Verification result (True/False)
    - Error messages for invalid signatures (SIG_FAIL)

Result:
    - Ensures message integrity (detects tampering)
    - Provides message authenticity (proves sender identity)
    - Enables non-repudiation (sender cannot deny sending message)
    - Prevents unauthorized message modification

================================================================================
"""

"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
raise NotImplementedError("students: implement RSA helpers")
