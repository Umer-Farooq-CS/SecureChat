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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from app.common.utils import b64e, b64d


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> str:
    """
    Signs data using RSA private key with PKCS#1 v1.5 and SHA-256.
    
    Args:
        data: Data to sign (bytes)
        private_key: RSA private key
        
    Returns:
        str: Base64-encoded signature
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return b64e(signature)


def verify_signature(
    signature: str,
    data: bytes,
    public_key: rsa.RSAPublicKey
) -> bool:
    """
    Verifies RSA signature using public key.
    
    Args:
        signature: Base64-encoded signature string
        data: Original data that was signed (bytes)
        public_key: RSA public key for verification
        
    Returns:
        bool: True if signature is valid, False otherwise
        
    Raises:
        InvalidSignature: If signature verification fails
    """
    try:
        signature_bytes = b64d(signature)
        public_key.verify(
            signature_bytes,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def load_private_key_from_pem(pem_data: bytes, password: bytes = None) -> rsa.RSAPrivateKey:
    """
    Loads RSA private key from PEM format.
    
    Args:
        pem_data: PEM-encoded private key data
        password: Optional password for encrypted keys
        
    Returns:
        RSAPrivateKey: Loaded private key
    """
    return load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend(),
        unsafe_skip_rsa_key_validation=False
    )


def get_public_key_from_private(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    """
    Extracts public key from private key.
    
    Args:
        private_key: RSA private key
        
    Returns:
        RSAPublicKey: Corresponding public key
    """
    return private_key.public_key()
