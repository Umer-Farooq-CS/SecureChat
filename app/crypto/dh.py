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
File: app/crypto/dh.py
Purpose: Diffie-Hellman key exchange and session key derivation
================================================================================

Description:
    This module implements the Diffie-Hellman key exchange protocol for
    establishing a shared secret between client and server. It provides:
    - DH parameter generation (p, g)
    - Public value computation (A = g^a mod p, B = g^b mod p)
    - Shared secret derivation (Ks = A^b mod p = B^a mod p)
    - Session key derivation: K = Trunc16(SHA256(big-endian(Ks)))

Key Features:
    - Classic Diffie-Hellman key exchange
    - Secure key derivation using SHA-256
    - 16-byte AES key generation for session encryption

Links to Other Files:
    - app/crypto/aes.py: Provides session key K for AES encryption
    - app/client.py: Used for client-side DH exchange
    - app/server.py: Used for server-side DH exchange
    - app/common/utils.py: Uses SHA-256 hashing for key derivation

Input:
    - DH parameters (p, g) - large prime and generator
    - Private exponent (a for client, b for server)
    - Public value from peer (A or B)

Output:
    - Public value (A or B) for transmission
    - Shared secret Ks (for internal use)
    - 16-byte session key K (for AES encryption)

Result:
    - Establishes shared secret without transmitting it over network
    - Derives unique session key for each chat session
    - Provides forward secrecy (each session has different key)

================================================================================
"""

from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh as dh_module

from app.common.utils import sha256_hex


def generate_dh_parameters(generator: int = 2, key_size: int = 2048) -> dh_module.DHParameters:
    """
    Generates Diffie-Hellman parameters (p, g).
    
    Args:
        generator: Generator value (typically 2)
        key_size: Key size in bits (minimum 512, recommended 2048+)
        
    Returns:
        DHParameters: Generated DH parameters
    """
    return dh_module.generate_parameters(generator, key_size, default_backend())


def create_dh_parameters_from_numbers(p: int, g: int) -> dh_module.DHParameters:
    """
    Creates DH parameters from given prime and generator.
    
    Args:
        p: Large prime number
        g: Generator value
        
    Returns:
        DHParameters: DH parameters object
    """
    param_numbers = dh_module.DHParameterNumbers(p, g)
    return param_numbers.parameters(default_backend())


def generate_private_key(parameters: dh_module.DHParameters) -> dh_module.DHPrivateKey:
    """
    Generates a private key from DH parameters.
    
    Args:
        parameters: DH parameters
        
    Returns:
        DHPrivateKey: Generated private key
    """
    return parameters.generate_private_key()


def get_public_key(private_key: dh_module.DHPrivateKey) -> dh_module.DHPublicKey:
    """
    Gets public key from private key.
    
    Args:
        private_key: DH private key
        
    Returns:
        DHPublicKey: Corresponding public key
    """
    return private_key.public_key()


def get_public_value(public_key: dh_module.DHPublicKey) -> int:
    """
    Extracts public value (y) from public key.
    
    Args:
        public_key: DH public key
        
    Returns:
        int: Public value y = g^x mod p
    """
    return public_key.public_numbers().y


def exchange_key(
    private_key: dh_module.DHPrivateKey,
    peer_public_key: dh_module.DHPublicKey
) -> bytes:
    """
    Performs key exchange to derive shared secret.
    
    Computes: Ks = peer_public_key^private_key mod p
    
    Args:
        private_key: Local private key
        peer_public_key: Peer's public key
        
    Returns:
        bytes: Shared secret Ks as bytes (big-endian)
    """
    return private_key.exchange(peer_public_key)


def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derives 16-byte AES session key from shared secret.
    
    Formula: K = Trunc16(SHA256(big-endian(Ks)))
    
    Args:
        shared_secret: Shared secret Ks from DH exchange (bytes)
        
    Returns:
        bytes: 16-byte session key for AES-128
    """
    # SHA-256 hash of shared secret (already in big-endian bytes)
    hash_hex = sha256_hex(shared_secret)
    hash_bytes = bytes.fromhex(hash_hex)
    
    # Truncate to 16 bytes (128 bits) for AES-128
    return hash_bytes[:16]


def create_public_key_from_value(
    public_value: int,
    parameters: dh_module.DHParameters
) -> dh_module.DHPublicKey:
    """
    Creates public key object from public value and parameters.
    
    Args:
        public_value: Public value (y = g^x mod p)
        parameters: DH parameters
        
    Returns:
        DHPublicKey: Public key object
    """
    param_numbers = parameters.parameter_numbers()
    public_numbers = dh_module.DHPublicNumbers(public_value, param_numbers)
    return public_numbers.public_key(default_backend())


def get_parameters_from_key(key: Union[dh_module.DHPrivateKey, dh_module.DHPublicKey]) -> dh_module.DHParameters:
    """
    Extracts parameters from a DH key.
    
    Args:
        key: DH private or public key
        
    Returns:
        DHParameters: DH parameters
    """
    return key.parameters()
