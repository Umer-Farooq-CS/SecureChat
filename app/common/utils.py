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
File: app/common/utils.py
Purpose: Utility functions for encoding, hashing, and timestamps
================================================================================

Description:
    This module provides common utility functions used throughout the
    application for:
    - Base64 encoding and decoding
    - SHA-256 hashing
    - Timestamp generation (Unix milliseconds)
    - Data format conversions

Functions:
    - now_ms(): Returns current Unix timestamp in milliseconds
    - b64e(b: bytes): Base64 encodes bytes to string
    - b64d(s: str): Base64 decodes string to bytes
    - sha256_hex(data: bytes): Computes SHA-256 hash and returns hex string

Links to Other Files:
    - app/client.py: Uses all utility functions
    - app/server.py: Uses all utility functions
    - app/crypto/aes.py: Uses base64 encoding for ciphertext
    - app/crypto/dh.py: Uses SHA-256 for key derivation
    - app/crypto/sign.py: Uses SHA-256 for message hashing
    - app/common/protocol.py: Uses base64 for binary fields in messages
    - app/storage/transcript.py: Uses SHA-256 for transcript hashing

Input:
    - Bytes data (for encoding/hashing)
    - String data (for decoding)
    - No input (for timestamp generation)

Output:
    - Base64-encoded strings
    - Decoded bytes
    - SHA-256 hash (hex string)
    - Unix timestamp (milliseconds)

Result:
    - Provides consistent encoding/decoding across the system
    - Ensures proper timestamp generation for replay protection
    - Enables hash computation for integrity checking
    - Standardizes data format conversions

================================================================================
"""

import base64
import hashlib
import time


def now_ms() -> int:
    """
    Returns current Unix timestamp in milliseconds.
    
    Returns:
        int: Current timestamp in milliseconds since epoch
    """
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """
    Base64 encodes bytes to string.
    
    Args:
        b: Bytes to encode
        
    Returns:
        str: Base64-encoded string
    """
    return base64.b64encode(b).decode('utf-8')


def b64d(s: str) -> bytes:
    """
    Base64 decodes string to bytes.
    
    Args:
        s: Base64-encoded string to decode
        
    Returns:
        bytes: Decoded bytes
    """
    return base64.b64decode(s)


def sha256_hex(data: bytes) -> str:
    """
    Computes SHA-256 hash and returns hex string.
    
    Args:
        data: Bytes to hash
        
    Returns:
        str: Hexadecimal representation of SHA-256 hash (64 characters)
    """
    return hashlib.sha256(data).hexdigest()
