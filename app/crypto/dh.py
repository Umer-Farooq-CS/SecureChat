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

"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
raise NotImplementedError("students: implement DH helpers")
