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
File: app/crypto/pki.py
Purpose: X.509 certificate validation and PKI operations
================================================================================

Description:
    This module provides Public Key Infrastructure (PKI) operations for
    certificate validation and management. It implements:
    - Certificate loading from PEM files
    - Certificate chain validation (CA signature verification)
    - Certificate expiry checking
    - Common Name (CN) and Subject Alternative Name (SAN) validation
    - Certificate fingerprint computation

Key Features:
    - Validates certificates are signed by trusted CA
    - Checks certificate validity period (not expired)
    - Verifies hostname/CN matches expected value
    - Rejects invalid, self-signed, or expired certificates

Links to Other Files:
    - app/client.py: Validates server certificate during connection
    - app/server.py: Validates client certificate during authentication
    - scripts/gen_ca.py: Uses CA certificate for validation
    - scripts/gen_cert.py: Uses issued certificates for validation

Input:
    - Certificate file path (PEM format)
    - CA certificate file path (for chain validation)
    - Expected Common Name (CN) or hostname

Output:
    - Validation result (True/False)
    - Certificate object (for extracting public key)
    - Error messages for invalid certificates (BAD_CERT)

Result:
    - Ensures mutual authentication between client and server
    - Prevents Man-in-the-Middle (MitM) attacks
    - Validates identity before establishing secure channel
    - Provides foundation for trust in the system

================================================================================
"""

"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 
raise NotImplementedError("students: implement PKI checks")
