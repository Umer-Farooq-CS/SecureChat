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
File: scripts/gen_ca.py
Purpose: Root Certificate Authority (CA) generation
================================================================================

Description:
    This script creates a self-signed Root Certificate Authority (CA) that
    will be used to issue certificates for the server and clients. It:
    - Generates RSA private key (2048-bit minimum)
    - Creates self-signed X.509 certificate
    - Stores CA private key and certificate in certs/ directory

Key Features:
    - Creates root CA with configurable validity period
    - Generates RSA keypair for CA
    - Self-signs CA certificate
    - Stores CA key and certificate in PEM format

Usage:
    python scripts/gen_ca.py --name "FAST-NU Root CA"
    
    Options:
        --name: CA name (default: "FAST-NU Root CA")
        --validity: Validity period in days (default: 3650)
        --out: Output directory (default: certs/)

Output Files:
    - certs/ca-key.pem: CA private key (NEVER commit to Git)
    - certs/ca-cert.pem: CA certificate (can be shared)

Links to Other Files:
    - scripts/gen_cert.py: Uses CA key and certificate to issue certificates
    - app/crypto/pki.py: Uses CA certificate for certificate validation
    - app/client.py: Uses CA certificate to verify server certificate
    - app/server.py: Uses CA certificate to verify client certificates

Input:
    - CA name (from command line argument)
    - Validity period (from command line argument or default)
    - Output directory (from command line argument or default)

Output:
    - CA private key file (ca-key.pem)
    - CA certificate file (ca-cert.pem)
    - Console confirmation message

Result:
    - Creates trusted root CA for the system
    - Enables certificate issuance for server and clients
    - Provides foundation for PKI trust chain
    - Must be run before generating server/client certificates

================================================================================
"""

"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
raise NotImplementedError("students: implement CA generation")
