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
File: scripts/gen_cert.py
Purpose: Certificate issuance for server and clients
================================================================================

Description:
    This script issues X.509 certificates for server and clients, signed by
    the Root CA. It:
    - Generates RSA keypair for the entity (server/client)
    - Creates X.509 certificate signed by CA
    - Includes Common Name (CN) and Subject Alternative Name (SAN)
    - Stores certificate and private key in certs/ directory

Key Features:
    - Issues certificates signed by Root CA
    - Generates RSA keypair for each entity
    - Includes CN and SAN (DNS name) in certificate
    - Configurable validity period
    - Stores certificates in PEM format

Usage:
    # Generate server certificate
    python scripts/gen_cert.py --cn server.local --out certs/server
    
    # Generate client certificate
    python scripts/gen_cert.py --cn client.local --out certs/client
    
    Options:
        --cn: Common Name (hostname) for the certificate
        --out: Output file prefix (default: certs/cert)
        --validity: Validity period in days (default: 365)
        --ca-cert: CA certificate path (default: certs/ca-cert.pem)
        --ca-key: CA private key path (default: certs/ca-key.pem)

Output Files:
    - certs/{entity}-key.pem: Entity private key (NEVER commit to Git)
    - certs/{entity}-cert.pem: Entity certificate (can be shared)

Links to Other Files:
    - scripts/gen_ca.py: Requires CA key and certificate (must run first)
    - app/crypto/pki.py: Uses issued certificates for validation
    - app/client.py: Uses client certificate for authentication
    - app/server.py: Uses server certificate for authentication

Input:
    - Common Name (CN) or hostname (from command line)
    - CA certificate and private key (from certs/ directory)
    - Output file prefix (from command line)

Output:
    - Entity private key file ({entity}-key.pem)
    - Entity certificate file ({entity}-cert.pem)
    - Console confirmation message

Result:
    - Creates certificates for server and clients
    - Enables mutual authentication between client and server
    - Provides identity verification in the system
    - Must be run after CA generation (gen_ca.py)

================================================================================
"""

"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
raise NotImplementedError("students: implement cert issuance")
