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

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def load_ca_files(ca_cert_path: str, ca_key_path: str):
    """
    Loads CA certificate and private key from files.
    
    Args:
        ca_cert_path: Path to CA certificate file
        ca_key_path: Path to CA private key file
        
    Returns:
        tuple: (ca_certificate, ca_private_key)
    """
    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert_data = f.read()
    ca_certificate = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
    
    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_key_data = f.read()
    ca_private_key = serialization.load_pem_private_key(
        ca_key_data,
        password=None,
        backend=default_backend()
    )
    
    return ca_certificate, ca_private_key


def generate_certificate(
    cn: str,
    output_prefix: str = "certs/cert",
    validity_days: int = 365,
    ca_cert_path: str = "certs/ca-cert.pem",
    ca_key_path: str = "certs/ca-key.pem"
):
    """
    Generates a certificate signed by the Root CA.
    
    Args:
        cn: Common Name (hostname) for the certificate
        output_prefix: Output file prefix (e.g., "certs/server" -> "certs/server-key.pem")
        validity_days: Certificate validity period in days
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        
    Returns:
        tuple: (cert_key_path, cert_path)
    """
    # Load CA certificate and key
    print(f"[INFO] Loading CA certificate from {ca_cert_path}...")
    print(f"[INFO] Loading CA private key from {ca_key_path}...")
    ca_certificate, ca_private_key = load_ca_files(ca_cert_path, ca_key_path)
    
    # Generate RSA private key for entity (2048-bit minimum)
    print(f"[INFO] Generating RSA private key (2048-bit) for {cn}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    # Get CA issuer name
    issuer = ca_certificate.subject
    
    # Calculate validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now
    valid_to = now + datetime.timedelta(days=validity_days)
    
    # Create certificate signed by CA
    print(f"[INFO] Creating certificate signed by CA...")
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),  # SAN = DNSName(CN)
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_certificate.public_key()),
        critical=False,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Determine output paths
    output_path = Path(output_prefix)
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Extract base name (e.g., "certs/server" -> "server")
    base_name = output_path.name
    
    # Save private key
    cert_key_path = output_dir / f"{base_name}-key.pem"
    print(f"[INFO] Saving private key to {cert_key_path}...")
    with open(cert_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_path = output_dir / f"{base_name}-cert.pem"
    print(f"[INFO] Saving certificate to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"[SUCCESS] Certificate generated successfully!")
    print(f"  Common Name: {cn}")
    print(f"  Valid from: {valid_from.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Valid to: {valid_to.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Private key: {cert_key_path}")
    print(f"  Certificate: {cert_path}")
    
    return cert_key_path, cert_path


def main():
    """Main entry point for certificate generation script."""
    parser = argparse.ArgumentParser(
        description="Generate X.509 certificate signed by Root CA"
    )
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="Common Name (hostname) for the certificate (e.g., 'server.local' or 'client.local')"
    )
    parser.add_argument(
        "--out",
        type=str,
        default="certs/cert",
        help="Output file prefix (default: certs/cert). Outputs will be {prefix}-key.pem and {prefix}-cert.pem"
    )
    parser.add_argument(
        "--validity",
        type=int,
        default=365,
        help="Validity period in days (default: 365)"
    )
    parser.add_argument(
        "--ca-cert",
        type=str,
        default="certs/ca-cert.pem",
        help="CA certificate path (default: certs/ca-cert.pem)"
    )
    parser.add_argument(
        "--ca-key",
        type=str,
        default="certs/ca-key.pem",
        help="CA private key path (default: certs/ca-key.pem)"
    )
    
    args = parser.parse_args()
    
    try:
        generate_certificate(
            cn=args.cn,
            output_prefix=args.out,
            validity_days=args.validity,
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key
        )
    except Exception as e:
        print(f"[ERROR] Failed to generate certificate: {e}")
        raise


if __name__ == "__main__":
    main()
