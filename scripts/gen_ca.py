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

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_ca(name: str = "FAST-NU Root CA", validity_days: int = 3650, output_dir: str = "certs"):
    """
    Generates a Root Certificate Authority (CA).
    
    Args:
        name: CA name (Common Name)
        validity_days: Certificate validity period in days
        output_dir: Output directory for CA files
        
    Returns:
        tuple: (ca_key_path, ca_cert_path)
    """
    # Create output directory if it doesn't exist
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Generate RSA private key (2048-bit minimum)
    print("[INFO] Generating RSA private key (2048-bit)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject (CA information)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    
    # Calculate validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now
    valid_to = now + datetime.timedelta(days=validity_days)
    
    # Create self-signed CA certificate
    print("[INFO] Creating self-signed CA certificate...")
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer  # Self-signed, so issuer = subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    ca_key_path = output_path / "ca-key.pem"
    print(f"[INFO] Saving CA private key to {ca_key_path}...")
    with open(ca_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    ca_cert_path = output_path / "ca-cert.pem"
    print(f"[INFO] Saving CA certificate to {ca_cert_path}...")
    with open(ca_cert_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print("[SUCCESS] Root CA generated successfully!")
    print(f"  CA Name: {name}")
    print(f"  Valid from: {valid_from.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Valid to: {valid_to.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Private key: {ca_key_path}")
    print(f"  Certificate: {ca_cert_path}")
    
    return ca_key_path, ca_cert_path


def main():
    """Main entry point for CA generation script."""
    parser = argparse.ArgumentParser(
        description="Generate Root Certificate Authority (CA)"
    )
    parser.add_argument(
        "--name",
        type=str,
        default="FAST-NU Root CA",
        help="CA name (Common Name) (default: 'FAST-NU Root CA')"
    )
    parser.add_argument(
        "--validity",
        type=int,
        default=3650,
        help="Validity period in days (default: 3650)"
    )
    parser.add_argument(
        "--out",
        type=str,
        default="certs",
        help="Output directory (default: certs/)"
    )
    
    args = parser.parse_args()
    
    try:
        generate_ca(
            name=args.name,
            validity_days=args.validity,
            output_dir=args.out
        )
    except Exception as e:
        print(f"[ERROR] Failed to generate CA: {e}")
        raise


if __name__ == "__main__":
    main()
