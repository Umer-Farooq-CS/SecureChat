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

import datetime
from pathlib import Path
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import oid


class CertificateValidationError(Exception):
    """Custom exception for certificate validation errors."""
    pass


def load_certificate_from_file(cert_path: Union[str, Path]) -> x509.Certificate:
    """
    Loads X.509 certificate from PEM file.
    
    Args:
        cert_path: Path to certificate file
        
    Returns:
        Certificate: Loaded certificate object
        
    Raises:
        ValueError: If certificate cannot be loaded
    """
    cert_path = Path(cert_path)
    if not cert_path.exists():
        raise CertificateValidationError(f"Certificate file not found: {cert_path}")
    
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    
    try:
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    except ValueError as e:
        raise CertificateValidationError(f"Invalid certificate format: {e}")


def load_certificate_from_bytes(cert_data: bytes) -> x509.Certificate:
    """
    Loads X.509 certificate from PEM bytes.
    
    Args:
        cert_data: PEM-encoded certificate data
        
    Returns:
        Certificate: Loaded certificate object
        
    Raises:
        ValueError: If certificate cannot be loaded
    """
    try:
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    except ValueError as e:
        raise CertificateValidationError(f"Invalid certificate format: {e}")


def validate_certificate_chain(
    cert: x509.Certificate,
    ca_cert: x509.Certificate
) -> bool:
    """
    Validates that certificate is signed by the CA.
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate
        
    Returns:
        bool: True if certificate is signed by CA
        
    Raises:
        CertificateValidationError: If validation fails
    """
    try:
        # Verify that the certificate is signed by the CA
        cert.verify_directly_issued_by(ca_cert)
        return True
    except (InvalidSignature, ValueError) as e:
        raise CertificateValidationError(f"Certificate not signed by CA: {e}")


def check_certificate_expiry(cert: x509.Certificate) -> bool:
    """
    Checks if certificate is within validity period.
    
    Args:
        cert: Certificate to check
        
    Returns:
        bool: True if certificate is valid (not expired)
        
    Raises:
        CertificateValidationError: If certificate is expired
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if cert.not_valid_before_utc > now:
        raise CertificateValidationError(
            f"Certificate not yet valid. Valid from: {cert.not_valid_before_utc}"
        )
    
    if cert.not_valid_after_utc < now:
        raise CertificateValidationError(
            f"Certificate expired. Expired on: {cert.not_valid_after_utc}"
        )
    
    return True


def get_certificate_cn(cert: x509.Certificate) -> Union[str, None]:
    """
    Extracts Common Name (CN) from certificate subject.
    
    Args:
        cert: Certificate to extract CN from
        
    Returns:
        str: Common Name or None if not found
    """
    try:
        cn = cert.subject.get_attributes_for_oid(oid.NameOID.COMMON_NAME)[0].value
        return cn
    except (IndexError, ValueError):
        return None


def get_certificate_san(cert: x509.Certificate) -> list:
    """
    Extracts Subject Alternative Names (SAN) from certificate.
    
    Args:
        cert: Certificate to extract SAN from
        
    Returns:
        list[str]: List of DNS names from SAN extension
    """
    san_list = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_list.append(name.value)
    except x509.ExtensionNotFound:
        pass
    
    return san_list


def validate_certificate_hostname(
    cert: x509.Certificate,
    expected_hostname: str
) -> bool:
    """
    Validates that certificate matches expected hostname.
    
    Checks both CN and SAN (DNS names).
    
    Args:
        cert: Certificate to validate
        expected_hostname: Expected hostname/CN
        
    Returns:
        bool: True if hostname matches
        
    Raises:
        CertificateValidationError: If hostname doesn't match
    """
    # Check CN
    cn = get_certificate_cn(cert)
    if cn == expected_hostname:
        return True
    
    # Check SAN
    san_list = get_certificate_san(cert)
    if expected_hostname in san_list:
        return True
    
    raise CertificateValidationError(
        f"Hostname mismatch. Expected: {expected_hostname}, "
        f"CN: {cn}, SAN: {san_list}"
    )


def validate_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_hostname: Union[str, None] = None
) -> bool:
    """
    Comprehensive certificate validation.
    
    Validates:
    1. Certificate is signed by CA
    2. Certificate is not expired
    3. Hostname matches (if provided)
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate
        expected_hostname: Optional expected hostname/CN
        
    Returns:
        bool: True if all validations pass
        
    Raises:
        CertificateValidationError: If any validation fails
    """
    # Validate CA signature
    validate_certificate_chain(cert, ca_cert)
    
    # Check expiry
    check_certificate_expiry(cert)
    
    # Check hostname if provided
    if expected_hostname:
        validate_certificate_hostname(cert, expected_hostname)
    
    return True


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """
    Computes SHA-256 fingerprint of certificate.
    
    Args:
        cert: Certificate to fingerprint
        
    Returns:
        str: Hexadecimal fingerprint (64 characters)
    """
    return cert.fingerprint(hashes.SHA256()).hex()


def get_public_key_from_certificate(cert: x509.Certificate):
    """
    Extracts public key from certificate.
    
    Args:
        cert: Certificate to extract public key from
        
    Returns:
        Public key object (RSAPublicKey, etc.)
    """
    return cert.public_key()
