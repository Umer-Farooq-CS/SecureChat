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
File: tests/test_pki.py
Purpose: Unit tests for X.509 certificate validation
================================================================================

Description:
    This file contains comprehensive unit tests for PKI operations in
    app/crypto/pki.py. It tests:
    - Certificate loading from bytes
    - Certificate chain validation
    - Certificate expiry checking
    - Common Name (CN) extraction
    - Subject Alternative Name (SAN) extraction
    - Hostname validation
    - Certificate fingerprint computation

Test Cases:
    - Certificate loading
    - Chain validation (CA signature)
    - Expiry validation
    - CN/SAN extraction
    - Hostname matching
    - Invalid certificate rejection

Links to Other Files:
    - app/crypto/pki.py: Module being tested
    - scripts/gen_ca.py: Generates CA certificates
    - scripts/gen_cert.py: Generates client/server certificates

Result:
    - Verifies certificate validation works correctly
    - Ensures proper CA chain validation
    - Validates expiry checking
    - Confirms hostname matching

Note: This test requires certificates to be generated first using
      scripts/gen_ca.py and scripts/gen_cert.py. If certificates don't
      exist, some tests will be skipped.

================================================================================
"""

import sys
import unittest
import datetime
from pathlib import Path

# Configure UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if hasattr(sys.stderr, 'buffer'):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ExtensionOID

from app.crypto.pki import (
    CertificateValidationError,
    load_certificate_from_file,
    load_certificate_from_bytes,
    validate_certificate_chain,
    check_certificate_expiry,
    get_certificate_cn,
    get_certificate_san,
    validate_certificate_hostname,
    validate_certificate,
    get_certificate_fingerprint,
    get_public_key_from_certificate
)


class TestPKI(unittest.TestCase):
    """Test cases for X.509 certificate validation."""

    def setUp(self):
        """Set up test fixtures - create test certificates."""
        print("\n[SETUP] Creating test certificates...")
        
        # Generate CA key pair
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        ca_public_key = ca_private_key.public_key()
        
        # Create CA certificate
        ca_subject = ca_issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ])
        
        self.ca_cert = x509.CertificateBuilder().subject_name(
            ca_subject
        ).issuer_name(
            ca_issuer
        ).public_key(
            ca_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).sign(ca_private_key, hashes.SHA256())
        
        # Generate server key pair
        server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        server_public_key = server_private_key.public_key()
        
        # Create server certificate signed by CA
        server_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "server.local"),
        ])
        
        self.server_cert = x509.CertificateBuilder().subject_name(
            server_subject
        ).issuer_name(
            ca_subject  # Issued by CA
        ).public_key(
            server_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("server.local"),
                x509.DNSName("*.server.local"),
            ]),
            critical=False,
        ).sign(ca_private_key, hashes.SHA256())
        
        # Create expired certificate
        self.expired_cert = x509.CertificateBuilder().subject_name(
            server_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            server_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)  # Expired
        ).sign(ca_private_key, hashes.SHA256())
        
        # Create self-signed certificate (not signed by CA)
        self_signed_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.self_signed_cert = x509.CertificateBuilder().subject_name(
            server_subject
        ).issuer_name(
            server_subject  # Self-signed
        ).public_key(
            self_signed_private.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).sign(self_signed_private, hashes.SHA256())
        
        print("  ✓ Test certificates created")

    def test_certificate_loading_from_bytes(self):
        """Test loading certificate from bytes."""
        print("\n[TEST] Certificate Loading from Bytes")
        
        # Serialize certificate to PEM bytes
        cert_pem = self.server_cert.public_bytes(Encoding.PEM)
        print(f"  Certificate PEM length: {len(cert_pem)} bytes")
        
        # Load certificate from bytes
        loaded_cert = load_certificate_from_bytes(cert_pem)
        print("  ✓ Certificate loaded from bytes")
        
        # Verify it's the same certificate
        self.assertEqual(loaded_cert.serial_number, self.server_cert.serial_number,
                       "Loaded certificate should match original")
        
        print("  ✓ All loading tests passed")

    def test_certificate_chain_validation(self):
        """Test certificate chain validation."""
        print("\n[TEST] Certificate Chain Validation")
        
        # Valid chain: server cert signed by CA
        is_valid = validate_certificate_chain(self.server_cert, self.ca_cert)
        print(f"  Server cert signed by CA: {'✓ Valid' if is_valid else '✗ Invalid'}")
        self.assertTrue(is_valid,
                      "Server certificate should be valid (signed by CA)")
        
        # Invalid chain: self-signed cert (should raise exception)
        with self.assertRaises(CertificateValidationError,
                             msg="Self-signed certificate should raise exception"):
            validate_certificate_chain(self.self_signed_cert, self.ca_cert)
        print("  ✓ Self-signed cert correctly rejected (exception raised)")
        
        # Invalid chain: wrong CA
        # (We can't easily test this without another CA, but the logic is covered)
        
        print("  ✓ All chain validation tests passed")

    def test_certificate_expiry(self):
        """Test certificate expiry checking."""
        print("\n[TEST] Certificate Expiry Checking")
        
        # Valid certificate (not expired)
        is_valid = check_certificate_expiry(self.server_cert)
        print(f"  Valid certificate: {'✓ Not expired' if is_valid else '✗ Expired'}")
        self.assertTrue(is_valid,
                      "Valid certificate should not be expired")
        
        # Expired certificate (should raise exception)
        with self.assertRaises(CertificateValidationError,
                             msg="Expired certificate should raise exception"):
            check_certificate_expiry(self.expired_cert)
        print("  ✓ Expired certificate correctly rejected (exception raised)")
        
        print("  ✓ All expiry tests passed")

    def test_certificate_cn_extraction(self):
        """Test Common Name (CN) extraction."""
        print("\n[TEST] Common Name Extraction")
        
        # Extract CN from server certificate
        cn = get_certificate_cn(self.server_cert)
        print(f"  Server certificate CN: {cn}")
        
        self.assertEqual(cn, "server.local",
                       "CN should be 'server.local'")
        
        # Extract CN from CA certificate
        ca_cn = get_certificate_cn(self.ca_cert)
        print(f"  CA certificate CN: {ca_cn}")
        
        self.assertEqual(ca_cn, "Test CA",
                       "CA CN should be 'Test CA'")
        
        print("  ✓ All CN extraction tests passed")

    def test_certificate_san_extraction(self):
        """Test Subject Alternative Name (SAN) extraction."""
        print("\n[TEST] Subject Alternative Name Extraction")
        
        # Extract SAN from server certificate
        san_list = get_certificate_san(self.server_cert)
        print(f"  Server certificate SAN: {san_list}")
        
        self.assertIn("server.local", san_list,
                     "SAN should contain 'server.local'")
        self.assertIn("*.server.local", san_list,
                     "SAN should contain '*.server.local'")
        
        # CA certificate might not have SAN
        ca_san = get_certificate_san(self.ca_cert)
        print(f"  CA certificate SAN: {ca_san}")
        # This is fine - CA might not have SAN
        
        print("  ✓ All SAN extraction tests passed")

    def test_hostname_validation(self):
        """Test hostname validation against CN and SAN."""
        print("\n[TEST] Hostname Validation")
        
        # Valid hostname (matches CN)
        is_valid = validate_certificate_hostname(self.server_cert, "server.local")
        print(f"  Hostname 'server.local' (CN match): {'✓ Valid' if is_valid else '✗ Invalid'}")
        self.assertTrue(is_valid,
                      "Hostname matching CN should be valid")
        
        # Valid hostname (matches SAN)
        is_valid = validate_certificate_hostname(self.server_cert, "server.local")
        print(f"  Hostname 'server.local' (SAN match): {'✓ Valid' if is_valid else '✗ Invalid'}")
        self.assertTrue(is_valid,
                      "Hostname matching SAN should be valid")
        
        # Invalid hostname (doesn't match) - should raise exception
        with self.assertRaises(CertificateValidationError,
                             msg="Wrong hostname should raise exception"):
            validate_certificate_hostname(self.server_cert, "wrong.hostname")
        print("  ✓ Wrong hostname correctly rejected (exception raised)")
        
        print("  ✓ All hostname validation tests passed")

    def test_comprehensive_certificate_validation(self):
        """Test comprehensive certificate validation."""
        print("\n[TEST] Comprehensive Certificate Validation")
        
        # Valid certificate
        try:
            result = validate_certificate(
                self.server_cert,
                self.ca_cert,
                expected_hostname="server.local"
            )
            print(f"  Valid certificate: {'✓ Valid' if result else '✗ Invalid'}")
            self.assertTrue(result,
                          "Valid certificate should pass validation")
        except CertificateValidationError as e:
            self.fail(f"Valid certificate should not raise error: {e}")
        
        # Invalid hostname
        with self.assertRaises(CertificateValidationError):
            validate_certificate(
                self.server_cert,
                self.ca_cert,
                expected_hostname="wrong.hostname"
            )
        print("  ✓ Invalid hostname correctly rejected")
        
        # Expired certificate
        with self.assertRaises(CertificateValidationError):
            validate_certificate(
                self.expired_cert,
                self.ca_cert,
                expected_hostname="server.local"
            )
        print("  ✓ Expired certificate correctly rejected")
        
        # Self-signed certificate
        with self.assertRaises(CertificateValidationError):
            validate_certificate(
                self.self_signed_cert,
                self.ca_cert,
                expected_hostname="server.local"
            )
        print("  ✓ Self-signed certificate correctly rejected")
        
        print("  ✓ All comprehensive validation tests passed")

    def test_certificate_fingerprint(self):
        """Test certificate fingerprint computation."""
        print("\n[TEST] Certificate Fingerprint")
        
        # Compute fingerprint
        fingerprint = get_certificate_fingerprint(self.server_cert)
        print(f"  Server certificate fingerprint: {fingerprint}")
        
        # Verify fingerprint is hex string
        self.assertEqual(len(fingerprint), 64,
                       "Fingerprint should be 64 hex characters (SHA-256)")
        
        # Verify it's hexadecimal
        self.assertTrue(all(c in '0123456789abcdef' for c in fingerprint),
                      "Fingerprint should be hexadecimal")
        
        # Verify deterministic (same cert = same fingerprint)
        fingerprint2 = get_certificate_fingerprint(self.server_cert)
        self.assertEqual(fingerprint, fingerprint2,
                        "Fingerprint should be deterministic")
        
        # Different certificates should have different fingerprints
        ca_fingerprint = get_certificate_fingerprint(self.ca_cert)
        self.assertNotEqual(fingerprint, ca_fingerprint,
                           "Different certificates should have different fingerprints")
        
        print("  ✓ All fingerprint tests passed")

    def test_public_key_extraction(self):
        """Test public key extraction from certificate."""
        print("\n[TEST] Public Key Extraction")
        
        # Extract public key
        public_key = get_public_key_from_certificate(self.server_cert)
        print("  ✓ Public key extracted from certificate")
        
        # Verify it's an RSA public key
        self.assertIsInstance(public_key, rsa.RSAPublicKey,
                            "Extracted key should be RSA public key")
        
        # Verify key size
        key_size = public_key.key_size
        print(f"  Public key size: {key_size} bits")
        self.assertEqual(key_size, 2048,
                       "Public key should be 2048 bits")
        
        print("  ✓ All public key extraction tests passed")


def run_tests():
    """Run all tests with verbose output."""
    print("=" * 70)
    print("Testing PKI Operations (app/crypto/pki.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestPKI)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("✓ All PKI tests PASSED")
    else:
        print("✗ Some tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()

