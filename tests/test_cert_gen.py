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
File: tests/test_cert_gen.py
Purpose: Unit tests for certificate generation scripts
================================================================================

Description:
    This file contains comprehensive unit tests for certificate generation:
    - gen_ca.py: Root CA generation
    - gen_cert.py: Certificate issuance
    - Certificate validation
    - Certificate chain verification

================================================================================
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from app.crypto.pki import (
    get_certificate_cn,
    get_certificate_fingerprint,
    get_certificate_san,
    load_certificate_from_file,
    validate_certificate,
)
from scripts.gen_ca import generate_ca
from scripts.gen_cert import generate_certificate


class TestCertGen(unittest.TestCase):
    """Test certificate generation scripts."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for test certificates
        self.test_dir = tempfile.mkdtemp(prefix="securechat_test_")
        self.ca_key_path = Path(self.test_dir) / "ca-key.pem"
        self.ca_cert_path = Path(self.test_dir) / "ca-cert.pem"
        self.server_key_path = Path(self.test_dir) / "server-key.pem"
        self.server_cert_path = Path(self.test_dir) / "server-cert.pem"
        self.client_key_path = Path(self.test_dir) / "client-key.pem"
        self.client_cert_path = Path(self.test_dir) / "client-cert.pem"
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_ca_generation(self):
        """Test Root CA generation."""
        print("\n[TEST] Root CA Generation")
        
        # Generate CA
        ca_key_path, ca_cert_path = generate_ca(
            name="Test Root CA",
            validity_days=365,
            output_dir=self.test_dir
        )
        
        # Update instance variables for use in other tests
        self.ca_key_path = ca_key_path
        self.ca_cert_path = ca_cert_path
        
        # Verify files exist
        self.assertTrue(ca_key_path.exists(), "CA key file should exist")
        self.assertTrue(ca_cert_path.exists(), "CA cert file should exist")
        
        # Load and verify CA certificate
        ca_cert = load_certificate_from_file(ca_cert_path)
        self.assertIsNotNone(ca_cert, "CA certificate should load")
        
        # Verify CA properties
        cn = get_certificate_cn(ca_cert)
        self.assertEqual(cn, "Test Root CA", "CA CN should match")
        
        # Verify it's a CA certificate
        basic_constraints = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(basic_constraints.value.ca, "Should be a CA certificate")
        
        print("  CA generation works correctly")
    
    def test_certificate_issuance(self):
        """Test certificate issuance."""
        print("\n[TEST] Certificate Issuance")
        
        # First generate CA
        generate_ca(
            name="Test Root CA",
            validity_days=365,
            output_dir=self.test_dir
        )
        
        # Generate server certificate
        server_key_path, server_cert_path = generate_certificate(
            cn="server.local",
            output_prefix=str(Path(self.test_dir) / "server"),
            validity_days=365,
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path)
        )
        
        # Verify files exist
        self.assertTrue(server_key_path.exists(), "Server key file should exist")
        self.assertTrue(server_cert_path.exists(), "Server cert file should exist")
        
        # Load certificates
        ca_cert = load_certificate_from_file(self.ca_cert_path)
        server_cert = load_certificate_from_file(server_cert_path)
        
        # Verify certificate chain
        try:
            validate_certificate(server_cert, ca_cert, expected_hostname="server.local")
            chain_valid = True
        except Exception:
            chain_valid = False
        
        self.assertTrue(chain_valid, "Certificate should be signed by CA")
        
        # Verify CN
        cn = get_certificate_cn(server_cert)
        self.assertEqual(cn, "server.local", "CN should match")
        
        # Verify SAN
        san_list = get_certificate_san(server_cert)
        self.assertIn("server.local", san_list, "SAN should contain CN")
        
        # Verify it's not a CA certificate
        basic_constraints = server_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertFalse(basic_constraints.value.ca, "Should not be a CA certificate")
        
        print("  Certificate issuance works correctly")
    
    def test_client_certificate_issuance(self):
        """Test client certificate issuance."""
        print("\n[TEST] Client Certificate Issuance")
        
        # Generate CA
        generate_ca(
            name="Test Root CA",
            validity_days=365,
            output_dir=self.test_dir
        )
        
        # Generate client certificate
        client_key_path, client_cert_path = generate_certificate(
            cn="client.local",
            output_prefix=str(Path(self.test_dir) / "client"),
            validity_days=365,
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path)
        )
        
        # Verify files exist
        self.assertTrue(client_key_path.exists())
        self.assertTrue(client_cert_path.exists())
        
        # Load and verify
        ca_cert = load_certificate_from_file(self.ca_cert_path)
        client_cert = load_certificate_from_file(client_cert_path)
        
        # Verify chain
        validate_certificate(client_cert, ca_cert, expected_hostname="client.local")
        
        # Verify CN
        cn = get_certificate_cn(client_cert)
        self.assertEqual(cn, "client.local")
        
        print("  Client certificate issuance works correctly")
    
    def test_certificate_validation(self):
        """Test certificate validation."""
        print("\n[TEST] Certificate Validation")
        
        # Generate CA and server cert
        generate_ca(name="Test Root CA", validity_days=365, output_dir=self.test_dir)
        generate_certificate(
            cn="server.local",
            output_prefix=str(Path(self.test_dir) / "server"),
            ca_cert_path=str(self.ca_cert_path),
            ca_key_path=str(self.ca_key_path)
        )
        
        # Load certificates
        ca_cert = load_certificate_from_file(self.ca_cert_path)
        server_cert = load_certificate_from_file(self.server_cert_path)
        
        # Test valid certificate
        try:
            validate_certificate(server_cert, ca_cert, expected_hostname="server.local")
            valid = True
        except Exception:
            valid = False
        self.assertTrue(valid, "Valid certificate should pass validation")
        
        # Test wrong hostname
        with self.assertRaises(Exception):
            validate_certificate(server_cert, ca_cert, expected_hostname="wrong.hostname")
        
        print("  Certificate validation works correctly")
    
    def test_certificate_fingerprint(self):
        """Test certificate fingerprint computation."""
        print("\n[TEST] Certificate Fingerprint")
        
        # Generate CA
        generate_ca(name="Test Root CA", validity_days=365, output_dir=self.test_dir)
        ca_cert = load_certificate_from_file(self.ca_cert_path)
        
        # Compute fingerprint
        fingerprint = get_certificate_fingerprint(ca_cert)
        
        # Verify fingerprint format (64 hex chars for SHA-256)
        self.assertEqual(len(fingerprint), 64, "Fingerprint should be 64 hex characters")
        self.assertTrue(all(c in '0123456789abcdef' for c in fingerprint.lower()),
                       "Fingerprint should be hexadecimal")
        
        # Verify consistency
        fingerprint2 = get_certificate_fingerprint(ca_cert)
        self.assertEqual(fingerprint, fingerprint2, "Fingerprint should be consistent")
        
        print("  Certificate fingerprint works correctly")
    
    def test_private_key_format(self):
        """Test that private keys are in correct format."""
        print("\n[TEST] Private Key Format")
        
        # Generate CA
        generate_ca(name="Test Root CA", validity_days=365, output_dir=self.test_dir)
        
        # Load private key
        with open(self.ca_key_path, "rb") as f:
            key_data = f.read()
        
        # Verify it's PEM format
        self.assertIn(b"BEGIN PRIVATE KEY", key_data, "Should be PEM format")
        
        # Verify it can be loaded
        private_key = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )
        self.assertIsNotNone(private_key, "Private key should load")
        
        print("  Private key format is correct")


def run_tests():
    """Run all certificate generation tests."""
    print("=" * 70)
    print("Testing Certificate Generation (scripts/gen_ca.py, gen_cert.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestCertGen)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("All certificate generation tests PASSED")
    else:
        print("Some certificate generation tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    unittest.main()

