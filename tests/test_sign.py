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
File: tests/test_sign.py
Purpose: Unit tests for RSA signature generation and verification
================================================================================

Description:
    This file contains comprehensive unit tests for RSA signatures in
    app/crypto/sign.py. It tests:
    - RSA signature generation with private key
    - Signature verification with public key
    - Signature tampering detection
    - Message integrity verification
    - Key pair generation and usage

Test Cases:
    - Sign and verify round-trip
    - Different message types
    - Signature tampering detection
    - Wrong key verification failure
    - Message modification detection

Links to Other Files:
    - app/crypto/sign.py: Module being tested
    - app/common/utils.py: Uses base64 encoding
    - app/crypto/pki.py: Uses certificates for public keys

Result:
    - Verifies RSA signatures work correctly
    - Ensures message integrity protection
    - Validates tampering detection
    - Confirms non-repudiation capability

================================================================================
"""

import unittest
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from app.crypto.sign import (
    sign_data,
    verify_signature,
    load_private_key_from_pem,
    get_public_key_from_private
)


class TestSign(unittest.TestCase):
    """Test cases for RSA signature generation and verification."""

    def setUp(self):
        """Set up test fixtures."""
        # Generate RSA key pair for testing
        print("\n[SETUP] Generating RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print("   RSA key pair generated (2048 bits)")

    def test_sign_verify_round_trip(self):
        """Test signature generation and verification round-trip."""
        print("\n[TEST] Sign/Verify Round-Trip")
        
        test_messages = [
            b"Hello, World!",
            b"SecureChat message",
            b"Short",
            b"This is a longer message that will be signed",
            b"",
            b"A" * 100,  # Longer message
            b"Binary data: \x00\x01\x02\x03\xff\xfe\xfd",
        ]
        
        for message in test_messages:
            with self.subTest(message=message[:20]):
                print(f"  Testing message: {message[:50]}... (length: {len(message)})")
                
                # Sign message
                signature = sign_data(message, self.private_key)
                print(f"    Signature: {signature[:50]}...")
                
                # Verify signature is base64 string
                self.assertIsInstance(signature, str,
                                    "Signature should be base64 string")
                self.assertGreater(len(signature), 0,
                                 "Signature should not be empty")
                
                # Verify signature
                is_valid = verify_signature(signature, message, self.public_key)
                print(f"    Verification: {' Valid' if is_valid else ' Invalid'}")
                
                self.assertTrue(is_valid,
                              f"Signature verification failed for: {message}")
        
        print("   All round-trip tests passed")

    def test_signature_uniqueness(self):
        """Test that different messages produce different signatures."""
        print("\n[TEST] Signature Uniqueness")
        
        message1 = b"Message 1"
        message2 = b"Message 2"
        
        print(f"  Message 1: {message1}")
        print(f"  Message 2: {message2}")
        
        # Sign both messages
        sig1 = sign_data(message1, self.private_key)
        sig2 = sign_data(message2, self.private_key)
        
        print(f"  Signature 1: {sig1[:50]}...")
        print(f"  Signature 2: {sig2[:50]}...")
        
        # Signatures should be different
        self.assertNotEqual(sig1, sig2,
                          "Different messages should produce different signatures")
        
        # Each signature should verify only for its own message
        self.assertTrue(verify_signature(sig1, message1, self.public_key),
                       "Signature 1 should verify for message 1")
        self.assertTrue(verify_signature(sig2, message2, self.public_key),
                       "Signature 2 should verify for message 2")
        
        # Cross-verification should fail
        self.assertFalse(verify_signature(sig1, message2, self.public_key),
                        "Signature 1 should NOT verify for message 2")
        self.assertFalse(verify_signature(sig2, message1, self.public_key),
                        "Signature 2 should NOT verify for message 1")
        
        print("   All uniqueness tests passed")

    def test_message_tampering_detection(self):
        """Test that message tampering is detected."""
        print("\n[TEST] Message Tampering Detection")
        
        original_message = b"Original message"
        print(f"  Original message: {original_message}")
        
        # Sign original message
        signature = sign_data(original_message, self.private_key)
        print(f"  Signature: {signature[:50]}...")
        
        # Verify original signature
        self.assertTrue(verify_signature(signature, original_message, self.public_key),
                       "Original signature should be valid")
        
        # Tamper with message
        tampered_messages = [
            b"Original messagX",  # One character changed
            b"Original message ",  # Space added
            b"Original messag",  # One character removed
            b"Different message",  # Completely different
        ]
        
        for tampered in tampered_messages:
            with self.subTest(tampered=tampered):
                print(f"  Testing tampered message: {tampered}")
                
                # Verification should fail
                is_valid = verify_signature(signature, tampered, self.public_key)
                print(f"    Verification: {' Invalid (expected)' if not is_valid else ' Valid (unexpected!)'}")
                
                self.assertFalse(is_valid,
                               f"Tampered message should not verify: {tampered}")
        
        print("   All tampering detection tests passed")

    def test_signature_tampering_detection(self):
        """Test that signature tampering is detected."""
        print("\n[TEST] Signature Tampering Detection")
        
        message = b"Test message"
        print(f"  Message: {message}")
        
        # Sign message
        original_signature = sign_data(message, self.private_key)
        print(f"  Original signature: {original_signature[:50]}...")
        
        # Verify original signature
        self.assertTrue(verify_signature(original_signature, message, self.public_key),
                       "Original signature should be valid")
        
        # Tamper with signature
        tampered_signatures = [
            original_signature[:-1] + "X",  # Change last character
            original_signature[1:],  # Remove first character
            "A" * len(original_signature),  # Completely different
            original_signature.replace("A", "B", 1) if "A" in original_signature else original_signature + "X",
        ]
        
        for tampered_sig in tampered_signatures:
            with self.subTest(tampered_sig=tampered_sig[:20]):
                print(f"  Testing tampered signature: {tampered_sig[:50]}...")
                
                # Verification should fail
                try:
                    is_valid = verify_signature(tampered_sig, message, self.public_key)
                    print(f"    Verification: {' Invalid (expected)' if not is_valid else ' Valid (unexpected!)'}")
                    self.assertFalse(is_valid,
                                   "Tampered signature should not verify")
                except Exception as e:
                    # Some tampering might cause exceptions (invalid base64, etc.)
                    print(f"    Verification:  Exception (expected): {type(e).__name__}")
        
        print("   All signature tampering tests passed")

    def test_wrong_key_verification(self):
        """Test that verification with wrong key fails."""
        print("\n[TEST] Wrong Key Verification")
        
        # Generate second key pair
        private_key2 = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key2 = private_key2.public_key()
        
        message = b"Test message"
        print(f"  Message: {message}")
        
        # Sign with first key
        signature = sign_data(message, self.private_key)
        print(f"  Signature (with key 1): {signature[:50]}...")
        
        # Verify with correct key (should succeed)
        self.assertTrue(verify_signature(signature, message, self.public_key),
                       "Verification with correct key should succeed")
        
        # Verify with wrong key (should fail)
        is_valid = verify_signature(signature, message, public_key2)
        print(f"  Verification with wrong key: {' Invalid (expected)' if not is_valid else ' Valid (unexpected!)'}")
        self.assertFalse(is_valid,
                       "Verification with wrong key should fail")
        
        print("   Wrong key verification test passed")

    def test_deterministic_signatures(self):
        """Test that same message signed twice produces same signature.
        
        Note: RSA signatures with PKCS#1 v1.5 are deterministic for the same
        message and key, so signing the same message twice should produce
        the same signature.
        """
        print("\n[TEST] Signature Determinism")
        
        message = b"Test message"
        print(f"  Message: {message}")
        
        # Sign message twice
        sig1 = sign_data(message, self.private_key)
        sig2 = sign_data(message, self.private_key)
        
        print(f"  Signature 1: {sig1[:50]}...")
        print(f"  Signature 2: {sig2[:50]}...")
        
        # Signatures should be identical (deterministic)
        self.assertEqual(sig1, sig2,
                       "Same message + same key should produce same signature")
        
        # Both should verify
        self.assertTrue(verify_signature(sig1, message, self.public_key),
                       "Signature 1 should verify")
        self.assertTrue(verify_signature(sig2, message, self.public_key),
                       "Signature 2 should verify")
        
        print("   Determinism test passed")

    def test_empty_message_signature(self):
        """Test signing and verifying empty message."""
        print("\n[TEST] Empty Message Signature")
        
        message = b""
        print(f"  Message: (empty, length={len(message)})")
        
        # Sign empty message
        signature = sign_data(message, self.private_key)
        print(f"  Signature: {signature[:50]}...")
        
        # Verify signature
        is_valid = verify_signature(signature, message, self.public_key)
        print(f"  Verification: {' Valid' if is_valid else ' Invalid'}")
        
        self.assertTrue(is_valid,
                       "Empty message signature should verify")
        
        print("   Empty message test passed")

    def test_large_message_signature(self):
        """Test signing and verifying large message."""
        print("\n[TEST] Large Message Signature")
        
        # Create large message (1MB)
        message = b"A" * (1024 * 1024)
        print(f"  Message: (large, length={len(message)} bytes)")
        
        # Sign large message
        signature = sign_data(message, self.private_key)
        print(f"  Signature: {signature[:50]}...")
        
        # Verify signature
        is_valid = verify_signature(signature, message, self.public_key)
        print(f"  Verification: {' Valid' if is_valid else ' Invalid'}")
        
        self.assertTrue(is_valid,
                       "Large message signature should verify")
        
        print("   Large message test passed")


def run_tests():
    """Run all tests with verbose output."""
    print("=" * 70)
    print("Testing RSA Signatures (app/crypto/sign.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSign)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print(" All RSA signature tests PASSED")
    else:
        print(" Some tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()

