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
File: tests/test_utils.py
Purpose: Unit tests for utility functions (base64, hashing, timestamps)
================================================================================

Description:
    This file contains comprehensive unit tests for the utility functions in
    app/common/utils.py. It tests:
    - Base64 encoding and decoding
    - SHA-256 hashing
    - Timestamp generation
    - Round-trip encoding/decoding

Test Cases:
    - Base64 encoding/decoding with various inputs
    - SHA-256 hash computation and consistency
    - Timestamp generation and monotonicity
    - Edge cases (empty strings, special characters)

Links to Other Files:
    - app/common/utils.py: Module being tested
    - All crypto modules: Use these utilities

Result:
    - Verifies utility functions work correctly
    - Ensures consistent encoding/decoding
    - Validates hash computation accuracy
    - Confirms timestamp generation works

================================================================================
"""

import unittest
import time
import hashlib
import base64

from app.common.utils import now_ms, b64e, b64d, sha256_hex


class TestUtils(unittest.TestCase):
    """Test cases for utility functions."""

    def test_base64_encode_decode(self):
        """Test base64 encoding and decoding round-trip."""
        print("\n[TEST] Base64 Encoding/Decoding")
        
        test_cases = [
            b"Hello, World!",
            b"SecureChat",
            b"",
            b"1234567890",
            b"Special chars: !@#$%^&*()",
            b"Unicode: \xe2\x9c\x93",  # Checkmark symbol
        ]
        
        for original in test_cases:
            with self.subTest(original=original):
                # Encode
                encoded = b64e(original)
                print(f"  Original: {original}")
                print(f"  Encoded:  {encoded}")
                
                # Decode
                decoded = b64d(encoded)
                print(f"  Decoded:  {decoded}")
                
                # Verify round-trip
                self.assertEqual(original, decoded, 
                               f"Round-trip failed for: {original}")
        
        print("  ✓ All base64 tests passed")

    def test_base64_known_values(self):
        """Test base64 encoding with known values."""
        print("\n[TEST] Base64 Known Values")
        
        # Known test vectors
        test_vectors = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ]
        
        for original, expected_encoded in test_vectors:
            with self.subTest(original=original):
                encoded = b64e(original)
                decoded = b64d(encoded)
                
                self.assertEqual(encoded, expected_encoded,
                               f"Encoding mismatch for: {original}")
                self.assertEqual(decoded, original,
                               f"Decoding mismatch for: {original}")
                print(f"  ✓ {original} -> {encoded}")
        
        print("  ✓ All known value tests passed")

    def test_sha256_hash(self):
        """Test SHA-256 hash computation."""
        print("\n[TEST] SHA-256 Hashing")
        
        test_cases = [
            (b"Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"),
            (b"SecureChat", None),  # We'll compute and verify consistency (no hardcoded value)
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"test message", None),  # We'll compute and verify consistency
        ]
        
        for data, expected_hash in test_cases:
            with self.subTest(data=data):
                computed_hash = sha256_hex(data)
                print(f"  Data: {data}")
                print(f"  Hash: {computed_hash}")
                
                # Verify length (SHA-256 produces 64 hex characters)
                self.assertEqual(len(computed_hash), 64,
                               "Hash length should be 64 hex characters")
                
                # Verify it's hexadecimal
                self.assertTrue(all(c in '0123456789abcdef' for c in computed_hash),
                              "Hash should be hexadecimal")
                
                # If expected hash provided, verify it matches
                if expected_hash:
                    self.assertEqual(computed_hash, expected_hash,
                                   f"Hash mismatch for: {data}")
                
                # Verify consistency (same input = same output)
                hash2 = sha256_hex(data)
                self.assertEqual(computed_hash, hash2,
                               "Hash should be deterministic")
        
        print("  ✓ All SHA-256 tests passed")

    def test_sha256_known_vectors(self):
        """Test SHA-256 with known test vectors."""
        print("\n[TEST] SHA-256 Known Test Vectors")
        
        # Known SHA-256 test vectors
        known_vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"),
        ]
        
        for data, expected_hash in known_vectors:
            with self.subTest(data=data):
                computed_hash = sha256_hex(data)
                self.assertEqual(computed_hash, expected_hash,
                               f"Hash mismatch for: {data}")
                print(f"  ✓ {data} -> {computed_hash[:16]}...")
        
        print("  ✓ All known vector tests passed")

    def test_timestamp_generation(self):
        """Test timestamp generation."""
        print("\n[TEST] Timestamp Generation")
        
        # Get current timestamp
        ts1 = now_ms()
        print(f"  Timestamp 1: {ts1}")
        
        # Wait a bit
        time.sleep(0.1)
        
        # Get another timestamp
        ts2 = now_ms()
        print(f"  Timestamp 2: {ts2}")
        
        # Verify timestamps are integers
        self.assertIsInstance(ts1, int, "Timestamp should be integer")
        self.assertIsInstance(ts2, int, "Timestamp should be integer")
        
        # Verify timestamps are in milliseconds (should be large numbers)
        self.assertGreater(ts1, 1000000000000,  # Year 2001 in ms
                          "Timestamp should be in milliseconds")
        
        # Verify monotonicity (ts2 should be >= ts1)
        self.assertGreaterEqual(ts2, ts1,
                               "Timestamps should be monotonic")
        
        # Verify difference is approximately 100ms (with some tolerance)
        diff = ts2 - ts1
        print(f"  Difference: {diff} ms")
        self.assertGreaterEqual(diff, 90,  # At least 90ms
                              "Timestamp difference should reflect sleep time")
        self.assertLessEqual(diff, 200,  # At most 200ms (with tolerance)
                           "Timestamp difference should not be too large")
        
        print("  ✓ All timestamp tests passed")

    def test_timestamp_format(self):
        """Test timestamp format and range."""
        print("\n[TEST] Timestamp Format")
        
        ts = now_ms()
        print(f"  Current timestamp: {ts}")
        
        # Convert to seconds to verify it's reasonable
        ts_seconds = ts / 1000
        current_year = time.localtime().tm_year
        
        # Timestamp should represent a date around current year
        ts_year = time.localtime(ts_seconds).tm_year
        print(f"  Timestamp year: {ts_year}")
        
        # Should be within reasonable range (2000-2100)
        self.assertGreaterEqual(ts_year, 2000,
                               "Timestamp year should be >= 2000")
        self.assertLessEqual(ts_year, 2100,
                           "Timestamp year should be <= 2100")
        
        # Should be close to current year
        self.assertAlmostEqual(ts_year, current_year, delta=1,
                               msg="Timestamp should represent current time")
        
        print("  ✓ All format tests passed")

    def test_integration_encoding_hashing(self):
        """Test integration of encoding and hashing."""
        print("\n[TEST] Integration: Encoding + Hashing")
        
        message = b"SecureChat message for encryption"
        print(f"  Original message: {message}")
        
        # Encode message
        encoded = b64e(message)
        print(f"  Base64 encoded: {encoded}")
        
        # Hash original message
        hash_original = sha256_hex(message)
        print(f"  Hash of original: {hash_original[:32]}...")
        
        # Decode and verify
        decoded = b64d(encoded)
        hash_decoded = sha256_hex(decoded)
        print(f"  Hash of decoded: {hash_decoded[:32]}...")
        
        # Verify round-trip
        self.assertEqual(message, decoded,
                       "Round-trip encoding/decoding failed")
        
        # Verify hash consistency
        self.assertEqual(hash_original, hash_decoded,
                       "Hash should be same for original and decoded")
        
        print("  ✓ Integration test passed")


def run_tests():
    """Run all tests with verbose output."""
    print("=" * 70)
    print("Testing Utility Functions (app/common/utils.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestUtils)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("✓ All utility function tests PASSED")
    else:
        print("✗ Some tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()

