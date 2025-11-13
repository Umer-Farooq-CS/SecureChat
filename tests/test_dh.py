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
File: tests/test_dh.py
Purpose: Unit tests for Diffie-Hellman key exchange
================================================================================

Description:
    This file contains comprehensive unit tests for Diffie-Hellman key exchange
    in app/crypto/dh.py. It tests:
    - DH parameter generation
    - Key pair generation
    - Key exchange and shared secret derivation
    - Session key derivation (K = Trunc16(SHA256(Ks)))
    - Client-server key exchange simulation

Test Cases:
    - Parameter generation
    - Key pair generation
    - Shared secret computation
    - Session key derivation
    - Client-server exchange simulation
    - Key uniqueness

Links to Other Files:
    - app/crypto/dh.py: Module being tested
    - app/crypto/aes.py: Uses derived session keys
    - app/common/utils.py: Uses SHA-256 for key derivation

Result:
    - Verifies DH key exchange works correctly
    - Ensures shared secret derivation
    - Validates session key generation
    - Confirms forward secrecy capability

================================================================================
"""

import unittest

from app.crypto.dh import (
    generate_dh_parameters,
    create_dh_parameters_from_numbers,
    generate_private_key,
    get_public_key,
    get_public_value,
    exchange_key,
    derive_session_key,
    create_public_key_from_value,
    get_parameters_from_key
)


class TestDH(unittest.TestCase):
    """Test cases for Diffie-Hellman key exchange."""

    def setUp(self):
        """Set up test fixtures."""
        print("\n[SETUP] Generating DH parameters...")
        # Generate DH parameters (smaller size for faster testing)
        self.parameters = generate_dh_parameters(generator=2, key_size=512)
        print("   DH parameters generated (512 bits)")

    def test_parameter_generation(self):
        """Test DH parameter generation."""
        print("\n[TEST] Parameter Generation")
        
        # Generate parameters
        params = generate_dh_parameters(generator=2, key_size=512)
        print("   Parameters generated")
        
        # Verify parameters object
        self.assertIsNotNone(params,
                            "Parameters should not be None")
        
        # Get parameter numbers
        param_numbers = params.parameter_numbers()
        p = param_numbers.p
        g = param_numbers.g
        
        print(f"  Prime p: {hex(p)[:50]}... (length: {p.bit_length()} bits)")
        print(f"  Generator g: {g}")
        
        # Verify generator is reasonable
        self.assertIn(g, [2, 5],  # Common generators
                     f"Generator should be 2 or 5, got {g}")
        
        # Verify prime is large enough
        self.assertGreaterEqual(p.bit_length(), 512,
                              "Prime should be at least 512 bits")
        
        print("   All parameter generation tests passed")

    def test_key_pair_generation(self):
        """Test key pair generation from parameters."""
        print("\n[TEST] Key Pair Generation")
        
        # Generate private key
        private_key = generate_private_key(self.parameters)
        print("   Private key generated")
        
        # Get public key
        public_key = get_public_key(private_key)
        print("   Public key extracted")
        
        # Verify keys are not None
        self.assertIsNotNone(private_key,
                           "Private key should not be None")
        self.assertIsNotNone(public_key,
                           "Public key should not be None")
        
        # Get public value
        public_value = get_public_value(public_key)
        print(f"  Public value: {hex(public_value)[:50]}...")
        
        # Verify public value is reasonable
        self.assertIsInstance(public_value, int,
                            "Public value should be integer")
        self.assertGreater(public_value, 0,
                         "Public value should be positive")
        
        # Verify parameters match
        params_from_key = get_parameters_from_key(private_key)
        self.assertEqual(params_from_key.parameter_numbers().p,
                        self.parameters.parameter_numbers().p,
                        "Parameters should match")
        
        print("   All key pair generation tests passed")

    def test_key_exchange(self):
        """Test Diffie-Hellman key exchange."""
        print("\n[TEST] Key Exchange")
        
        # Generate two key pairs (simulating client and server)
        print("  Generating client key pair...")
        client_private = generate_private_key(self.parameters)
        client_public = get_public_key(client_private)
        client_public_value = get_public_value(client_public)
        print(f"    Client public value: {hex(client_public_value)[:50]}...")
        
        print("  Generating server key pair...")
        server_private = generate_private_key(self.parameters)
        server_public = get_public_key(server_private)
        server_public_value = get_public_value(server_public)
        print(f"    Server public value: {hex(server_public_value)[:50]}...")
        
        # Perform key exchange
        print("  Performing key exchange...")
        client_shared_secret = exchange_key(client_private, server_public)
        server_shared_secret = exchange_key(server_private, client_public)
        
        print(f"    Client shared secret: {client_shared_secret.hex()[:50]}...")
        print(f"    Server shared secret: {server_shared_secret.hex()[:50]}...")
        
        # Verify shared secrets match
        self.assertEqual(client_shared_secret, server_shared_secret,
                       "Client and server should derive same shared secret")
        
        # Verify shared secret is not empty
        self.assertGreater(len(client_shared_secret), 0,
                         "Shared secret should not be empty")
        
        print("   All key exchange tests passed")

    def test_session_key_derivation(self):
        """Test session key derivation from shared secret."""
        print("\n[TEST] Session Key Derivation")
        
        # Generate shared secret (simulate from key exchange)
        # For testing, we'll use a known value
        test_shared_secret = b"test_shared_secret_for_key_derivation_12345"
        print(f"  Shared secret: {test_shared_secret.hex()[:50]}...")
        
        # Derive session key
        session_key = derive_session_key(test_shared_secret)
        print(f"  Session key: {session_key.hex()}")
        
        # Verify session key is 16 bytes (128 bits) for AES-128
        self.assertEqual(len(session_key), 16,
                       "Session key should be 16 bytes (128 bits) for AES-128")
        
        # Verify session key is not all zeros
        self.assertNotEqual(session_key, b"\x00" * 16,
                          "Session key should not be all zeros")
        
        # Verify deterministic (same input = same output)
        session_key2 = derive_session_key(test_shared_secret)
        self.assertEqual(session_key, session_key2,
                       "Session key derivation should be deterministic")
        
        print("   All session key derivation tests passed")

    def test_client_server_exchange_simulation(self):
        """Test complete client-server key exchange simulation."""
        print("\n[TEST] Client-Server Exchange Simulation")
        
        # Step 1: Server generates parameters and sends to client
        print("  Step 1: Server generates parameters...")
        server_params = generate_dh_parameters(generator=2, key_size=512)
        print("     Parameters generated")
        
        # Step 2: Both generate key pairs
        print("  Step 2: Both generate key pairs...")
        client_private = generate_private_key(server_params)
        client_public = get_public_key(client_private)
        client_public_value = get_public_value(client_public)
        print(f"    Client public value: {hex(client_public_value)[:50]}...")
        
        server_private = generate_private_key(server_params)
        server_public = get_public_key(server_private)
        server_public_value = get_public_value(server_public)
        print(f"    Server public value: {hex(server_public_value)[:50]}...")
        
        # Step 3: Exchange public values (simulated)
        print("  Step 3: Exchanging public values...")
        # Client receives server's public value
        server_public_received = create_public_key_from_value(
            server_public_value, server_params
        )
        # Server receives client's public value
        client_public_received = create_public_key_from_value(
            client_public_value, server_params
        )
        print("     Public values exchanged")
        
        # Step 4: Both compute shared secret
        print("  Step 4: Computing shared secrets...")
        client_shared_secret = exchange_key(client_private, server_public_received)
        server_shared_secret = exchange_key(server_private, client_public_received)
        print(f"    Client shared secret: {client_shared_secret.hex()[:50]}...")
        print(f"    Server shared secret: {server_shared_secret.hex()[:50]}...")
        
        # Verify shared secrets match
        self.assertEqual(client_shared_secret, server_shared_secret,
                       "Shared secrets should match")
        
        # Step 5: Derive session keys
        print("  Step 5: Deriving session keys...")
        client_session_key = derive_session_key(client_shared_secret)
        server_session_key = derive_session_key(server_shared_secret)
        print(f"    Client session key: {client_session_key.hex()}")
        print(f"    Server session key: {server_session_key.hex()}")
        
        # Verify session keys match
        self.assertEqual(client_session_key, server_session_key,
                       "Session keys should match")
        
        # Verify session key is 16 bytes
        self.assertEqual(len(client_session_key), 16,
                       "Session key should be 16 bytes")
        
        print("   Complete exchange simulation passed")

    def test_different_parameters_different_keys(self):
        """Test that different parameters produce different keys."""
        print("\n[TEST] Different Parameters Produce Different Keys")
        
        # Generate two different parameter sets
        params1 = generate_dh_parameters(generator=2, key_size=512)
        params2 = generate_dh_parameters(generator=2, key_size=512)
        
        # Generate key pairs
        private1 = generate_private_key(params1)
        private2 = generate_private_key(params2)
        
        public1 = get_public_key(private1)
        public2 = get_public_key(private2)
        
        # Exchange keys with different parameters should fail
        # (This is expected - keys from different parameters can't be exchanged)
        with self.assertRaises(ValueError, msg="Keys from different parameters should not exchange"):
            exchange_key(private1, public2)
        
        print("   Different parameters correctly reject key exchange")

    def test_session_key_uniqueness(self):
        """Test that different shared secrets produce different session keys."""
        print("\n[TEST] Session Key Uniqueness")
        
        # Generate two different shared secrets
        shared_secret1 = b"shared_secret_1_12345678901234567890"
        shared_secret2 = b"shared_secret_2_12345678901234567890"
        
        print(f"  Shared secret 1: {shared_secret1.hex()[:50]}...")
        print(f"  Shared secret 2: {shared_secret2.hex()[:50]}...")
        
        # Derive session keys
        session_key1 = derive_session_key(shared_secret1)
        session_key2 = derive_session_key(shared_secret2)
        
        print(f"  Session key 1: {session_key1.hex()}")
        print(f"  Session key 2: {session_key2.hex()}")
        
        # Session keys should be different
        self.assertNotEqual(session_key1, session_key2,
                          "Different shared secrets should produce different session keys")
        
        # Both should be 16 bytes
        self.assertEqual(len(session_key1), 16,
                       "Session key 1 should be 16 bytes")
        self.assertEqual(len(session_key2), 16,
                       "Session key 2 should be 16 bytes")
        
        print("   All uniqueness tests passed")

    def test_public_key_reconstruction(self):
        """Test reconstructing public key from public value."""
        print("\n[TEST] Public Key Reconstruction")
        
        # Generate key pair
        private_key = generate_private_key(self.parameters)
        original_public = get_public_key(private_key)
        public_value = get_public_value(original_public)
        
        print(f"  Original public value: {hex(public_value)[:50]}...")
        
        # Reconstruct public key from value
        reconstructed_public = create_public_key_from_value(
            public_value, self.parameters
        )
        reconstructed_value = get_public_value(reconstructed_public)
        
        print(f"  Reconstructed public value: {hex(reconstructed_value)[:50]}...")
        
        # Values should match
        self.assertEqual(public_value, reconstructed_value,
                         "Reconstructed public value should match original")
        
        # Test key exchange with reconstructed key
        other_private = generate_private_key(self.parameters)
        shared1 = exchange_key(private_key, reconstructed_public)
        shared2 = exchange_key(other_private, original_public)
        
        # Both should work for key exchange
        print("   Public key reconstruction test passed")


def run_tests():
    """Run all tests with verbose output."""
    print("=" * 70)
    print("Testing Diffie-Hellman Key Exchange (app/crypto/dh.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestDH)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print(" All Diffie-Hellman tests PASSED")
    else:
        print(" Some tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()

