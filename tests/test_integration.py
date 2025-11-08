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
File: tests/test_integration.py
Purpose: Integration tests for end-to-end crypto operations
================================================================================

Description:
    This file contains integration tests that verify the crypto modules work
    together correctly. It tests:
    - Complete secure message flow (DH -> AES -> Sign)
    - End-to-end encryption and signing
    - Message integrity and authenticity
    - Session key derivation and usage

Test Cases:
    - Complete secure message exchange
    - Encryption + signing workflow
    - Decryption + verification workflow
    - Tampering detection in encrypted messages
    - Multiple message exchange

Links to Other Files:
    - app/crypto/dh.py: Diffie-Hellman key exchange
    - app/crypto/aes.py: AES encryption
    - app/crypto/sign.py: RSA signatures
    - app/common/utils.py: Utilities

Result:
    - Verifies all crypto modules work together
    - Ensures complete secure communication flow
    - Validates end-to-end security properties

================================================================================
"""

import unittest
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from app.crypto.dh import (
    generate_dh_parameters,
    generate_private_key,
    get_public_key,
    get_public_value,
    exchange_key,
    derive_session_key,
    create_public_key_from_value
)
from app.crypto.aes import encrypt_aes128, decrypt_aes128
from app.crypto.sign import sign_data, verify_signature, get_public_key_from_private


class TestIntegration(unittest.TestCase):
    """Integration tests for complete crypto workflow."""

    def setUp(self):
        """Set up test fixtures."""
        print("\n[SETUP] Setting up integration test environment...")
        
        # Generate DH parameters
        self.dh_params = generate_dh_parameters(generator=2, key_size=512)
        print("  ✓ DH parameters generated")
        
        # Generate RSA key pairs for client and server
        self.client_rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.client_rsa_public = get_public_key_from_private(self.client_rsa_private)
        
        self.server_rsa_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.server_rsa_public = get_public_key_from_private(self.server_rsa_private)
        
        print("  ✓ RSA key pairs generated")
        print("  ✓ Integration test environment ready")

    def test_complete_secure_message_flow(self):
        """Test complete secure message flow: DH -> AES -> Sign."""
        print("\n[TEST] Complete Secure Message Flow")
        
        # Step 1: Diffie-Hellman key exchange
        print("  Step 1: Diffie-Hellman key exchange...")
        client_dh_private = generate_private_key(self.dh_params)
        client_dh_public = get_public_key(client_dh_private)
        client_public_value = get_public_value(client_dh_public)
        print(f"    Client DH public value: {hex(client_public_value)[:50]}...")
        
        server_dh_private = generate_private_key(self.dh_params)
        server_dh_public = get_public_key(server_dh_private)
        server_public_value = get_public_value(server_dh_public)
        print(f"    Server DH public value: {hex(server_public_value)[:50]}...")
        
        # Exchange public values and compute shared secret
        server_public_received = create_public_key_from_value(
            server_public_value, self.dh_params
        )
        client_public_received = create_public_key_from_value(
            client_public_value, self.dh_params
        )
        
        client_shared_secret = exchange_key(client_dh_private, server_public_received)
        server_shared_secret = exchange_key(server_dh_private, client_public_received)
        
        self.assertEqual(client_shared_secret, server_shared_secret,
                       "Shared secrets should match")
        print("    ✓ Shared secret derived")
        
        # Step 2: Derive session keys
        print("  Step 2: Deriving session keys...")
        client_session_key = derive_session_key(client_shared_secret)
        server_session_key = derive_session_key(server_shared_secret)
        
        self.assertEqual(client_session_key, server_session_key,
                       "Session keys should match")
        self.assertEqual(len(client_session_key), 16,
                       "Session key should be 16 bytes")
        print(f"    Session key: {client_session_key.hex()}")
        print("    ✓ Session keys derived")
        
        # Step 3: Encrypt and sign message
        print("  Step 3: Encrypting and signing message...")
        message = b"Hello, this is a secure message!"
        print(f"    Original message: {message}")
        
        # Client encrypts message
        ciphertext = encrypt_aes128(message, client_session_key)
        print(f"    Ciphertext: {ciphertext[:50]}...")
        
        # Client signs ciphertext (ciphertext is already a string, convert to bytes)
        signature = sign_data(ciphertext.encode('utf-8'), self.client_rsa_private)
        print(f"    Signature: {signature[:50]}...")
        
        # Step 4: Server verifies and decrypts
        print("  Step 4: Verifying signature and decrypting...")
        
        # Server verifies signature (ciphertext is already a string, convert to bytes)
        is_valid = verify_signature(
            signature,
            ciphertext.encode('utf-8'),
            self.client_rsa_public
        )
        self.assertTrue(is_valid, "Signature should be valid")
        print("    ✓ Signature verified")
        
        # Server decrypts message
        decrypted = decrypt_aes128(ciphertext, server_session_key)
        print(f"    Decrypted message: {decrypted}")
        
        # Verify round-trip
        self.assertEqual(message, decrypted,
                       "Decrypted message should match original")
        print("    ✓ Message decrypted correctly")
        
        print("  ✓ Complete secure message flow test passed")

    def test_multiple_messages_exchange(self):
        """Test multiple messages in a session."""
        print("\n[TEST] Multiple Messages Exchange")
        
        # Setup session (same as above)
        client_dh_private = generate_private_key(self.dh_params)
        server_dh_private = generate_private_key(self.dh_params)
        
        client_dh_public = get_public_key(client_dh_private)
        server_dh_public = get_public_key(server_dh_private)
        
        client_shared_secret = exchange_key(client_dh_private, server_dh_public)
        server_shared_secret = exchange_key(server_dh_private, client_dh_public)
        
        session_key = derive_session_key(client_shared_secret)
        print(f"  Session key: {session_key.hex()}")
        
        # Exchange multiple messages
        messages = [
            b"Message 1: Hello!",
            b"Message 2: How are you?",
            b"Message 3: This is a longer message with more content.",
            b"Message 4: Final message.",
        ]
        
        print(f"  Exchanging {len(messages)} messages...")
        
        for i, message in enumerate(messages, 1):
            print(f"\n  Message {i}:")
            print(f"    Original: {message}")
            
            # Encrypt
            ciphertext = encrypt_aes128(message, session_key)
            print(f"    Ciphertext: {ciphertext[:50]}...")
            
            # Sign (ciphertext is already a string, convert to bytes)
            signature = sign_data(ciphertext.encode('utf-8'), self.client_rsa_private)
            
            # Verify (ciphertext is already a string, convert to bytes)
            is_valid = verify_signature(
                signature,
                ciphertext.encode('utf-8'),
                self.client_rsa_public
            )
            self.assertTrue(is_valid, f"Signature {i} should be valid")
            
            # Decrypt
            decrypted = decrypt_aes128(ciphertext, session_key)
            print(f"    Decrypted: {decrypted}")
            
            # Verify round-trip
            self.assertEqual(message, decrypted,
                          f"Message {i} round-trip failed")
        
        print("\n  ✓ All messages exchanged successfully")

    def test_tampering_detection_in_encrypted_message(self):
        """Test that tampering is detected in encrypted messages."""
        print("\n[TEST] Tampering Detection in Encrypted Messages")
        
        # Setup session
        client_dh_private = generate_private_key(self.dh_params)
        server_dh_private = generate_private_key(self.dh_params)
        
        client_dh_public = get_public_key(client_dh_private)
        server_dh_public = get_public_key(server_dh_private)
        
        client_shared_secret = exchange_key(client_dh_private, server_dh_public)
        session_key = derive_session_key(client_shared_secret)
        
        # Encrypt and sign message
        message = b"Original secure message"
        ciphertext = encrypt_aes128(message, session_key)
        signature = sign_data(ciphertext.encode('utf-8'), self.client_rsa_private)
        
        print(f"  Original message: {message}")
        print(f"  Original ciphertext: {ciphertext[:50]}...")
        print(f"  Original signature: {signature[:50]}...")
        
        # Tamper with ciphertext
        tampered_ciphertext = ciphertext[:-1] + "X"
        print(f"  Tampered ciphertext: {tampered_ciphertext[:50]}...")
        
        # Verify signature with tampered ciphertext (should fail)
        # Note: tampered_ciphertext is already a string, convert to bytes
        is_valid = verify_signature(
            signature,
            tampered_ciphertext.encode('utf-8'),
            self.client_rsa_public
        )
        print(f"  Signature verification: {'✓ Valid' if is_valid else '✗ Invalid (expected)'}")
        self.assertFalse(is_valid,
                        "Tampered ciphertext should not verify")
        
        # Try to decrypt tampered ciphertext (might succeed but produce garbage)
        try:
            decrypted = decrypt_aes128(tampered_ciphertext, session_key)
            self.assertNotEqual(message, decrypted,
                              "Tampered ciphertext should not decrypt to original")
            print(f"  Decryption result: {decrypted[:50]}... (garbage, expected)")
        except Exception as e:
            print(f"  Decryption failed (expected): {type(e).__name__}")
        
        print("  ✓ Tampering detection test passed")

    def test_bidirectional_communication(self):
        """Test bidirectional secure communication."""
        print("\n[TEST] Bidirectional Communication")
        
        # Setup session
        client_dh_private = generate_private_key(self.dh_params)
        server_dh_private = generate_private_key(self.dh_params)
        
        client_dh_public = get_public_key(client_dh_private)
        server_dh_public = get_public_key(server_dh_private)
        
        client_shared_secret = exchange_key(client_dh_private, server_dh_public)
        server_shared_secret = exchange_key(server_dh_private, client_dh_public)
        
        session_key = derive_session_key(client_shared_secret)
        
        # Client sends message to server
        client_message = b"Hello from client!"
        print(f"  Client message: {client_message}")
        
        client_ciphertext = encrypt_aes128(client_message, session_key)
        # Sign ciphertext (ciphertext is already a string, convert to bytes)
        client_signature = sign_data(client_ciphertext.encode('utf-8'), self.client_rsa_private)
        
        # Server receives and processes
        # Verify signature (ciphertext is already a string, convert to bytes)
        is_valid = verify_signature(client_signature, client_ciphertext.encode('utf-8'), self.client_rsa_public)
        self.assertTrue(is_valid, "Client signature should be valid")
        
        server_decrypted = decrypt_aes128(client_ciphertext, session_key)
        self.assertEqual(client_message, server_decrypted, "Server should decrypt client message")
        print("  ✓ Client -> Server communication successful")
        
        # Server sends response to client
        server_message = b"Hello from server!"
        print(f"  Server message: {server_message}")
        
        server_ciphertext = encrypt_aes128(server_message, session_key)
        # Sign ciphertext (ciphertext is already a string, convert to bytes)
        server_signature = sign_data(server_ciphertext.encode('utf-8'), self.server_rsa_private)
        
        # Client receives and processes
        # Verify signature (ciphertext is already a string, convert to bytes)
        is_valid = verify_signature(server_signature, server_ciphertext.encode('utf-8'), self.server_rsa_public)
        self.assertTrue(is_valid, "Server signature should be valid")
        
        client_decrypted = decrypt_aes128(server_ciphertext, session_key)
        self.assertEqual(server_message, client_decrypted, "Client should decrypt server message")
        print("  ✓ Server -> Client communication successful")
        
        print("  ✓ Bidirectional communication test passed")


def run_tests():
    """Run all integration tests with verbose output."""
    print("=" * 70)
    print("Integration Tests - Complete Crypto Workflow")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestIntegration)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("✓ All integration tests PASSED")
    else:
        print("✗ Some tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    run_tests()

