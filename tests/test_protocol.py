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
File: tests/test_protocol.py
Purpose: Unit tests for protocol message models
================================================================================

Description:
    This file contains comprehensive unit tests for the protocol message models
    in app/common/protocol.py. It tests:
    - All message type models (HelloMessage, ServerHelloMessage, etc.)
    - Message serialization and deserialization
    - Message validation
    - parse_message and serialize_message functions

================================================================================
"""

import json
import unittest

from app.common.protocol import (
    ChatMessage,
    DHClientMessage,
    DHServerMessage,
    HelloMessage,
    LoginMessage,
    RegisterMessage,
    ServerHelloMessage,
    SessionReceipt,
    parse_message,
    serialize_message,
)
from app.common.utils import b64e


class TestProtocol(unittest.TestCase):
    """Test protocol message models."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_cert = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
        self.test_nonce = b64e(b"test_nonce_12345")
        self.test_salt = b64e(b"test_salt_12345")
        self.test_ciphertext = b64e(b"encrypted_data")
        self.test_signature = b64e(b"signature_data")
    
    def test_hello_message(self):
        """Test HelloMessage model."""
        print("\n[TEST] HelloMessage")
        
        msg = HelloMessage(
            client_cert=self.test_cert,
            nonce=self.test_nonce
        )
        
        self.assertEqual(msg.type, "hello")
        self.assertEqual(msg.client_cert, self.test_cert)
        self.assertEqual(msg.nonce, self.test_nonce)
        
        # Test serialization
        data = msg.model_dump()
        self.assertEqual(data["type"], "hello")
        self.assertEqual(data["client_cert"], self.test_cert)
        
        print("  HelloMessage model works correctly")
    
    def test_server_hello_message(self):
        """Test ServerHelloMessage model."""
        print("\n[TEST] ServerHelloMessage")
        
        msg = ServerHelloMessage(
            server_cert=self.test_cert,
            nonce=self.test_nonce
        )
        
        self.assertEqual(msg.type, "server_hello")
        self.assertEqual(msg.server_cert, self.test_cert)
        self.assertEqual(msg.nonce, self.test_nonce)
        
        print("  ServerHelloMessage model works correctly")
    
    def test_register_message(self):
        """Test RegisterMessage model."""
        print("\n[TEST] RegisterMessage")
        
        msg = RegisterMessage(
            email="test@example.com",
            username="testuser",
            pwd=self.test_ciphertext,
            salt=self.test_salt
        )
        
        self.assertEqual(msg.type, "register")
        self.assertEqual(msg.email, "test@example.com")
        self.assertEqual(msg.username, "testuser")
        self.assertEqual(msg.pwd, self.test_ciphertext)
        self.assertEqual(msg.salt, self.test_salt)
        
        print("  RegisterMessage model works correctly")
    
    def test_login_message(self):
        """Test LoginMessage model."""
        print("\n[TEST] LoginMessage")
        
        msg = LoginMessage(
            email="test@example.com",
            pwd=self.test_ciphertext,
            nonce=self.test_nonce
        )
        
        self.assertEqual(msg.type, "login")
        self.assertEqual(msg.email, "test@example.com")
        self.assertEqual(msg.pwd, self.test_ciphertext)
        self.assertEqual(msg.nonce, self.test_nonce)
        
        print("  LoginMessage model works correctly")
    
    def test_dh_client_message(self):
        """Test DHClientMessage model."""
        print("\n[TEST] DHClientMessage")
        
        msg = DHClientMessage(
            g=2,
            p=12345678901234567890,
            A=98765432109876543210
        )
        
        self.assertEqual(msg.type, "dh_client")
        self.assertEqual(msg.g, 2)
        self.assertEqual(msg.p, 12345678901234567890)
        self.assertEqual(msg.A, 98765432109876543210)
        
        print("  DHClientMessage model works correctly")
    
    def test_dh_server_message(self):
        """Test DHServerMessage model."""
        print("\n[TEST] DHServerMessage")
        
        msg = DHServerMessage(B=11223344556677889900)
        
        self.assertEqual(msg.type, "dh_server")
        self.assertEqual(msg.B, 11223344556677889900)
        
        print("  DHServerMessage model works correctly")
    
    def test_chat_message(self):
        """Test ChatMessage model."""
        print("\n[TEST] ChatMessage")
        
        msg = ChatMessage(
            seqno=1,
            ts=1699123456789,
            ct=self.test_ciphertext,
            sig=self.test_signature
        )
        
        self.assertEqual(msg.type, "msg")
        self.assertEqual(msg.seqno, 1)
        self.assertEqual(msg.ts, 1699123456789)
        self.assertEqual(msg.ct, self.test_ciphertext)
        self.assertEqual(msg.sig, self.test_signature)
        
        # Test validation (seqno >= 1)
        with self.assertRaises(Exception):
            ChatMessage(seqno=0, ts=1699123456789, ct=self.test_ciphertext, sig=self.test_signature)
        
        print("  ChatMessage model works correctly")
    
    def test_session_receipt(self):
        """Test SessionReceipt model."""
        print("\n[TEST] SessionReceipt")
        
        # Create a proper 64-character hex string (SHA-256 hash)
        test_hash = "a" * 64  # 64 hex characters
        
        msg = SessionReceipt(
            peer="client",
            first_seq=1,
            last_seq=10,
            transcript_sha256=test_hash,
            sig=self.test_signature
        )
        
        self.assertEqual(msg.type, "receipt")
        self.assertEqual(msg.peer, "client")
        self.assertEqual(msg.first_seq, 1)
        self.assertEqual(msg.last_seq, 10)
        self.assertEqual(len(msg.transcript_sha256), 64)
        self.assertEqual(msg.sig, self.test_signature)
        
        # Test validation
        with self.assertRaises(Exception):
            SessionReceipt(peer="invalid", first_seq=1, last_seq=10,
                          transcript_sha256="abc" * 20, sig=self.test_signature)
        
        print("  SessionReceipt model works correctly")
    
    def test_parse_message(self):
        """Test parse_message function."""
        print("\n[TEST] parse_message function")
        
        # Test parsing HelloMessage
        hello_data = {
            "type": "hello",
            "client_cert": self.test_cert,
            "nonce": self.test_nonce
        }
        msg = parse_message(hello_data)
        self.assertIsInstance(msg, HelloMessage)
        
        # Test parsing from JSON string
        json_str = json.dumps(hello_data)
        msg2 = parse_message(json_str)
        self.assertIsInstance(msg2, HelloMessage)
        
        # Test invalid message type
        with self.assertRaises(ValueError):
            parse_message({"type": "invalid_type"})
        
        # Test missing type
        with self.assertRaises(ValueError):
            parse_message({"data": "test"})
        
        print("  parse_message function works correctly")
    
    def test_serialize_message(self):
        """Test serialize_message function."""
        print("\n[TEST] serialize_message function")
        
        msg = HelloMessage(
            client_cert=self.test_cert,
            nonce=self.test_nonce
        )
        
        json_str = serialize_message(msg)
        self.assertIsInstance(json_str, str)
        
        # Verify it's valid JSON
        data = json.loads(json_str)
        self.assertEqual(data["type"], "hello")
        self.assertEqual(data["client_cert"], self.test_cert)
        
        print("  serialize_message function works correctly")
    
    def test_round_trip_serialization(self):
        """Test round-trip serialization/deserialization."""
        print("\n[TEST] Round-trip serialization")
        
        # Test all message types
        messages = [
            HelloMessage(client_cert=self.test_cert, nonce=self.test_nonce),
            ServerHelloMessage(server_cert=self.test_cert, nonce=self.test_nonce),
            RegisterMessage(email="test@example.com", username="user",
                          pwd=self.test_ciphertext, salt=self.test_salt),
            LoginMessage(email="test@example.com", pwd=self.test_ciphertext,
                        nonce=self.test_nonce),
            DHClientMessage(g=2, p=12345, A=67890),
            DHServerMessage(B=11111),
            ChatMessage(seqno=1, ts=1234567890, ct=self.test_ciphertext,
                       sig=self.test_signature),
            SessionReceipt(peer="client", first_seq=1, last_seq=10,
                          transcript_sha256="a" * 64, sig=self.test_signature)
        ]
        
        for original_msg in messages:
            # Serialize
            json_str = serialize_message(original_msg)
            
            # Deserialize
            parsed_msg = parse_message(json_str)
            
            # Verify type matches
            self.assertEqual(type(parsed_msg), type(original_msg))
            self.assertEqual(parsed_msg.type, original_msg.type)
        
        print("  All message types round-trip correctly")


def run_tests():
    """Run all protocol tests."""
    print("=" * 70)
    print("Testing Protocol Message Models (app/common/protocol.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestProtocol)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("All protocol tests PASSED")
    else:
        print("Some protocol tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    unittest.main()

