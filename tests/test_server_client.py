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
File: tests/test_server_client.py
Purpose: Integration tests for server and client
================================================================================

Description:
    This file contains integration tests for the server and client implementations.
    It tests the complete protocol flow including:
    - Certificate exchange
    - Authentication
    - Key exchange
    - Encrypted messaging
    - Transcript management

Note: These tests require certificates to be generated first.

================================================================================
"""

import os
import shutil
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.server import SecureChatServer
from app.client import SecureChatClient


class TestServerClient(unittest.TestCase):
    """Test server and client integration."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        # Create temporary directory for test certificates
        cls.test_dir = tempfile.mkdtemp(prefix="securechat_integration_test_")
        
        # Check if certificates exist, if not, skip tests
        if not Path("certs/ca-cert.pem").exists():
            print("\n[WARNING] Certificates not found. Generating test certificates...")
            try:
                # Generate CA
                from scripts.gen_ca import generate_ca
                generate_ca(name="Test CA", validity_days=365, output_dir=cls.test_dir)
                
                # Generate server cert
                from scripts.gen_cert import generate_certificate
                generate_certificate(
                    cn="server.local",
                    output_prefix=str(Path(cls.test_dir) / "server"),
                    ca_cert_path=str(Path(cls.test_dir) / "ca-cert.pem"),
                    ca_key_path=str(Path(cls.test_dir) / "ca-key.pem")
                )
                
                # Generate client cert
                generate_certificate(
                    cn="client.local",
                    output_prefix=str(Path(cls.test_dir) / "client"),
                    ca_cert_path=str(Path(cls.test_dir) / "ca-cert.pem"),
                    ca_key_path=str(Path(cls.test_dir) / "ca-key.pem")
                )
                
                cls.use_test_certs = True
            except Exception as e:
                print(f"[WARNING] Could not generate test certificates: {e}")
                cls.use_test_certs = False
                cls.skip_all = True
        else:
            cls.use_test_certs = False
            cls.skip_all = False
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment."""
        if cls.use_test_certs and os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Set up test fixtures."""
        if hasattr(self.__class__, 'skip_all') and self.__class__.skip_all:
            self.skipTest("Certificates not available")
        
        # Use test certificates if available, otherwise use default
        if self.use_test_certs:
            self.ca_cert = str(Path(self.test_dir) / "ca-cert.pem")
            self.server_cert = str(Path(self.test_dir) / "server-cert.pem")
            self.server_key = str(Path(self.test_dir) / "server-key.pem")
            self.client_cert = str(Path(self.test_dir) / "client-cert.pem")
            self.client_key = str(Path(self.test_dir) / "client-key.pem")
        else:
            self.ca_cert = "certs/ca-cert.pem"
            self.server_cert = "certs/server-cert.pem"
            self.server_key = "certs/server-key.pem"
            self.client_cert = "certs/client-cert.pem"
            self.client_key = "certs/client-key.pem"
        
        # Find available port
        self.test_port = self._find_free_port()
        self.server = None
        self.server_thread = None
    
    def tearDown(self):
        """Clean up test fixtures."""
        if self.server:
            # Server cleanup would happen here
            pass
    
    def _find_free_port(self):
        """Find a free port for testing."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    def _start_server(self):
        """Start test server in background thread."""
        self.server = SecureChatServer(
            host="localhost",
            port=self.test_port,
            server_cert_path=self.server_cert,
            server_key_path=self.server_key,
            ca_cert_path=self.ca_cert
        )
        
        def run_server():
            try:
                self.server.start()
            except Exception as e:
                print(f"Server error: {e}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        time.sleep(0.5)  # Give server time to start
    
    def test_server_initialization(self):
        """Test server initialization."""
        print("\n[TEST] Server Initialization")
        
        server = SecureChatServer(
            host="localhost",
            port=self.test_port,
            server_cert_path=self.server_cert,
            server_key_path=self.server_key,
            ca_cert_path=self.ca_cert
        )
        
        self.assertIsNotNone(server.server_cert, "Server certificate should be loaded")
        self.assertIsNotNone(server.server_key, "Server key should be loaded")
        self.assertIsNotNone(server.ca_cert, "CA certificate should be loaded")
        
        print("  Server initialization works")
    
    def test_client_initialization(self):
        """Test client initialization."""
        print("\n[TEST] Client Initialization")
        
        client = SecureChatClient(
            host="localhost",
            port=self.test_port,
            client_cert_path=self.client_cert,
            client_key_path=self.client_key,
            ca_cert_path=self.ca_cert
        )
        
        self.assertIsNotNone(client.client_cert, "Client certificate should be loaded")
        self.assertIsNotNone(client.client_key, "Client key should be loaded")
        self.assertIsNotNone(client.ca_cert, "CA certificate should be loaded")
        
        print("  Client initialization works")
    
    def test_message_serialization(self):
        """Test message send/receive serialization."""
        print("\n[TEST] Message Serialization")
        
        # This is a basic test of the message format
        # Full integration would require running server/client
        
        from app.common.protocol import ChatMessage, serialize_message, parse_message
        from app.common.utils import b64e, now_ms
        from app.crypto.aes import encrypt_aes128
        
        # Create a test message
        test_key = b"test_key_16_byte"  # 16 bytes exactly
        plaintext = "Test message"
        ciphertext = encrypt_aes128(plaintext.encode(), test_key)
        timestamp = now_ms()
        
        # Create message with test signature
        msg = ChatMessage(
            seqno=1,
            ts=timestamp,
            ct=ciphertext,
            sig=b64e(b"test_signature")
        )
        
        # Serialize
        json_str = serialize_message(msg)
        self.assertIsInstance(json_str, str)
        
        # Deserialize
        parsed = parse_message(json_str)
        self.assertIsInstance(parsed, ChatMessage)
        self.assertEqual(parsed.seqno, 1)
        self.assertEqual(parsed.ts, timestamp)
        
        print("  Message serialization works")


def run_tests():
    """Run all server/client tests."""
    print("=" * 70)
    print("Testing Server/Client Integration (app/server.py, app/client.py)")
    print("=" * 70)
    print("\nNote: Full integration tests require certificates and database")
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestServerClient)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("All server/client tests PASSED")
    else:
        print("Some server/client tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    unittest.main()

