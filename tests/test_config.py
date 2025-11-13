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
File: tests/test_config.py
Purpose: Unit tests for configuration system
================================================================================

Description:
    This file contains unit tests for the configuration system in config/.
    It tests:
    - Configuration loading
    - Configuration structure
    - Environment variable overrides
    - Default values

================================================================================
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from config import get_config, load_config
from config.config_loader import reload_config


class TestConfig(unittest.TestCase):
    """Test configuration system."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Save original environment
        self.original_env = {}
        for key in ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]:
            if key in os.environ:
                self.original_env[key] = os.environ[key]
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Restore original environment
        for key, value in self.original_env.items():
            os.environ[key] = value
        for key in ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"]:
            if key not in self.original_env:
                os.environ.pop(key, None)
    
    def test_config_loading(self):
        """Test configuration loading."""
        print("\n[TEST] Configuration Loading")
        
        config = get_config()
        
        # Verify config object exists
        self.assertIsNotNone(config, "Config should be loaded")
        
        # Verify structure
        self.assertTrue(hasattr(config, "server"))
        self.assertTrue(hasattr(config, "client"))
        self.assertTrue(hasattr(config, "ca"))
        self.assertTrue(hasattr(config, "database"))
        self.assertTrue(hasattr(config, "paths"))
        self.assertTrue(hasattr(config, "crypto"))
        
        print("  Configuration loading works")
    
    def test_server_config(self):
        """Test server configuration."""
        print("\n[TEST] Server Configuration")
        
        config = get_config()
        
        # Verify server config structure
        self.assertTrue(hasattr(config.server, "host"))
        self.assertTrue(hasattr(config.server, "port"))
        self.assertTrue(hasattr(config.server, "cert_path"))
        self.assertTrue(hasattr(config.server, "key_path"))
        
        # Verify types
        self.assertIsInstance(config.server.host, str)
        self.assertIsInstance(config.server.port, int)
        self.assertGreater(config.server.port, 0)
        self.assertLess(config.server.port, 65536)
        
        print("  Server configuration works")
    
    def test_database_config(self):
        """Test database configuration."""
        print("\n[TEST] Database Configuration")
        
        config = get_config()
        
        # Verify database config structure
        self.assertTrue(hasattr(config.database, "host"))
        self.assertTrue(hasattr(config.database, "port"))
        self.assertTrue(hasattr(config.database, "name"))
        self.assertTrue(hasattr(config.database, "user"))
        self.assertTrue(hasattr(config.database, "password"))
        
        # Verify types
        self.assertIsInstance(config.database.host, str)
        self.assertIsInstance(config.database.port, int)
        self.assertGreater(config.database.port, 0)
        
        print("  Database configuration works")
    
    def test_environment_variable_override(self):
        """Test environment variable overrides."""
        print("\n[TEST] Environment Variable Override")
        
        # Set environment variables
        os.environ["DB_HOST"] = "test_host"
        os.environ["DB_PORT"] = "9999"
        os.environ["DB_NAME"] = "test_db"
        os.environ["DB_USER"] = "test_user"
        os.environ["DB_PASSWORD"] = "test_password"
        
        # Reload config to pick up environment variables
        reload_config()
        config = get_config()
        
        # Verify overrides
        self.assertEqual(config.database.host, "test_host")
        self.assertEqual(config.database.port, 9999)
        self.assertEqual(config.database.name, "test_db")
        self.assertEqual(config.database.user, "test_user")
        self.assertEqual(config.database.password, "test_password")
        
        print("  Environment variable override works")
    
    def test_crypto_config(self):
        """Test crypto configuration."""
        print("\n[TEST] Crypto Configuration")
        
        config = get_config()
        
        # Verify crypto config
        self.assertTrue(hasattr(config.crypto, "dh_key_size"))
        self.assertTrue(hasattr(config.crypto, "dh_generator"))
        self.assertTrue(hasattr(config.crypto, "aes_key_size"))
        
        # Verify values
        self.assertGreaterEqual(config.crypto.dh_key_size, 512)
        self.assertIn(config.crypto.dh_generator, [2, 5])
        self.assertEqual(config.crypto.aes_key_size, 16)
        
        print("  Crypto configuration works")
    
    def test_paths_config(self):
        """Test paths configuration."""
        print("\n[TEST] Paths Configuration")
        
        config = get_config()
        
        # Verify paths config
        self.assertTrue(hasattr(config.paths, "certs_dir"))
        self.assertTrue(hasattr(config.paths, "transcripts_dir"))
        
        # Verify they are strings
        self.assertIsInstance(config.paths.certs_dir, str)
        self.assertIsInstance(config.paths.transcripts_dir, str)
        
        print("  Paths configuration works")


def run_tests():
    """Run all config tests."""
    print("=" * 70)
    print("Testing Configuration System (config/)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestConfig)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("All config tests PASSED")
    else:
        print("Some config tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    unittest.main()

