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
File: tests/test_db.py
Purpose: Unit tests for database operations
================================================================================

Description:
    This file contains comprehensive unit tests for database operations in
    app/storage/db.py. It tests:
    - Database connection
    - User registration
    - User authentication
    - Salted password hashing
    - Duplicate user prevention
    - Error handling

Note: Requires MySQL database to be running. Tests use a test database.

================================================================================
"""

import os
import unittest

from app.storage.db import (
    AuthenticationError,
    DatabaseError,
    UserExistsError,
    authenticate_user,
    generate_salt,
    get_db_connection,
    get_user_by_email,
    hash_password,
    initialize_database,
    register_user,
)


class TestDatabase(unittest.TestCase):
    """Test database operations."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database."""
        # Use test database
        os.environ["DB_NAME"] = "securechat_test"
        os.environ["DB_USER"] = os.getenv("DB_USER", "scuser")
        os.environ["DB_PASSWORD"] = os.getenv("DB_PASSWORD", "scpass")
        
        # Initialize test database
        try:
            initialize_database()
            print("\n[SETUP] Test database initialized")
        except Exception as e:
            print(f"\n[WARNING] Could not initialize test database: {e}")
            print("  Database tests will be skipped")
            cls.skip_all = True
        else:
            cls.skip_all = False
    
    def setUp(self):
        """Set up test fixtures."""
        if self.skip_all:
            self.skipTest("Database not available")
        
        # Clean up test users
        try:
            conn = get_db_connection()
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM users WHERE email LIKE 'test%@example.com'")
                conn.commit()
            conn.close()
        except Exception:
            pass
    
    def test_database_connection(self):
        """Test database connection."""
        print("\n[TEST] Database Connection")
        
        conn = get_db_connection()
        self.assertIsNotNone(conn, "Connection should be established")
        conn.close()
        
        print("  Database connection works")
    
    def test_salt_generation(self):
        """Test salt generation."""
        print("\n[TEST] Salt Generation")
        
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        # Verify salt is 16 bytes
        self.assertEqual(len(salt1), 16, "Salt should be 16 bytes")
        self.assertEqual(len(salt2), 16, "Salt should be 16 bytes")
        
        # Verify salts are different (very high probability)
        self.assertNotEqual(salt1, salt2, "Salts should be unique")
        
        print("  Salt generation works correctly")
    
    def test_password_hashing(self):
        """Test password hashing."""
        print("\n[TEST] Password Hashing")
        
        password = "test_password_123"
        salt = generate_salt()
        
        # Hash password
        pwd_hash = hash_password(password, salt)
        
        # Verify hash format (64 hex chars for SHA-256)
        self.assertEqual(len(pwd_hash), 64, "Hash should be 64 hex characters")
        self.assertTrue(all(c in '0123456789abcdef' for c in pwd_hash.lower()),
                       "Hash should be hexadecimal")
        
        # Verify consistency
        pwd_hash2 = hash_password(password, salt)
        self.assertEqual(pwd_hash, pwd_hash2, "Hash should be deterministic")
        
        # Verify different passwords produce different hashes
        pwd_hash3 = hash_password("different_password", salt)
        self.assertNotEqual(pwd_hash, pwd_hash3, "Different passwords should produce different hashes")
        
        print("  Password hashing works correctly")
    
    def test_user_registration(self):
        """Test user registration."""
        print("\n[TEST] User Registration")
        
        email = "test_register@example.com"
        username = "testuser_register"
        password = "test_password_123"
        
        # Register user
        result = register_user(email, username, password)
        self.assertTrue(result, "Registration should succeed")
        
        # Verify user exists
        user = get_user_by_email(email)
        self.assertIsNotNone(user, "User should exist in database")
        self.assertEqual(user["email"], email)
        self.assertEqual(user["username"], username)
        self.assertIsNotNone(user["salt"], "Salt should be stored")
        self.assertIsNotNone(user["pwd_hash"], "Password hash should be stored")
        
        # Verify password is not stored in plaintext
        self.assertNotIn(password, str(user), "Password should not be in plaintext")
        
        print("  User registration works correctly")
    
    def test_duplicate_email_registration(self):
        """Test duplicate email registration prevention."""
        print("\n[TEST] Duplicate Email Prevention")
        
        email = "test_duplicate@example.com"
        username = "testuser1"
        password = "password123"
        
        # Register first time
        register_user(email, username, password)
        
        # Try to register again with same email
        with self.assertRaises(UserExistsError):
            register_user(email, "different_username", "different_password")
        
        print("  Duplicate email prevention works")
    
    def test_duplicate_username_registration(self):
        """Test duplicate username registration prevention."""
        print("\n[TEST] Duplicate Username Prevention")
        
        email1 = "test1@example.com"
        email2 = "test2@example.com"
        username = "duplicate_username"
        password = "password123"
        
        # Register first time
        register_user(email1, username, password)
        
        # Try to register again with same username
        with self.assertRaises(UserExistsError):
            register_user(email2, username, "different_password")
        
        print("  Duplicate username prevention works")
    
    def test_user_authentication(self):
        """Test user authentication."""
        print("\n[TEST] User Authentication")
        
        email = "test_auth@example.com"
        username = "testuser_auth"
        password = "correct_password"
        
        # Register user
        register_user(email, username, password)
        
        # Authenticate with correct password
        success, user_data = authenticate_user(email, password)
        self.assertTrue(success, "Authentication should succeed with correct password")
        self.assertIsNotNone(user_data, "User data should be returned")
        self.assertEqual(user_data["email"], email)
        self.assertEqual(user_data["username"], username)
        
        # Authenticate with wrong password
        with self.assertRaises(AuthenticationError):
            authenticate_user(email, "wrong_password")
        
        # Authenticate with non-existent user
        with self.assertRaises(AuthenticationError):
            authenticate_user("nonexistent@example.com", "any_password")
        
        print("  User authentication works correctly")
    
    def test_password_hash_verification(self):
        """Test that password hash verification works correctly."""
        print("\n[TEST] Password Hash Verification")
        
        email = "test_hash@example.com"
        username = "testuser_hash"
        password = "my_secret_password"
        
        # Register user
        register_user(email, username, password)
        
        # Get stored hash
        user = get_user_by_email(email)
        stored_hash = user["pwd_hash"]
        stored_salt = user["salt"]
        
        # Recompute hash with same salt
        computed_hash = hash_password(password, stored_salt)
        
        # Hashes should match
        self.assertEqual(stored_hash, computed_hash, "Stored and computed hashes should match")
        
        # Wrong password should produce different hash
        wrong_hash = hash_password("wrong_password", stored_salt)
        self.assertNotEqual(stored_hash, wrong_hash, "Wrong password should produce different hash")
        
        print("  Password hash verification works correctly")
    
    def test_get_user_by_email(self):
        """Test retrieving user by email."""
        print("\n[TEST] Get User by Email")
        
        email = "test_get@example.com"
        username = "testuser_get"
        password = "password123"
        
        # Register user
        register_user(email, username, password)
        
        # Get user
        user = get_user_by_email(email)
        self.assertIsNotNone(user, "User should be found")
        self.assertEqual(user["email"], email)
        self.assertEqual(user["username"], username)
        
        # Get non-existent user
        user2 = get_user_by_email("nonexistent@example.com")
        self.assertIsNone(user2, "Non-existent user should return None")
        
        print("  Get user by email works correctly")


def run_tests():
    """Run all database tests."""
    print("=" * 70)
    print("Testing Database Operations (app/storage/db.py)")
    print("=" * 70)
    print("\nNote: Requires MySQL database to be running")
    print("Set DB_USER and DB_PASSWORD environment variables if needed")
    print()
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestDatabase)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("All database tests PASSED")
    else:
        print("Some database tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    unittest.main()

