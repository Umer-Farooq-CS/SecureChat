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
File: app/storage/db.py
Purpose: MySQL database operations for user management
================================================================================

Description:
    This module handles all database operations for user registration and
    authentication. It provides:
    - Database connection management
    - User registration with salted password hashing
    - User authentication with password verification
    - Database schema initialization

Key Features:
    - Stores user credentials securely (salted SHA-256 hashes)
    - Per-user random salt (16 bytes minimum)
    - Password hash: hex(SHA256(salt || password))
    - Prevents duplicate usernames/emails
    - Constant-time password comparison

Database Schema:
    users(
        email VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL,
        created_at TIMESTAMP,
        last_login TIMESTAMP
    )

Links to Other Files:
    - app/server.py: Uses for user registration and login verification
    - app/common/utils.py: Uses SHA-256 hashing for password hashing
    - schema.sql: Database schema definition

Input:
    - User registration data (email, username, password)
    - User login credentials (email, password)
    - Database connection parameters (from .env)

Output:
    - Registration success/failure
    - Authentication success/failure
    - User data (for verification)

Result:
    - Securely stores user credentials in MySQL database
    - Enables user registration and authentication
    - Provides salted password hashing for security
    - Maintains user account information

================================================================================
"""

"""MySQL users table + salted hashing (no chat storage)."""

import argparse
import os
import secrets
from typing import Optional, Tuple

import pymysql

from app.common.utils import sha256_hex
from config import get_config


class DatabaseError(Exception):
    """Custom exception for database errors."""
    pass


class UserExistsError(DatabaseError):
    """Exception raised when user already exists."""
    pass


class AuthenticationError(DatabaseError):
    """Exception raised when authentication fails."""
    pass


def get_db_connection():
    """
    Creates and returns a MySQL database connection.
    
    Reads connection parameters from configuration file.
    Environment variables (DB_USER, DB_PASSWORD) can override config values
    for security purposes.
    
    Returns:
        pymysql.Connection: Database connection object
        
    Raises:
        DatabaseError: If connection fails or required credentials are missing
    """
    config = get_config()
    
    # Allow environment variable overrides for sensitive values
    host = os.getenv("DB_HOST", config.database.host)
    port = int(os.getenv("DB_PORT", str(config.database.port)))
    database = os.getenv("DB_NAME", config.database.name)
    user = os.getenv("DB_USER", config.database.user)
    password = os.getenv("DB_PASSWORD", config.database.password)
    
    if not user or not password:
        raise DatabaseError(
            "Database credentials are required. Set DB_USER and DB_PASSWORD "
            "environment variables or configure them in config/config.json"
        )
    
    try:
        connection = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        return connection
    except pymysql.Error as e:
        raise DatabaseError(f"Failed to connect to database: {e}")


def generate_salt() -> bytes:
    """
    Generates a random 16-byte salt for password hashing.
    
    Returns:
        bytes: 16-byte random salt
    """
    return secrets.token_bytes(16)


def hash_password(password: str, salt: bytes) -> str:
    """
    Computes salted password hash.
    
    Formula: hex(SHA256(salt || password))
    
    Args:
        password: Plaintext password
        salt: 16-byte salt
        
    Returns:
        str: Hexadecimal hash (64 characters)
    """
    password_bytes = password.encode('utf-8')
    combined = salt + password_bytes
    return sha256_hex(combined)


def register_user(email: str, username: str, password: str) -> bool:
    """
    Registers a new user with salted password hashing.
    
    Args:
        email: User email address (primary key)
        username: Username (must be unique)
        password: Plaintext password
        
    Returns:
        bool: True if registration successful
        
    Raises:
        UserExistsError: If email or username already exists
        DatabaseError: If database operation fails
    """
    connection = None
    try:
        connection = get_db_connection()
        
        # Check if user already exists
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT email, username FROM users WHERE email = %s OR username = %s",
                (email, username)
            )
            existing = cursor.fetchone()
            if existing:
                if existing['email'] == email:
                    raise UserExistsError(f"User with email '{email}' already exists")
                else:
                    raise UserExistsError(f"Username '{username}' is already taken")
        
        # Generate salt and hash password
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        # Insert user into database
        with connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO users (email, username, salt, pwd_hash)
                   VALUES (%s, %s, %s, %s)""",
                (email, username, salt, pwd_hash)
            )
            connection.commit()
        
        return True
        
    except UserExistsError:
        raise
    except pymysql.Error as e:
        if connection:
            connection.rollback()
        raise DatabaseError(f"Database error during registration: {e}")
    finally:
        if connection:
            connection.close()


def authenticate_user(email: str, password: str) -> Tuple[bool, Optional[dict]]:
    """
    Authenticates a user by verifying password hash.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Args:
        email: User email address
        password: Plaintext password
        
    Returns:
        tuple: (success: bool, user_data: dict or None)
        
    Raises:
        AuthenticationError: If authentication fails
        DatabaseError: If database operation fails
    """
    connection = None
    try:
        connection = get_db_connection()
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT email, username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            
            if not user:
                raise AuthenticationError("Invalid email or password")
            
            # Recompute hash with stored salt
            salt = user['salt']
            computed_hash = hash_password(password, salt)
            stored_hash = user['pwd_hash']
            
            # Constant-time comparison
            if not secrets.compare_digest(computed_hash, stored_hash):
                raise AuthenticationError("Invalid email or password")
            
            # Update last_login timestamp
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = %s",
                (email,)
            )
            connection.commit()
            
            return True, {
                'email': user['email'],
                'username': user['username']
            }
            
    except AuthenticationError:
        raise
    except pymysql.Error as e:
        if connection:
            connection.rollback()
        raise DatabaseError(f"Database error during authentication: {e}")
    finally:
        if connection:
            connection.close()


def get_user_by_email(email: str) -> Optional[dict]:
    """
    Retrieves user data by email.
    
    Args:
        email: User email address
        
    Returns:
        dict: User data or None if not found
        
    Raises:
        DatabaseError: If database operation fails
    """
    connection = None
    try:
        connection = get_db_connection()
        
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT email, username, salt, pwd_hash, created_at, last_login FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
            return user
            
    except pymysql.Error as e:
        raise DatabaseError(f"Database error: {e}")
    finally:
        if connection:
            connection.close()


def initialize_database():
    """
    Initializes the database schema by creating the users table.
    
    Reads schema from schema.sql or creates table directly.
    
    Raises:
        DatabaseError: If initialization fails
    """
    connection = None
    try:
        connection = get_db_connection()
        
        with connection.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) PRIMARY KEY COMMENT 'User email address (unique identifier)',
                    username VARCHAR(255) UNIQUE NOT NULL COMMENT 'Username (must be unique)',
                    salt VARBINARY(16) NOT NULL COMMENT '16-byte random salt for password hashing',
                    pwd_hash CHAR(64) NOT NULL COMMENT 'SHA-256 hash of salt||password (hex encoded, 64 chars)',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation timestamp',
                    last_login TIMESTAMP NULL DEFAULT NULL COMMENT 'Last successful login timestamp',
                    INDEX idx_username (username),
                    INDEX idx_email (email)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User credentials storage'
            """)
            connection.commit()
            print("[SUCCESS] Database initialized successfully!")
            print("  Table 'users' created/verified")
            
    except pymysql.Error as e:
        if connection:
            connection.rollback()
        raise DatabaseError(f"Failed to initialize database: {e}")
    finally:
        if connection:
            connection.close()


def main():
    """Main entry point for database operations."""
    parser = argparse.ArgumentParser(
        description="Database operations for SecureChat"
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialize database schema"
    )
    
    args = parser.parse_args()
    
    if args.init:
        try:
            initialize_database()
        except DatabaseError as e:
            print(f"[ERROR] {e}")
            raise
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
