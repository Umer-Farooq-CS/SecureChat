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
raise NotImplementedError("students: implement DB layer")
