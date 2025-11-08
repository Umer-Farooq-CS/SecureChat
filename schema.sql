-- ================================================================================
-- Assignment #2 - Secure Chat System
-- Information Security (CS-3002)
-- FAST-NUCES, Fall 2025
-- ================================================================================
--
-- Student Information:
--     Name: Umer Farooq
--     Roll No: 22I-0891
--     Section: CS-7D
--     Instructor: Urooj Ghani
--
-- ================================================================================
-- File: schema.sql
-- Purpose: MySQL database schema definition
-- ================================================================================
--
-- Description:
--     This file contains the MySQL database schema for the SecureChat system.
--     It defines the users table structure for storing user credentials with
--     salted password hashes.
--
-- Links to Other Files:
--     - app/storage/db.py: Uses this schema for database operations
--     - SETUP.md: Referenced in setup instructions
--     - README.md: Referenced in documentation
--
-- Usage:
--     Run this script to initialize the database:
--       mysql -u root -p securechat < schema.sql
--     
--     Or use the Python initialization:
--       python -m app.storage.db --init
--
-- Result:
--     - Creates users table in MySQL database
--     - Enables user registration and authentication
--     - Provides secure storage for user credentials
--
-- ================================================================================

-- SecureChat Database Schema
-- MySQL 8.0+

-- Create database (if not exists)
CREATE DATABASE IF NOT EXISTS securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE securechat;

-- Users table
-- Stores user credentials with salted password hashes
-- Note: Chat messages are NOT stored in the database (only in transcripts)
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) PRIMARY KEY COMMENT 'User email address (unique identifier)',
    username VARCHAR(255) UNIQUE NOT NULL COMMENT 'Username (must be unique)',
    salt VARBINARY(16) NOT NULL COMMENT '16-byte random salt for password hashing',
    pwd_hash CHAR(64) NOT NULL COMMENT 'SHA-256 hash of salt||password (hex encoded, 64 chars)',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Account creation timestamp',
    last_login TIMESTAMP NULL DEFAULT NULL COMMENT 'Last successful login timestamp',
    INDEX idx_username (username),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='User credentials storage';

-- Sample records (for testing)
-- Password: "password123" with salt
-- Note: These are example records. In production, use proper random salts.
-- 
-- To generate a proper salt and hash:
--   salt = os.urandom(16)
--   pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
--
-- Example (DO NOT USE IN PRODUCTION):
-- INSERT INTO users (email, username, salt, pwd_hash) VALUES
-- ('alice@example.com', 'alice', UNHEX('0123456789ABCDEF0123456789ABCDEF'), 
--  'a1b2c3d4e5f6...'); -- Replace with actual hash
--
-- INSERT INTO users (email, username, salt, pwd_hash) VALUES
-- ('bob@example.com', 'bob', UNHEX('FEDCBA9876543210FEDCBA9876543210'), 
--  'f6e5d4c3b2a1...'); -- Replace with actual hash

-- Verification query
-- SELECT email, username, HEX(salt) as salt_hex, pwd_hash, created_at 
-- FROM users;

