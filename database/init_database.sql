-- ================================================================================
-- Assignment #2 - Secure Chat System
-- Information Security (CS-3002)
-- FAST-NUCES, Fall 2025
-- ================================================================================
--
-- File: database/init_database.sql
-- Purpose: Initialize database and create schema
--
-- Usage:
--   mysql -u scuser -p < database/init_database.sql
--   OR
--   mysql -u root -p < database/init_database.sql
--
-- ================================================================================

-- Create database (if not exists)
CREATE DATABASE IF NOT EXISTS securechat 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

-- Use the database
USE securechat;

-- Drop existing table if you want to start fresh (uncomment if needed)
-- DROP TABLE IF EXISTS users;

-- Create users table
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

-- Verify table creation
SHOW TABLES;

-- Show table structure
DESCRIBE users;

-- Show indexes
SHOW INDEXES FROM users;

-- Show table status
SHOW TABLE STATUS LIKE 'users';

