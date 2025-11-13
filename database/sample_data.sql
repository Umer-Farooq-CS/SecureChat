-- ================================================================================
-- Assignment #2 - Secure Chat System
-- Information Security (CS-3002)
-- FAST-NUCES, Fall 2025
-- ================================================================================
--
-- File: database/sample_data.sql
-- Purpose: Insert sample test users
--
-- WARNING: These are test users with example data.
-- DO NOT USE THESE IN PRODUCTION!
--
-- Usage:
--   mysql -u scuser -p securechat < database/sample_data.sql
--
-- ================================================================================

USE securechat;

-- Clear existing test data (optional)
-- DELETE FROM users WHERE email LIKE '%@example.com';

-- Sample User 1: alice@example.com
-- Password: "testpass123"
-- Salt: 0123456789ABCDEF0123456789ABCDEF (16 bytes)
-- Hash: Generated using Python: sha256_hex(salt + password.encode())
-- 
-- To generate proper hash:
--   import secrets
--   from app.common.utils import sha256_hex
--   salt = bytes.fromhex('0123456789ABCDEF0123456789ABCDEF')
--   pwd_hash = sha256_hex(salt + b'testpass123')
--
-- Note: The hash below is an example. Generate a real one for testing.

INSERT INTO users (email, username, salt, pwd_hash) VALUES
('alice@example.com', 'alice', 
 UNHEX('0123456789ABCDEF0123456789ABCDEF'),
 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456')
ON DUPLICATE KEY UPDATE 
    username = VALUES(username),
    salt = VALUES(salt),
    pwd_hash = VALUES(pwd_hash);

-- Sample User 2: bob@example.com
-- Password: "testpass123"
-- Salt: FEDCBA9876543210FEDCBA9876543210 (16 bytes)

INSERT INTO users (email, username, salt, pwd_hash) VALUES
('bob@example.com', 'bob',
 UNHEX('FEDCBA9876543210FEDCBA9876543210'),
 'f6e5d4c3b2a198765432109876543210fedcba9876543210fedcba9876543210')
ON DUPLICATE KEY UPDATE 
    username = VALUES(username),
    salt = VALUES(salt),
    pwd_hash = VALUES(pwd_hash);

-- Verify inserted data
SELECT 
    email, 
    username, 
    HEX(salt) as salt_hex, 
    SUBSTRING(pwd_hash, 1, 16) as pwd_hash_prefix,
    created_at 
FROM users 
WHERE email LIKE '%@example.com';

-- Count total users
SELECT COUNT(*) as total_users FROM users;

