-- ================================================================================
-- Assignment #2 - Secure Chat System
-- Information Security (CS-3002)
-- FAST-NUCES, Fall 2025
-- ================================================================================
--
-- File: database/create_user.sql
-- Purpose: Create database user for SecureChat
--
-- Usage:
--   mysql -u root -p < database/create_user.sql
--
-- ================================================================================

-- Create database user
-- Note: Change password in production!
CREATE USER IF NOT EXISTS 'scuser'@'localhost' IDENTIFIED BY 'scpass';

-- Grant all privileges on securechat database
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify user creation
SELECT user, host, authentication_string IS NOT NULL as has_password 
FROM mysql.user 
WHERE user = 'scuser';

-- Show grants
SHOW GRANTS FOR 'scuser'@'localhost';

