# Database Setup Guide

**Assignment #2 - Secure Chat System**  
**Information Security (CS-3002)**  
**FAST-NUCES, Fall 2025**

This guide provides detailed step-by-step instructions for setting up the MySQL database for the SecureChat system.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Database Setup](#database-setup)
4. [Configuration](#configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

- **MySQL Server 8.0+** (or MariaDB 10.3+)
- **Python 3.8+** with `PyMySQL` package
- **MySQL Client** (for command-line access)

### System Requirements

- Linux, macOS, or Windows
- At least 100MB free disk space
- Network access (if using remote database)

---

## Installation

### Step 1: Install MySQL Server

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
```

#### macOS (using Homebrew)
```bash
brew install mysql
brew services start mysql
```

#### Windows
1. Download MySQL Installer from: https://dev.mysql.com/downloads/installer/
2. Run the installer
3. Select "Server only" or "Full" installation
4. Follow the installation wizard
5. Note the root password you set

### Step 2: Verify MySQL Installation

```bash
mysql --version
# Should show: mysql Ver 8.0.x or similar
```

### Step 3: Secure MySQL Installation (Recommended)

```bash
sudo mysql_secure_installation
```

Follow the prompts:
- Set root password (if not already set)
- Remove anonymous users: **Yes**
- Disallow root login remotely: **Yes** (unless needed)
- Remove test database: **Yes**
- Reload privilege tables: **Yes**

---

## Database Setup

### Step 1: Create Database User

**Option A: Using MySQL Command Line (Recommended)**

```bash
# Login as root
sudo mysql -u root -p
```

Then run:
```sql
-- Create database user
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';

-- Grant privileges
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';

-- Apply changes
FLUSH PRIVILEGES;

-- Verify user creation
SELECT user, host FROM mysql.user WHERE user = 'scuser';

-- Exit
EXIT;
```

**Option B: Using SQL Script**

```bash
mysql -u root -p < database/create_user.sql
```

### Step 2: Create Database and Schema

**Option A: Using SQL Script (Recommended)**

```bash
# From SecureChat directory
mysql -u scuser -p < schema.sql
```

**Option B: Using Python Script**

```bash
# Set environment variables
export DB_USER=scuser
export DB_PASSWORD=scpass

# Initialize database
python -m app.storage.db --init
```

**Option C: Manual SQL Execution**

```bash
mysql -u scuser -p
```

Then run:
```sql
-- Create database
CREATE DATABASE IF NOT EXISTS securechat 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

-- Use database
USE securechat;

-- Create users table (see schema.sql for full SQL)
SOURCE schema.sql;
```

### Step 3: Verify Database Creation

```bash
mysql -u scuser -p -e "SHOW DATABASES;"
mysql -u scuser -p -e "USE securechat; SHOW TABLES;"
mysql -u scuser -p -e "USE securechat; DESCRIBE users;"
```

---

## Configuration

### Step 1: Update Configuration File

Edit `config/config.json`:

```json
{
  "database": {
    "host": "localhost",
    "port": 3306,
    "name": "securechat",
    "user": "scuser",
    "password": "scpass"
  }
}
```

### Step 2: Set Environment Variables (Optional, More Secure)

Create a `.env` file in the SecureChat directory:

```bash
# .env file
DB_HOST=localhost
DB_PORT=3306
DB_NAME=securechat
DB_USER=scuser
DB_PASSWORD=scpass
```

**Note:** Environment variables override config.json values.

### Step 3: Test Database Connection

```bash
# Test connection using Python
python -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('Connection successful!'); conn.close()"
```

---

## Verification

### Step 1: Run Database Tests

```bash
# Run database tests
python -m unittest tests.test_db -v
```

### Step 2: Manual Verification

```bash
mysql -u scuser -p securechat
```

```sql
-- Check table structure
DESCRIBE users;

-- Check indexes
SHOW INDEXES FROM users;

-- Verify empty table (should return 0 rows)
SELECT COUNT(*) FROM users;

-- Exit
EXIT;
```

### Step 3: Test Registration

```bash
# Start server
python app/server.py

# In another terminal, start client and try to register
python app/client.py
```

---

## Sample Data (Optional)

### Add Test Users

```bash
mysql -u scuser -p securechat < database/sample_data.sql
```

Or manually:

```sql
-- Note: These are example users with known passwords
-- Password for both: "testpass123"
-- DO NOT USE IN PRODUCTION

USE securechat;

-- User 1: alice@example.com
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('alice@example.com', 'alice', 
 UNHEX('0123456789ABCDEF0123456789ABCDEF'),
 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456');

-- User 2: bob@example.com  
INSERT INTO users (email, username, salt, pwd_hash) VALUES
('bob@example.com', 'bob',
 UNHEX('FEDCBA9876543210FEDCBA9876543210'),
 'f6e5d4c3b2a198765432109876543210fedcba9876543210fedcba9876543210');
```

**Warning:** The above hashes are examples. Generate proper hashes using the Python code.

---

## Troubleshooting

### Problem: "Access denied for user"

**Solution:**
1. Verify username and password
2. Check user exists: `SELECT user, host FROM mysql.user;`
3. Verify privileges: `SHOW GRANTS FOR 'scuser'@'localhost';`
4. Recreate user if needed (see Step 1)

### Problem: "Can't connect to MySQL server"

**Solution:**
1. Check MySQL is running:
   ```bash
   # Linux
   sudo systemctl status mysql
   
   # macOS
   brew services list
   
   # Windows
   # Check Services panel
   ```

2. Verify port 3306 is not blocked
3. Check MySQL is listening: `netstat -an | grep 3306`

### Problem: "Unknown database 'securechat'"

**Solution:**
1. Create database manually:
   ```sql
   CREATE DATABASE securechat;
   ```

2. Or run schema.sql again

### Problem: "Table 'users' already exists"

**Solution:**
- This is normal if database was already initialized
- To reset: `DROP TABLE users;` then run initialization again

### Problem: "Authentication plugin 'caching_sha2_password' cannot be loaded"

**Solution:**
```sql
-- Change authentication method
ALTER USER 'scuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'scpass';
FLUSH PRIVILEGES;
```

---

## Security Best Practices

1. **Use Strong Passwords**
   - Database user password should be at least 16 characters
   - Use a password manager

2. **Limit User Privileges**
   - Only grant necessary privileges
   - Use specific database, not all databases

3. **Use Environment Variables**
   - Store sensitive credentials in `.env` file
   - Add `.env` to `.gitignore`

4. **Regular Backups**
   ```bash
   mysqldump -u scuser -p securechat > backup_$(date +%Y%m%d).sql
   ```

5. **Firewall Rules**
   - Only allow localhost connections
   - Block external access if not needed

---

## Quick Setup Script

For automated setup, use:

```bash
# Linux/macOS
chmod +x database/setup_database.sh
./database/setup_database.sh

# Windows
database\setup_database.bat
```

---

## Next Steps

After database setup:
1. ✅ Verify connection works
2. ✅ Run database tests
3. ✅ Test user registration
4. ✅ Test user login
5. ✅ Proceed with application testing

---

## Support

If you encounter issues:
1. Check the troubleshooting section
2. Review MySQL error logs
3. Verify all prerequisites are met
4. Check configuration files

---

**Last Updated:** 2025-11-13

