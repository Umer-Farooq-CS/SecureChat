# Database Setup - Complete Summary

## 📋 Overview

This document provides a complete overview of the database setup process for SecureChat.

## 📁 Files Created

### Documentation
- **`SETUP_DATABASE.md`** - Complete step-by-step guide (READ THIS FIRST)
- **`QUICK_START.md`** - Quick reference for common operations
- **`README.md`** - Overview of all database files

### SQL Scripts
- **`create_user.sql`** - Creates database user (scuser)
- **`init_database.sql`** - Creates database and users table
- **`sample_data.sql`** - Inserts sample test users

### Setup Scripts
- **`setup_database.sh`** - Automated setup (Linux/macOS)
- **`setup_database.bat`** - Automated setup (Windows)
- **`verify_database.sh`** - Verify database setup
- **`reset_database.sh`** - Reset database (WARNING: deletes data)

### Utilities
- **`generate_sample_user.py`** - Generate SQL for new users

## 🚀 Quick Setup (3 Steps)

### Step 1: Install MySQL
```bash
# Ubuntu/Debian
sudo apt-get install mysql-server

# macOS
brew install mysql

# Windows
# Download from: https://dev.mysql.com/downloads/installer/
```

### Step 2: Run Setup Script
```bash
# Linux/macOS
chmod +x database/setup_database.sh
./database/setup_database.sh

# Windows
database\setup_database.bat
```

### Step 3: Verify
```bash
python -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('OK'); conn.close()"
```

## 📊 Database Schema

### Database: `securechat`
- Character Set: `utf8mb4`
- Collation: `utf8mb4_unicode_ci`

### Table: `users`
```sql
CREATE TABLE users (
    email VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL DEFAULT NULL,
    INDEX idx_username (username),
    INDEX idx_email (email)
);
```

## 🔐 Default Credentials

**Database User:**
- Username: `scuser`
- Password: `scpass`
- Host: `localhost`
- Database: `securechat`

**⚠️ WARNING:** Change these in production!

## 📝 Configuration

### Option 1: Config File
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

### Option 2: Environment Variables (More Secure)
Create `.env` file:
```bash
DB_HOST=localhost
DB_PORT=3306
DB_NAME=securechat
DB_USER=scuser
DB_PASSWORD=scpass
```

## ✅ Verification Checklist

- [ ] MySQL server is running
- [ ] Database user `scuser` exists
- [ ] Database `securechat` exists
- [ ] Table `users` exists with correct structure
- [ ] Python connection test passes
- [ ] Database tests pass: `python -m unittest tests.test_db`

## 🧪 Testing

### Test Connection
```bash
python -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('OK'); conn.close()"
```

### Run Database Tests
```bash
python -m unittest tests.test_db -v
```

### Test Registration
1. Start server: `python app/server.py`
2. Start client: `python app/client.py`
3. Try to register a new user

## 🔧 Common Operations

### View Users
```bash
mysql -u scuser -p securechat -e "SELECT email, username, created_at FROM users;"
```

### Add Test User
```bash
python database/generate_sample_user.py user@example.com username password123
# Then run the generated SQL in MySQL
```

### Reset Database
```bash
./database/reset_database.sh  # Linux/macOS
# OR
database\reset_database.bat   # Windows
```

### Backup Database
```bash
mysqldump -u scuser -p securechat > backup_$(date +%Y%m%d).sql
```

### Restore Database
```bash
mysql -u scuser -p securechat < backup_20251113.sql
```

## 🐛 Troubleshooting

### "Access denied for user"
- Verify username and password
- Check user exists: `SELECT user FROM mysql.user WHERE user='scuser';`
- Recreate user: Run `create_user.sql` again

### "Can't connect to MySQL server"
- Check MySQL is running: `sudo systemctl status mysql` (Linux)
- Verify port 3306 is not blocked
- Check MySQL is listening: `netstat -an | grep 3306`

### "Unknown database 'securechat'"
- Create database: Run `init_database.sql`
- Or use Python: `python -m app.storage.db --init`

### "Table 'users' already exists"
- This is normal if already initialized
- To reset: `DROP TABLE users;` then run `init_database.sql`

## 📚 Additional Resources

- **Full Setup Guide:** `SETUP_DATABASE.md`
- **Quick Reference:** `QUICK_START.md`
- **Schema File:** `../schema.sql`
- **Database Module:** `../app/storage/db.py`

## 🎯 Next Steps

After database setup:
1. ✅ Verify connection works
2. ✅ Run database tests
3. ✅ Test user registration
4. ✅ Test user login
5. ✅ Proceed with application testing

---

**Need Help?** See `SETUP_DATABASE.md` for detailed troubleshooting.

