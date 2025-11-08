# Detailed Setup Guide

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
File: SETUP.md
Purpose: Detailed setup guide with step-by-step instructions
================================================================================

Description:
    This file provides comprehensive step-by-step instructions for setting up
    the SecureChat system from scratch, including prerequisites installation,
    environment configuration, database setup, and certificate generation.

Links to Other Files:
    - README.md: Main project documentation
    - PROJECT_STRUCTURE.md: Project structure reference
    - schema.sql: Database schema for initialization
    - .env.example: Configuration template
    - scripts/gen_ca.py: CA generation script
    - scripts/gen_cert.py: Certificate issuance script

Result:
    - Enables users to set up the system from scratch
    - Provides troubleshooting guidance
    - Includes verification checklist
    - Ensures proper system configuration

================================================================================

This guide provides step-by-step instructions for setting up the SecureChat system from scratch.

## Prerequisites Installation

### 1. Python 3.8+

**Windows:**
- Download from [python.org](https://www.python.org/downloads/)
- During installation, check "Add Python to PATH"
- Verify: `python --version`

**Linux:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

**macOS:**
```bash
brew install python3
```

### 2. MySQL 8.0+

**Option A: Docker (Recommended)**

Install Docker Desktop:
- Windows/Mac: [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
- Linux: Follow distribution-specific instructions

**Option B: Native MySQL**

**Windows:**
- Download MySQL Installer from [mysql.com](https://dev.mysql.com/downloads/installer/)

**Linux:**
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql
```

**macOS:**
```bash
brew install mysql
brew services start mysql
```

### 3. Git

**Windows:**
- Download from [git-scm.com](https://git-scm.com/download/win)

**Linux:**
```bash
sudo apt install git
```

**macOS:**
```bash
brew install git
```

## Project Setup

### Step 1: Clone Repository

```bash
git clone [Your GitHub Repository URL]
cd securechat-cryptography
```

### Step 2: Create Virtual Environment

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should see `(.venv)` in your prompt.

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Verify installation:**
```bash
pip list
```

You should see:
- cryptography
- PyMySQL
- python-dotenv
- pydantic
- rich

### Step 4: Configure Environment

```bash
# Copy example file
cp .env.example .env

# Edit .env with your settings
# Windows: notepad .env
# Linux/Mac: nano .env or vim .env
```

**Minimum required settings:**
```env
DB_HOST=localhost
DB_PORT=3306
DB_NAME=securechat
DB_USER=scuser
DB_PASSWORD=scpass
SERVER_HOST=localhost
SERVER_PORT=8888
```

### Step 5: Set Up MySQL Database

**Using Docker:**

```bash
docker run -d \
  --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8
```

**Verify container is running:**
```bash
docker ps
```

**Using Native MySQL:**

```bash
# Login as root
mysql -u root -p

# Create database and user
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'scuser'@'localhost' IDENTIFIED BY 'scpass';
GRANT ALL PRIVILEGES ON securechat.* TO 'scuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

**Initialize schema:**
```bash
# Option 1: Using Python script
python -m app.storage.db --init

# Option 2: Using SQL file
mysql -u scuser -p securechat < schema.sql
```

**Verify table creation:**
```bash
mysql -u scuser -p securechat -e "DESCRIBE users;"
```

### Step 6: Generate Certificates

**Create directories:**
```bash
mkdir -p certs transcripts
```

**Generate Root CA:**
```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

This should create:
- `certs/ca-key.pem`
- `certs/ca-cert.pem`

**Generate Server Certificate:**
```bash
python scripts/gen_cert.py --cn server.local --out certs/server
```

This should create:
- `certs/server-key.pem`
- `certs/server-cert.pem`

**Generate Client Certificate:**
```bash
python scripts/gen_cert.py --cn client.local --out certs/client
```

This should create:
- `certs/client-key.pem`
- `certs/client-cert.pem`

**Verify certificates:**
```bash
# View CA certificate
openssl x509 -text -in certs/ca-cert.pem -noout

# View server certificate
openssl x509 -text -in certs/server-cert.pem -noout

# Verify certificate chain
openssl verify -CAfile certs/ca-cert.pem certs/server-cert.pem
openssl verify -CAfile certs/ca-cert.pem certs/client-cert.pem
```

## Running the System

### Start Server

**Terminal 1:**
```bash
# Activate virtual environment
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac

# Start server
python -m app.server
```

**Expected output:**
```
[INFO] Server starting on localhost:8888
[INFO] Loading server certificate from certs/server-cert.pem
[INFO] Database connection established
[INFO] Server listening for connections...
```

### Start Client

**Terminal 2:**
```bash
# Activate virtual environment
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac

# Start client
python -m app.client
```

**Expected output:**
```
[INFO] Connecting to localhost:8888
[INFO] Connected to server
[INFO] Certificate verified: ✓
Choose action: [1] Register [2] Login
```

## Troubleshooting

### Issue: "Module not found"

**Solution:**
```bash
# Ensure virtual environment is activated
# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: "Cannot connect to MySQL"

**Check:**
1. MySQL service is running: `docker ps` or `sudo systemctl status mysql`
2. Credentials in `.env` are correct
3. Port 3306 is not blocked by firewall
4. Database exists: `mysql -u scuser -p -e "SHOW DATABASES;"`

**Solution:**
```bash
# Test connection
mysql -u scuser -p -h localhost -P 3306 securechat
```

### Issue: "Certificate not found"

**Solution:**
1. Verify certificates exist: `ls certs/`
2. Check paths in `.env` file
3. Regenerate certificates if needed

### Issue: "Port already in use"

**Solution:**
```bash
# Find process using port 8888
# Windows:
netstat -ano | findstr :8888
# Linux/Mac:
lsof -i :8888

# Kill process or change SERVER_PORT in .env
```

### Issue: "Permission denied" (Linux/Mac)

**Solution:**
```bash
# Make scripts executable
chmod +x scripts/*.py
```

## Verification Checklist

Before running tests, verify:

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] All dependencies installed (`pip list`)
- [ ] `.env` file configured
- [ ] MySQL database running
- [ ] Database schema initialized
- [ ] CA certificate generated
- [ ] Server certificate generated
- [ ] Client certificate generated
- [ ] Certificates verified with OpenSSL
- [ ] Server starts without errors
- [ ] Client can connect to server

## Next Steps

After setup is complete:

1. Read the main [README.md](README.md) for usage instructions
2. Review [tests/manual/NOTES.md](tests/manual/NOTES.md) for testing procedures
3. Start implementing the protocol according to the assignment specification

## Getting Help

If you encounter issues:

1. Check error messages carefully
2. Verify all prerequisites are installed
3. Ensure configuration files are correct
4. Review logs for detailed error information
5. Check that all required files exist

---

**Note:** This setup guide assumes a clean installation. If you're working on an existing system, you may need to adjust paths and configurations accordingly.

