# Quick Start Guide - Database Setup

## For Linux/macOS Users

### Option 1: Automated Setup (Recommended)
```bash
cd SecureChat
chmod +x database/setup_database.sh
./database/setup_database.sh
```

### Option 2: Manual Setup
```bash
# 1. Create user
mysql -u root -p < database/create_user.sql

# 2. Create database
mysql -u scuser -p < database/init_database.sql

# 3. Verify
./database/verify_database.sh
```

## For Windows Users

### Option 1: Automated Setup
```cmd
cd SecureChat
database\setup_database.bat
```

### Option 2: Manual Setup
```cmd
REM 1. Create user
mysql -u root -p < database\create_user.sql

REM 2. Create database  
mysql -u scuser -p < database\init_database.sql
```

## Configuration

After setup, update `config/config.json`:

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

## Test Connection

```bash
python -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('OK'); conn.close()"
```

## Run Tests

```bash
python -m unittest tests.test_db -v
```

## Generate Sample User

```bash
python database/generate_sample_user.py alice@example.com alice testpass123
```

## Troubleshooting

See `SETUP_DATABASE.md` for detailed troubleshooting.

