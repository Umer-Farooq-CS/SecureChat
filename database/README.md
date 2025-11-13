# Database Setup Files

This directory contains all files needed to set up the MySQL database for SecureChat.

## Files

### Setup Scripts
- **`setup_database.sh`** - Automated database setup script (Linux/macOS)
- **`verify_database.sh`** - Verify database setup is correct
- **`reset_database.sh`** - Reset database (WARNING: deletes all data)

### SQL Files
- **`create_user.sql`** - Creates database user (scuser)
- **`init_database.sql`** - Creates database and users table
- **`sample_data.sql`** - Inserts sample test users

### Utilities
- **`generate_sample_user.py`** - Generate SQL for a new user with proper hash

### Documentation
- **`SETUP_DATABASE.md`** - Complete step-by-step setup guide

## Quick Start

### Automated Setup (Recommended)

```bash
cd SecureChat
chmod +x database/setup_database.sh
./database/setup_database.sh
```

### Manual Setup

1. **Create user:**
   ```bash
   mysql -u root -p < database/create_user.sql
   ```

2. **Create database:**
   ```bash
   mysql -u scuser -p < database/init_database.sql
   ```

3. **Verify:**
   ```bash
   ./database/verify_database.sh
   ```

## Configuration

After setup, configure credentials in:
- `config/config.json` (database section)
- Or use environment variables: `DB_USER`, `DB_PASSWORD`

## Testing

Test the database connection:
```bash
python -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('OK'); conn.close()"
```

Run database tests:
```bash
python -m unittest tests.test_db -v
```

## Troubleshooting

See `SETUP_DATABASE.md` for detailed troubleshooting guide.

