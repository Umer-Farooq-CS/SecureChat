#!/usr/bin/env python3
"""
================================================================================
Assignment #2 - Secure Chat System
Generate sample user with proper salt and hash
================================================================================

This script generates a properly hashed user for insertion into the database.

Usage:
    python database/generate_sample_user.py alice@example.com alice testpass123
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.storage.db import generate_salt, hash_password
from app.common.utils import b64e


def generate_user_sql(email: str, username: str, password: str):
    """Generate SQL INSERT statement for a user."""
    
    # Generate salt
    salt = generate_salt()
    
    # Hash password
    pwd_hash = hash_password(password, salt)
    
    # Generate SQL
    salt_hex = salt.hex().upper()
    
    sql = f"""-- User: {username} ({email})
-- Password: {password}
-- Salt: {salt_hex}
-- Hash: {pwd_hash}

INSERT INTO users (email, username, salt, pwd_hash) VALUES
('{email}', '{username}', 
 UNHEX('{salt_hex}'),
 '{pwd_hash}')
ON DUPLICATE KEY UPDATE 
    username = VALUES(username),
    salt = VALUES(salt),
    pwd_hash = VALUES(pwd_hash);
"""
    
    return sql


def main():
    if len(sys.argv) != 4:
        print("Usage: python generate_sample_user.py <email> <username> <password>")
        print("Example: python generate_sample_user.py alice@example.com alice testpass123")
        sys.exit(1)
    
    email = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    
    sql = generate_user_sql(email, username, password)
    
    print("=" * 70)
    print("Generated SQL for User")
    print("=" * 70)
    print()
    print(sql)
    print("=" * 70)
    print()
    print("Copy the SQL above and run it in MySQL:")
    print(f"  mysql -u scuser -p securechat")
    print("Then paste the INSERT statement.")


if __name__ == "__main__":
    main()

