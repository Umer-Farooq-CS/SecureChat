#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Database Verification Script
#================================================================================
#
# This script verifies the database setup is correct.
#
# Usage:
#   chmod +x database/verify_database.sh
#   ./database/verify_database.sh
#
#================================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Database Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Prompt for password
read -sp "Enter scuser password (default: scpass): " PASSWORD
PASSWORD=${PASSWORD:-scpass}
echo ""
echo ""

# Test 1: Check database exists
echo -e "${BLUE}[TEST 1] Checking database exists...${NC}"
if mysql -u scuser -p"${PASSWORD}" -e "USE securechat;" 2>/dev/null; then
    echo -e "${GREEN}[PASS] Database 'securechat' exists${NC}"
else
    echo -e "${RED}[FAIL] Database 'securechat' does not exist${NC}"
    exit 1
fi
echo ""

# Test 2: Check table exists
echo -e "${BLUE}[TEST 2] Checking table exists...${NC}"
TABLE_COUNT=$(mysql -u scuser -p"${PASSWORD}" securechat -e "SHOW TABLES LIKE 'users';" 2>/dev/null | wc -l)
if [ "$TABLE_COUNT" -gt 1 ]; then
    echo -e "${GREEN}[PASS] Table 'users' exists${NC}"
else
    echo -e "${RED}[FAIL] Table 'users' does not exist${NC}"
    exit 1
fi
echo ""

# Test 3: Check table structure
echo -e "${BLUE}[TEST 3] Checking table structure...${NC}"
COLUMNS=$(mysql -u scuser -p"${PASSWORD}" securechat -e "DESCRIBE users;" 2>/dev/null | grep -c "email\|username\|salt\|pwd_hash")
if [ "$COLUMNS" -ge 4 ]; then
    echo -e "${GREEN}[PASS] Table structure is correct${NC}"
    echo ""
    echo "Table structure:"
    mysql -u scuser -p"${PASSWORD}" securechat -e "DESCRIBE users;" 2>/dev/null
else
    echo -e "${RED}[FAIL] Table structure is incorrect${NC}"
    exit 1
fi
echo ""

# Test 4: Check indexes
echo -e "${BLUE}[TEST 4] Checking indexes...${NC}"
INDEX_COUNT=$(mysql -u scuser -p"${PASSWORD}" securechat -e "SHOW INDEXES FROM users;" 2>/dev/null | wc -l)
if [ "$INDEX_COUNT" -gt 1 ]; then
    echo -e "${GREEN}[PASS] Indexes exist${NC}"
else
    echo -e "${YELLOW}[WARNING] Indexes might be missing${NC}"
fi
echo ""

# Test 5: Check user count
echo -e "${BLUE}[TEST 5] Checking user count...${NC}"
USER_COUNT=$(mysql -u scuser -p"${PASSWORD}" securechat -e "SELECT COUNT(*) as count FROM users;" 2>/dev/null | tail -1)
echo -e "${GREEN}[INFO] Current users in database: ${USER_COUNT}${NC}"
echo ""

# Test 6: Python connection test
echo -e "${BLUE}[TEST 6] Testing Python connection...${NC}"
cd "${SCRIPT_DIR}/.."
if python3 -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('Connection successful'); conn.close()" 2>/dev/null; then
    echo -e "${GREEN}[PASS] Python connection works${NC}"
else
    echo -e "${RED}[FAIL] Python connection failed${NC}"
    echo "Check your config/config.json or environment variables"
    exit 1
fi
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Verification Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}All tests passed! Database is ready to use.${NC}"
echo ""

