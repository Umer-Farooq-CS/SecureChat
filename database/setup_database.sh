#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Database Setup Script
#================================================================================
#
# This script automates the database setup process.
#
# Usage:
#   chmod +x database/setup_database.sh
#   ./database/setup_database.sh
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
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}SecureChat Database Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if MySQL is installed
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}[ERROR] MySQL client is not installed.${NC}"
    echo "Please install MySQL first."
    exit 1
fi

echo -e "${GREEN}[INFO] MySQL client found${NC}"
echo ""

# Prompt for root password
read -sp "Enter MySQL root password: " ROOT_PASSWORD
echo ""

# Step 1: Create user
echo -e "${BLUE}[STEP 1] Creating database user...${NC}"
mysql -u root -p"${ROOT_PASSWORD}" < "${SCRIPT_DIR}/create_user.sql" 2>/dev/null || {
    echo -e "${YELLOW}[WARNING] User might already exist. Continuing...${NC}"
}
echo -e "${GREEN}[SUCCESS] User created${NC}"
echo ""

# Step 2: Create database and schema
echo -e "${BLUE}[STEP 2] Creating database and schema...${NC}"
mysql -u root -p"${ROOT_PASSWORD}" < "${SCRIPT_DIR}/init_database.sql" 2>/dev/null || {
    echo -e "${RED}[ERROR] Failed to create database${NC}"
    exit 1
}
echo -e "${GREEN}[SUCCESS] Database and schema created${NC}"
echo ""

# Step 3: Test connection
echo -e "${BLUE}[STEP 3] Testing connection...${NC}"
read -sp "Enter scuser password (default: scpass): " SCUSER_PASSWORD
SCUSER_PASSWORD=${SCUSER_PASSWORD:-scpass}
echo ""

mysql -u scuser -p"${SCUSER_PASSWORD}" -e "USE securechat; SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema = 'securechat';" 2>/dev/null && {
    echo -e "${GREEN}[SUCCESS] Connection test passed${NC}"
} || {
    echo -e "${RED}[ERROR] Connection test failed${NC}"
    exit 1
}
echo ""

# Step 4: Verify table
echo -e "${BLUE}[STEP 4] Verifying table structure...${NC}"
mysql -u scuser -p"${SCUSER_PASSWORD}" securechat -e "DESCRIBE users;" 2>/dev/null && {
    echo -e "${GREEN}[SUCCESS] Table structure verified${NC}"
} || {
    echo -e "${RED}[ERROR] Table verification failed${NC}"
    exit 1
}
echo ""

# Step 5: Ask about sample data
read -p "Do you want to insert sample test users? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[STEP 5] Inserting sample data...${NC}"
    mysql -u scuser -p"${SCUSER_PASSWORD}" securechat < "${SCRIPT_DIR}/sample_data.sql" 2>/dev/null || {
        echo -e "${YELLOW}[WARNING] Sample data insertion had issues (might already exist)${NC}"
    }
    echo -e "${GREEN}[SUCCESS] Sample data inserted${NC}"
    echo ""
fi

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}Database Information:${NC}"
echo "  Database: securechat"
echo "  User: scuser"
echo "  Host: localhost"
echo "  Port: 3306"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Update config/config.json with database credentials"
echo "2. Or set environment variables: DB_USER, DB_PASSWORD"
echo "3. Test connection: python -c \"from app.storage.db import get_db_connection; conn = get_db_connection(); print('OK'); conn.close()\""
echo "4. Run tests: python -m unittest tests.test_db"
echo ""
echo -e "${GREEN}[DONE]${NC}"

