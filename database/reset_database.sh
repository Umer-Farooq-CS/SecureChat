#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Database Reset Script
#================================================================================
#
# WARNING: This script will DELETE all data in the database!
# Use only for testing/development.
#
# Usage:
#   chmod +x database/reset_database.sh
#   ./database/reset_database.sh
#
#================================================================================

set -e

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${RED}========================================${NC}"
echo -e "${RED}WARNING: Database Reset${NC}"
echo -e "${RED}========================================${NC}"
echo ""
echo -e "${YELLOW}This will DELETE all data in the securechat database!${NC}"
echo ""
read -p "Are you sure you want to continue? (type 'yes' to confirm): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Reset cancelled."
    exit 0
fi

echo ""
read -sp "Enter scuser password (default: scpass): " PASSWORD
PASSWORD=${PASSWORD:-scpass}
echo ""
echo ""

echo -e "${BLUE}[INFO] Dropping and recreating database...${NC}"

# Drop and recreate database
mysql -u scuser -p"${PASSWORD}" << EOF
DROP DATABASE IF EXISTS securechat;
CREATE DATABASE securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
EOF

# Recreate schema
echo -e "${BLUE}[INFO] Recreating schema...${NC}"
mysql -u scuser -p"${PASSWORD}" securechat < "${SCRIPT_DIR}/init_database.sql"

echo ""
echo -e "${BLUE}[SUCCESS] Database reset complete!${NC}"
echo ""

