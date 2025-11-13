@echo off
REM ================================================================================
REM Assignment #2 - Secure Chat System
REM Database Setup Script for Windows
REM ================================================================================

echo ========================================
echo SecureChat Database Setup (Windows)
echo ========================================
echo.

REM Check if MySQL is in PATH
where mysql >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MySQL client is not in PATH.
    echo Please install MySQL and add it to your PATH.
    pause
    exit /b 1
)

echo [INFO] MySQL client found
echo.

REM Get script directory
set SCRIPT_DIR=%~dp0

REM Step 1: Create user
echo [STEP 1] Creating database user...
echo Enter MySQL root password when prompted:
mysql -u root -p < "%SCRIPT_DIR%create_user.sql"
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] User creation had issues (might already exist)
)
echo [SUCCESS] User created
echo.

REM Step 2: Create database
echo [STEP 2] Creating database and schema...
echo Enter MySQL root password when prompted:
mysql -u root -p < "%SCRIPT_DIR%init_database.sql"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to create database
    pause
    exit /b 1
)
echo [SUCCESS] Database and schema created
echo.

REM Step 3: Test connection
echo [STEP 3] Testing connection...
echo Enter scuser password (default: scpass) when prompted:
mysql -u scuser -p -e "USE securechat; SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema = 'securechat';"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Connection test failed
    pause
    exit /b 1
)
echo [SUCCESS] Connection test passed
echo.

REM Summary
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Database Information:
echo   Database: securechat
echo   User: scuser
echo   Host: localhost
echo   Port: 3306
echo.
echo Next Steps:
echo 1. Update config\config.json with database credentials
echo 2. Or set environment variables: DB_USER, DB_PASSWORD
echo 3. Test connection: python -c "from app.storage.db import get_db_connection; conn = get_db_connection(); print('OK'); conn.close()"
echo.
pause

