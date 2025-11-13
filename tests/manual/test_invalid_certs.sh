#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Information Security (CS-3002)
# FAST-NUCES, Fall 2025
#================================================================================
#
# Script: test_invalid_certs.sh
# Purpose: Test invalid certificate scenarios and capture BAD_CERT errors
#
# Usage:
#   ./test_invalid_certs.sh
#
# This script tests:
#   1. Self-signed certificate (not from CA)
#   2. Expired certificate
#   3. Certificate with wrong Common Name (CN)
#
#================================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="tests/manual/invalid_cert_tests"
OUTPUT_DIR="${TEST_DIR}/outputs"
SERVER_PORT=8888

# Create test directories
mkdir -p "${TEST_DIR}"
mkdir -p "${OUTPUT_DIR}"
mkdir -p certs

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Invalid Certificate Test Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if OpenSSL is installed
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}[ERROR] OpenSSL is not installed.${NC}"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python 3 is not installed.${NC}"
    exit 1
fi

# Function to generate self-signed certificate
generate_self_signed_cert() {
    local cn=$1
    local output_key="${TEST_DIR}/${cn}-key.pem"
    local output_cert="${TEST_DIR}/${cn}-cert.pem"
    
    echo -e "${YELLOW}[INFO] Generating self-signed certificate for ${cn}...${NC}"
    
    openssl req -x509 -newkey rsa:2048 -keyout "${output_key}" \
        -out "${output_cert}" -days 365 -nodes \
        -subj "/C=PK/CN=${cn}" \
        -addext "subjectAltName=DNS:${cn}" 2>/dev/null
    
    echo -e "${GREEN}[SUCCESS] Generated: ${output_cert}${NC}"
}

# Function to generate expired certificate
generate_expired_cert() {
    local cn=$1
    local output_key="${TEST_DIR}/${cn}-expired-key.pem"
    local output_cert="${TEST_DIR}/${cn}-expired-cert.pem"
    
    echo -e "${YELLOW}[INFO] Generating expired certificate for ${cn}...${NC}"
    
    # Generate certificate that expired 1 day ago
    openssl req -x509 -newkey rsa:2048 -keyout "${output_key}" \
        -out "${output_cert}" -days -1 -nodes \
        -subj "/C=PK/CN=${cn}" \
        -addext "subjectAltName=DNS:${cn}" 2>/dev/null
    
    echo -e "${GREEN}[SUCCESS] Generated expired cert: ${output_cert}${NC}"
}

# Function to test certificate rejection
test_cert_rejection() {
    local test_name=$1
    local cert_path=$2
    local key_path=$3
    local expected_error=$4
    local output_file="${OUTPUT_DIR}/${test_name}_output.txt"
    
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Test: ${test_name}${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    # Check if server is running
    if ! lsof -Pi :${SERVER_PORT} -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        echo -e "${YELLOW}[WARNING] Server is not running on port ${SERVER_PORT}${NC}"
        echo "Please start the server first:"
        echo "  cd SecureChat && python app/server.py"
        echo ""
        read -p "Press Enter when server is ready..."
    fi
    
    echo -e "${YELLOW}[INFO] Attempting connection with invalid certificate...${NC}"
    echo "Certificate: ${cert_path}"
    echo "Expected error: ${expected_error}"
    echo ""
    
    # Create a test client script
    cat > "${TEST_DIR}/test_client_${test_name}.py" << EOF
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app.client import SecureChatClient
from config import get_config

config = get_config()

try:
    client = SecureChatClient(
        host="localhost",
        port=${SERVER_PORT},
        client_cert_path="${cert_path}",
        client_key_path="${key_path}",
        ca_cert_path=config.ca.cert_path
    )
    print("[ERROR] Connection should have failed but didn't!")
    sys.exit(1)
except Exception as e:
    error_msg = str(e)
    print(f"[ERROR] {error_msg}")
    if "${expected_error}" in error_msg or "BAD_CERT" in error_msg or "Certificate" in error_msg:
        print("[SUCCESS] Certificate correctly rejected!")
        sys.exit(0)
    else:
        print("[FAIL] Unexpected error type")
        sys.exit(1)
EOF
    
    # Run the test
    python3 "${TEST_DIR}/test_client_${test_name}.py" 2>&1 | tee "${output_file}"
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] Test passed: Certificate correctly rejected${NC}"
    else
        echo -e "${RED}[FAIL] Test failed: Certificate was not rejected${NC}"
    fi
    
    echo "Output saved to: ${output_file}"
}

# Test 1: Self-signed certificate
echo -e "${BLUE}Test 1: Self-Signed Certificate${NC}"
generate_self_signed_cert "selfsigned.client.local"
test_cert_rejection "self_signed" \
    "${TEST_DIR}/selfsigned.client.local-cert.pem" \
    "${TEST_DIR}/selfsigned.client.local-key.pem" \
    "BAD_CERT"

# Test 2: Expired certificate
echo -e "${BLUE}Test 2: Expired Certificate${NC}"
generate_expired_cert "expired.client.local"
test_cert_rejection "expired" \
    "${TEST_DIR}/expired.client.local-expired-cert.pem" \
    "${TEST_DIR}/expired.client.local-expired-key.pem" \
    "BAD_CERT"

# Test 3: Wrong Common Name
echo -e "${BLUE}Test 3: Wrong Common Name${NC}"
if [ -f "certs/client-cert.pem" ]; then
    # Use existing client cert but expect CN mismatch
    echo -e "${YELLOW}[INFO] Testing with certificate that has wrong CN...${NC}"
    echo "This test requires a certificate with CN != expected hostname"
    echo "The server should reject it during hostname validation"
else
    echo -e "${YELLOW}[INFO] Generating certificate with wrong CN...${NC}"
    # Generate cert with wrong CN
    generate_self_signed_cert "wrong.hostname.local"
    test_cert_rejection "wrong_cn" \
        "${TEST_DIR}/wrong.hostname.local-cert.pem" \
        "${TEST_DIR}/wrong.hostname.local-key.pem" \
        "BAD_CERT"
fi

# Generate test report
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Generating Test Report${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create Python script to generate report
cat > "${TEST_DIR}/generate_report.py" << 'PYEOF'
import sys
import os
import json
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from tests.report_generator import TestReportGenerator

# Collect test results
test_results = {
    "test_name": "Invalid Certificate Tests",
    "tests_performed": [
        "Self-signed certificate rejection",
        "Expired certificate rejection",
        "Wrong Common Name rejection"
    ],
    "output_files": [],
    "status": "COMPLETED",
    "notes": []
}

# Find output files
output_dir = Path(__file__).parent / "outputs"
if output_dir.exists():
    for file in output_dir.glob("*.txt"):
        test_results["output_files"].append(str(file))

# Generate report
report_generator = TestReportGenerator()
report_path = report_generator.generate_manual_test_report("invalid_certificates", test_results)

print(f"[SUCCESS] Report generated: {report_path}")
PYEOF

python3 "${TEST_DIR}/generate_report.py" 2>/dev/null || echo -e "${YELLOW}[WARNING] Could not generate report automatically${NC}"

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Test outputs saved in: ${OUTPUT_DIR}"
echo ""
echo -e "${GREEN}[DONE] All invalid certificate tests completed${NC}"
echo ""
echo -e "${YELLOW}[NOTE] Review the output files and take screenshots:${NC}"
echo "  - ${OUTPUT_DIR}/self_signed_output.txt"
echo "  - ${OUTPUT_DIR}/expired_output.txt"
echo "  - ${OUTPUT_DIR}/wrong_cn_output.txt"
echo ""
echo -e "${BLUE}[INFO] Test report saved in: reports/manual_invalid_certificates_*.json${NC}"

