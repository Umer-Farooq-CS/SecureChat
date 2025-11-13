#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Information Security (CS-3002)
# FAST-NUCES, Fall 2025
#================================================================================
#
# Script: run_all_tests.sh
# Purpose: Run all manual tests in sequence
#
# Usage:
#   ./run_all_tests.sh
#
# This script runs:
#   1. Traffic capture test
#   2. Invalid certificate tests
#   3. Tampering test guide
#   4. Replay test guide
#
#================================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Manual Test Suite Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Make all scripts executable
chmod +x *.sh 2>/dev/null || true

echo -e "${GREEN}[INFO] Manual Test Suite${NC}"
echo ""
echo "This script will guide you through all manual tests."
echo ""
echo "Available tests:"
echo "  1. Traffic Capture (Wireshark)"
echo "  2. Invalid Certificate Tests"
echo "  3. Message Tampering Test"
echo "  4. Replay Attack Test"
echo ""

read -p "Press Enter to continue..."

# Test 1: Traffic Capture
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test 1: Traffic Capture${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "This will start Wireshark capture."
echo "You need to start the server and client in separate terminals."
echo ""
read -p "Press Enter to start traffic capture test..."
./capture_traffic.sh

# Test 2: Invalid Certificates
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test 2: Invalid Certificate Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "This will test invalid certificate scenarios."
echo "Make sure the server is running."
echo ""
read -p "Press Enter to start invalid certificate tests..."
./test_invalid_certs.sh

# Test 3: Tampering
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test 3: Message Tampering Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "This test requires manual interaction."
echo "See: tampering_tests/outputs/TAMPERING_TEST_GUIDE.md"
echo ""
read -p "Press Enter to view tampering test guide..."
cat tampering_tests/outputs/TAMPERING_TEST_GUIDE.md

# Test 4: Replay
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test 4: Replay Attack Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "This test requires manual interaction."
echo "See: replay_tests/outputs/REPLAY_TEST_GUIDE.md"
echo ""
read -p "Press Enter to view replay test guide..."
cat replay_tests/outputs/REPLAY_TEST_GUIDE.md

# Generate summary report
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Generating Summary Report${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create Python script to generate summary
cat > "${SCRIPT_DIR}/generate_summary.py" << 'PYEOF'
import sys
import os
from pathlib import Path
from glob import glob

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from tests.report_generator import TestReportGenerator

# Find all report files
reports_dir = Path(__file__).parent.parent.parent / "reports"
all_reports = []

if reports_dir.exists():
    # Find all JSON reports
    for report_file in reports_dir.glob("*.json"):
        all_reports.append(str(report_file))

if all_reports:
    report_generator = TestReportGenerator()
    summary_path = report_generator.generate_summary_report(all_reports)
    print(f"[SUCCESS] Summary report generated: {summary_path}")
else:
    print("[INFO] No reports found to summarize")
PYEOF

python3 "${SCRIPT_DIR}/generate_summary.py" 2>/dev/null || echo -e "${YELLOW}[WARNING] Could not generate summary report${NC}"
rm -f "${SCRIPT_DIR}/generate_summary.py" 2>/dev/null || true

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "${GREEN}[INFO] All test guides have been displayed${NC}"
echo ""
echo "Test outputs are in:"
echo "  - captures/ (Wireshark captures)"
echo "  - invalid_cert_tests/outputs/ (Certificate test outputs)"
echo "  - tampering_tests/outputs/ (Tampering test guide)"
echo "  - replay_tests/outputs/ (Replay test guide)"
echo ""
echo "Test reports are in:"
echo "  - reports/ (All test reports)"
echo ""
echo -e "${YELLOW}[NEXT STEPS]${NC}"
echo "1. Review all test outputs"
echo "2. Take screenshots of errors (BAD_CERT, SIG_FAIL, REPLAY)"
echo "3. Save Wireshark captures"
echo "4. Review test reports in reports/ directory"
echo "5. Create test report document"
echo ""
echo -e "${GREEN}[DONE]${NC}"

