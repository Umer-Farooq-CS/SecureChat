#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Information Security (CS-3002)
# FAST-NUCES, Fall 2025
#================================================================================
#
# Script: capture_traffic.sh
# Purpose: Capture network traffic using Wireshark/tshark during a chat session
#
# Usage:
#   ./capture_traffic.sh [output_file]
#
# Example:
#   ./capture_traffic.sh captures/normal_session.pcapng
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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_FILE="${1:-${SCRIPT_DIR}/../captures/normal_session_$(date +%Y%m%d_%H%M%S).pcapng}"
CAPTURE_DURATION=30  # seconds
SERVER_PORT=8888
TEST_DIR="${SCRIPT_DIR}"

# Create captures directory if it doesn't exist
mkdir -p captures

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Wireshark Traffic Capture Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo -e "${RED}[ERROR] tshark is not installed.${NC}"
    echo "Install it with: sudo apt-get install tshark"
    exit 1
fi

# Check if server port is available
if lsof -Pi :${SERVER_PORT} -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo -e "${YELLOW}[WARNING] Port ${SERVER_PORT} is already in use.${NC}"
    echo "Please stop any existing server before running this script."
    exit 1
fi

echo -e "${GREEN}[INFO] Starting traffic capture...${NC}"
echo "Output file: ${OUTPUT_FILE}"
echo "Port: ${SERVER_PORT}"
echo "Duration: ${CAPTURE_DURATION} seconds"
echo ""

# Start tshark capture in background
echo -e "${BLUE}[INFO] Starting tshark capture...${NC}"
tshark -i lo -f "tcp port ${SERVER_PORT}" -w "${OUTPUT_FILE}" &
TSHARK_PID=$!

# Wait a moment for tshark to start
sleep 2

echo -e "${GREEN}[INFO] Capture started (PID: ${TSHARK_PID})${NC}"
echo ""
echo -e "${YELLOW}[INSTRUCTIONS]${NC}"
echo "1. In another terminal, start the server:"
echo "   cd SecureChat && python app/server.py"
echo ""
echo "2. In another terminal, start the client and perform:"
echo "   - Registration or login"
echo "   - Send several chat messages"
echo ""
echo "3. Wait for the capture to complete (${CAPTURE_DURATION} seconds)"
echo "   or press Ctrl+C to stop early"
echo ""

# Wait for specified duration or until interrupted
trap "kill $TSHARK_PID 2>/dev/null; exit" INT TERM
sleep ${CAPTURE_DURATION}

# Stop tshark
echo ""
echo -e "${BLUE}[INFO] Stopping capture...${NC}"
kill $TSHARK_PID 2>/dev/null
wait $TSHARK_PID 2>/dev/null

echo -e "${GREEN}[SUCCESS] Capture completed!${NC}"
echo "Output file: ${OUTPUT_FILE}"
echo ""

# Display capture statistics
if [ -f "${OUTPUT_FILE}" ]; then
    echo -e "${BLUE}[INFO] Capture Statistics:${NC}"
    tshark -r "${OUTPUT_FILE}" -q -z conv,tcp
    echo ""
    echo -e "${BLUE}[INFO] To view the capture:${NC}"
    echo "  wireshark ${OUTPUT_FILE}"
    echo ""
    echo -e "${BLUE}[INFO] Display filters to use in Wireshark:${NC}"
    echo "  tcp.port == ${SERVER_PORT}"
    echo "  tcp contains \"type\""
    echo "  tcp contains \"ct\""
    echo "  frame contains \"encrypted\""
fi

# Generate test report
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Generating Test Report${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create temporary directory for report script
TEMP_REPORT_DIR="$(dirname "${OUTPUT_FILE}")"
mkdir -p "${TEMP_REPORT_DIR}"

# Create Python script to generate report
cat > "${TEMP_REPORT_DIR}/generate_report.py" << PYEOF
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from tests.report_generator import TestReportGenerator

test_results = {
    "test_name": "Traffic Capture",
    "test_type": "wireshark",
    "capture_file": "${OUTPUT_FILE}",
    "port": ${SERVER_PORT},
    "duration_seconds": ${CAPTURE_DURATION},
    "status": "COMPLETED" if Path("${OUTPUT_FILE}").exists() else "FAILED",
    "notes": [
        "Display filters: tcp.port == ${SERVER_PORT}",
        "View in Wireshark: wireshark ${OUTPUT_FILE}"
    ]
}

report_generator = TestReportGenerator()
report_path = report_generator.generate_manual_test_report("traffic_capture", test_results)

print(f"[SUCCESS] Report generated: {report_path}")
PYEOF

python3 "${TEMP_REPORT_DIR}/generate_report.py" 2>/dev/null || echo -e "${YELLOW}[WARNING] Could not generate report automatically${NC}"
rm -f "${TEMP_REPORT_DIR}/generate_report.py" 2>/dev/null || true

echo -e "${GREEN}[DONE]${NC}"
echo ""
echo -e "${BLUE}[INFO] Test report saved in: reports/manual_traffic_capture_*.json${NC}"

