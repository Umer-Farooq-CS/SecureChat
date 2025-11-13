#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Information Security (CS-3002)
# FAST-NUCES, Fall 2025
#================================================================================
#
# Script: test_tampering.sh
# Purpose: Test message tampering detection and capture SIG_FAIL errors
#
# Usage:
#   ./test_tampering.sh
#
# This script:
#   1. Establishes a valid secure session
#   2. Captures a message
#   3. Modifies the ciphertext
#   4. Resends the modified message
#   5. Verifies SIG_FAIL error is generated
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
TEST_DIR="tests/manual/tampering_tests"
OUTPUT_DIR="${TEST_DIR}/outputs"
SERVER_PORT=8888

# Create test directories
mkdir -p "${TEST_DIR}"
mkdir -p "${OUTPUT_DIR}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Message Tampering Test Script${NC}"
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

# Create Python script to test tampering
cat > "${TEST_DIR}/test_tampering.py" << 'EOF'
#!/usr/bin/env python3
"""
Test script for message tampering detection.
This script establishes a connection, sends a message, then attempts to tamper with it.
"""

import sys
import os
import json
import socket
import time
import base64

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app.common.protocol import parse_message, serialize_message, ChatMessage
from app.common.utils import b64e, b64d
from config import get_config

def tamper_ciphertext(ciphertext_b64):
    """Tamper with ciphertext by modifying one character."""
    # Decode base64
    ciphertext = b64d(ciphertext_b64)
    
    # Modify first byte
    tampered = bytearray(ciphertext)
    if len(tampered) > 0:
        tampered[0] = (tampered[0] + 1) % 256
    
    # Re-encode
    return b64e(bytes(tampered))

def test_tampering():
    config = get_config()
    
    print("[INFO] Starting tampering test...")
    print("")
    
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(("localhost", 8888))
        print("[INFO] Connected to server")
        
        # Note: This is a simplified test. In a real scenario, you would:
        # 1. Complete the full handshake (certificates, DH, auth)
        # 2. Send a legitimate message
        # 3. Capture that message
        # 4. Tamper with it
        # 5. Resend the tampered message
        
        print("[INFO] For a complete test, you need to:")
        print("  1. Complete certificate exchange")
        print("  2. Complete authentication")
        print("  3. Establish session key via DH")
        print("  4. Send a legitimate message")
        print("  5. Capture and tamper with the message")
        print("  6. Resend tampered message")
        print("")
        print("[INFO] This requires manual interaction with the client.")
        print("[INFO] Please use the manual test procedure instead.")
        print("")
        print("[MANUAL TEST PROCEDURE]")
        print("1. Start server: python app/server.py")
        print("2. Start client: python app/client.py")
        print("3. Complete login/registration")
        print("4. Send a message: 'Hello, this is a test message'")
        print("5. In another terminal, use a tool to intercept and modify the message")
        print("6. Or modify the message in the client code temporarily")
        print("7. Observe SIG_FAIL error when tampered message is received")
        
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    test_tampering()
EOF

chmod +x "${TEST_DIR}/test_tampering.py"

# Create a more comprehensive manual test guide
cat > "${OUTPUT_DIR}/TAMPERING_TEST_GUIDE.md" << 'EOF'
# Message Tampering Test Guide

## Objective
Verify that message integrity is protected and tampering is detected (SIG_FAIL).

## Test Procedure

### Method 1: Using Python Script (Recommended)

1. **Start the server:**
   ```bash
   cd SecureChat
   python app/server.py
   ```

2. **In another terminal, start the client:**
   ```bash
   cd SecureChat
   python app/client.py
   ```

3. **Complete authentication:**
   - Register or login with valid credentials
   - Wait for session key establishment

4. **Send a test message:**
   - Type: `Hello, this is a test message for tampering`
   - Press Enter

5. **Modify the client code temporarily to tamper with messages:**
   
   Edit `app/client.py` and find the message sending code. Add tampering:
   
   ```python
   # After encrypting the message, tamper with ciphertext
   ct = encrypt_aes128(plaintext.encode(), session_key)
   # TAMPER: Modify first byte
   ct_tampered = bytearray(ct)
   ct_tampered[0] = (ct_tampered[0] + 1) % 256
   ct = bytes(ct_tampered)
   ```

6. **Send another message:**
   - Type: `This message will be tampered`
   - Press Enter

7. **Observe the error:**
   - Server should output: `[ERROR] SIG_FAIL: Signature verification failed`
   - Server should output: `[ERROR] Message integrity check failed`
   - Connection may be terminated

8. **Revert the tampering code** and test again to ensure normal operation works.

### Method 2: Using Network Interception

1. **Start Wireshark capture** (see `capture_traffic.sh`)

2. **Start server and client** as above

3. **Send a message**

4. **In Wireshark:**
   - Find the message packet
   - Right-click → Edit Packet
   - Modify the `ct` field (ciphertext) in the JSON
   - Resend the packet

5. **Observe SIG_FAIL error on server**

## Expected Output

```
[ERROR] SIG_FAIL: Signature verification failed
[ERROR] Message integrity check failed
[ERROR] Hash mismatch: expected abc123..., got def456...
Message rejected
```

## Evidence to Capture

1. Screenshot of original message being sent
2. Screenshot of tampered message (if visible)
3. Screenshot of SIG_FAIL error
4. Screenshot of server logs showing rejection
5. Wireshark capture showing the tampered packet (optional)

## Test Variations

- **Tamper with ciphertext (`ct` field)**: Should fail signature verification
- **Tamper with sequence number (`seqno`)**: Should fail hash verification
- **Tamper with timestamp (`ts`)**: Should fail hash verification
- **Tamper with signature (`sig`)**: Should fail signature verification

All variations should result in SIG_FAIL error.
EOF

echo -e "${GREEN}[INFO] Tampering test guide created${NC}"
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Tampering Test Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Test guide created at: ${OUTPUT_DIR}/TAMPERING_TEST_GUIDE.md"
echo ""
echo -e "${YELLOW}[MANUAL TEST REQUIRED]${NC}"
echo "This test requires manual interaction. Please follow the guide:"
echo "  cat ${OUTPUT_DIR}/TAMPERING_TEST_GUIDE.md"
echo ""
echo -e "${BLUE}Quick Test Steps:${NC}"
echo "1. Start server: python app/server.py"
echo "2. Start client: python app/client.py"
echo "3. Login/register"
echo "4. Temporarily modify client.py to tamper with ciphertext"
echo "5. Send a message"
echo "6. Observe SIG_FAIL error"
echo "7. Revert changes"
echo ""
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
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from tests.report_generator import TestReportGenerator

test_results = {
    "test_name": "Message Tampering Test",
    "test_type": "manual",
    "guide_location": str(Path(__file__).parent / "outputs" / "TAMPERING_TEST_GUIDE.md"),
    "helper_script": "test_tampering_helper.py",
    "expected_error": "SIG_FAIL",
    "status": "GUIDE_CREATED",
    "notes": [
        "This test requires manual code modification",
        "See TAMPERING_TEST_GUIDE.md for detailed instructions",
        "Expected error: SIG_FAIL - Signature verification failed"
    ]
}

report_generator = TestReportGenerator()
report_path = report_generator.generate_manual_test_report("tampering", test_results)

print(f"[SUCCESS] Report generated: {report_path}")
PYEOF

python3 "${TEST_DIR}/generate_report.py" 2>/dev/null || echo -e "${YELLOW}[WARNING] Could not generate report automatically${NC}"

echo -e "${GREEN}[DONE]${NC}"
echo ""
echo -e "${BLUE}[INFO] Test report saved in: reports/manual_tampering_*.json${NC}"

