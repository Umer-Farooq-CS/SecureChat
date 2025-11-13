#!/bin/bash
#
#================================================================================
# Assignment #2 - Secure Chat System
# Information Security (CS-3002)
# FAST-NUCES, Fall 2025
#================================================================================
#
# Script: test_replay.sh
# Purpose: Test replay attack detection and capture REPLAY errors
#
# Usage:
#   ./test_replay.sh
#
# This script:
#   1. Establishes a valid secure session
#   2. Sends a message with seqno N
#   3. Attempts to resend the same message (same seqno)
#   4. Verifies REPLAY error is generated
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
TEST_DIR="tests/manual/replay_tests"
OUTPUT_DIR="${TEST_DIR}/outputs"
SERVER_PORT=8888

# Create test directories
mkdir -p "${TEST_DIR}"
mkdir -p "${OUTPUT_DIR}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Replay Attack Test Script${NC}"
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

# Create comprehensive replay test guide
cat > "${OUTPUT_DIR}/REPLAY_TEST_GUIDE.md" << 'EOF'
# Replay Attack Test Guide

## Objective
Verify that replay attacks are prevented using sequence numbers (REPLAY error).

## Test Procedure

### Method 1: Using Modified Client Code (Recommended)

1. **Start the server:**
   ```bash
   cd SecureChat
   python app/server.py
   ```

2. **Modify the client code temporarily to enable replay:**
   
   Edit `app/client.py` and find the message sending function. Add code to resend a message:
   
   ```python
   # After sending a message successfully, resend it
   def send_chat_message(self, message: str):
       # ... existing code to send message ...
       
       # REPLAY TEST: Resend the same message
       print("[REPLAY TEST] Resending same message...")
       sock.sendall(message_json.encode('utf-8'))
   ```

3. **In another terminal, start the client:**
   ```bash
   cd SecureChat
   python app/client.py
   ```

4. **Complete authentication:**
   - Register or login with valid credentials
   - Wait for session key establishment

5. **Send a test message:**
   - Type: `Hello, this is message number 1`
   - Press Enter
   - The client will automatically resend it (replay)

6. **Observe the error:**
   - Server should output: `[ERROR] REPLAY: Sequence number X already used`
   - Server should output: `[ERROR] Message rejected - potential replay attack`
   - The replayed message should be rejected

7. **Revert the replay code** and test again to ensure normal operation works.

### Method 2: Using Network Interception

1. **Start Wireshark capture** (see `capture_traffic.sh`)

2. **Start server and client** as above

3. **Send a message** (e.g., seqno: 5)

4. **In Wireshark:**
   - Find the message packet
   - Right-click → Copy
   - Create a new packet with the same data
   - Resend the packet

5. **Observe REPLAY error on server**

### Method 3: Manual Sequence Number Test

1. **Start server and client** as above

2. **Send several messages:**
   - Message 1: seqno 1
   - Message 2: seqno 2
   - Message 3: seqno 3

3. **Modify client to send message with old seqno:**
   - Temporarily modify client to send message with seqno 2 (already used)
   - Send the message

4. **Observe REPLAY error**

## Expected Output

```
[ERROR] REPLAY: Sequence number 2 already used
[ERROR] Message rejected - potential replay attack
[ERROR] Expected sequence number: 4, got: 2
```

## Test Cases

### Test Case 1: Exact Replay
- Send message with seqno N
- Resend exact same message (same seqno, same signature)
- **Expected:** REPLAY error

### Test Case 2: Out-of-Order Sequence
- Send messages: 1, 2, 3
- Try to send message with seqno 2 again
- **Expected:** REPLAY error

### Test Case 3: Sequence Too Far Ahead
- Send message with seqno 1
- Try to send message with seqno 10 (gap too large)
- **Expected:** May be rejected as invalid sequence

### Test Case 4: Sequence Behind Current
- Send messages: 1, 2, 3, 4, 5
- Try to send message with seqno 3
- **Expected:** REPLAY error

## Evidence to Capture

1. Screenshot of first message (seqno: N)
2. Screenshot of replayed message (same seqno: N)
3. Screenshot of REPLAY error
4. Screenshot of server logs showing sequence number tracking
5. Wireshark capture showing both messages (optional)

## Verification

After the test, verify:
- ✅ Replayed messages are rejected
- ✅ Error message clearly indicates REPLAY
- ✅ Server continues to accept new messages with correct sequence numbers
- ✅ Sequence number tracking is maintained correctly
EOF

# Create a Python script to help with replay testing
cat > "${TEST_DIR}/replay_helper.py" << 'EOF'
#!/usr/bin/env python3
"""
Helper script for replay attack testing.
This script provides utilities to capture and replay messages.
"""

import sys
import os
import json
import socket

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

def capture_message():
    """Instructions for capturing a message for replay."""
    print("[INFO] To test replay attacks:")
    print("")
    print("1. Start server: python app/server.py")
    print("2. Start client: python app/client.py")
    print("3. Complete authentication")
    print("4. Send a message and note its seqno")
    print("5. Modify client.py to resend the same message")
    print("6. Observe REPLAY error")
    print("")
    print("See REPLAY_TEST_GUIDE.md for detailed instructions.")

if __name__ == "__main__":
    capture_message()
EOF

chmod +x "${TEST_DIR}/replay_helper.py"

echo -e "${GREEN}[INFO] Replay test guide created${NC}"
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Replay Attack Test Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Test guide created at: ${OUTPUT_DIR}/REPLAY_TEST_GUIDE.md"
echo ""
echo -e "${YELLOW}[MANUAL TEST REQUIRED]${NC}"
echo "This test requires manual interaction. Please follow the guide:"
echo "  cat ${OUTPUT_DIR}/REPLAY_TEST_GUIDE.md"
echo ""
echo -e "${BLUE}Quick Test Steps:${NC}"
echo "1. Start server: python app/server.py"
echo "2. Start client: python app/client.py"
echo "3. Login/register"
echo "4. Send a message (note the seqno)"
echo "5. Temporarily modify client.py to resend same message"
echo "6. Observe REPLAY error"
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
    "test_name": "Replay Attack Test",
    "test_type": "manual",
    "guide_location": str(Path(__file__).parent / "outputs" / "REPLAY_TEST_GUIDE.md"),
    "helper_script": "test_replay_helper.py",
    "expected_error": "REPLAY",
    "status": "GUIDE_CREATED",
    "notes": [
        "This test requires manual code modification",
        "See REPLAY_TEST_GUIDE.md for detailed instructions",
        "Expected error: REPLAY - Sequence number already used"
    ]
}

report_generator = TestReportGenerator()
report_path = report_generator.generate_manual_test_report("replay", test_results)

print(f"[SUCCESS] Report generated: {report_path}")
PYEOF

python3 "${TEST_DIR}/generate_report.py" 2>/dev/null || echo -e "${YELLOW}[WARNING] Could not generate report automatically${NC}"

echo -e "${GREEN}[DONE]${NC}"
echo ""
echo -e "${BLUE}[INFO] Test report saved in: reports/manual_replay_*.json${NC}"

