#!/usr/bin/env python3
"""
================================================================================
Assignment #2 - Secure Chat System
Helper script for message tampering testing
================================================================================

This script helps test message tampering by modifying messages before sending.
It can be used to demonstrate SIG_FAIL errors.

Usage:
    python test_tampering_helper.py

Note: This requires modifying the client code temporarily.
================================================================================
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

def show_tampering_instructions():
    """Display instructions for testing message tampering."""
    
    print("=" * 70)
    print("Message Tampering Test Helper")
    print("=" * 70)
    print()
    print("This script provides code snippets to test message tampering.")
    print()
    print("STEP 1: Locate the message sending code in app/client.py")
    print("        Look for the send_chat_message or similar function")
    print()
    print("STEP 2: Find where ciphertext is created, add tampering code:")
    print()
    print("-" * 70)
    print("TAMPERING CODE SNIPPET:")
    print("-" * 70)
    print("""
# After encrypting the message, add this code to tamper with ciphertext:
from app.common.utils import b64d, b64e

# Decode the base64 ciphertext
ct_bytes = b64d(ct)

# Tamper: Modify first byte
ct_tampered = bytearray(ct_bytes)
if len(ct_tampered) > 0:
    ct_tampered[0] = (ct_tampered[0] + 1) % 256

# Re-encode
ct = b64e(bytes(ct_tampered))
print("[TAMPERING] Modified ciphertext first byte")
""")
    print("-" * 70)
    print()
    print("STEP 3: Start server and client")
    print("        python app/server.py")
    print("        python app/client.py")
    print()
    print("STEP 4: Complete authentication and send a message")
    print("        The tampered message should trigger SIG_FAIL error")
    print()
    print("STEP 5: Remove the tampering code and test again")
    print("        Normal messages should work fine")
    print()
    print("=" * 70)
    print("Expected Server Output:")
    print("=" * 70)
    print("""
[ERROR] SIG_FAIL: Signature verification failed
[ERROR] Message integrity check failed
[ERROR] Hash mismatch: expected abc123..., got def456...
Message rejected
""")
    print()
    print("=" * 70)

if __name__ == "__main__":
    show_tampering_instructions()

