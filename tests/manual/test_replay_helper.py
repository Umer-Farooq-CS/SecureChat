#!/usr/bin/env python3
"""
================================================================================
Assignment #2 - Secure Chat System
Helper script for replay attack testing
================================================================================

This script helps test replay attacks by resending messages.
It can be used to demonstrate REPLAY errors.

Usage:
    python test_replay_helper.py

Note: This requires modifying the client code temporarily.
================================================================================
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

def show_replay_instructions():
    """Display instructions for testing replay attacks."""
    
    print("=" * 70)
    print("Replay Attack Test Helper")
    print("=" * 70)
    print()
    print("This script provides code snippets to test replay attacks.")
    print()
    print("STEP 1: Locate the message sending code in app/client.py")
    print("        Look for the send_chat_message or similar function")
    print()
    print("STEP 2: After successfully sending a message, add replay code:")
    print()
    print("-" * 70)
    print("REPLAY CODE SNIPPET:")
    print("-" * 70)
    print("""
# After successfully sending a message, add this to resend it:
import time

# Store the last sent message
last_message_json = message_json  # The JSON that was just sent

# Wait a moment
time.sleep(1)

# REPLAY: Resend the exact same message
print("[REPLAY TEST] Resending same message with same seqno...")
sock.sendall(last_message_json.encode('utf-8'))
""")
    print("-" * 70)
    print()
    print("Alternative: Modify seqno to reuse an old sequence number")
    print()
    print("-" * 70)
    print("ALTERNATIVE REPLAY CODE:")
    print("-" * 70)
    print("""
# Before sending, modify the seqno to reuse an old one
# For example, if current seqno is 5, change it to 2 (already used)

# In the message creation:
msg = ChatMessage(
    seqno=2,  # Use an old sequence number
    ts=now_ms(),
    ct=ciphertext,
    sig=signature
)
print("[REPLAY TEST] Sending message with reused seqno: 2")
""")
    print("-" * 70)
    print()
    print("STEP 3: Start server and client")
    print("        python app/server.py")
    print("        python app/client.py")
    print()
    print("STEP 4: Complete authentication and send a message")
    print("        The replayed message should trigger REPLAY error")
    print()
    print("STEP 5: Remove the replay code and test again")
    print("        Normal messages should work fine")
    print()
    print("=" * 70)
    print("Expected Server Output:")
    print("=" * 70)
    print("""
[ERROR] REPLAY: Sequence number 2 already used
[ERROR] Message rejected - potential replay attack
[ERROR] Expected sequence number: 5, got: 2
""")
    print()
    print("=" * 70)

if __name__ == "__main__":
    show_replay_instructions()

