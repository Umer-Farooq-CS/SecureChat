"""
================================================================================
Assignment #2 - Secure Chat System
Information Security (CS-3002)
FAST-NUCES, Fall 2025
================================================================================

Student Information:
    Name: Umer Farooq
    Roll No: 22I-0891
    Section: CS-7D
    Instructor: Urooj Ghani

================================================================================
File: app/common/protocol.py
Purpose: Protocol message definitions using Pydantic models
================================================================================

Description:
    This module defines all message types used in the secure chat protocol
    using Pydantic models for validation and serialization. It includes:
    - Control Plane messages (hello, server_hello, register, login)
    - Key Agreement messages (dh_client, dh_server)
    - Data Plane messages (msg)
    - Non-Repudiation messages (receipt)

Message Types:
    1. HelloMessage: Client certificate exchange
    2. ServerHelloMessage: Server certificate exchange
    3. RegisterMessage: User registration with encrypted credentials
    4. LoginMessage: User login with encrypted credentials
    5. DHClientMessage: Client DH public value
    6. DHServerMessage: Server DH public value
    7. ChatMessage: Encrypted chat message with signature
    8. SessionReceipt: Signed transcript hash for non-repudiation

Links to Other Files:
    - app/client.py: Serializes client messages, deserializes server messages
    - app/server.py: Serializes server messages, deserializes client messages
    - app/crypto/aes.py: ChatMessage contains encrypted ciphertext
    - app/crypto/sign.py: ChatMessage and SessionReceipt contain signatures
    - app/common/utils.py: Uses base64 encoding for binary data

Input:
    - Message data (dictionaries or JSON strings)
    - Validated by Pydantic models

Output:
    - Validated message objects
    - JSON-serialized strings for transmission
    - Error messages for invalid message formats

Result:
    - Provides type-safe message handling
    - Ensures message format correctness
    - Enables JSON serialization/deserialization
    - Validates required fields and data types

================================================================================
"""

"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
raise NotImplementedError("students: define pydantic models")
