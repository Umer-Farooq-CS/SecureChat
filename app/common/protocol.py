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

from typing import Literal, Union
from pydantic import BaseModel, Field


# ============================================================================
# Control Plane Messages
# ============================================================================

class HelloMessage(BaseModel):
    """Client hello message with certificate exchange."""
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="Client certificate in PEM format")
    nonce: str = Field(..., description="Base64-encoded nonce for freshness")


class ServerHelloMessage(BaseModel):
    """Server hello message with certificate exchange."""
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="Server certificate in PEM format")
    nonce: str = Field(..., description="Base64-encoded nonce for freshness")


class RegisterMessage(BaseModel):
    """User registration message with encrypted credentials."""
    type: Literal["register"] = "register"
    email: str = Field(..., description="User email address")
    username: str = Field(..., description="Username")
    pwd: str = Field(..., description="Base64-encoded SHA256(salt||password)")
    salt: str = Field(..., description="Base64-encoded salt")


class LoginMessage(BaseModel):
    """User login message with encrypted credentials."""
    type: Literal["login"] = "login"
    email: str = Field(..., description="User email address")
    pwd: str = Field(..., description="Base64-encoded SHA256(salt||password)")
    nonce: str = Field(..., description="Base64-encoded nonce for freshness")


# ============================================================================
# Key Agreement Messages
# ============================================================================

class DHClientMessage(BaseModel):
    """Client Diffie-Hellman key exchange message."""
    type: Literal["dh_client"] = "dh_client"
    g: int = Field(..., description="Generator value")
    p: int = Field(..., description="Prime modulus")
    A: int = Field(..., description="Client public value (g^a mod p)")


class DHServerMessage(BaseModel):
    """Server Diffie-Hellman key exchange message."""
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server public value (g^b mod p)")


# ============================================================================
# Data Plane Messages
# ============================================================================

class ChatMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection", ge=1)
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded AES-128 encrypted ciphertext")
    sig: str = Field(..., description="Base64-encoded RSA signature over SHA256(seqno||ts||ct)")


# ============================================================================
# Non-Repudiation Messages
# ============================================================================

class SessionReceipt(BaseModel):
    """Session receipt for non-repudiation."""
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"] = Field(..., description="Peer type (client or server)")
    first_seq: int = Field(..., description="First sequence number in transcript", ge=1)
    last_seq: int = Field(..., description="Last sequence number in transcript", ge=1)
    transcript_sha256: str = Field(..., description="SHA-256 hash of transcript (hex)")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript hash")


# ============================================================================
# Union type for all messages
# ============================================================================

Message = Union[
    HelloMessage,
    ServerHelloMessage,
    RegisterMessage,
    LoginMessage,
    DHClientMessage,
    DHServerMessage,
    ChatMessage,
    SessionReceipt
]


# ============================================================================
# Helper functions for message parsing
# ============================================================================

def parse_message(data: Union[dict, str]) -> Message:
    """
    Parses a message from dictionary or JSON string.
    
    Args:
        data: Message data as dict or JSON string
        
    Returns:
        Message: Parsed message object
        
    Raises:
        ValueError: If message type is unknown or invalid
    """
    import json
    
    if isinstance(data, str):
        data = json.loads(data)
    
    if not isinstance(data, dict):
        raise ValueError("Message must be a dictionary or JSON string")
    
    msg_type = data.get("type")
    if not msg_type:
        raise ValueError("Message must have a 'type' field")
    
    # Map message types to model classes
    type_map = {
        "hello": HelloMessage,
        "server_hello": ServerHelloMessage,
        "register": RegisterMessage,
        "login": LoginMessage,
        "dh_client": DHClientMessage,
        "dh_server": DHServerMessage,
        "msg": ChatMessage,
        "receipt": SessionReceipt,
    }
    
    if msg_type not in type_map:
        raise ValueError(f"Unknown message type: {msg_type}")
    
    model_class = type_map[msg_type]
    return model_class(**data)


def serialize_message(message: Message) -> str:
    """
    Serializes a message to JSON string.
    
    Args:
        message: Message object to serialize
        
    Returns:
        str: JSON-serialized message string
    """
    import json
    return json.dumps(message.model_dump(), separators=(',', ':'))
