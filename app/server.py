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
File: app/server.py
Purpose: Server-side implementation of the secure chat system
================================================================================

Description:
    This module implements the server-side workflow for the secure chat system.
    It handles multiple client connections and manages:
    - Certificate exchange and mutual authentication
    - User registration and login verification
    - Diffie-Hellman key exchange
    - Encrypted message exchange
    - Session transcript management
    - Non-repudiation receipt generation

Protocol Flow:
    1. LISTEN: Wait for incoming client connections
    2. SEND_SERVER_CERT: Send server certificate to client
    3. AUTH_CRED_DECRYPT_VERIFY: Decrypt and verify client credentials
    4. DH_CHAT_INIT: Complete DH exchange and establish session key
    5. CHAT_LOOP: Encrypted message exchange loop
    6. CLOSE_CLIENT_CONNECTION: Terminate session and return to LISTEN

Links to Other Files:
    - app/common/protocol.py: Uses Pydantic models for message deserialization
    - app/common/utils.py: Uses utility functions (base64, hashing, timestamps)
    - app/crypto/pki.py: Uses certificate loading and validation
    - app/crypto/dh.py: Uses Diffie-Hellman key exchange
    - app/crypto/aes.py: Uses AES-128 encryption/decryption
    - app/crypto/sign.py: Uses RSA signature verification
    - app/storage/db.py: Uses database for user registration and authentication
    - app/storage/transcript.py: Uses transcript management for non-repudiation

Input:
    - Server hostname and port (from .env or command line)
    - Server certificate and private key (from certs/)
    - CA certificate (from certs/) for client certificate verification
    - MySQL database connection (from .env)

Output:
    - Console logs showing connection status and client activity
    - Encrypted messages sent to clients
    - Decrypted messages received from clients
    - Session transcript files (in transcripts/)
    - SessionReceipt JSON files (in transcripts/)

Result:
    - Accepts multiple client connections
    - Manages secure chat sessions
    - Maintains cryptographic proof of communication (transcript + receipt)
    - Stores user credentials securely in MySQL database

================================================================================
"""

"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import json
import os
import secrets
import socket
from typing import Optional

from config import get_config

from app.common.protocol import (
    ChatMessage,
    DHClientMessage,
    DHServerMessage,
    HelloMessage,
    LoginMessage,
    parse_message,
    RegisterMessage,
    ServerHelloMessage,
)
from app.common.utils import b64e, b64d, now_ms, sha256_hex
from app.crypto.aes import decrypt_aes128, encrypt_aes128
from app.crypto.dh import (
    create_dh_parameters_from_numbers,
    create_public_key_from_value,
    derive_session_key,
    exchange_key,
    generate_private_key,
    get_public_key,
    get_public_value,
)
from app.crypto.pki import (
    CertificateValidationError,
    get_certificate_fingerprint,
    get_public_key_from_certificate,
    load_certificate_from_bytes,
    load_certificate_from_file,
    validate_certificate,
)
from app.crypto.sign import load_private_key_from_pem, sign_data, verify_signature
from app.storage.db import AuthenticationError, UserExistsError, authenticate_user, register_user
from app.storage.transcript import TranscriptManager


class SecureChatServer:
    """Secure chat server implementing CIANR protocol."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8888,
        server_cert_path: str = "certs/server-cert.pem",
        server_key_path: str = "certs/server-key.pem",
        ca_cert_path: str = "certs/ca-cert.pem"
    ):
        """
        Initializes secure chat server.
        
        Args:
            host: Server hostname
            port: Server port
            server_cert_path: Path to server certificate
            server_key_path: Path to server private key
            ca_cert_path: Path to CA certificate
        """
        self.host = host
        self.port = port
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path
        self.ca_cert_path = ca_cert_path
        
        # Load server certificate and key
        self.server_cert = load_certificate_from_file(server_cert_path)
        with open(server_key_path, "rb") as f:
            self.server_key = load_private_key_from_pem(f.read())
        
        # Load CA certificate
        self.ca_cert = load_certificate_from_file(ca_cert_path)
        
        # Server certificate as PEM string
        with open(server_cert_path, "rb") as f:
            self.server_cert_pem = f.read().decode('utf-8')
        
        self.socket: Optional[socket.socket] = None
    
    def send_message(self, conn: socket.socket, message: dict):
        """Sends JSON message over socket."""
        data = json.dumps(message).encode('utf-8')
        # Send length prefix
        length = len(data).to_bytes(4, 'big')
        conn.sendall(length + data)
    
    def receive_message(self, conn: socket.socket) -> dict:
        """Receives JSON message from socket."""
        # Receive length prefix
        length_bytes = conn.recv(4)
        if len(length_bytes) < 4:
            raise ConnectionError("Connection closed")
        length = int.from_bytes(length_bytes, 'big')
        
        # Receive message data
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        
        return json.loads(data.decode('utf-8'))
    
    def handle_client(self, conn: socket.socket, addr: tuple):
        """Handles a single client connection."""
        try:
            print(f"[INFO] Client connected from {addr[0]}:{addr[1]}")
            
            # Phase 1: Certificate Exchange
            print("[INFO] Starting certificate exchange...")
            
            # Receive client hello
            client_hello_data = self.receive_message(conn)
            client_hello = parse_message(client_hello_data)
            
            if not isinstance(client_hello, HelloMessage):
                raise ValueError("Expected HelloMessage")
            
            # Load and validate client certificate
            client_cert = load_certificate_from_bytes(client_hello.client_cert.encode('utf-8'))
            try:
                validate_certificate(client_cert, self.ca_cert, expected_hostname=None)
                print("[INFO] Client certificate verified")
            except CertificateValidationError as e:
                print(f"[ERROR] BAD_CERT: {e}")
                conn.close()
                return
            
            # Send server hello
            server_nonce = secrets.token_bytes(16)
            server_hello = ServerHelloMessage(
                server_cert=self.server_cert_pem,
                nonce=b64e(server_nonce)
            )
            self.send_message(conn, server_hello.model_dump())
            
            # Phase 2: Temporary DH for Credential Encryption
            print("[INFO] Establishing temporary DH key for credential encryption...")
            
            # Receive client DH message
            client_dh_data = self.receive_message(conn)
            client_dh = parse_message(client_dh_data)
            
            if not isinstance(client_dh, DHClientMessage):
                raise ValueError("Expected DHClientMessage")
            
            # Create DH parameters and generate server private key
            dh_params = create_dh_parameters_from_numbers(client_dh.p, client_dh.g)
            server_dh_private = generate_private_key(dh_params)
            server_dh_public = get_public_key(server_dh_private)
            server_dh_value = get_public_value(server_dh_public)
            
            # Send server DH response
            server_dh = DHServerMessage(B=server_dh_value)
            self.send_message(conn, server_dh.model_dump())
            
            # Derive temporary AES key
            client_dh_public = create_public_key_from_value(client_dh.A, dh_params)
            temp_shared_secret = exchange_key(server_dh_private, client_dh_public)
            temp_aes_key = derive_session_key(temp_shared_secret)
            
            # Phase 3: Registration/Login
            print("[INFO] Waiting for authentication...")
            
            auth_data = self.receive_message(conn)
            auth_msg = parse_message(auth_data)
            
            if isinstance(auth_msg, RegisterMessage):
                # Decrypt registration data (pwd is already base64-encoded encrypted password)
                password = decrypt_aes128(auth_msg.pwd, temp_aes_key).decode('utf-8')
                
                # Register user
                try:
                    register_user(auth_msg.email, auth_msg.username, password)
                    print(f"[INFO] User '{auth_msg.username}' registered successfully")
                    response = {"status": "success", "message": "Registration successful"}
                except UserExistsError as e:
                    print(f"[ERROR] Registration failed: {e}")
                    response = {"status": "error", "message": str(e)}
                    self.send_message(conn, response)
                    conn.close()
                    return
                
                self.send_message(conn, response)
                
            elif isinstance(auth_msg, LoginMessage):
                # Decrypt login data (pwd is already base64-encoded encrypted password)
                password = decrypt_aes128(auth_msg.pwd, temp_aes_key).decode('utf-8')
                
                # Authenticate user
                try:
                    success, user_data = authenticate_user(auth_msg.email, password)
                    if success:
                        print(f"[INFO] User '{user_data['username']}' authenticated successfully")
                        response = {"status": "success", "message": "Login successful"}
                    else:
                        response = {"status": "error", "message": "Authentication failed"}
                except AuthenticationError as e:
                    print(f"[ERROR] Authentication failed: {e}")
                    response = {"status": "error", "message": str(e)}
                    self.send_message(conn, response)
                    conn.close()
                    return
                
                self.send_message(conn, response)
                
                if not success:
                    conn.close()
                    return
            else:
                print("[ERROR] Invalid authentication message")
                conn.close()
                return
            
            # Phase 4: Session Key Establishment (New DH Exchange)
            print("[INFO] Establishing session key...")
            
            # Receive client session DH
            session_dh_data = self.receive_message(conn)
            session_dh = parse_message(session_dh_data)
            
            if not isinstance(session_dh, DHClientMessage):
                raise ValueError("Expected DHClientMessage for session")
            
            # Generate server session DH key
            session_params = create_dh_parameters_from_numbers(session_dh.p, session_dh.g)
            server_session_private = generate_private_key(session_params)
            server_session_public = get_public_key(server_session_private)
            server_session_value = get_public_value(server_session_public)
            
            # Send server session DH
            server_session_dh = DHServerMessage(B=server_session_value)
            self.send_message(conn, server_session_dh.model_dump())
            
            # Derive session key
            client_session_public = create_public_key_from_value(session_dh.A, session_params)
            session_shared_secret = exchange_key(server_session_private, client_session_public)
            session_key = derive_session_key(session_shared_secret)
            
            print("[INFO] Session key established")
            
            # Phase 5: Encrypted Chat Loop
            print("[INFO] Entering chat mode...")
            
            # Initialize transcript
            transcript = TranscriptManager()
            transcript.create_transcript()
            
            client_cert_fingerprint = get_certificate_fingerprint(client_cert)
            client_public_key = get_public_key_from_certificate(client_cert)
            
            expected_seqno = 1
            
            while True:
                try:
                    # Receive message
                    msg_data = self.receive_message(conn)
                    msg = parse_message(msg_data)
                    
                    if not isinstance(msg, ChatMessage):
                        # Check for session end
                        if isinstance(msg, dict) and msg.get("type") == "close":
                            break
                        continue
                    
                    # Verify sequence number (replay protection)
                    if msg.seqno != expected_seqno:
                        print(f"[ERROR] REPLAY: Expected seqno {expected_seqno}, got {msg.seqno}")
                        error_response = {"status": "error", "message": "REPLAY: Invalid sequence number"}
                        self.send_message(conn, error_response)
                        continue
                    
                    # Compute hash for signature verification
                    hash_input = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
                    computed_hash = sha256_hex(hash_input)
                    hash_bytes = bytes.fromhex(computed_hash)
                    
                    # Verify signature
                    if not verify_signature(msg.sig, hash_bytes, client_public_key):
                        print(f"[ERROR] SIG_FAIL: Signature verification failed for message {msg.seqno}")
                        error_response = {"status": "error", "message": "SIG_FAIL: Signature verification failed"}
                        self.send_message(conn, error_response)
                        continue
                    
                    # Decrypt message
                    try:
                        plaintext = decrypt_aes128(msg.ct, session_key).decode('utf-8')
                        print(f"[Received] Client: {plaintext}")
                        print(f"[INFO] Message #{msg.seqno} verified")
                    except Exception as e:
                        print(f"[ERROR] Decryption failed: {e}")
                        continue
                    
                    # Add to transcript
                    transcript.add_entry(
                        msg.seqno,
                        msg.ts,
                        msg.ct,
                        msg.sig,
                        client_cert_fingerprint
                    )
                    
                    expected_seqno += 1
                    
                    # Send response
                    response_text = input("> ")
                    if not response_text:
                        continue
                    
                    # Encrypt and sign response
                    response_seqno = expected_seqno
                    response_ts = now_ms()
                    response_ct = encrypt_aes128(response_text.encode('utf-8'), session_key)
                    
                    # Compute hash and sign
                    response_hash_input = f"{response_seqno}{response_ts}{response_ct}".encode('utf-8')
                    response_hash = sha256_hex(response_hash_input)
                    response_sig = sign_data(bytes.fromhex(response_hash), self.server_key)
                    
                    response_msg = ChatMessage(
                        seqno=response_seqno,
                        ts=response_ts,
                        ct=response_ct,
                        sig=response_sig
                    )
                    
                    self.send_message(conn, response_msg.model_dump())
                    
                    # Add to transcript
                    transcript.add_entry(
                        response_seqno,
                        response_ts,
                        response_ct,
                        response_sig,
                        client_cert_fingerprint
                    )
                    
                    expected_seqno += 1
                    
                except (ConnectionError, ValueError) as e:
                    print(f"[ERROR] Error in chat loop: {e}")
                    break
            
            # Phase 6: Generate Session Receipt
            print("[INFO] Generating session receipt...")
            receipt = transcript.generate_receipt("server", self.server_key)
            receipt_path = transcript.save_receipt(receipt)
            print(f"[INFO] Session receipt saved to {receipt_path}")
            
            conn.close()
            print(f"[INFO] Client {addr[0]}:{addr[1]} disconnected")
            
        except Exception as e:
            print(f"[ERROR] Error handling client: {e}")
            import traceback
            traceback.print_exc()
            if conn:
                conn.close()
    
    def start(self):
        """Starts the server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"[INFO] Server starting on {self.host}:{self.port}")
            print(f"[INFO] Loading server certificate from {self.server_cert_path}")
            print("[INFO] Server listening for connections...")
            
            while True:
                conn, addr = self.socket.accept()
                self.handle_client(conn, addr)
                
        except KeyboardInterrupt:
            print("\n[INFO] Server shutting down...")
        except Exception as e:
            print(f"[ERROR] Server error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.socket:
                self.socket.close()


def main():
    """Main entry point for server."""
    config = get_config()
    
    server = SecureChatServer(
        host=config.server.host,
        port=config.server.port,
        server_cert_path=config.server.cert_path,
        server_key_path=config.server.key_path,
        ca_cert_path=config.ca.cert_path
    )
    
    server.start()


if __name__ == "__main__":
    main()
