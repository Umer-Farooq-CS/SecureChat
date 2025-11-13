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
File: app/client.py
Purpose: Client-side implementation of the secure chat system
================================================================================

Description:
    This module implements the client-side workflow for the secure chat system.
    It handles the complete client protocol flow including:
    - Certificate exchange and mutual authentication
    - User registration and login
    - Diffie-Hellman key exchange
    - Encrypted message exchange
    - Session transcript management
    - Non-repudiation receipt generation

Protocol Flow:
    1. BOOT → PKI_CONNECT: Establish TCP connection to server
    2. CERT_VERIFY: Verify server certificate
    3. DH_REGISTER_LOGIN_INIT: Initialize DH exchange and authentication
    4. AUTH_CRED_ENCRYPT: Send encrypted credentials (register/login)
    5. AUTH_RESPONSE_WAIT: Wait for authentication response
    6. CHAT: Encrypted message exchange loop
    7. CLOSE_CONNECTION: Graceful session termination

Links to Other Files:
    - app/common/protocol.py: Uses Pydantic models for message serialization
    - app/common/utils.py: Uses utility functions (base64, hashing, timestamps)
    - app/crypto/pki.py: Uses certificate loading and validation
    - app/crypto/dh.py: Uses Diffie-Hellman key exchange
    - app/crypto/aes.py: Uses AES-128 encryption/decryption
    - app/crypto/sign.py: Uses RSA signature generation/verification
    - app/storage/transcript.py: Uses transcript management for non-repudiation

Input:
    - Server hostname and port (from .env or command line)
    - Client certificate and private key (from certs/)
    - CA certificate (from certs/) for server certificate verification
    - User credentials (email, username, password) via console input

Output:
    - Console messages showing connection status
    - Encrypted messages sent to server
    - Decrypted messages received from server
    - Session transcript file (in transcripts/)
    - SessionReceipt JSON file (in transcripts/)

Result:
    - Establishes secure communication channel with server
    - Enables encrypted chat messaging
    - Maintains cryptographic proof of communication (transcript + receipt)

================================================================================
"""

"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import json
import os
import secrets
import socket
import threading
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
    generate_dh_parameters,
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
from app.storage.transcript import TranscriptManager


class SecureChatClient:
    """Secure chat client implementing CIANR protocol."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8888,
        client_cert_path: str = "certs/client-cert.pem",
        client_key_path: str = "certs/client-key.pem",
        ca_cert_path: str = "certs/ca-cert.pem"
    ):
        """
        Initializes secure chat client.
        
        Args:
            host: Server hostname
            port: Server port
            client_cert_path: Path to client certificate
            client_key_path: Path to client private key
            ca_cert_path: Path to CA certificate
        """
        self.host = host
        self.port = port
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.ca_cert_path = ca_cert_path
        
        # Load client certificate and key
        self.client_cert = load_certificate_from_file(client_cert_path)
        with open(client_key_path, "rb") as f:
            self.client_key = load_private_key_from_pem(f.read())
        
        # Load CA certificate
        self.ca_cert = load_certificate_from_file(ca_cert_path)
        
        # Client certificate as PEM string
        with open(client_cert_path, "rb") as f:
            self.client_cert_pem = f.read().decode('utf-8')
        
        self.socket: Optional[socket.socket] = None
    
    def send_message(self, message: dict):
        """Sends JSON message over socket."""
        data = json.dumps(message).encode('utf-8')
        # Send length prefix
        length = len(data).to_bytes(4, 'big')
        self.socket.sendall(length + data)
    
    def receive_message(self) -> dict:
        """Receives JSON message from socket."""
        # Receive length prefix
        length_bytes = self.socket.recv(4)
        if len(length_bytes) < 4:
            raise ConnectionError("Connection closed")
        length = int.from_bytes(length_bytes, 'big')
        
        # Receive message data
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        
        return json.loads(data.decode('utf-8'))
    
    def connect(self):
        """Connects to server and performs full protocol handshake."""
        try:
            # Connect to server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"[INFO] Connected to server at {self.host}:{self.port}")
            
            # Phase 1: Certificate Exchange
            print("[INFO] Starting certificate exchange...")
            
            # Send client hello
            client_nonce = secrets.token_bytes(16)
            client_hello = HelloMessage(
                client_cert=self.client_cert_pem,
                nonce=b64e(client_nonce)
            )
            self.send_message(client_hello.model_dump())
            
            # Receive server hello
            server_hello_data = self.receive_message()
            server_hello = parse_message(server_hello_data)
            
            if not isinstance(server_hello, ServerHelloMessage):
                raise ValueError("Expected ServerHelloMessage")
            
            # Load and validate server certificate
            server_cert = load_certificate_from_bytes(server_hello.server_cert.encode('utf-8'))
            try:
                validate_certificate(server_cert, self.ca_cert, expected_hostname="server.local")
                print("[INFO] Certificate verified")
            except CertificateValidationError as e:
                print(f"[ERROR] BAD_CERT: {e}")
                self.socket.close()
                return False
            
            # Phase 2: Temporary DH for Credential Encryption
            print("[INFO] Establishing temporary DH key for credential encryption...")
            
            # Generate DH parameters and client private key
            dh_params = generate_dh_parameters(generator=2, key_size=2048)
            client_dh_private = generate_private_key(dh_params)
            client_dh_public = get_public_key(client_dh_private)
            client_dh_value = get_public_value(client_dh_public)
            
            # Get parameters as numbers
            param_numbers = dh_params.parameter_numbers()
            
            # Send client DH message
            client_dh = DHClientMessage(
                g=param_numbers.g,
                p=param_numbers.p,
                A=client_dh_value
            )
            self.send_message(client_dh.model_dump())
            
            # Receive server DH response
            server_dh_data = self.receive_message()
            server_dh = parse_message(server_dh_data)
            
            if not isinstance(server_dh, DHServerMessage):
                raise ValueError("Expected DHServerMessage")
            
            # Derive temporary AES key
            server_dh_public = create_public_key_from_value(server_dh.B, dh_params)
            temp_shared_secret = exchange_key(client_dh_private, server_dh_public)
            temp_aes_key = derive_session_key(temp_shared_secret)
            
            # Phase 3: Registration/Login
            print("Choose action: [1] Register [2] Login")
            choice = input("> ").strip()
            
            if choice == "1":
                # Registration
                email = input("Enter email: ").strip()
                username = input("Enter username: ").strip()
                password = input("Enter password: ").strip()
                
                # Encrypt password with temporary AES key
                encrypted_pwd = encrypt_aes128(password.encode('utf-8'), temp_aes_key)
                
                # Create registration message
                # Note: salt is generated by server, so we send empty or placeholder
                register_msg = RegisterMessage(
                    email=email,
                    username=username,
                    pwd=encrypted_pwd,  # Already base64-encoded by encrypt_aes128
                    salt=b64e(secrets.token_bytes(16))  # Placeholder, server will generate
                )
                
                self.send_message(register_msg.model_dump())
                
                # Receive response
                response = self.receive_message()
                if response.get("status") == "success":
                    print("[INFO] Registration successful!")
                else:
                    print(f"[ERROR] Registration failed: {response.get('message')}")
                    self.socket.close()
                    return False
                    
            elif choice == "2":
                # Login
                email = input("Enter email: ").strip()
                password = input("Enter password: ").strip()
                
                # Encrypt password with temporary AES key
                encrypted_pwd = encrypt_aes128(password.encode('utf-8'), temp_aes_key)
                
                # Create login message
                login_nonce = secrets.token_bytes(16)
                login_msg = LoginMessage(
                    email=email,
                    pwd=encrypted_pwd,  # Already base64-encoded by encrypt_aes128
                    nonce=b64e(login_nonce)
                )
                
                self.send_message(login_msg.model_dump())
                
                # Receive response
                response = self.receive_message()
                if response.get("status") == "success":
                    print("[INFO] Login successful!")
                else:
                    print(f"[ERROR] Login failed: {response.get('message')}")
                    self.socket.close()
                    return False
            else:
                print("[ERROR] Invalid choice")
                self.socket.close()
                return False
            
            # Phase 4: Session Key Establishment (New DH Exchange)
            print("[INFO] Establishing session key...")
            
            # Generate session DH parameters
            session_params = generate_dh_parameters(generator=2, key_size=2048)
            client_session_private = generate_private_key(session_params)
            client_session_public = get_public_key(client_session_private)
            client_session_value = get_public_value(client_session_public)
            
            session_param_numbers = session_params.parameter_numbers()
            
            # Send client session DH
            session_dh = DHClientMessage(
                g=session_param_numbers.g,
                p=session_param_numbers.p,
                A=client_session_value
            )
            self.send_message(session_dh.model_dump())
            
            # Receive server session DH
            server_session_dh_data = self.receive_message()
            server_session_dh = parse_message(server_session_dh_data)
            
            if not isinstance(server_session_dh, DHServerMessage):
                raise ValueError("Expected DHServerMessage for session")
            
            # Derive session key
            server_session_public = create_public_key_from_value(server_session_dh.B, session_params)
            session_shared_secret = exchange_key(client_session_private, server_session_public)
            session_key = derive_session_key(session_shared_secret)
            
            print("[INFO] Session key established")
            print("[INFO] Entering chat mode...")
            
            # Phase 5: Encrypted Chat Loop
            # Initialize transcript
            transcript = TranscriptManager()
            transcript.create_transcript()
            
            server_cert_fingerprint = get_certificate_fingerprint(server_cert)
            server_public_key = get_public_key_from_certificate(server_cert)
            
            seqno = 1
            running = True
            
            # Start receiving thread
            def receive_messages():
                nonlocal running
                expected_seqno = 1
                while running:
                    try:
                        msg_data = self.receive_message()
                        msg = parse_message(msg_data)
                        
                        if isinstance(msg, ChatMessage):
                            # Verify sequence number
                            if msg.seqno != expected_seqno:
                                print(f"[ERROR] REPLAY: Expected seqno {expected_seqno}, got {msg.seqno}")
                                continue
                            
                            # Compute hash for signature verification
                            hash_input = f"{msg.seqno}{msg.ts}{msg.ct}".encode('utf-8')
                            computed_hash = sha256_hex(hash_input)
                            hash_bytes = bytes.fromhex(computed_hash)
                            
                            # Verify signature
                            if not verify_signature(msg.sig, hash_bytes, server_public_key):
                                print(f"[ERROR] SIG_FAIL: Signature verification failed for message {msg.seqno}")
                                continue
                            
                            # Decrypt message
                            try:
                                plaintext = decrypt_aes128(msg.ct, session_key).decode('utf-8')
                                print(f"[Received] Server: {plaintext}")
                            except Exception as e:
                                print(f"[ERROR] Decryption failed: {e}")
                                continue
                            
                            # Add to transcript
                            transcript.add_entry(
                                msg.seqno,
                                msg.ts,
                                msg.ct,
                                msg.sig,
                                server_cert_fingerprint
                            )
                            
                            expected_seqno += 1
                        elif isinstance(msg, dict) and msg.get("type") == "close":
                            running = False
                            break
                    except (ConnectionError, ValueError, json.JSONDecodeError) as e:
                        print(f"[ERROR] Error receiving message: {e}")
                        running = False
                        break
            
            receive_thread = threading.Thread(target=receive_messages, daemon=True)
            receive_thread.start()
            
            # Send messages
            while running:
                try:
                    message_text = input("> ")
                    if not message_text:
                        continue
                    
                    if message_text.lower() == "/quit":
                        # Send close message
                        self.send_message({"type": "close"})
                        running = False
                        break
                    
                    # Encrypt and sign message
                    msg_ts = now_ms()
                    msg_ct = encrypt_aes128(message_text.encode('utf-8'), session_key)
                    
                    # Compute hash and sign
                    hash_input = f"{seqno}{msg_ts}{msg_ct}".encode('utf-8')
                    msg_hash = sha256_hex(hash_input)
                    msg_sig = sign_data(bytes.fromhex(msg_hash), self.client_key)
                    
                    msg = ChatMessage(
                        seqno=seqno,
                        ts=msg_ts,
                        ct=msg_ct,
                        sig=msg_sig
                    )
                    
                    self.send_message(msg.model_dump())
                    
                    # Add to transcript
                    transcript.add_entry(
                        seqno,
                        msg_ts,
                        msg_ct,
                        msg_sig,
                        server_cert_fingerprint
                    )
                    
                    seqno += 1
                    
                except (ConnectionError, KeyboardInterrupt) as e:
                    print(f"\n[INFO] Closing connection: {e}")
                    running = False
                    break
            
            # Wait for receive thread
            receive_thread.join(timeout=1)
            
            # Phase 6: Generate Session Receipt
            print("[INFO] Generating session receipt...")
            receipt = transcript.generate_receipt("client", self.client_key)
            receipt_path = transcript.save_receipt(receipt)
            print(f"[INFO] Session receipt saved to {receipt_path}")
            
            self.socket.close()
            print("[INFO] Connection closed")
            return True
            
        except Exception as e:
            print(f"[ERROR] Error: {e}")
            import traceback
            traceback.print_exc()
            if self.socket:
                self.socket.close()
            return False


def main():
    """Main entry point for client."""
    config = get_config()
    
    client = SecureChatClient(
        host=config.server.host,
        port=config.server.port,
        client_cert_path=config.client.cert_path,
        client_key_path=config.client.key_path,
        ca_cert_path=config.ca.cert_path
    )
    
    client.connect()


if __name__ == "__main__":
    main()
