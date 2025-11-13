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
File: app/storage/transcript.py
Purpose: Session transcript management and non-repudiation
================================================================================

Description:
    This module manages session transcripts for non-repudiation. It provides:
    - Append-only transcript file management
    - Transcript hash computation
    - SessionReceipt generation and signing
    - Offline transcript verification

Key Features:
    - Maintains append-only transcript (seqno | ts | ct | sig | peer-cert-fingerprint)
    - Computes transcript hash: SHA256(concatenation of all transcript lines)
    - Generates signed SessionReceipt for non-repudiation
    - Enables offline verification of transcript integrity

Transcript Format:
    seqno | timestamp | ciphertext | signature | peer-cert-fingerprint

SessionReceipt Format (JSON):
    {
        "type": "receipt",
        "peer": "client|server",
        "first_seq": 1,
        "last_seq": 10,
        "transcript_sha256": "hex_hash",
        "sig": "base64_rsa_signature"
    }

Links to Other Files:
    - app/client.py: Maintains client-side transcript and generates receipt
    - app/server.py: Maintains server-side transcript and generates receipt
    - app/crypto/sign.py: Signs transcript hash for SessionReceipt
    - app/crypto/pki.py: Extracts certificate fingerprint
    - app/common/utils.py: Uses SHA-256 for transcript hashing

Input:
    - Message metadata (seqno, timestamp, ciphertext, signature)
    - Peer certificate fingerprint
    - Private key (for signing SessionReceipt)

Output:
    - Transcript file (in transcripts/ directory)
    - SessionReceipt JSON file
    - Verification results (for offline verification)

Result:
    - Provides cryptographic proof of communication
    - Enables non-repudiation (neither party can deny participation)
    - Allows offline verification of transcript integrity
    - Serves as evidence for audit purposes

================================================================================
"""

"""Append-only transcript + TranscriptHash helpers."""

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa

from app.common.protocol import SessionReceipt
from app.common.utils import b64d, sha256_hex
from app.crypto.pki import get_certificate_fingerprint, load_certificate_from_file
from app.crypto.sign import load_private_key_from_pem, sign_data, verify_signature
from config import get_config


class TranscriptManager:
    """Manages append-only session transcripts for non-repudiation."""
    
    def __init__(self, transcript_dir: Optional[str] = None):
        """
        Initializes transcript manager.
        
        Args:
            transcript_dir: Directory to store transcript files. If None, uses config value.
        """
        if transcript_dir is None:
            config = get_config()
            transcript_dir = config.paths.transcripts_dir
        self.transcript_dir = Path(transcript_dir)
        self.transcript_dir.mkdir(parents=True, exist_ok=True)
        self.transcript_file: Optional[Path] = None
        self.entries: list = []
        self.first_seq: Optional[int] = None
        self.last_seq: Optional[int] = None
    
    def create_transcript(self, session_id: Optional[str] = None) -> Path:
        """
        Creates a new transcript file.
        
        Args:
            session_id: Optional session identifier. If None, generates from timestamp.
            
        Returns:
            Path: Path to transcript file
        """
        if session_id is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_id = f"session_{timestamp}"
        
        self.transcript_file = self.transcript_dir / f"{session_id}.txt"
        self.entries = []
        self.first_seq = None
        self.last_seq = None
        
        # Create empty file
        self.transcript_file.touch()
        
        return self.transcript_file
    
    def add_entry(
        self,
        seqno: int,
        timestamp: int,
        ciphertext: str,
        signature: str,
        peer_cert_fingerprint: str
    ):
        """
        Adds an entry to the transcript (append-only).
        
        Format: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
        
        Args:
            seqno: Sequence number
            timestamp: Unix timestamp in milliseconds
            ciphertext: Base64-encoded ciphertext
            signature: Base64-encoded signature
            peer_cert_fingerprint: Peer certificate fingerprint (hex)
        """
        if self.transcript_file is None:
            raise ValueError("Transcript file not created. Call create_transcript() first.")
        
        # Track sequence numbers
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # Format: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}\n"
        
        # Append to file
        with open(self.transcript_file, "a", encoding="utf-8") as f:
            f.write(line)
        
        # Store in memory for hash computation
        self.entries.append(line.rstrip('\n'))
    
    def compute_transcript_hash(self) -> str:
        """
        Computes SHA-256 hash of transcript.
        
        Formula: SHA256(concatenation of all transcript lines)
        
        Returns:
            str: Hexadecimal hash (64 characters)
        """
        if not self.entries:
            # If no entries in memory, read from file
            if self.transcript_file and self.transcript_file.exists():
                with open(self.transcript_file, "r", encoding="utf-8") as f:
                    lines = [line.rstrip('\n') for line in f if line.strip()]
            else:
                raise ValueError("No transcript entries found")
        else:
            lines = self.entries
        
        # Concatenate all lines
        transcript_content = '\n'.join(lines)
        
        # Compute hash
        return sha256_hex(transcript_content.encode('utf-8'))
    
    def generate_receipt(
        self,
        peer_type: str,
        private_key: rsa.RSAPrivateKey
    ) -> SessionReceipt:
        """
        Generates a signed SessionReceipt for non-repudiation.
        
        Args:
            peer_type: "client" or "server"
            private_key: RSA private key for signing
            
        Returns:
            SessionReceipt: Signed session receipt
        """
        if self.first_seq is None or self.last_seq is None:
            raise ValueError("No transcript entries found")
        
        if peer_type not in ["client", "server"]:
            raise ValueError("peer_type must be 'client' or 'server'")
        
        # Compute transcript hash
        transcript_hash = self.compute_transcript_hash()
        
        # Sign the hash
        hash_bytes = bytes.fromhex(transcript_hash)
        signature = sign_data(hash_bytes, private_key)
        
        # Create SessionReceipt
        receipt = SessionReceipt(
            peer=peer_type,
            first_seq=self.first_seq,
            last_seq=self.last_seq,
            transcript_sha256=transcript_hash,
            sig=signature
        )
        
        return receipt
    
    def save_receipt(self, receipt: SessionReceipt) -> Path:
        """
        Saves SessionReceipt to JSON file.
        
        Args:
            receipt: SessionReceipt to save
            
        Returns:
            Path: Path to receipt file
        """
        if self.transcript_file is None:
            raise ValueError("Transcript file not created")
        
        # Generate receipt filename from transcript filename
        receipt_file = self.transcript_file.with_suffix('.receipt.json')
        
        # Save receipt as JSON
        with open(receipt_file, "w", encoding="utf-8") as f:
            json.dump(receipt.model_dump(), f, indent=2)
        
        return receipt_file


def verify_transcript(transcript_path: str, receipt_path: str, cert_path: str) -> bool:
    """
    Verifies transcript integrity and receipt signature (offline verification).
    
    Args:
        transcript_path: Path to transcript file
        receipt_path: Path to SessionReceipt JSON file
        cert_path: Path to certificate for signature verification
        
    Returns:
        bool: True if verification succeeds
        
    Raises:
        ValueError: If verification fails
    """
    # Load transcript
    transcript_file = Path(transcript_path)
    if not transcript_file.exists():
        raise ValueError(f"Transcript file not found: {transcript_path}")
    
    with open(transcript_file, "r", encoding="utf-8") as f:
        lines = [line.rstrip('\n') for line in f if line.strip()]
    
    if not lines:
        raise ValueError("Transcript file is empty")
    
    # Compute transcript hash
    transcript_content = '\n'.join(lines)
    computed_hash = sha256_hex(transcript_content.encode('utf-8'))
    
    # Load receipt
    receipt_file = Path(receipt_path)
    if not receipt_file.exists():
        raise ValueError(f"Receipt file not found: {receipt_path}")
    
    with open(receipt_file, "r", encoding="utf-8") as f:
        receipt_data = json.load(f)
    
    receipt = SessionReceipt(**receipt_data)
    
    # Verify transcript hash matches
    if receipt.transcript_sha256 != computed_hash:
        raise ValueError(
            f"Transcript hash mismatch. Expected: {receipt.transcript_sha256}, "
            f"Got: {computed_hash}"
        )
    
    # Load certificate and verify signature
    cert = load_certificate_from_file(cert_path)
    public_key = cert.public_key()
    
    # Verify signature
    hash_bytes = bytes.fromhex(receipt.transcript_sha256)
    is_valid = verify_signature(receipt.sig, hash_bytes, public_key)
    
    if not is_valid:
        raise ValueError("Receipt signature verification failed")
    
    return True


def verify_transcript_file(transcript_path: str) -> Tuple[bool, dict]:
    """
    Verifies individual message entries in transcript.
    
    Args:
        transcript_path: Path to transcript file
        
    Returns:
        tuple: (all_valid: bool, verification_results: dict)
    """
    transcript_file = Path(transcript_path)
    if not transcript_file.exists():
        raise ValueError(f"Transcript file not found: {transcript_path}")
    
    results = {
        'total_entries': 0,
        'valid_entries': 0,
        'invalid_entries': [],
        'errors': []
    }
    
    with open(transcript_file, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line.strip():
                continue
            
            results['total_entries'] += 1
            
            try:
                # Parse line: seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
                parts = line.split('|')
                if len(parts) != 5:
                    results['invalid_entries'].append({
                        'line': line_num,
                        'error': f"Invalid format: expected 5 fields, got {len(parts)}"
                    })
                    continue
                
                seqno, timestamp, ciphertext, signature, peer_fingerprint = parts
                
                # Basic validation
                int(seqno)  # Validate seqno is integer
                int(timestamp)  # Validate timestamp is integer
                
                # Validate base64 encoding
                try:
                    b64d(ciphertext)
                    b64d(signature)
                except Exception as e:
                    results['invalid_entries'].append({
                        'line': line_num,
                        'error': f"Invalid base64 encoding: {e}"
                    })
                    continue
                
                # Validate fingerprint format (hex, 64 chars)
                if len(peer_fingerprint) != 64 or not all(c in '0123456789abcdefABCDEF' for c in peer_fingerprint):
                    results['invalid_entries'].append({
                        'line': line_num,
                        'error': "Invalid fingerprint format"
                    })
                    continue
                
                results['valid_entries'] += 1
                
            except Exception as e:
                results['invalid_entries'].append({
                    'line': line_num,
                    'error': str(e)
                })
    
    all_valid = results['invalid_entries'] == []
    return all_valid, results


def main():
    """Main entry point for transcript operations."""
    parser = argparse.ArgumentParser(
        description="Transcript management and verification"
    )
    parser.add_argument(
        "--verify",
        type=str,
        metavar="TRANSCRIPT_FILE",
        help="Verify transcript file integrity"
    )
    parser.add_argument(
        "--receipt",
        type=str,
        metavar="RECEIPT_FILE",
        help="Receipt file for verification (required with --verify)"
    )
    parser.add_argument(
        "--cert",
        type=str,
        metavar="CERT_FILE",
        help="Certificate file for signature verification (required with --verify)"
    )
    
    args = parser.parse_args()
    
    if args.verify:
        if not args.receipt or not args.cert:
            parser.error("--receipt and --cert are required with --verify")
        
        try:
            # Verify transcript format
            print(f"[INFO] Verifying transcript format: {args.verify}")
            all_valid, results = verify_transcript_file(args.verify)
            
            if all_valid:
                print(f"[SUCCESS] All {results['total_entries']} entries are valid")
            else:
                print(f"[WARNING] {results['valid_entries']}/{results['total_entries']} entries are valid")
                for invalid in results['invalid_entries']:
                    print(f"  Line {invalid['line']}: {invalid['error']}")
            
            # Verify receipt
            print(f"[INFO] Verifying receipt: {args.receipt}")
            verify_transcript(args.verify, args.receipt, args.cert)
            print("[SUCCESS] Transcript and receipt verification passed!")
            print("  Transcript hash matches")
            print("  Receipt signature verified")
            
        except Exception as e:
            print(f"[ERROR] Verification failed: {e}")
            raise
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
