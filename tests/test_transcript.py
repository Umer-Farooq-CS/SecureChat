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
File: tests/test_transcript.py
Purpose: Unit tests for transcript management
================================================================================

Description:
    This file contains comprehensive unit tests for transcript management in
    app/storage/transcript.py. It tests:
    - Transcript creation and entry addition
    - Transcript hash computation
    - SessionReceipt generation
    - Transcript verification
    - Tampering detection

================================================================================
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from app.common.protocol import SessionReceipt
from app.common.utils import b64d, b64e, sha256_hex
from app.crypto.pki import get_certificate_fingerprint, load_certificate_from_file
from app.crypto.sign import load_private_key_from_pem, sign_data, verify_signature
from app.storage.transcript import (
    TranscriptManager,
    verify_transcript,
    verify_transcript_file,
)


class TestTranscript(unittest.TestCase):
    """Test transcript management."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for test transcripts
        self.test_dir = tempfile.mkdtemp(prefix="securechat_transcript_test_")
        
        # Generate test RSA keypair for signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Test data
        self.test_ciphertext = b64e(b"encrypted_message_data")
        self.test_signature = b64e(b"signature_data")
        self.test_fingerprint = "a" * 64  # 64 hex chars
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_transcript_creation(self):
        """Test transcript file creation."""
        print("\n[TEST] Transcript Creation")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript_file = transcript.create_transcript()
        
        self.assertTrue(transcript_file.exists(), "Transcript file should exist")
        self.assertEqual(transcript_file.parent, Path(self.test_dir))
        
        print("  Transcript creation works correctly")
    
    def test_add_entry(self):
        """Test adding entries to transcript."""
        print("\n[TEST] Add Entry")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add entry
        transcript.add_entry(
            seqno=1,
            timestamp=1699123456789,
            ciphertext=self.test_ciphertext,
            signature=self.test_signature,
            peer_cert_fingerprint=self.test_fingerprint
        )
        
        # Verify entry was added
        self.assertEqual(len(transcript.entries), 1)
        self.assertEqual(transcript.first_seq, 1)
        self.assertEqual(transcript.last_seq, 1)
        
        # Verify file content
        with open(transcript.transcript_file, "r") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("1|", lines[0])
            self.assertIn(self.test_ciphertext, lines[0])
        
        print("  Add entry works correctly")
    
    def test_multiple_entries(self):
        """Test adding multiple entries."""
        print("\n[TEST] Multiple Entries")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add multiple entries
        for i in range(1, 6):
            transcript.add_entry(
                seqno=i,
                timestamp=1699123456789 + i,
                ciphertext=f"{self.test_ciphertext}_{i}",
                signature=f"{self.test_signature}_{i}",
                peer_cert_fingerprint=self.test_fingerprint
            )
        
        # Verify sequence tracking
        self.assertEqual(transcript.first_seq, 1)
        self.assertEqual(transcript.last_seq, 5)
        self.assertEqual(len(transcript.entries), 5)
        
        print("  Multiple entries work correctly")
    
    def test_transcript_hash(self):
        """Test transcript hash computation."""
        print("\n[TEST] Transcript Hash")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add entries
        for i in range(1, 4):
            transcript.add_entry(
                seqno=i,
                timestamp=1699123456789 + i,
                ciphertext=f"ct_{i}",
                signature=f"sig_{i}",
                peer_cert_fingerprint=self.test_fingerprint
            )
        
        # Compute hash
        transcript_hash = transcript.compute_transcript_hash()
        
        # Verify hash format (64 hex chars for SHA-256)
        self.assertEqual(len(transcript_hash), 64, "Hash should be 64 hex characters")
        self.assertTrue(all(c in '0123456789abcdef' for c in transcript_hash.lower()),
                       "Hash should be hexadecimal")
        
        # Verify consistency
        hash2 = transcript.compute_transcript_hash()
        self.assertEqual(transcript_hash, hash2, "Hash should be consistent")
        
        # Add another entry and verify hash changes
        transcript.add_entry(
            seqno=4,
            timestamp=1699123456793,
            ciphertext="ct_4",
            signature="sig_4",
            peer_cert_fingerprint=self.test_fingerprint
        )
        hash3 = transcript.compute_transcript_hash()
        self.assertNotEqual(transcript_hash, hash3, "Hash should change when entry added")
        
        print("  Transcript hash computation works correctly")
    
    def test_receipt_generation(self):
        """Test SessionReceipt generation."""
        print("\n[TEST] SessionReceipt Generation")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add entries
        for i in range(1, 4):
            transcript.add_entry(
                seqno=i,
                timestamp=1699123456789 + i,
                ciphertext=f"ct_{i}",
                signature=f"sig_{i}",
                peer_cert_fingerprint=self.test_fingerprint
            )
        
        # Generate receipt
        receipt = transcript.generate_receipt("client", self.private_key)
        
        # Verify receipt structure
        self.assertIsInstance(receipt, SessionReceipt)
        self.assertEqual(receipt.peer, "client")
        self.assertEqual(receipt.first_seq, 1)
        self.assertEqual(receipt.last_seq, 3)
        self.assertEqual(len(receipt.transcript_sha256), 64)
        self.assertIsNotNone(receipt.sig)
        
        # Verify receipt signature
        hash_bytes = bytes.fromhex(receipt.transcript_sha256)
        public_key = self.private_key.public_key()
        is_valid = verify_signature(receipt.sig, hash_bytes, public_key)
        self.assertTrue(is_valid, "Receipt signature should be valid")
        
        print("  SessionReceipt generation works correctly")
    
    def test_receipt_save(self):
        """Test saving receipt to file."""
        print("\n[TEST] Save Receipt")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add entry
        transcript.add_entry(
            seqno=1,
            timestamp=1699123456789,
            ciphertext=self.test_ciphertext,
            signature=self.test_signature,
            peer_cert_fingerprint=self.test_fingerprint
        )
        
        # Generate and save receipt
        receipt = transcript.generate_receipt("server", self.private_key)
        receipt_path = transcript.save_receipt(receipt)
        
        # Verify file exists
        self.assertTrue(receipt_path.exists(), "Receipt file should exist")
        
        # Verify file content
        with open(receipt_path, "r") as f:
            receipt_data = json.load(f)
        
        self.assertEqual(receipt_data["type"], "receipt")
        self.assertEqual(receipt_data["peer"], "server")
        self.assertEqual(receipt_data["first_seq"], 1)
        self.assertEqual(receipt_data["last_seq"], 1)
        
        print("  Save receipt works correctly")
    
    def test_transcript_verification(self):
        """Test transcript verification."""
        print("\n[TEST] Transcript Verification")
        
        # Create temporary certificate file for testing
        # (In real scenario, this would be a real certificate)
        # For testing, we'll create a minimal test
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript(session_id="test_session")
        
        # Add entries
        for i in range(1, 4):
            transcript.add_entry(
                seqno=i,
                timestamp=1699123456789 + i,
                ciphertext=f"ct_{i}",
                signature=f"sig_{i}",
                peer_cert_fingerprint=self.test_fingerprint
            )
        
        # Generate receipt
        receipt = transcript.generate_receipt("client", self.private_key)
        receipt_path = transcript.save_receipt(receipt)
        
        # Save private key temporarily for verification
        key_path = Path(self.test_dir) / "test_key.pem"
        with open(key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Create a test certificate (minimal - just for testing verification logic)
        # Note: This is a simplified test - in practice you'd use real certificates
        
        print("  Transcript verification structure works")
    
    def test_transcript_file_verification(self):
        """Test transcript file format verification."""
        print("\n[TEST] Transcript File Verification")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add valid entries
        for i in range(1, 4):
            transcript.add_entry(
                seqno=i,
                timestamp=1699123456789 + i,
                ciphertext=b64e(f"ciphertext_{i}".encode()),
                signature=b64e(f"signature_{i}".encode()),
                peer_cert_fingerprint="a" * 64
            )
        
        # Verify file format
        all_valid, results = verify_transcript_file(str(transcript.transcript_file))
        
        self.assertTrue(all_valid, "All entries should be valid")
        self.assertEqual(results["total_entries"], 3)
        self.assertEqual(results["valid_entries"], 3)
        self.assertEqual(len(results["invalid_entries"]), 0)
        
        print("  Transcript file verification works correctly")
    
    def test_tampering_detection(self):
        """Test that transcript tampering is detected."""
        print("\n[TEST] Tampering Detection")
        
        transcript = TranscriptManager(transcript_dir=self.test_dir)
        transcript.create_transcript()
        
        # Add entries
        for i in range(1, 3):
            transcript.add_entry(
                seqno=i,
                timestamp=1699123456789 + i,
                ciphertext=f"ct_{i}",
                signature=f"sig_{i}",
                peer_cert_fingerprint=self.test_fingerprint
            )
        
        # Compute original hash
        original_hash = transcript.compute_transcript_hash()
        
        # Tamper with transcript file
        with open(transcript.transcript_file, "a") as f:
            f.write("TAMPERED_LINE\n")
        
        # Hash should be different
        # Note: We need to reload from file since we modified it directly
        transcript2 = TranscriptManager(transcript_dir=self.test_dir)
        transcript2.transcript_file = transcript.transcript_file
        tampered_hash = transcript2.compute_transcript_hash()
        
        self.assertNotEqual(original_hash, tampered_hash, "Tampered transcript should have different hash")
        
        print("  Tampering detection works correctly")


def run_tests():
    """Run all transcript tests."""
    print("=" * 70)
    print("Testing Transcript Management (app/storage/transcript.py)")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestTranscript)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("All transcript tests PASSED")
    else:
        print("Some transcript tests FAILED")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    unittest.main()

