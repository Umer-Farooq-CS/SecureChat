# Test Suite Documentation

---

**Assignment #2 - Secure Chat System**  
**Information Security (CS-3002)**  
**FAST-NUCES, Fall 2025**

**Student Information:**
- **Name:** Umer Farooq
- **Roll No:** 22I-0891
- **Section:** CS-7D
- **Instructor:** Urooj Ghani

---

**File:** `tests/README.md`  
**Purpose:** Documentation for the test suite

**Description:**
This directory contains comprehensive unit tests and integration tests for all crypto modules in the SecureChat system. The tests verify that all cryptographic operations work correctly and securely.

**Test Files:**
- `test_utils.py`: Tests for utility functions (base64, hashing, timestamps)
- `test_aes.py`: Tests for AES-128 encryption/decryption
- `test_sign.py`: Tests for RSA signature generation/verification
- `test_dh.py`: Tests for Diffie-Hellman key exchange
- `test_pki.py`: Tests for X.509 certificate validation
- `test_integration.py`: Integration tests for complete crypto workflow
- `run_all_tests.py`: Script to run all test suites

**Links to Other Files:**
- `app/common/utils.py`: Utility functions being tested
- `app/crypto/aes.py`: AES encryption being tested
- `app/crypto/sign.py`: RSA signatures being tested
- `app/crypto/dh.py`: Diffie-Hellman being tested
- `app/crypto/pki.py`: PKI operations being tested

**Result:**
- Provides comprehensive test coverage for all crypto modules
- Verifies correct implementation of cryptographic primitives
- Ensures security properties are maintained
- Validates end-to-end crypto workflow

---

## Running Tests

### Run Individual Test Files

From the `SecureChat` directory:

```bash
# Test utility functions
python -m unittest tests.test_utils

# Test AES encryption
python -m unittest tests.test_aes

# Test RSA signatures
python -m unittest tests.test_sign

# Test Diffie-Hellman
python -m unittest tests.test_dh

# Test PKI operations
python -m unittest tests.test_pki

# Test integration
python -m unittest tests.test_integration
```

### Run All Tests

```bash
# Using unittest
python -m unittest discover tests

# Using the test runner script
python tests/run_all_tests.py
```

### Run with Verbose Output

```bash
python -m unittest tests.test_utils -v
```

## Test Coverage

### Utility Functions (`test_utils.py`)
- ✅ Base64 encoding/decoding round-trip
- ✅ SHA-256 hash computation
- ✅ Timestamp generation
- ✅ Known test vectors
- ✅ Edge cases (empty strings, special characters)

### AES Encryption (`test_aes.py`)
- ✅ Encryption/decryption round-trip
- ✅ PKCS#7 padding handling
- ✅ Various message lengths
- ✅ Invalid key size detection
- ✅ Ciphertext tampering detection
- ✅ Unicode message handling

### RSA Signatures (`test_sign.py`)
- ✅ Sign/verify round-trip
- ✅ Signature uniqueness
- ✅ Message tampering detection
- ✅ Signature tampering detection
- ✅ Wrong key verification failure
- ✅ Deterministic signatures
- ✅ Large message signing

### Diffie-Hellman (`test_dh.py`)
- ✅ Parameter generation
- ✅ Key pair generation
- ✅ Key exchange
- ✅ Shared secret derivation
- ✅ Session key derivation (K = Trunc16(SHA256(Ks)))
- ✅ Client-server exchange simulation
- ✅ Public key reconstruction

### PKI Operations (`test_pki.py`)
- ✅ Certificate loading
- ✅ Certificate chain validation
- ✅ Certificate expiry checking
- ✅ Common Name (CN) extraction
- ✅ Subject Alternative Name (SAN) extraction
- ✅ Hostname validation
- ✅ Certificate fingerprint computation
- ✅ Invalid certificate rejection

### Integration Tests (`test_integration.py`)
- ✅ Complete secure message flow (DH -> AES -> Sign)
- ✅ Multiple message exchange
- ✅ Tampering detection in encrypted messages
- ✅ Bidirectional communication

## Example Test Output

```
======================================================================
Testing Utility Functions (app/common/utils.py)
======================================================================

[TEST] Base64 Encoding/Decoding
  Original: b'Hello, World!'
  Encoded:  SGVsbG8sIFdvcmxkIQ==
  Decoded:  b'Hello, World!'
  ✓ All base64 tests passed

[TEST] SHA-256 Hashing
  Data: b'Hello, World!'
  Hash: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
  ✓ All SHA-256 tests passed

======================================================================
✓ All utility function tests PASSED
======================================================================
```

## Test Requirements

All tests use Python's built-in `unittest` framework. No additional test dependencies are required beyond the project dependencies listed in `requirements.txt`.

## Notes

- Tests are designed to be run from the `SecureChat` directory
- Some tests may take longer to run (especially DH tests with larger key sizes)
- PKI tests create test certificates on-the-fly (no external certificates needed)
- Integration tests simulate complete client-server crypto workflows

---

**Note:** These tests verify the correctness of cryptographic implementations. They do not replace security audits or penetration testing.

