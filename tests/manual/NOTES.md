# Manual Testing & Evidence Checklist

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

**File:** `tests/manual/NOTES.md`  
**Purpose:** Manual testing procedures and evidence collection checklist

**Description:**
This file outlines the manual testing procedures and evidence collection required for Assignment #2, including Wireshark captures, certificate validation tests, tampering tests, replay tests, and non-repudiation verification.

**Links to Other Files:**
- `README.md`: Referenced in main documentation
- `app/client.py`: Client implementation to test
- `app/server.py`: Server implementation to test
- `app/crypto/pki.py`: Certificate validation to test
- `app/crypto/sign.py`: Signature verification to test
- `app/storage/transcript.py`: Transcript management to test

**Result:**
- Provides comprehensive testing checklist
- Documents evidence collection procedures
- Ensures all security properties are tested
- Serves as guide for test report generation

---

This document outlines the manual testing procedures and evidence collection required for Assignment #2.

## 📋 Testing Checklist

### 1. Wireshark Capture - Encrypted Payloads

**Objective:** Demonstrate that all sensitive data is encrypted and no plaintext credentials or messages are visible.

**Procedure:**
1. Start Wireshark
2. Select the appropriate network interface (loopback for localhost)
3. Apply filter: `tcp.port == 8888`
4. Start the server
5. Start the client and perform registration/login
6. Exchange several chat messages
7. Stop capture

**Expected Results:**
- ✅ All message payloads show base64-encoded ciphertext
- ✅ No plaintext passwords visible
- ✅ No plaintext chat messages visible
- ✅ Certificate exchange visible (expected - certificates are public)
- ✅ JSON structure visible but content encrypted

**Display Filters Used:**
```
tcp.port == 8888
tcp contains "type"
tcp contains "ct"
```

**Evidence Required:**
- Screenshot of Wireshark showing encrypted payloads
- Note the display filters used
- Highlight at least 3 encrypted messages

---

### 2. Invalid Certificate Test - BAD_CERT

**Objective:** Verify that the system rejects invalid, self-signed, or expired certificates.

**Test Cases:**

#### 2.1 Self-Signed Certificate (Not from CA)
**Procedure:**
1. Generate a self-signed certificate (not signed by your CA)
2. Attempt to connect with this certificate
3. Observe server/client response

**Expected Output:**
```
[ERROR] BAD_CERT: Certificate not signed by trusted CA
[ERROR] Certificate validation failed
Connection terminated
```

#### 2.2 Expired Certificate
**Procedure:**
1. Generate a certificate with past expiration date
2. Attempt to connect
3. Observe validation failure

**Expected Output:**
```
[ERROR] BAD_CERT: Certificate expired
[ERROR] Certificate validity check failed
Connection terminated
```

#### 2.3 Wrong Common Name (CN)
**Procedure:**
1. Generate certificate with CN="wrong.hostname"
2. Attempt to connect to server with CN="server.local"
3. Observe CN mismatch rejection

**Expected Output:**
```
[ERROR] BAD_CERT: Common Name mismatch
[ERROR] Expected: server.local, Got: wrong.hostname
Connection terminated
```

**Evidence Required:**
- Screenshots of error messages for each test case
- Certificate inspection (using `openssl x509 -text -in cert.pem`)
- Log entries showing rejection

---

### 3. Tampering Test - SIG_FAIL

**Objective:** Verify that message integrity is protected and tampering is detected.

**Procedure:**
1. Establish a valid secure session
2. Capture a message in Wireshark or log it
3. Modify a single bit in the ciphertext (`ct` field)
4. Resend the modified message
5. Observe signature verification failure

**Expected Output:**
```
[ERROR] SIG_FAIL: Signature verification failed
[ERROR] Message integrity check failed
[ERROR] Hash mismatch: expected abc123..., got def456...
Message rejected
```

**Alternative Test:**
- Modify the `seqno` field
- Modify the `ts` (timestamp) field
- Modify the `sig` field itself

**Expected Result:** All modifications should be detected and rejected.

**Evidence Required:**
- Screenshot of original message
- Screenshot of modified message
- Screenshot of error output
- Explanation of which bit/field was modified

---

### 4. Replay Attack Test - REPLAY

**Objective:** Verify that replay attacks are prevented using sequence numbers.

**Procedure:**
1. Establish a valid secure session
2. Send message with `seqno: 5`
3. Capture the message
4. Resend the exact same message (same seqno, same signature)
5. Observe replay detection

**Expected Output:**
```
[ERROR] REPLAY: Sequence number 5 already used
[ERROR] Message rejected - potential replay attack
```

**Additional Test:**
- Try sending a message with `seqno` less than the current sequence
- Try sending a message with `seqno` that's too far ahead

**Expected Result:** Out-of-order sequence numbers should be rejected.

**Evidence Required:**
- Screenshot of first message (seqno: 5)
- Screenshot of replayed message (same seqno)
- Screenshot of error output
- Log showing sequence number tracking

---

### 5. Non-Repudiation - Transcript & SessionReceipt

**Objective:** Demonstrate that session transcripts and receipts provide cryptographic proof of communication.

#### 5.1 Transcript Generation

**Procedure:**
1. Complete a chat session with multiple messages
2. End the session gracefully
3. Locate the transcript file in `transcripts/` directory

**Expected Transcript Format:**
```
seqno | timestamp | ciphertext | signature | peer-cert-fingerprint
1 | 1699123456789 | base64_ct_1 | base64_sig_1 | abc123def456...
2 | 1699123456790 | base64_ct_2 | base64_sig_2 | abc123def456...
3 | 1699123456791 | base64_ct_3 | base64_sig_3 | abc123def456...
...
```

#### 5.2 SessionReceipt Generation

**Expected Receipt Format (JSON):**
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "abc123def456...",
  "sig": "base64_rsa_signature"
}
```

#### 5.3 Offline Verification

**Procedure:**
1. Export transcript file
2. Export SessionReceipt
3. Run verification script:
   ```bash
   python -m app.storage.transcript --verify transcripts/session_20231201_120000.txt
   ```

**Expected Output:**
```
[INFO] Loading transcript: transcripts/session_20231201_120000.txt
[INFO] Computing transcript hash...
[INFO] Transcript hash: abc123def456...
[INFO] Loading SessionReceipt...
[INFO] Verifying receipt signature...
[INFO] ✓ Receipt signature verified
[INFO] ✓ Transcript integrity confirmed
[INFO] ✓ Non-repudiation evidence valid
```

#### 5.4 Tampering Detection

**Procedure:**
1. Modify the transcript file (add/remove/edit a line)
2. Attempt to verify again
3. Observe verification failure

**Expected Output:**
```
[ERROR] Transcript hash mismatch
[ERROR] Expected: abc123..., Got: def456...
[ERROR] Transcript has been tampered with
[ERROR] Verification failed
```

**Evidence Required:**
- Screenshot of transcript file (first few lines)
- Screenshot of SessionReceipt (JSON)
- Screenshot of successful verification
- Screenshot of failed verification after tampering
- Certificate fingerprint verification

---

## 📊 Test Report Template

For each test, document:

1. **Test Name:** [e.g., "Invalid Certificate - Self-Signed"]
2. **Objective:** What security property is being tested
3. **Procedure:** Step-by-step instructions
4. **Expected Result:** What should happen
5. **Actual Result:** What actually happened
6. **Evidence:** Screenshots, logs, captures
7. **Status:** ✅ Pass / ❌ Fail / ⚠️ Partial

---

## 🔍 Additional Verification

### Certificate Inspection

```bash
# View CA certificate
openssl x509 -text -in certs/ca-cert.pem -noout

# View server certificate
openssl x509 -text -in certs/server-cert.pem -noout

# View client certificate
openssl x509 -text -in certs/client-cert.pem -noout

# Verify certificate chain
openssl verify -CAfile certs/ca-cert.pem certs/server-cert.pem
openssl verify -CAfile certs/ca-cert.pem certs/client-cert.pem
```

### Database Verification

```sql
-- Check user table structure
DESCRIBE users;

-- View users (without showing sensitive data)
SELECT email, username, HEX(salt) as salt_hex, 
       SUBSTRING(pwd_hash, 1, 8) as pwd_hash_prefix, 
       created_at 
FROM users;

-- Verify no plaintext passwords
SELECT * FROM users WHERE pwd_hash LIKE '%password%';
-- Should return 0 rows
```

---

## ✅ Final Checklist

Before submission, ensure:

- [ ] Wireshark capture shows encrypted payloads only
- [ ] Invalid certificate tests documented with screenshots
- [ ] Tampering test shows SIG_FAIL error
- [ ] Replay test shows REPLAY error
- [ ] Transcript file exported and verified
- [ ] SessionReceipt generated and verified
- [ ] Offline verification script works
- [ ] Tampering detection works (transcript modification breaks verification)
- [ ] All evidence is reproducible by TA
- [ ] Test report document completed

---

**Note:** All tests should be reproducible. Document any setup steps, configuration changes, or special conditions required to run the tests.
