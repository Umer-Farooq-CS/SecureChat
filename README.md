# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

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

**File:** `README.md`  
**Purpose:** Main project documentation and user guide

**Description:**
This file provides comprehensive documentation for the SecureChat system, including setup instructions, execution steps, configuration details, sample input/output formats, and testing procedures.

**Links to Other Files:**
- `SETUP.md`: Detailed setup guide with prerequisites
- `PROJECT_STRUCTURE.md`: Project structure documentation
- `schema.sql`: Database schema definition
- `tests/manual/NOTES.md`: Testing checklist and procedures
- `.env.example`: Configuration template
- `requirements.txt`: Python dependencies

**Result:**
- Provides complete user guide for the system
- Documents all setup and execution procedures
- Includes sample I/O formats and testing guidelines
- Serves as primary reference for users and TAs

---

A **console-based, PKI-enabled Secure Chat System** implemented in **Python**, demonstrating how cryptographic primitives combine to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🔗 Repository

**GitHub Repository:** [https://github.com/Umer-Farooq-CS/SecureChat](https://github.com/Umer-Farooq-CS/SecureChat)

**Repository Topics:**
- `secure-chat`
- `cryptography`
- `pki`
- `aes-128`
- `rsa`
- `diffie-hellman`
- `sha-256`
- `x509-certificates`
- `information-security`
- `python`
- `client-server`
- `encryption`
- `authentication`
- `non-repudiation`
- `ciandr`

## 🧩 Overview

This project implements a secure client-server chat system that uses:
- **AES-128** (block cipher) for encryption
- **RSA** with X.509 certificates for authentication and signatures
- **Diffie-Hellman (DH)** for key agreement
- **SHA-256** for hashing
- **Self-built Root CA** for certificate issuance
- **MySQL** for secure user credential storage

The system achieves CIANR through:
- **Confidentiality**: All messages encrypted with AES-128
- **Integrity**: SHA-256 hashing and RSA signatures on every message
- **Authenticity**: X.509 certificate validation and mutual authentication
- **Non-Repudiation**: Signed session transcripts and SessionReceipts

## 🏗️ Project Structure

```
securechat-cryptography/
├─ app/
│  ├─ client.py              # Client workflow (plain TCP, no TLS)
│  ├─ server.py              # Server workflow (plain TCP, no TLS)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 (use cryptography lib)
│  │  ├─ dh.py               # Classic DH helpers + key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py             # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models (hello/login/msg/receipt)
│  │  └─ utils.py            # Helpers (base64, now_ms, sha256_hex)
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA (RSA + self-signed X.509)
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/
│  └─ manual/
│     └─ NOTES.md            # Manual testing + Wireshark evidence checklist
├─ certs/                    # Local certs/keys (gitignored)
├─ transcripts/              # Session logs (gitignored)
├─ .env.example              # Sample configuration (no secrets)
├─ .gitignore                # Ignore secrets, binaries, logs, and certs
├─ requirements.txt          # Python dependencies
└─ README.md                 # This file
```

## ⚙️ Prerequisites

- **Python 3.8+**
- **MySQL 8.0+** (or Docker for MySQL)
- **Git** (for version control)

## 🚀 Setup Instructions

### 1. Clone the Repository

```bash
git clone [Your GitHub Repository URL]
cd securechat-cryptography
```

### 2. Set Up Python Virtual Environment

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your actual configuration
# Update database credentials, server settings, etc.
```

**Required Configuration in `.env`:**
- `DB_HOST`: MySQL host (default: localhost)
- `DB_PORT`: MySQL port (default: 3306)
- `DB_NAME`: Database name (default: securechat)
- `DB_USER`: MySQL username
- `DB_PASSWORD`: MySQL password
- `SERVER_HOST`: Server hostname (default: localhost)
- `SERVER_PORT`: Server port (default: 8888)

### 4. Initialize MySQL Database

**Option A: Using Docker (Recommended)**

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8
```

**Option B: Using Local MySQL**

1. Create a database named `securechat`
2. Create a user with appropriate permissions
3. Update `.env` with your credentials

**Initialize Database Schema:**

```bash
python -m app.storage.db --init
```

This creates the `users` table with the following schema:
```sql
CREATE TABLE users (
    email VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL
);
```

### 5. Generate Certificates

**Step 1: Generate Root CA**

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

This creates:
- `certs/ca-key.pem` (CA private key)
- `certs/ca-cert.pem` (CA certificate)

**Step 2: Generate Server Certificate**

```bash
python scripts/gen_cert.py --cn server.local --out certs/server
```

This creates:
- `certs/server-key.pem` (server private key)
- `certs/server-cert.pem` (server certificate signed by CA)

**Step 3: Generate Client Certificate**

```bash
python scripts/gen_cert.py --cn client.local --out certs/client
```

This creates:
- `certs/client-key.pem` (client private key)
- `certs/client-cert.pem` (client certificate signed by CA)

**⚠️ Important:** Never commit certificate files or private keys to Git!

## 🎮 Execution Steps

### Running the Server

```bash
# Activate virtual environment first
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac

# Start the server
python -m app.server
```

The server will:
1. Load its certificate and private key
2. Connect to MySQL database
3. Listen on the configured port (default: 8888)
4. Wait for client connections

**Expected Server Output:**
```
[INFO] Server starting on localhost:8888
[INFO] Loading server certificate from certs/server-cert.pem
[INFO] Database connection established
[INFO] Server listening for connections...
```

### Running the Client

In a **separate terminal**:

```bash
# Activate virtual environment
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac

# Start the client
python -m app.client
```

The client will:
1. Connect to the server
2. Exchange certificates (mutual authentication)
3. Prompt for registration or login
4. Establish secure session
5. Allow encrypted chat messaging

## 📝 Sample Input/Output Formats

### Registration Flow

**Client Input:**
```
Connected to server
Certificate verified: ✓
Choose action: [1] Register [2] Login
> 1
Enter email: user@example.com
Enter username: alice
Enter password: ********
Registration successful!
```

**Server Output:**
```
[INFO] Client connected from 127.0.0.1:54321
[INFO] Client certificate verified
[INFO] Registration request received
[INFO] User 'alice' registered successfully
```

### Login Flow

**Client Input:**
```
Connected to server
Certificate verified: ✓
Choose action: [1] Register [2] Login
> 2
Enter email: user@example.com
Enter password: ********
Login successful!
Session key established
```

**Server Output:**
```
[INFO] Client connected from 127.0.0.1:54322
[INFO] Client certificate verified
[INFO] Login request received
[INFO] User 'alice' authenticated successfully
[INFO] Session key established
```

### Chat Message Exchange

**Client Input:**
```
> Hello, this is a secure message!
[Sent] Message #1 sent and signed
[Received] Server: Message received and verified
```

**Server Output:**
```
[Received] Client: Hello, this is a secure message!
[INFO] Message #1 verified: ✓
> Response message
[Sent] Message #2 sent and signed
```

### Message Format (JSON)

**Control Plane Messages:**
```json
{
  "type": "hello",
  "client_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "nonce": "base64_encoded_nonce"
}
```

```json
{
  "type": "server_hello",
  "server_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "nonce": "base64_encoded_nonce"
}
```

```json
{
  "type": "register",
  "email": "user@example.com",
  "username": "alice",
  "pwd": "base64_encrypted_password",
  "salt": "base64_salt"
}
```

```json
{
  "type": "login",
  "email": "user@example.com",
  "pwd": "base64_encrypted_password",
  "nonce": "base64_nonce"
}
```

**Key Agreement Messages:**
```json
{
  "type": "dh_client",
  "g": 2,
  "p": 12345678901234567890,
  "A": 98765432109876543210
}
```

```json
{
  "type": "dh_server",
  "B": 11223344556677889900
}
```

**Data Plane Messages:**
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1699123456789,
  "ct": "base64_encrypted_ciphertext",
  "sig": "base64_rsa_signature"
}
```

**Non-Repudiation Receipt:**
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "hex_hash_of_transcript",
  "sig": "base64_rsa_signature"
}
```

### Error Messages

**Certificate Validation Errors:**
```
[ERROR] BAD_CERT: Certificate validation failed
[ERROR] Certificate expired
[ERROR] Certificate not signed by trusted CA
[ERROR] Invalid Common Name (CN)
```

**Authentication Errors:**
```
[ERROR] Invalid credentials
[ERROR] User not found
[ERROR] Password mismatch
```

**Message Integrity Errors:**
```
[ERROR] SIG_FAIL: Signature verification failed
[ERROR] Message tampered
[ERROR] REPLAY: Sequence number already used
[ERROR] Stale message (timestamp check failed)
```

## 🧪 Testing & Evidence

### 1. Wireshark Capture

**Setup:**
1. Start Wireshark
2. Capture on loopback interface (lo0 on Linux/Mac, or your network adapter)
3. Apply filter: `tcp.port == 8888`

**Expected Results:**
- All payloads should be encrypted (base64 encoded ciphertext)
- No plaintext credentials visible
- Certificate exchange visible but encrypted data in messages

**Display Filters:**
```
tcp.port == 8888
tcp contains "type"
```

### 2. Invalid Certificate Test

**Test Cases:**
- Self-signed certificate (not from CA)
- Expired certificate
- Certificate with wrong Common Name (CN)
- Forged certificate

**Expected Output:**
```
[ERROR] BAD_CERT: Certificate not signed by trusted CA
Connection terminated
```

### 3. Tampering Test

**Test Procedure:**
1. Capture a message in Wireshark
2. Modify a single bit in the ciphertext (`ct` field)
3. Resend the modified message

**Expected Output:**
```
[ERROR] SIG_FAIL: Signature verification failed
[ERROR] Message integrity check failed
Message rejected
```

### 4. Replay Attack Test

**Test Procedure:**
1. Capture a valid message with `seqno: 5`
2. Resend the same message (same seqno)

**Expected Output:**
```
[ERROR] REPLAY: Sequence number 5 already used
Message rejected
```

### 5. Non-Repudiation Verification

**Test Procedure:**
1. Complete a chat session
2. Export transcript and SessionReceipt
3. Verify transcript hash
4. Verify SessionReceipt signature

**Expected Output:**
```
[INFO] Session ended
[INFO] Transcript saved to transcripts/session_20231201_120000.txt
[INFO] SessionReceipt generated
[INFO] Transcript hash: abc123def456...
[INFO] Receipt signature verified: ✓
```

**Offline Verification:**
```bash
python -m app.storage.transcript --verify transcripts/session_20231201_120000.txt
```

## 🚫 Important Rules

- **Do NOT use TLS/SSL or any secure-channel abstraction**  
  (e.g., `ssl`, HTTPS, WSS, OpenSSL socket wrappers).  
  All crypto operations must occur **explicitly** at the application layer.

- **Do NOT commit secrets** (certs, private keys, salts, `.env` values) to Git.

- **Do NOT implement cryptographic algorithms from scratch**  
  Use standard libraries (`cryptography`, `PyMySQL`, etc.)

- **Maintain commit history**  
  At least **10 meaningful commits** showing progressive development.

## 📊 Protocol Phases

### 1. Control Plane (Negotiation and Authentication)
- Certificate exchange and mutual verification
- Registration/Login with encrypted credentials
- Temporary DH key exchange for credential encryption

### 2. Key Agreement (Post-Authentication)
- Diffie-Hellman key exchange
- Session key derivation: `K = Trunc16(SHA256(big-endian(Ks)))`
- AES-128 key establishment

### 3. Data Plane (Encrypted Message Exchange)
- AES-128 encryption with PKCS#7 padding
- SHA-256 hashing: `h = SHA256(seqno || timestamp || ciphertext)`
- RSA signature: `sig = RSA_SIGN(h)`
- Replay protection via sequence numbers

### 4. Non-Repudiation (Session Evidence)
- Append-only transcript maintenance
- Transcript hash computation
- Signed SessionReceipt generation

## 🧾 Deliverables

When submitting on Google Classroom (GCR):

1. **GitHub Repository ZIP** - Complete repository with all commits
2. **MySQL Schema Dump** - `schema.sql` with table structure and sample records
3. **README.md** - This file (with your GitHub repo link)
4. **Report** - `RollNumber-FullName-Report-A02.docx`
5. **Test Report** - `RollNumber-FullName-TestReport-A02.docx`

## 📚 References

- [SEED Security Lab - PKI](https://seedsecuritylabs.org/Labs_16.04/Crypto/Crypto_PKI/)
- [Python Cryptography Library](https://cryptography.io/)
- [PyMySQL Documentation](https://pymysql.readthedocs.io/)

## 👤 Author

**Umer Farooq**  
**Roll No:** 22I-0891  
**Section:** CS-7D  
**Institution:** FAST-NUCES  
**Semester:** Fall 2025  
**Course:** Information Security (CS-3002)  
**Instructor:** Urooj Ghani

**Contact:**
- GitHub: [@Umer-Farooq-CS](https://github.com/Umer-Farooq-CS)

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

**Note:** This project is for educational purposes only. Do not use in production without proper security audits.

---

**⚠️ Security Notice:** This implementation is for educational purposes. Do not use in production without proper security audits.
