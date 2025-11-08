# Project Structure Documentation

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
File: PROJECT_STRUCTURE.md
Purpose: Complete project structure documentation
================================================================================

Description:
    This file documents the complete structure of the SecureChat project,
    including directory tree, file descriptions, protocol flow, and
    development workflow.

Links to Other Files:
    - README.md: Main project documentation
    - SETUP.md: Setup instructions
    - All Python files: Referenced in file descriptions
    - All configuration files: Referenced in structure

Result:
    - Provides complete overview of project structure
    - Documents relationships between files
    - Explains development workflow
    - Serves as reference for understanding the codebase

================================================================================

This document describes the complete structure of the SecureChat project.

## Directory Tree

```
securechat-cryptography/
├── app/                          # Main application code
│   ├── client.py                 # Client implementation (plain TCP)
│   ├── server.py                # Server implementation (plain TCP)
│   ├── crypto/                   # Cryptographic primitives
│   │   ├── aes.py               # AES-128 encryption/decryption
│   │   ├── dh.py                # Diffie-Hellman key exchange
│   │   ├── pki.py               # X.509 certificate validation
│   │   └── sign.py              # RSA signature generation/verification
│   ├── common/                   # Shared utilities
│   │   ├── protocol.py          # Message protocol definitions (Pydantic)
│   │   └── utils.py             # Helper functions (base64, hashing, etc.)
│   └── storage/                  # Data persistence
│       ├── db.py                # MySQL database operations
│       └── transcript.py        # Session transcript management
│
├── scripts/                      # Certificate generation scripts
│   ├── gen_ca.py                # Root CA generation
│   └── gen_cert.py              # Certificate issuance
│
├── tests/                        # Testing and evidence
│   └── manual/
│       └── NOTES.md             # Manual testing checklist
│
├── certs/                        # Certificate storage (gitignored)
│   └── .keep                    # Directory placeholder
│
├── transcripts/                  # Session transcripts (gitignored)
│   └── .keep                    # Directory placeholder
│
├── .env.example                  # Environment configuration template
├── .gitignore                   # Git ignore rules
├── requirements.txt             # Python dependencies
├── schema.sql                   # Database schema
├── README.md                    # Main documentation
├── SETUP.md                     # Detailed setup guide
└── PROJECT_STRUCTURE.md         # This file
```

## File Descriptions

### Application Code (`app/`)

#### `app/client.py`
- Client-side implementation
- Handles connection to server
- Implements client protocol flow:
  - Certificate exchange
  - Registration/Login
  - Key agreement
  - Encrypted messaging
  - Session closure

#### `app/server.py`
- Server-side implementation
- Listens for client connections
- Implements server protocol flow:
  - Certificate exchange
  - Authentication
  - Key agreement
  - Encrypted messaging
  - Session management

#### `app/crypto/aes.py`
- AES-128 encryption/decryption
- PKCS#7 padding
- Uses `cryptography` library

#### `app/crypto/dh.py`
- Diffie-Hellman key exchange
- Key derivation: `K = Trunc16(SHA256(big-endian(Ks)))`
- Parameter generation

#### `app/crypto/pki.py`
- X.509 certificate validation
- CA chain verification
- Expiry and CN checking
- Certificate loading

#### `app/crypto/sign.py`
- RSA signature generation (PKCS#1 v1.5)
- RSA signature verification
- SHA-256 hashing

#### `app/common/protocol.py`
- Pydantic models for message types:
  - `HelloMessage`
  - `ServerHelloMessage`
  - `RegisterMessage`
  - `LoginMessage`
  - `DHClientMessage`
  - `DHServerMessage`
  - `ChatMessage`
  - `SessionReceipt`

#### `app/common/utils.py`
- Base64 encoding/decoding
- Timestamp utilities
- SHA-256 hashing
- Helper functions

#### `app/storage/db.py`
- MySQL database connection
- User registration
- User authentication
- Salted password hashing
- Database initialization

#### `app/storage/transcript.py`
- Append-only transcript management
- Transcript hash computation
- SessionReceipt generation
- Offline verification

### Scripts (`scripts/`)

#### `scripts/gen_ca.py`
- Generates Root CA
- Creates self-signed X.509 certificate
- Outputs: `ca-key.pem`, `ca-cert.pem`

#### `scripts/gen_cert.py`
- Issues certificates signed by CA
- Generates RSA keypairs
- Creates X.509 certificates with SAN
- Outputs: `*-key.pem`, `*-cert.pem`

### Configuration Files

#### `.env.example`
- Template for environment variables
- Database configuration
- Server configuration
- Certificate paths
- CA details

#### `.gitignore`
- Excludes secrets and sensitive files
- Python artifacts
- IDE files
- Certificates and keys
- Transcripts and logs

#### `requirements.txt`
- Python package dependencies:
  - `cryptography` - Cryptographic operations
  - `PyMySQL` - MySQL database connector
  - `python-dotenv` - Environment variable management
  - `pydantic` - Data validation
  - `rich` - Terminal formatting

#### `schema.sql`
- MySQL database schema
- `users` table definition
- Sample data template

### Documentation

#### `README.md`
- Project overview
- Setup instructions
- Execution steps
- Sample I/O formats
- Testing procedures

#### `SETUP.md`
- Detailed setup guide
- Prerequisites installation
- Step-by-step instructions
- Troubleshooting

#### `tests/manual/NOTES.md`
- Manual testing checklist
- Evidence collection procedures
- Test report template

## Directory Purposes

### `certs/`
- Stores all certificates and private keys
- **Never committed to Git**
- Files:
  - `ca-key.pem` - CA private key
  - `ca-cert.pem` - CA certificate
  - `server-key.pem` - Server private key
  - `server-cert.pem` - Server certificate
  - `client-key.pem` - Client private key
  - `client-cert.pem` - Client certificate

### `transcripts/`
- Stores session transcripts
- Stores SessionReceipts
- **Never committed to Git**
- Format: `session_YYYYMMDD_HHMMSS.txt`
- Receipt format: `session_YYYYMMDD_HHMMSS_receipt.json`

## Protocol Flow

1. **Control Plane**
   - Certificate exchange (`app/common/protocol.py`)
   - Certificate validation (`app/crypto/pki.py`)
   - Registration/Login (`app/storage/db.py`)

2. **Key Agreement**
   - Diffie-Hellman exchange (`app/crypto/dh.py`)
   - Key derivation

3. **Data Plane**
   - Message encryption (`app/crypto/aes.py`)
   - Message signing (`app/crypto/sign.py`)
   - Protocol messages (`app/common/protocol.py`)

4. **Non-Repudiation**
   - Transcript management (`app/storage/transcript.py`)
   - Receipt generation

## Security Considerations

- **No secrets in Git**: All certificates, keys, and sensitive data are gitignored
- **Environment variables**: Sensitive configuration in `.env` (not committed)
- **Salted hashing**: Passwords stored with per-user salts
- **Encrypted transmission**: All messages encrypted with AES-128
- **Signature verification**: All messages signed and verified
- **Replay protection**: Sequence numbers prevent replay attacks

## Development Workflow

1. Implement certificate generation scripts
2. Implement PKI validation
3. Implement database layer
4. Implement cryptographic primitives
5. Implement protocol messages
6. Implement client/server workflows
7. Implement transcript management
8. Test and collect evidence

## Commit Strategy

Each major feature should be a separate commit:
1. CA generation script
2. Certificate issuance script
3. PKI validation
4. Database setup
5. Registration/Login
6. Diffie-Hellman key exchange
7. AES encryption
8. RSA signatures
9. Message protocol
10. Client implementation
11. Server implementation
12. Transcript management
13. Non-repudiation
14. Testing and documentation

---

**Note:** This structure follows the assignment requirements and best practices for secure software development.

