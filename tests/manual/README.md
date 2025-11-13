# Manual Testing Scripts

This directory contains shell scripts for manual testing and evidence collection.

## Scripts

### 1. `capture_traffic.sh`
Captures network traffic using Wireshark/tshark during a chat session.

**Usage:**
```bash
./capture_traffic.sh [output_file]
```

**Example:**
```bash
./capture_traffic.sh captures/normal_session.pcapng
```

**What it does:**
- Starts tshark capture on loopback interface
- Filters for TCP port 8888 (server port)
- Captures for 30 seconds (configurable)
- Saves to PCAP file
- Provides display filters for Wireshark

**Requirements:**
- tshark installed: `sudo apt-get install tshark`
- Server not running (script will check)

---

### 2. `test_invalid_certs.sh`
Tests invalid certificate scenarios and captures BAD_CERT errors.

**Usage:**
```bash
./test_invalid_certs.sh
```

**What it tests:**
1. Self-signed certificate (not from CA)
2. Expired certificate
3. Certificate with wrong Common Name (CN)

**What it does:**
- Generates test certificates (self-signed, expired)
- Attempts connection with invalid certificates
- Captures error output
- Saves results to `invalid_cert_tests/outputs/`

**Requirements:**
- OpenSSL installed
- Python 3 installed
- Server running on port 8888

**Output:**
- Test results in `invalid_cert_tests/outputs/`
- Screenshots should be taken manually

---

### 3. `test_tampering.sh`
Provides guide for testing message tampering detection (SIG_FAIL).

**Usage:**
```bash
./test_tampering.sh
```

**What it does:**
- Creates test guide in `tampering_tests/outputs/TAMPERING_TEST_GUIDE.md`
- Provides step-by-step instructions
- Explains multiple testing methods

**Manual Steps Required:**
1. Start server and client
2. Complete authentication
3. Modify client code to tamper with messages
4. Send tampered message
5. Observe SIG_FAIL error
6. Revert changes

**See:** `tampering_tests/outputs/TAMPERING_TEST_GUIDE.md` for detailed instructions.

---

### 4. `test_replay.sh`
Provides guide for testing replay attack detection (REPLAY).

**Usage:**
```bash
./test_replay.sh
```

**What it does:**
- Creates test guide in `replay_tests/outputs/REPLAY_TEST_GUIDE.md`
- Provides step-by-step instructions
- Explains multiple testing methods

**Manual Steps Required:**
1. Start server and client
2. Complete authentication
3. Send a message (note seqno)
4. Modify client code to resend same message
5. Observe REPLAY error
6. Revert changes

**See:** `replay_tests/outputs/REPLAY_TEST_GUIDE.md` for detailed instructions.

---

### 5. `run_all_tests.sh`
Runs all manual tests in sequence.

**Usage:**
```bash
./run_all_tests.sh
```

**What it does:**
- Guides you through all tests
- Runs traffic capture
- Runs invalid certificate tests
- Displays tampering test guide
- Displays replay test guide

---

## Quick Start

1. **Make scripts executable:**
   ```bash
   chmod +x *.sh
   ```

2. **Run all tests:**
   ```bash
   ./run_all_tests.sh
   ```

3. **Or run individually:**
   ```bash
   ./capture_traffic.sh
   ./test_invalid_certs.sh
   ./test_tampering.sh
   ./test_replay.sh
   ```

---

## Directory Structure

```
tests/manual/
├── README.md (this file)
├── capture_traffic.sh
├── test_invalid_certs.sh
├── test_tampering.sh
├── test_replay.sh
├── run_all_tests.sh
├── captures/              # Wireshark capture files
├── invalid_cert_tests/
│   └── outputs/          # Certificate test outputs
├── tampering_tests/
│   └── outputs/          # Tampering test guide
└── replay_tests/
    └── outputs/          # Replay test guide
```

---

## Evidence Collection Checklist

After running tests, collect:

- [ ] Wireshark PCAP file showing encrypted payloads
- [ ] Screenshot of invalid certificate error (BAD_CERT)
- [ ] Screenshot of tampering error (SIG_FAIL)
- [ ] Screenshot of replay error (REPLAY)
- [ ] Server logs showing error messages
- [ ] Test output files from `invalid_cert_tests/outputs/`

---

## Notes

- All scripts are designed for Linux/Unix systems
- On Windows, use WSL or Git Bash
- Some tests require manual interaction
- Screenshots should be taken manually during tests
- Test guides provide detailed step-by-step instructions

---

## Troubleshooting

**tshark not found:**
```bash
sudo apt-get install tshark
```

**Permission denied:**
```bash
chmod +x *.sh
```

**Port already in use:**
- Stop any existing server
- Or change SERVER_PORT in scripts

**Server not running:**
- Start server first: `python app/server.py`
- Then run test scripts

