# Quick Start Guide for Manual Testing

This guide provides quick instructions for running all manual tests on Linux.

## Prerequisites

1. **Install tshark (for Wireshark captures):**
   ```bash
   sudo apt-get update
   sudo apt-get install tshark
   ```

2. **Make scripts executable:**
   ```bash
   cd SecureChat/tests/manual
   chmod +x *.sh
   ```

3. **Ensure certificates are generated:**
   ```bash
   cd SecureChat
   python scripts/gen_ca.py
   python scripts/gen_cert.py --cn server.local
   python scripts/gen_cert.py --cn client.local
   ```

## Test 1: Traffic Capture

**Terminal 1 - Start capture:**
```bash
cd SecureChat/tests/manual
./capture_traffic.sh captures/test_session.pcapng
```

**Terminal 2 - Start server:**
```bash
cd SecureChat
python app/server.py
```

**Terminal 3 - Start client and chat:**
```bash
cd SecureChat
python app/client.py
# Register/login and send messages
```

**Result:** PCAP file saved in `captures/test_session.pcapng`

**View in Wireshark:**
```bash
wireshark captures/test_session.pcapng
```

**Display filters:**
- `tcp.port == 8888`
- `tcp contains "type"`
- `tcp contains "ct"`

---

## Test 2: Invalid Certificates

**Terminal 1 - Start server:**
```bash
cd SecureChat
python app/server.py
```

**Terminal 2 - Run invalid cert tests:**
```bash
cd SecureChat/tests/manual
./test_invalid_certs.sh
```

**Result:** 
- Test outputs in `invalid_cert_tests/outputs/`
- Take screenshots of BAD_CERT errors

---

## Test 3: Message Tampering

**Terminal 1 - Start server:**
```bash
cd SecureChat
python app/server.py
```

**Terminal 2 - View tampering instructions:**
```bash
cd SecureChat/tests/manual
python test_tampering_helper.py
```

**Steps:**
1. Edit `app/client.py` - add tampering code (see helper output)
2. Start client: `python app/client.py`
3. Login and send a message
4. Observe SIG_FAIL error
5. Remove tampering code
6. Test again (should work normally)

**Result:** Screenshot of SIG_FAIL error

---

## Test 4: Replay Attack

**Terminal 1 - Start server:**
```bash
cd SecureChat
python app/server.py
```

**Terminal 2 - View replay instructions:**
```bash
cd SecureChat/tests/manual
python test_replay_helper.py
```

**Steps:**
1. Edit `app/client.py` - add replay code (see helper output)
2. Start client: `python app/client.py`
3. Login and send a message
4. Observe REPLAY error (message will be resent automatically)
5. Remove replay code
6. Test again (should work normally)

**Result:** Screenshot of REPLAY error

---

## Run All Tests

**Quick way to run everything:**
```bash
cd SecureChat/tests/manual
./run_all_tests.sh
```

This will guide you through all tests step by step.

---

## Evidence Collection Checklist

After running all tests, collect:

- [ ] **Wireshark Capture:**
  - [ ] PCAP file showing encrypted payloads
  - [ ] Screenshot with display filters
  - [ ] Highlight encrypted messages

- [ ] **Invalid Certificate Tests:**
  - [ ] Screenshot: Self-signed cert → BAD_CERT
  - [ ] Screenshot: Expired cert → BAD_CERT
  - [ ] Screenshot: Wrong CN → BAD_CERT

- [ ] **Tampering Test:**
  - [ ] Screenshot: Original message
  - [ ] Screenshot: SIG_FAIL error
  - [ ] Screenshot: Server logs

- [ ] **Replay Test:**
  - [ ] Screenshot: First message (seqno N)
  - [ ] Screenshot: Replayed message (same seqno)
  - [ ] Screenshot: REPLAY error
  - [ ] Screenshot: Server logs

---

## Troubleshooting

**tshark permission denied:**
```bash
sudo usermod -aG wireshark $USER
# Log out and log back in
```

**Port 8888 already in use:**
```bash
# Find process using port
lsof -i :8888
# Kill it
kill <PID>
```

**Scripts not executable:**
```bash
chmod +x *.sh
```

**Python import errors:**
```bash
# Make sure you're in the SecureChat directory
cd SecureChat
python app/server.py
```

---

## Next Steps

1. Run all tests
2. Collect screenshots
3. Review test outputs
4. Create test report document
5. Include evidence in submission

