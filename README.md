# SUMIT KEY

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-204%20passing-4caf50?style=flat-square)
![KEM](https://img.shields.io/badge/KEM-ML--KEM--1024-7c3aed?style=flat-square)
![AES](https://img.shields.io/badge/AES-256--GCM-0ea5e9?style=flat-square)
![Extension](https://img.shields.io/badge/Chrome-Extension%20MV3-f59e0b?style=flat-square&logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-Proprietary%20%2F%20MIT-d29922?style=flat-square)

Generates cryptographic keys from the way you move your mouse and type — turning human behaviour into entropy. Includes a **fully self-contained Chrome extension** for ghost-encrypted message handoff between any two devices with no server, no installs, and no configuration.

![Architecture](docs/images/architecture.svg)

---

## Ghost key demo — just install the extension

Any volunteer can send and receive a one-time ghost-encrypted message using **only the Chrome extension**. No Python, no server, no extra downloads.

```
Sender                                    Receiver
──────                                    ────────
Install extension                         Install extension
Move mouse → presence score builds        (any device, any browser)
Type message → Create Ghost Package
  ↓ AES-256-GCM encrypted in browser
  ↓ PBKDF2-SHA-256, 210 000 iterations

Share PACKAGE JSON   ──────────────────→  Paste package JSON
Share GHOST CODE     ──  (separately) ──→ Enter ghost code
  (email / Slack)                         Move mouse → presence ≥ 40

                                          Click Open Now
                                          Message appears once
                                          Ghost key deleted from storage ✓
```

**Encryption happens entirely inside the browser** — `crypto.subtle` (Web Crypto API), no third-party library. The ghost code is the only secret and travels separately from the ciphertext, so intercepting the package JSON alone decrypts nothing.

### Install the extension (unpacked)

1. Open `chrome://extensions` → enable **Developer mode**
2. Click **Load unpacked** → select the `browser_extension/` folder
3. Done. The icon appears in the toolbar.

The extension falls back to the optional Python API automatically if it detects one running at the configured URL. When the API is offline (default for new users) it uses local AES-256-GCM exclusively.

---

## Encryption tiers

| Tier | Where | Algorithm | Key derivation | Ghost property |
|------|-------|-----------|---------------|----------------|
| **Local** (default) | In browser | AES-256-GCM | PBKDF2-SHA-256 · 210 k iter | burn-after-read in `chrome.storage` |
| **API** (optional) | Python server | AES-256-GCM | Argon2id + HKDF-SHA3-512 | server-side vault burn-after-read |
| **Quantum-safe** | Python server | ML-KEM-1024 + AES-256-GCM | HKDF-SHA3-512 | High-Voltage Vault · Shamir SSS |

---

## Security boundaries

SUMIT KEY treats mouse and keystroke behaviour as an entropy and risk signal, not as a standalone secret. Keys also include operating-system randomness and protected device/session material.

Important limits:

- Malware with control of the user's device can read plaintext before encryption or tamper with the browser.
- AES-GCM requires a fresh 96-bit nonce for every encryption under a key. Reusing a nonce with the same key is dangerous.
- The ghost code provides ~40 bits of entropy. For highest security, regenerate each package rather than reusing ghost codes.
- SMS/email OTP is a weaker fallback factor. Production deployments should prefer FIDO2/WebAuthn or hardware tokens.
- Local NIST SP 800-22 tests are engineering checks, not official NIST/FIPS validation.
- The presence score (mouse/keystroke count) is a local UI gate — it is not cryptographically bound to the key in local mode.

See [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md) for the full pre-volunteer checklist.

---

## MITM detection

Any mid-session intrusion attempt is automatically detected and logged. The threat logger records the attacker's **IP address and MAC address** (resolved from the OS ARP table) and exposes them at `GET /admin/threats`. The advanced threat engine tracks burst rate, replay attacks, entropy anomalies, honeypot probes, and suspicious user-agent patterns.

---

## How it works

Every person moves a mouse and types differently. SUMIT KEY captures that uniqueness — the micro-jitter in mouse movements, the tiny pauses between keystrokes — and feeds it into a cryptographic pipeline to produce keys that are tied to human behaviour, not just random bytes.

**Step 1 — Capture**
Mouse positions, velocities, direction changes, and keystroke inter-arrival times are collected in real time.

**Step 2 — Entropy extraction**
Raw events are processed into numerical features, hashed with SHA3-512, and merged into a 512-bit entropy pool. Basic health checks reject weak or synthetic input.

**Step 3 — Key derivation**
The pool is hardened through three independent cryptographic paths:

| Path | What it uses | Output |
|------|-------------|--------|
| Classical | HKDF-SHA3 + AES-256-GCM | 256-bit symmetric key |
| Post-quantum | ML-KEM-1024 + Argon2id + AES-256-GCM | Quantum-safe encrypted message |
| Zero-knowledge | Schnorr proof + Shamir secret sharing + Vault | Distributed secret with burn-after-read |

OS random bytes are always mixed in — behavioural entropy adds uniqueness on top of a secure baseline.

**Step 4 — Threat detection**
Before any key is used to encrypt, a threat engine checks for bot-like mouse patterns, replay attempts, brute-force signals, and entropy anomalies. Suspicious sessions are blocked before key material is derived.

---

## Key flow

![Key Flow](docs/images/key_flow.svg)

---

## Vault

The High-Voltage Vault splits a secret into shards using Shamir Secret Sharing over GF(2⁸). Each shard is individually encrypted with Argon2id + AES-256-GCM. Retrieving the secret requires a threshold of shards and the master password. Once retrieved, the vault is permanently destroyed.

![Vault](docs/images/vault.svg)

---

## Quick start

```bash
git clone https://github.com/rock4007/generating-random-number-and-key-with-the-mouse-and-keystroke-.git
cd generating-random-number-and-key-with-the-mouse-and-keystroke-
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Generate a key from your mouse and keyboard
python main.py

# Start the REST API (optional — extension works without this)
uvicorn api:app --port 8000
# Interactive docs → http://localhost:8000/docs

# Open the browser dashboard
python -m http.server 8080
# → http://127.0.0.1:8080/dashboard.html
```

### Sandbox demos

These demos use synthetic mouse and keystroke events, so they work in Codespaces
or CI without a display server:

```bash
python scripts/sandbox_demo.py --demo classic
python scripts/sandbox_demo.py --demo file
python scripts/sandbox_demo.py --demo ghost
python scripts/sandbox_demo.py --demo quantum-ghost
python scripts/sandbox_demo.py --demo all
```

### Extension only (no Python needed)

1. Download or clone the repo
2. Open `chrome://extensions` → Developer mode → Load unpacked → select `browser_extension/`
3. Click the extension icon → Send tab → type a message → Create Ghost Package
4. Share the package JSON to the other device (any channel)
5. Share the ghost code separately (different channel)
6. On the receiving device: install extension → Receive tab → paste JSON + ghost code → move mouse → Open Now

---

## Portable ghost API

For devices that need server-side burn-after-read, run the API on one trusted host:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/ghost/encrypt` | POST | Create an AES-GCM ghost package; server keeps the unlock key briefly |
| `/ghost/decrypt` | POST | Open the package once from any device; zeroizes the key after |
| `/ghost/status/{id}` | GET | Check whether the one-time key is still alive |
| `/ghost/revoke/{id}` | POST | Manually burn a ghost key before it is opened |
| `/ghost/quantum/session` | POST | Initiate ML-KEM-1024 quantum-safe session |
| `/ghost/quantum/send` | POST | Encrypt with mouse entropy + ML-KEM |
| `/ghost/quantum/receive` | POST | Decrypt and burn the vault (presence proof required) |
| `/admin/threats` | GET | Full threat log with attacker IP and MAC |

---

## Project layout

```
├── main.py               entry point — key generation and experiments
├── capture.py            mouse and keyboard event capture
├── entropy_engine.py     feature extraction and entropy pooling
├── key_generator.py      HKDF key derivation
├── api.py                REST API (FastAPI, 30+ endpoints)
├── dashboard.html        browser dashboard
├── security.py           rate limiting, threat logging, IP/MAC detection
├── nist_validator.py     NIST SP 800-22 statistical tests
├── crypto_tools.py       ⬤ classical + quantum-hybrid encryption
├── crypto_benchmark.py   ⬤ performance benchmark suite
├── advanced_security.py  ⬤ rotating-key envelope + threat detection
├── threat_model.py       ⬤ threat model framework
├── vault.py              ⬤ ZKP · Shamir SSS · Vault · MITM Shield
├── browser_extension/    Chrome MV3 extension (self-contained, no server needed)
│   ├── manifest.json       MV3 manifest v1.2.0
│   ├── background.js       service worker — crypto, presence, storage
│   ├── content.js          mouse/keystroke presence capture on any page
│   ├── popup.html          Send / Receive / Settings UI
│   └── popup.js            popup controller
├── tests/                204 passing · 2 skipped (mouse hardware)
└── scripts/              utilities, demos, and NIST experiments
```

`⬤` proprietary — All Rights Reserved

---

## License

Files marked `⬤` are proprietary. All other files are MIT licensed.
Copyright (c) 2026 Soumodeep Guha
