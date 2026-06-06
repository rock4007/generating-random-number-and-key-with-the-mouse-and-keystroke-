# SUMIT KEY

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-318%20passing-4caf50?style=flat-square)
![KEM](https://img.shields.io/badge/KEM-ML--KEM--1024%20FIPS%20203-7c3aed?style=flat-square)
![AES](https://img.shields.io/badge/AES-256--GCM-0ea5e9?style=flat-square)
![SDK](https://img.shields.io/badge/SDK-1%20dependency-22c55e?style=flat-square)
![Identity](https://img.shields.io/badge/Identity-per--user%20channels-e11d48?style=flat-square)
![Extension](https://img.shields.io/badge/Chrome-Extension%20MV3-f59e0b?style=flat-square&logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-Proprietary%20%2F%20MIT-d29922?style=flat-square)

> **Behavioural entropy key generation + a per-user identity layer + encryption that sits in front of any social media, messaging, or cloud storage platform.**

SUMIT KEY turns the way you move your mouse and type into cryptographic key material, then provides a complete identity-aware encryption stack — from a 1-dependency Python SDK to a full quantum-safe pipeline — that keeps your content private before it reaches WhatsApp, Telegram, Gmail, Google Drive, Instagram, or Twitter. Every person gets their own individual identity; every two-party conversation gets its own channel key.

---

## What it is

Most encrypted messaging systems require you to trust the platform. SUMIT KEY adds a layer **before** the platform ever sees your content, with each person's key bound to their own identity:

```
Alice (+44-7700-900001, WhatsApp)
  ↓  UserIdentity → Channel → encrypt("Meet at noon")
  ↓  opaque JSON envelope
WhatsApp  (sees only encrypted blob — cannot read it)
  ↓
Bob (+44-7700-900002, WhatsApp)
  ↓  UserIdentity → Channel → decrypt(envelope)
  ↓
"Meet at noon"
```

- Alice's key is tied to **her** phone number + platform + device
- Bob's key is tied to **his** phone number + platform + device
- The channel key is derived from **both** identities — only Alice and Bob can produce it
- A WhatsApp channel key **cannot** be replayed on Telegram

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SUMIT KEY Full Stack                         │
├──────────────────────────┬──────────────────────────────────────────┤
│   Behavioural Capture    │   sdk/identity.py — Per-user Identity    │
│   pynput · evdev · Web   │                                          │
├──────────────────────────┤   UserIdentity(user_id, platform,        │
│   Entropy Extraction     │               device_secret, behaviour)  │
│   velocity · tremor      │      ↓                                   │
│   dwell · flight         │   personal_key()  — your own docs        │
├──────────────────────────┤   channel_to(other_id, shared_secret)    │
│   Entropy Pool           │      ↓                                   │
│   SHA3-256               │   Channel.encrypt() / .decrypt()         │
├──────────────────────────┤                                          │
│   Key Derivation         │   sdk/core.py — Lightweight Core         │
│   HKDF-SHA3 + urandom    │   1 dependency (cryptography)            │
├──────────────────────────┤   encrypt_text / encrypt_file / decrypt  │
│   Stack A  AES-256-GCM   ├──────────────────────────────────────────┤
├──────────────────────────┤   Platform Integrations                  │
│   Stack B  ML-KEM-1024   │   WhatsApp · Telegram · Gmail            │
│           Argon2id        │   Drive · Instagram · Twitter            │
├──────────────────────────┤   Each with individual UserIdentity      │
│   Stack C  ZKP + Vault   ├──────────────────────────────────────────┤
│   Schnorr · Shamir        │   Browser Extension (MV3)                │
│   Burn-after-read        │   crypto.subtle · no server needed       │
│   MITM Shield            ├──────────────────────────────────────────┤
├──────────────────────────┤   Full REST API (api.py, 30+ endpoints)  │
│   Stack D  Rotating Keys │   NIST SP 800-22 Validation              │
└──────────────────────────┴──────────────────────────────────────────┘
```

---

## Quick start — Per-user identity (new)

```python
from sdk.identity import UserIdentity

# Step 1: Each person creates their own identity
alice = UserIdentity("+44-7700-900001", platform="whatsapp", display_name="Alice")
bob   = UserIdentity("+44-7700-900002", platform="whatsapp", display_name="Bob")

# Step 2: One-time key exchange (QR code / ghost code / in-person)
#         Share this secret via a DIFFERENT channel from the messages
secret = alice.new_shared_secret()

# Step 3: Each person creates their side of the channel
ch_alice = alice.channel_to(bob.public_id(),   shared_secret=secret)
ch_bob   = bob.channel_to(alice.public_id(),   shared_secret=secret)

# Step 4: Encrypt → send → decrypt
env = ch_alice.encrypt("Meet at noon — bring the documents.")
msg = ch_bob.decrypt(env)   # → "Meet at noon — bring the documents."

# Files work the same way
env_file = ch_alice.encrypt_file(open("report.pdf","rb").read(), "report.pdf")
doc      = ch_bob.decrypt_file(env_file)
```

**The same pattern works for every platform** — just change `platform=`:

```python
alice_tg = UserIdentity("@alice_tg",          platform="telegram")
alice_gm = UserIdentity("alice@company.com",  platform="gmail")
alice_dr = UserIdentity("alice@company.com",  platform="gdrive")
alice_ig = UserIdentity("@alice.photo",       platform="instagram")
alice_tw = UserIdentity("@alice_x",           platform="twitter")
```

---

## Quick start — Lightweight SDK (no identity needed)

```python
from sdk import SumitKey
sk  = SumitKey()
key = sk.new_key()                                   # random / passphrase / behavioural
env = sk.encrypt_text("hello", key, context="whatsapp")
msg = sk.decrypt_text(env, key)
```

---

## Quick start — Full stack

```bash
git clone https://github.com/rock4007/generating-random-number-and-key-with-the-mouse-and-keystroke-.git
cd generating-random-number-and-key-with-the-mouse-and-keystroke-
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py                      # generate key from mouse + keyboard
uvicorn api:app --port 8000         # full REST API (30+ endpoints)
uvicorn sdk.server:app --port 8001  # lightweight SDK server
```

---

## Quick start — Chrome Extension

1. Open `chrome://extensions` → enable **Developer mode**
2. Click **Load unpacked** → select `browser_extension/`
3. Send tab → type a message → **Create Ghost Package**
4. Share package JSON over any channel; ghost code over a **separate** channel
5. Receiver: paste JSON + ghost code → move mouse → **Open Now**

---

## Identity security model

Every `UserIdentity` object is built from four components:

| Component | Role | Secret? |
|---|---|---|
| `user_id` | Platform username / phone / email | No — public |
| `platform` | "whatsapp" / "telegram" / "gmail" / etc. | No — public |
| `device_secret` | 32-byte secret unique to this device | **Yes** |
| `behaviour` | Mouse + keystroke entropy bytes (optional) | **Yes** |

The channel key is derived as:

```
channel_key = HKDF-SHA3-256(
    SHA3-256(
        sorted(alice.public_id(), bob.public_id())   ← public info
        + platform
        + shared_secret                              ← exchanged once
    ),
    salt = "SUMITKEY_CHANNEL_V1",
    info = "channel:alice_pid↔bob_pid"               ← symmetric
)
```

**Properties:**
- Both parties derive the **same** key independently using `shared_secret`
- The key is **platform-bound** — a WhatsApp channel key is cryptographically different from a Telegram channel key, even for the same two people with the same secret
- Each envelope carries `context = "platform:sender→receiver"` in the GCM tag — directional binding prevents replay

### Security guarantees (verified by tests)

| Attack | Blocked by |
|---|---|
| Charlie intercepts Alice→Bob message | Charlie has a different key; GCM auth fails |
| Replay WhatsApp message on Telegram | Different platform in context label; GCM auth fails |
| Wrong shared secret | Different channel key; GCM auth fails |
| Different `user_id` same secret | Different channel context; GCM auth fails |
| Rename encrypted file | `expected_name=` check raises `ValueError` |
| Replay old packet on MITMShield | Monotonic sequence counter rejects it |

---

## Platform integrations — runnable demos

```bash
python -m sdk.integrations.whatsapp
python -m sdk.integrations.telegram
python -m sdk.integrations.gmail_drive
python -m sdk.integrations.instagram_twitter
```

| Platform | Identity format | What is encrypted |
|---|---|---|
| WhatsApp | Phone number `+44-7700-900001` | Message body |
| Telegram | Username `@alice_tg` | Message body, group channels |
| Gmail | Email `alice@company.com` | Email body |
| Google Drive | Email `alice@company.com` | File bytes before upload; personal key for private docs |
| Instagram | Handle `@alice.photo` | DM body |
| Twitter/X | Handle `@alice_x` | DM body |

Each demo ends with security checks printed to stdout — third-party isolation, cross-platform isolation, and per-user key uniqueness.

---

## Cryptographic stacks

### Stack A — Classical (AES-256-GCM)

| Property | Value |
|---|---|
| Symmetric cipher | AES-256-GCM |
| Key derivation | HKDF-SHA3-256 (RFC 5869) |
| Nonce | 96-bit, `os.urandom` per operation |
| Auth tag | 128-bit GCM |
| Classical security | 256-bit |
| Post-quantum security | 128-bit (Grover) |

### Stack B — Quantum-safe Hybrid (ML-KEM-1024 + Argon2id + AES-256-GCM)

| Property | Value |
|---|---|
| KEM | ML-KEM-1024 (NIST FIPS 203, 2024) |
| KEM security | NIST Level 5 · 128-bit post-quantum |
| Key hardening | Argon2id (RFC 9106) · 64 MB · t=1 |
| Session key | HKDF-SHA3-512(KEM_shared ‖ Argon2id_output) |
| Defense in depth | Breaking KEM alone insufficient; Argon2id blob also required |

### Stack C — Zero-Knowledge + Vault

| Layer | Algorithm | Property |
|---|---|---|
| ZKP | Schnorr / Fiat-Shamir, RFC 3526 Group 14 (2048-bit) | Proves knowledge without revealing secret |
| Secret sharing | Shamir SSS over GF(2⁸) | N-of-M threshold; information-theoretic |
| Vault | HighVoltageVault | Burn-after-read; TTL; ARMED→HOT→BURNED |
| Wire | MITM Shield | ML-KEM + AES-GCM + HMAC-SHA3-512; ±5-min replay window |

### Stack D — Rotating Keys

- Key rotates every 0.3 seconds, bound to user/session/device identity
- Threat engine blocks suspicious sessions before key derivation
- Self-healing retry with backup identity failover

---

## Entropy pipeline

```
Mouse events              Keystroke events
     │                         │
     ▼                         ▼
extract_mouse_entropy()   extract_keystroke_entropy()
 velocity σ · tremor RMS   dwell · flight · bigram timing
     │                         │
     └──────────┬──────────────┘
                ▼
         pool_entropy()
     SHA3-256(len‖mouse‖len‖keys)
                │
                ▼
         HKDF-Extract → HKDF-Expand
                │
         32-byte key ← + os.urandom (always mixed in)
```

Health checks reject constant, dominated (>85% one byte), and long-run inputs.

---

## NIST SP 800-22 Validation

| Experiment | Source | Purpose |
|---|---|---|
| A | Mouse only | Is mouse movement alone statistically random? |
| B | Keystroke only | Is typing rhythm alone statistically random? |
| C | Mouse + Keystroke | Does combination outperform either source? |

```bash
python main.py --mode experiments --num-keys 4000
```

---

## SDK server

```bash
uvicorn sdk.server:app --port 8001
```

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness |
| `/key/new` | POST | Generate key (random / passphrase) |
| `/encrypt` | POST | Encrypt text |
| `/encrypt-file` | POST | Encrypt binary file |
| `/decrypt` | POST | Decrypt any envelope |

---

## Full REST API

```bash
uvicorn api:app --port 8000   # docs → http://localhost:8000/docs
```

| Endpoint | Stack | Description |
|---|---|---|
| `POST /generate` | A | Mouse entropy → key + random number |
| `POST /encrypt/message` | A | AES-256-GCM message encrypt |
| `POST /decrypt/message` | A | AES-256-GCM message decrypt |
| `POST /ghost/encrypt` | A | One-time ghost package |
| `POST /ghost/decrypt` | A | Open ghost package once, zeroize key |
| `POST /quantum/keygen` | B | ML-KEM-1024 keypair |
| `POST /quantum/encrypt` | B | ML-KEM + Argon2id + AES-256-GCM |
| `POST /quantum/decrypt` | B | Quantum-safe decrypt |
| `POST /vault/serverless` | C | ZKP / Shamir / Vault dispatcher |
| `POST /encrypt/rotating-message` | D | 0.3-second rotating key encrypt |
| `POST /decrypt/rotating-message` | D | Rotating key decrypt |
| `GET /benchmark` | — | Crypto performance suite |
| `GET /threat-model` | — | Full cryptographic threat analysis |

---

## Test suite — 318 tests, 2 skipped (mouse hardware)

```bash
python -m pytest tests/ -q
# 318 passed, 2 skipped in ~33s
```

| Test file | Tests | What it covers |
|---|---|---|
| `test_identity.py` | 28 | Per-user identity, channel key derivation, all-platform isolation |
| `test_connectivity.py` | 53 | Cross-stack connectivity: all 8 stacks × all interfaces |
| `test_logical_fixes.py` | 17 | vault_store password, MITMShield AAD, serverless POST body |
| `test_file_decrypt_aad.py` | 14 | Filename AAD binding + rename-attack detection |
| `test_integration_system.py` | — | Full system integration across all layers |
| `test_blackbox_security.py` | — | Black-box security properties |
| `test_adversarial_scenarios.py` | — | Adversarial and attack scenarios |
| `test_attack_and_device_scenarios.py` | — | Device and replay attack scenarios |
| `test_deep_audit.py` | — | Vault TTL, sequence tracking, API key auth |
| `test_security_audit.py` | — | NIST compliance, nonce hygiene, FIDO2 gap |
| `test_browser_extension.py` | — | Extension manifest verification |
| `test_sandbox.py` | — | Synthetic-event pipeline smoke tests |

---

## Key material hygiene

| Rule | Implementation |
|---|---|
| Never written to disk | `results/*.json` stores only `fp:sha256[:16]` fingerprint |
| Never in URLs or logs | All endpoints use POST body models |
| API opt-in | `/generate` returns `key_fingerprint` by default; `?include_key=true` to opt in |
| Memory-only vault | Ghost keys zeroized (`bytearray` overwrite) on use or expiry |
| Filename binding | `decrypt_file(key, enc, out, expected_name="x.txt")` — rename raises `ValueError` |

---

## Documented limitations

1. **Pre-encryption malware** — kernel-level access can intercept plaintext before the crypto layer.
2. **Presence score** (local browser mode) — a UI gate, not a cryptographic commitment.
3. **40-bit ghost code** — suitable for demo; use FIDO2/WebAuthn for production.
4. **ARP MAC lookup is LAN-only** — remote attackers show "unknown" in the threat log.
5. **NIST tests are statistical, not FIPS-certified** — engineering check only.
6. **Schnorr ZKP is classical** — does not resist Shor's algorithm.

See [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md) for the full checklist.

---

## Project layout

```
├── sdk/
│   ├── identity.py           Per-user identity + Channel key derivation
│   ├── core.py               SumitKey class (1 dep: cryptography)
│   ├── server.py             Minimal FastAPI server (4 endpoints)
│   ├── sumitkey.js           Browser SDK (zero deps, Web Crypto API)
│   └── integrations/
│       ├── whatsapp.py       Individual identities · Alice ↔ Bob
│       ├── telegram.py       Individual identities · multi-channel
│       ├── gmail_drive.py    Individual identities · personal + shared keys
│       └── instagram_twitter.py  Individual identities · @handle based
├── main.py                   CLI key generation + NIST experiments
├── capture.py                Mouse and keyboard capture
├── entropy_engine.py         Feature extraction and entropy pooling
├── key_generator.py          HKDF-SHA3 key derivation
├── api.py                    Full REST API (FastAPI, 30+ endpoints)
├── crypto_tools.py           ⬤ Classical + quantum-hybrid encryption
├── vault.py                  ⬤ ZKP · Shamir SSS · Vault · MITM Shield
├── advanced_security.py      ⬤ Rotating-key envelope + threat detection
├── self_healing.py           ⬤ Self-healing crypto service
├── security.py               Rate limiting · threat logger · IP/MAC
├── nist_validator.py         NIST SP 800-22 statistical tests
├── crypto_benchmark.py       ⬤ Performance benchmark suite
├── threat_model.py           ⬤ Threat model framework
├── browser_extension/        Chrome MV3 extension (no server needed)
├── tests/                    318 passing · 2 skipped (mouse hardware)
├── scripts/                  Demos, utilities, NIST experiments
├── SPEAKING_NOTES.md         Dissertation presentation notes
├── STACKOVERFLOW_POST.md     Technical Q&A reference
├── .github/CODEOWNERS        All files require @rock4007 review
└── .github/CONTRIBUTING.md   Access request process
```

`⬤` proprietary — All Rights Reserved

---

## Dependency matrix

| Layer | Dependencies |
|---|---|
| `sdk/identity.py` + `sdk/core.py` | `cryptography` only |
| `sdk/server.py` | `cryptography`, `fastapi`, `uvicorn` |
| Full stack | `cryptography`, `argon2-cffi`, `kyber-py`, `fastapi`, `uvicorn`, `pynput`, `numpy`, `nistrng` |
| Browser extension | None — Web Crypto API built into every browser |

---

## License

Files marked `⬤` are proprietary — All Rights Reserved.
All other files are MIT licensed.
Copyright © 2026 Soumodeep Guha (rock4007)
