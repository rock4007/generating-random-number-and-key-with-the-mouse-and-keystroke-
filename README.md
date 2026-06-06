# SUMIT KEY

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-290%20passing-4caf50?style=flat-square)
![KEM](https://img.shields.io/badge/KEM-ML--KEM--1024%20FIPS%20203-7c3aed?style=flat-square)
![AES](https://img.shields.io/badge/AES-256--GCM-0ea5e9?style=flat-square)
![SDK](https://img.shields.io/badge/SDK-1%20dependency-22c55e?style=flat-square)
![Extension](https://img.shields.io/badge/Chrome-Extension%20MV3-f59e0b?style=flat-square&logo=googlechrome&logoColor=white)
![License](https://img.shields.io/badge/License-Proprietary%20%2F%20MIT-d29922?style=flat-square)

> **Behavioural entropy key generation + a lightweight encryption layer that sits in front of any social media, messaging, or cloud storage platform.**

SUMIT KEY turns the way you move your mouse and type into cryptographic key material, then provides a complete encryption stack — from a 1-dependency Python SDK to a full quantum-safe pipeline — that keeps your content private before it reaches WhatsApp, Telegram, Gmail, Google Drive, Instagram, or Twitter.

---

## What it is

Most encrypted messaging systems require you to trust the platform. SUMIT KEY adds a layer **before** the platform ever sees your content:

```
Your message
     ↓
SumitKey.encrypt_text("your message", key)
     ↓  opaque JSON envelope  ↓
WhatsApp  /  Telegram  /  Gmail  /  Drive  /  Instagram  /  Twitter
     ↓  platform sees only an encrypted blob  ↓
Recipient: SumitKey.decrypt_text(envelope, key)
     ↓
Your message
```

The platform transmits the encrypted blob. It cannot read it.
The key never leaves your device unless you share it explicitly.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SUMIT KEY Full Stack                        │
├────────────────────────────┬────────────────────────────────────┤
│   Behavioural Capture      │   sdk/ — Lightweight Layer         │
│   pynput · evdev · Web API │   1 dep · any platform             │
├────────────────────────────┤                                    │
│   Entropy Extraction       │   encrypt_text()                   │
│   velocity · tremor        │   encrypt_file()                   │
│   dwell · flight · bigram  │   decrypt()                        │
├────────────────────────────┤   new_key() passphrase/behavioural │
│   Entropy Pool             ├────────────────────────────────────┤
│   SHA3-256 length-prefixed │   Platform Integrations            │
├────────────────────────────┤   WhatsApp · Telegram · Gmail      │
│   Key Derivation           │   Drive · Instagram · Twitter      │
│   HKDF-SHA3 + os.urandom   ├────────────────────────────────────┤
├────────────────────────────┤   Browser Extension (MV3)          │
│   Stack A — Classical      │   crypto.subtle · Web Crypto API   │
│   AES-256-GCM              │   PBKDF2 · 210k iter · no server   │
├────────────────────────────┤   ghost code · burn-after-read     │
│   Stack B — Quantum Safe   ├────────────────────────────────────┤
│   ML-KEM-1024 (FIPS 203)   │   REST API (api.py)                │
│   Argon2id + HKDF-SHA3-512 │   30+ endpoints · FastAPI          │
├────────────────────────────┤   rate limit · security headers    │
│   Stack C — ZKP + Vault    │   AES-GCM · Quantum · Vault        │
│   Schnorr · Shamir GF(2⁸)  │   rotating keys · self-healing     │
│   Burn-after-read          ├────────────────────────────────────┤
│   MITM Shield              │   NIST SP 800-22 Validation        │
│   HMAC-SHA3-512            │   Exp A (mouse) · B (keys) · C (∪) │
└────────────────────────────┴────────────────────────────────────┘
```

---

## Quick start — Lightweight SDK (1 dependency)

```bash
pip install cryptography
```

```python
from sdk import SumitKey

sk  = SumitKey()
key = sk.new_key()                                   # random, passphrase, or behavioural
env = sk.encrypt_text("Meet at noon.", key, context="whatsapp")
msg = sk.decrypt_text(env, key)                      # → "Meet at noon."

# Works identically for files
env = sk.encrypt_file(open("report.pdf","rb").read(), "report.pdf", key, context="gdrive")
doc = sk.decrypt(env, key)
```

**Paste `env` into any platform. The platform cannot read it.**

---

## Quick start — Full stack

```bash
git clone https://github.com/rock4007/generating-random-number-and-key-with-the-mouse-and-keystroke-.git
cd generating-random-number-and-key-with-the-mouse-and-keystroke-
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py                          # generate key from mouse + keyboard
uvicorn api:app --port 8000             # full REST API
uvicorn sdk.server:app --port 8001      # lightweight SDK server
```

---

## Quick start — Chrome Extension (no Python, no server)

1. Open `chrome://extensions` → enable **Developer mode**
2. Click **Load unpacked** → select the `browser_extension/` folder
3. Send tab → type a message → **Create Ghost Package**
4. Share package JSON over any channel; share ghost code over a **separate** channel
5. Receiver: paste JSON + ghost code → move mouse → **Open Now**

The extension encrypts entirely in the browser using `crypto.subtle`. No data leaves the device without your action.

---

## Platform integrations

All six integrations are runnable and tested:

```bash
python -m sdk.integrations.whatsapp
python -m sdk.integrations.telegram
python -m sdk.integrations.gmail_drive
python -m sdk.integrations.instagram_twitter
```

| Platform | What is encrypted | Context label |
|---|---|---|
| WhatsApp | Message body | `whatsapp` |
| Telegram | Message body (bulk) | `telegram` |
| Gmail | Email body | `gmail` |
| Google Drive | File bytes before upload | `gdrive` |
| Instagram DM | DM body | `instagram` |
| Twitter/X DM | DM body | `twitter` |

**Context isolation**: an envelope encrypted with `context="whatsapp"` cannot be decrypted with `context="telegram"` — the label is bound into the AES-GCM authentication tag. A platform cannot swap or replay envelopes across channels.

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
| OS randomness | Always mixed in — behavioural entropy is additive |

### Stack B — Quantum-safe Hybrid (ML-KEM-1024 + Argon2id + AES-256-GCM)

| Property | Value |
|---|---|
| KEM | ML-KEM-1024 (NIST FIPS 203, 2024) |
| KEM security | NIST Level 5 — 128-bit post-quantum |
| KEM ciphertext | 1568 bytes |
| Key hardening | Argon2id (RFC 9106), 64 MB, t=1 |
| Session key | HKDF-SHA3-512(KEM_shared ‖ Argon2id_output) |
| Classical security | 256-bit |
| Defense in depth | Breaking KEM alone requires Argon2id blob; reproducing behaviour requires KEM dk |

### Stack C — Zero-Knowledge + Vault

| Layer | Algorithm | Property |
|---|---|---|
| ZKP | Schnorr / Fiat-Shamir over RFC 3526 Group 14 (2048-bit MODP) | Proves knowledge of secret without revealing it |
| Secret sharing | Shamir SSS over GF(2⁸) | Information-theoretic security; N shards, T threshold |
| Vault | HighVoltageVault | Burn-after-read; TTL dead-man switch; ARMED→HOT→BURNED |
| Wire | MITM Shield | ML-KEM session key + AES-GCM + HMAC-SHA3-512 envelope |
| Replay guard | ±5-minute timestamp + monotonic sequence counter | Replay and duplication rejected at packet level |

### Stack D — Rotating Keys (advanced_security)

- Key rotates every 0.3 seconds, bound to user/session/device identity
- Threat engine blocks suspicious sessions before key derivation
- Self-healing retry with backup identity failover

---

## Security model

### Key material hygiene

| Rule | Implementation |
|---|---|
| Never written to disk | `results/*.json` stores only `fp:sha256[:16]` fingerprint — never raw `key_hex` |
| Never in URLs or logs | All endpoints use POST body models; no `Query(key_hex=...)` anywhere |
| API opt-in | `/generate` returns `key_fingerprint` by default; full `key_hex` only with `?include_key=true` |
| Memory-only | Vault ghost keys zeroized (`bytearray` overwritten) on use or expiry |

### Filename AAD binding

Files encrypted with `encrypt_file()` bind the original filename into the AES-GCM tag:

```python
decrypt_file(key, enc_path, out_path, expected_name="report.pdf")
# ValueError if the file was renamed — prevents silent swap attacks
```

### Branch and access protection

- `CODEOWNERS`: every file in the repo requires `@rock4007` review
- Branch protection: no direct push to `main`, no force push, stale reviews dismissed
- Access requests: open an Issue titled "Access Request" — see `.github/CONTRIBUTING.md`

---

## Entropy pipeline

```
Mouse events                Keystroke events
    │                           │
    ▼                           ▼
extract_mouse_entropy()   extract_keystroke_entropy()
  · mean velocity               · dwell time mean + σ
  · velocity σ                  · flight time mean + σ
  · direction change freq       · bigram transition timings
  · micro-tremor RMS (<3px)
    │                           │
    └──────────┬────────────────┘
               ▼
        pool_entropy()
    SHA3-256(len(m)‖m‖len(k)‖k)
               │
               ▼
        HKDF-Extract (SHA3-256)
        HKDF-Expand  (SHA3-256)
               │
               ▼        ┌── + os.urandom (always)
        32-byte key ────┤
                        └── + personalization label
```

**Health checks** (NIST SP 800-90B inspired) reject inputs that are constant, single-byte dominated (>85%), or contain runs longer than 32 consecutive identical bytes.

OS randomness is always mixed in — a weak or synthetic capture still yields a cryptographically secure key. Behavioural entropy adds a human identity component on top.

---

## NIST SP 800-22 Validation

Three experiments run in parallel to compare entropy sources:

| Experiment | Source | Purpose |
|---|---|---|
| A | Mouse only | Baseline: is mouse movement alone statistically random? |
| B | Keystroke only | Baseline: is typing rhythm alone statistically random? |
| C | Mouse + Keystroke | Combined: does fusion outperform either source? |

Each experiment generates up to 20,000 keys. NIST tests run on the concatenated bit stream. The calibrated pass rate excludes tests that also fail on `os.urandom` in the test environment.

```bash
python main.py --mode experiments --num-keys 4000
# → results/combined_experiment_report.txt
```

---

## SDK server — drop-in encryption proxy

```bash
uvicorn sdk.server:app --port 8001
```

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check |
| `/key/new` | POST | Generate key (random, passphrase, or behavioural) |
| `/encrypt` | POST | Encrypt any text message |
| `/encrypt-file` | POST | Encrypt any binary file |
| `/decrypt` | POST | Decrypt any envelope |

No mouse hardware required. Designed to run as a sidecar process alongside any application.

---

## Full REST API (api.py)

```bash
uvicorn api:app --port 8000
# Interactive docs → http://localhost:8000/docs
```

Key endpoints:

| Endpoint | Stack | Description |
|---|---|---|
| `POST /generate` | A | Mouse entropy → key + random number |
| `POST /encrypt/message` | A | AES-256-GCM message encrypt |
| `POST /decrypt/message` | A | AES-256-GCM message decrypt |
| `POST /ghost/encrypt` | A | One-time ghost package (burn-after-read) |
| `POST /ghost/decrypt` | A | Open ghost package once, zeroize key |
| `POST /quantum/keygen` | B | ML-KEM-1024 keypair |
| `POST /quantum/encrypt` | B | ML-KEM + Argon2id + AES-256-GCM |
| `POST /quantum/decrypt` | B | Quantum-safe decrypt |
| `POST /vault/serverless` | C | ZKP / Shamir / Vault dispatcher |
| `POST /encrypt/rotating-message` | D | 0.3-second rotating key encrypt |
| `POST /decrypt/rotating-message` | D | Rotating key decrypt |
| `GET /debug/pipeline` | — | Synthetic pipeline trace |
| `GET /benchmark` | — | AES · Argon2id · ML-KEM · MAYO timing |
| `GET /threat-model` | — | Full cryptographic threat analysis |

---

## Test suite — 290 tests, 2 skipped (mouse hardware)

```bash
python -m pytest tests/ -q
# 290 passed, 2 skipped in ~33s
```

| Test file | What it covers |
|---|---|
| `test_connectivity.py` | 53 cross-stack connectivity tests across all 8 stacks |
| `test_logical_fixes.py` | vault_store password, MITMShield AAD, serverless POST body |
| `test_file_decrypt_aad.py` | Filename AAD binding + rename-attack detection |
| `test_integration_system.py` | Full system integration across all layers |
| `test_blackbox_security.py` | Black-box security properties |
| `test_adversarial_scenarios.py` | Adversarial and attack scenarios |
| `test_attack_and_device_scenarios.py` | Device and replay attack scenarios |
| `test_deep_audit.py` | Deep audit: vault TTL, sequence tracking, API key auth |
| `test_security_audit.py` | NIST compliance gaps, nonce hygiene, FIDO2 gap |
| `test_browser_extension.py` | Extension manifest and API endpoint verification |
| `test_sandbox.py` | Synthetic-event pipeline smoke tests |
| `test_mouse_entropy.py` | Mouse entropy extraction |
| `test_per_move_analysis.py` | Per-movement key/RNG analysis |

---

## Documented limitations

1. **Pre-encryption malware** — software with kernel-level access can intercept plaintext before the crypto layer. No key derivation system defends against this.
2. **Presence score is not cryptographically bound** (local browser mode) — the mouse/keystroke gate is a UI control, not a cryptographic commitment.
3. **40-bit ghost code** — ~40 bits of security; suitable for a demo channel. Use FIDO2/WebAuthn for production second factors.
4. **ARP MAC lookup is LAN-only** — remote attackers show "unknown" in the threat log.
5. **NIST tests are statistical, not FIPS-certified** — `nist_validator.py` is an engineering check, not a NIST/FIPS 140 submission.
6. **Schnorr ZKP is classical** — does not resist Shor's algorithm. Lattice-based ZKPs are the post-quantum recommendation.

See [SECURITY_LIMITATIONS.md](SECURITY_LIMITATIONS.md) for the full pre-deployment checklist.

---

## Project layout

```
├── sdk/                      Lightweight SDK (1 dep: cryptography)
│   ├── core.py               SumitKey class — encrypt/decrypt/keygen
│   ├── server.py             Minimal FastAPI server (4 endpoints)
│   ├── sumitkey.js           Browser SDK (zero deps, Web Crypto API)
│   └── integrations/         Platform examples
│       ├── whatsapp.py
│       ├── telegram.py
│       ├── gmail_drive.py
│       └── instagram_twitter.py
├── main.py                   CLI key generation + NIST experiments
├── capture.py                Mouse and keyboard event capture
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
├── threat_model.py           ⬤ Cryptographic threat model framework
├── browser_extension/        Chrome MV3 extension
│   ├── manifest.json
│   ├── background.js         Service worker — crypto, presence, storage
│   ├── content.js            Mouse/keystroke presence on any page
│   ├── popup.html            Send / Receive / Settings UI
│   └── popup.js              Popup controller
├── tests/                    290 passing · 2 skipped (mouse hardware)
├── scripts/                  Utilities, demos, NIST experiments
├── .github/
│   ├── CODEOWNERS            All files require @rock4007 review
│   └── CONTRIBUTING.md       Access request process
├── SPEAKING_NOTES.md         Dissertation presentation notes
└── STACKOVERFLOW_POST.md     Full technical Q&A reference
```

`⬤` proprietary — All Rights Reserved

---

## Dependency matrix

| Layer | Required | Optional |
|---|---|---|
| SDK core | `cryptography` | — |
| SDK server | `cryptography`, `fastapi`, `uvicorn` | — |
| Full stack | `cryptography`, `argon2-cffi`, `kyber-py`, `fastapi`, `uvicorn`, `pynput`, `numpy`, `nistrng` | `evdev` (Linux headless) |
| Browser extension | None (Web Crypto API) | — |

---

## License

Files marked `⬤` are proprietary — All Rights Reserved.
All other files are MIT licensed.
Copyright © 2026 Soumodeep Guha (rock4007)
