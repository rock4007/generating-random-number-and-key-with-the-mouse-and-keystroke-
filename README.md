# SUMIT KEY

**Behavioural Entropy Cryptographic Engine**  
*Mouse dynamics · Keystroke timing · Post-quantum hybrid encryption · Zero-knowledge proofs · High-Voltage Vault*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![KEM](https://img.shields.io/badge/KEM-ML--KEM--1024%20FIPS%20203-8957e5?style=flat-square)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-0075ca?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-Argon2id%20RFC%209106-0075ca?style=flat-square)
![ZKP](https://img.shields.io/badge/ZKP-Schnorr%20%2F%20Fiat--Shamir-6e40c9?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-21%20passing-2ea44f?style=flat-square)
![License](https://img.shields.io/badge/License-Proprietary%20%2F%20MIT-d29922?style=flat-square)
![Visibility](https://img.shields.io/badge/Repo-Private-f85149?style=flat-square)

---

> **Repository visibility: PRIVATE**  
> Core security modules are proprietary. See [License](#license) for details.

---

## Table of Contents

- [Overview](#overview)
- [Security Architecture](#security-architecture)
- [Cryptographic Stack](#cryptographic-stack)
- [Feature Matrix](#feature-matrix)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Modes](#cli-modes)
  - [REST API](#rest-api)
  - [Dashboard](#dashboard)
- [Module Reference](#module-reference)
- [Testing](#testing)
- [Benchmarks](#benchmarks)
- [Outputs](#outputs)
- [Security Considerations](#security-considerations)
- [License](#license)

---

## Overview

SUMIT KEY turns human behavioural signals — mouse micro-jitter, movement trajectories, keystroke inter-arrival timing — into high-entropy cryptographic material. The pipeline fuses that behavioural entropy with OS CSPRNG bytes, hardens the result through memory-hard KDFs, and exposes a full cryptographic service stack:

- **Hybrid quantum-safe encryption** (ML-KEM-1024 + Argon2id + AES-256-GCM)
- **Zero-knowledge identity proofs** (Schnorr / Fiat-Shamir over 2048-bit MODP)
- **High-Voltage Vault** with Shamir secret sharing, TTL dead-man switch, and burn-after-read
- **MITM Shield** wire protocol with post-quantum key exchange and HMAC envelope integrity
- **Rotating-key envelope** with 0.3-second epoch rotation and threat-gated encryption
- **Advanced threat detection** with honeypot, machine-timing, entropy-anomaly, and replay signals
- **REST API** (FastAPI) with 20+ endpoints covering entropy, keys, quantum, and vault operations

Behavioural entropy is treated as **additional input**, not the sole root of trust. Fresh-mode key generation always mixes OS CSPRNG bytes, ensuring cryptographic soundness even under zero user input.

---

## Security Architecture

![Architecture Diagram](docs/images/architecture.svg)

<details>
<summary>Text version (screen-reader / low-bandwidth)</summary>

```
┌────────────────────────────────────────────────────────────────────────┐
│                          INPUT LAYER                                   │
│   Mouse movements  ·  Keystroke timing  ·  Micro-vibration jitter      │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        ENTROPY ENGINE                                  │
│  Feature extraction → SHA3-512 pooling → SP 800-90B health checks      │
│  Output: 512-bit behavioural entropy pool                              │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
    ┌──────────────┐  ┌───────────────┐  ┌────────────────┐
    │  STACK A     │  │  STACK B      │  │  STACK C       │
    │  Classical   │  │  Post-Quantum │  │  ZKP / Vault   │
    │              │  │  Hybrid       │  │                │
    │ HKDF-SHA3    │  │ ML-KEM-1024   │  │ Schnorr ZKP    │
    │ AES-256-GCM  │  │ + Argon2id    │  │ Shamir SSS     │
    │ 0.3s rotate  │  │ + HKDF-SHA3  │  │ HV-Vault TTL   │
    │ Threat gate  │  │ + AES-256-GCM │  │ MITM Shield    │
    └──────────────┘  └───────────────┘  └────────────────┘
              │                │                │
              └────────────────┼────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    THREAT DETECTION LAYER                              │
│  Honeypot · Brute-force rate · Replay detection · Machine-timing CV   │
│  Entropy anomaly · Probe-rate · Suspicious UA · OTP bruteforce        │
│  Decision: ALLOW / MONITOR / QUARANTINE / BLOCK                       │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│               SERVERLESS / REST API SURFACE                            │
│  FastAPI · AWS Lambda · GCP Cloud Functions · Azure Functions          │
└────────────────────────────────────────────────────────────────────────┘
```

</details>

---

## Cryptographic Stack

| Layer | Algorithm | Standard | Parameters |
|-------|-----------|----------|------------|
| Post-quantum KEM | ML-KEM-1024 (Kyber) | FIPS 203 | ek=1568 B · dk=3168 B · ct=1568 B · ss=32 B |
| Memory-hard KDF | Argon2id | RFC 9106 | t=3 · m=65536 KB · p=1 · tag=64 B |
| Session key derivation | HKDF-SHA3-512 | RFC 5869 | ikm = KEM-ss ‖ Argon2id-out → 32 B |
| Symmetric encryption | AES-256-GCM | FIPS 197 / SP 800-38D | 96-bit nonce · 128-bit tag |
| Classical entropy extraction | SHA3-512 | FIPS 202 | 512-bit pool |
| Rotating key derivation | HMAC-SHA3-256 | FIPS 198 | 0.3-second epoch binding |
| Zero-knowledge proof | Schnorr (Fiat-Shamir) | RFC 3526 Group 14 | 2048-bit MODP safe prime · g=2 |
| Secret sharing | Shamir SSS over GF(2⁸) | — | AES field poly 0x11B · Lagrange interpolation |
| Wire integrity | HMAC-SHA3-512 | FIPS 198 | 64-byte envelope MAC |
| Shard encryption | Argon2id + AES-256-GCM | — | Per-shard unique salt |

### Key Derivation Flow

![Key Flow Diagram](docs/images/key_flow.svg)

---

## Feature Matrix

| Feature | Module | Status |
|---------|--------|--------|
| Mouse + keystroke behavioural entropy | `capture.py` / `entropy_engine.py` | Stable |
| SHA3 entropy pooling + health checks | `entropy_engine.py` | Stable |
| Classical HKDF key derivation | `key_generator.py` | Stable |
| AES-256-GCM message + file encryption | `crypto_tools.py` | Stable |
| 0.3-second rotating-key envelope | `advanced_security.py` | Stable |
| Threat-gated encryption | `advanced_security.py` | Stable |
| **ML-KEM-1024 quantum hybrid** | `crypto_tools.py` | Stable |
| **Argon2id memory-hard hardening** | `crypto_tools.py` | Stable |
| **Schnorr ZKP identity proofs** | `vault.py` | Stable |
| **Shamir secret sharing (GF 2⁸)** | `vault.py` | Stable |
| **High-Voltage Vault (TTL + burn)** | `vault.py` | Stable |
| **MITM Shield wire protocol** | `vault.py` | Stable |
| **Advanced threat detection** | `vault.py` / `advanced_security.py` | Stable |
| **Serverless handler** (Lambda/GCP/Azure) | `vault.py` | Stable |
| REST API (20+ endpoints) | `api.py` | Stable |
| Browser dashboard | `dashboard.html` | Stable |
| NIST SP 800-22 statistical validation | `nist_validator.py` | Stable |
| Per-move binary entropy output | `main.py` | Stable |
| Linux headless evdev capture | `capture.py` | Optional |

---

## System Requirements

**Runtime**

- Python 3.11 or newer
- pip 23+

**Desktop capture** (Windows / macOS / Linux with display)

- `pynput` — installed automatically via requirements

**Linux headless capture** (no display server)

- `evdev` — install manually: `pip install evdev`
- User must be in the `input` group: `sudo usermod -aG input $USER`

**API server**

- FastAPI + uvicorn — installed automatically

---

## Installation

```bash
# 1. Clone (private repo — requires GitHub auth)
git clone https://github.com/rock4007/generating-random-number-and-key-with-the-mouse-and-keystroke-.git
cd generating-random-number-and-key-with-the-mouse-and-keystroke-

# 2. Create isolated environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. (Optional) Linux headless
pip install evdev
```

---

## Usage

### CLI Modes

**Single generation** — one behavioural capture, one derived key:

```bash
python main.py
```

**Per-move generation** — one key + one binary output per mouse movement:

```bash
python main.py --mode per-move
```

Output: `results/per_move_generation.json`

**Quantum hybrid key generation** — ML-KEM-1024 + Argon2id session:

```python
from crypto_tools import quantum_keygen, quantum_encrypt_message, quantum_decrypt_message

session = quantum_keygen()                         # ML-KEM-1024 keypair
pkg     = quantum_encrypt_message("secret", session.ek)
plain   = quantum_decrypt_message(pkg, session.dk)
```

**Static-chain encryption** — repeatable key from captured mouse turns:

```bash
python debug_pipeline.py --static-chain
python debug_pipeline.py --static-chain-live 5    # 5-second live capture
```

**Fallback authentication** — movement quality → OTP → NFC decision chain:

```bash
python crypto_benchmark.py --quick
```

Four scenarios are exercised:

| Scenario | Movement | OTP | NFC | Result |
|----------|----------|-----|-----|--------|
| 1 | Good | — | — | PASS direct |
| 2 | Weak | Good | — | PASS via OTP |
| 3 | Bad | Bad | Good | PASS via NFC |
| 4 | Bad | Bad | Bad | DENY |

**NIST experiment batch** — statistical validation of 1000 keys:

```bash
python main.py --mode experiments --num-keys 1000
```

---

### REST API

Start the server:

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

Interactive docs available at `http://localhost:8000/docs`.

#### Endpoint Summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness check |
| POST | `/generate/random-number` | Derive 64-bit random number from behavioural entropy |
| POST | `/generate/key` | Derive AES key from behavioural entropy |
| POST | `/encrypt` | AES-256-GCM encrypt a message |
| POST | `/decrypt` | AES-256-GCM decrypt a message |
| POST | `/quantum/keygen` | Generate ML-KEM-1024 keypair |
| POST | `/quantum/encrypt` | Quantum-hybrid encrypt a message |
| POST | `/quantum/decrypt` | Quantum-hybrid decrypt a message |
| POST | `/vault/zkp/keygen` | Derive Schnorr ZKP keypair from entropy |
| POST | `/vault/zkp/prove` | Generate Schnorr proof of key knowledge |
| POST | `/vault/zkp/verify` | Verify Schnorr proof |
| POST | `/vault/store` | Store secret in High-Voltage Vault |
| POST | `/vault/retrieve` | Retrieve secret (burn-after-read enforced) |
| POST | `/vault/shamir/split` | Split secret into Shamir shards |
| POST | `/vault/shamir/combine` | Reconstruct secret from threshold shards |
| POST | `/vault/shield/begin` | Initiate MITM Shield session (client) |
| POST | `/vault/shield/accept` | Accept MITM Shield session (server) |
| POST | `/vault/shield/send` | Send protected message over Shield |
| POST | `/vault/threat/assess` | Run threat assessment on a session |
| GET | `/vault/info` | Vault capability summary |

#### Example — quantum encrypt/decrypt

```bash
# 1. Generate keypair
curl -X POST http://localhost:8000/quantum/keygen | jq .

# 2. Encrypt
curl -X POST http://localhost:8000/quantum/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "top secret", "ek_hex": "<ek from step 1>"}'

# 3. Decrypt
curl -X POST http://localhost:8000/quantum/decrypt \
  -H "Content-Type: application/json" \
  -d '{"package": <package from step 2>, "dk_hex": "<dk from step 1>"}'
```

#### High-Voltage Vault Lifecycle

![Vault Diagram](docs/images/vault.svg)

#### Example — High-Voltage Vault round-trip

```bash
# Store a secret (splits into 5 shards, requires 3 to recover)
curl -X POST http://localhost:8000/vault/store \
  -H "Content-Type: application/json" \
  -d '{
    "secret_hex": "deadbeef...",
    "master_password": "hunter2",
    "n_shards": 5,
    "threshold": 3,
    "ttl_seconds": 300,
    "burn_after_read": true
  }'

# Retrieve (vault is destroyed after one successful read)
curl -X POST http://localhost:8000/vault/retrieve \
  -H "Content-Type: application/json" \
  -d '{
    "vault_id": "<id from store>",
    "shard_xs": [1, 3, 5],
    "master_password": "hunter2"
  }'
```

---

### Dashboard

```bash
python -m http.server 8080
# Open: http://127.0.0.1:8080/dashboard.html
```

Features: live mouse-key generation, message encryption, one-minute scheduled file encryption, real-time key-stream monitoring, random number display.

---

## Screenshots

| Dashboard | Terminal output |
|-----------|----------------|
| ![Dashboard](docs/images/screenshot_dashboard.png) | ![Terminal](docs/images/screenshot_terminal.png) |

> **To add screenshots:** take a screenshot of `dashboard.html` and the CLI output, save them as `docs/images/screenshot_dashboard.png` and `docs/images/screenshot_terminal.png`, then `git add docs/images/ && git commit -m "Add screenshots"`.

---

## Module Reference

| File | Visibility | Description |
|------|-----------|-------------|
| `entropy_engine.py` | Open | Mouse + keystroke feature extraction, SHA3-512 pooling, health checks |
| `capture.py` | Open | pynput / evdev event capture with vibration-aware jitter scoring |
| `key_generator.py` | Open | HKDF-SHA3 key derivation, deterministic and fresh modes |
| `main.py` | Open | CLI runner — single, per-move, and batch experiment modes |
| `security.py` | Open | Security profile helpers and output formatting |
| `nist_validator.py` | Open | NIST SP 800-22 statistical test wrapper |
| `debug_pipeline.py` | Open | Static-chain and live-chain pipeline debug modes |
| `fallback_auth.py` | Open | Tiered authentication simulation (movement → OTP → NFC) |
| `api.py` | Open | FastAPI application — all 20+ REST endpoints |
| `dashboard.html` | Open | Browser-based live key and encryption dashboard |
| `test_sandbox.py` | Open | 21 synthetic pipeline validation tests |
| `test_blackbox_security.py` | Open | Black-box security property checks |
| `test_adversarial_scenarios.py` | Open | Adversarial entropy and attack scenario tests |
| **`crypto_tools.py`** | **Proprietary** | Classical + quantum-hybrid encryption stack |
| **`crypto_benchmark.py`** | **Proprietary** | 8-section performance benchmark suite |
| **`advanced_security.py`** | **Proprietary** | Rotating-key envelope + threat-gated encryption |
| **`threat_model.py`** | **Proprietary** | Formal threat model and risk assessment framework |
| **`vault.py`** | **Proprietary** | ZKP · Shamir SSS · High-Voltage Vault · MITM Shield · Serverless handler |

---

## Testing

**Full pipeline (21 tests):**

```bash
python test_sandbox.py
```

Covers: mouse entropy, keystroke entropy, entropy pooling, key derivation, deterministic behaviour, AES-GCM encryption, quantum hybrid roundtrip, ZKP prove/verify, Shamir split/combine, vault store/retrieve/burn, MITM Shield session, and threat detection signals.

**Black-box security:**

```bash
python test_blackbox_security.py
```

Validates: fresh-key uniqueness, avalanche behaviour, health-check rejection, quantum output length, AES-GCM tag authentication.

**Adversarial scenarios:**

```bash
python test_adversarial_scenarios.py
```

Simulates: entropy starvation, replay attacks, pattern injection, weak input rejection.

**Expected result across all suites:**

```
Results: 21 passed, 0 failed
```

---

## Benchmarks

Run the full 8-section benchmark:

```bash
python crypto_benchmark.py
```

Sections:

| # | Section | Metric |
|---|---------|--------|
| 1 | Entropy extraction | ops/s · latency ms |
| 2 | Key derivation (HKDF) | ops/s · latency ms |
| 3 | AES-256-GCM throughput | MB/s |
| 4 | Argon2id hardening | latency ms |
| 5 | ML-KEM-1024 keygen | ops/s |
| 6 | ML-KEM-1024 encaps/decaps | ops/s |
| 7 | Fallback auth scenarios | latency ms |
| 8 | Full quantum hybrid pipeline | ops/s · latency ms |

Quick mode (sections 1–3 only):

```bash
python crypto_benchmark.py --quick
```

---

## Outputs

| Path | Description |
|------|-------------|
| `results/latest_generation.json` | Most recent single-run output metadata |
| `results/per_move_generation.json` | Per-movement generation records |
| `results/combined_experiment_report.txt` | NIST experiment batch summary |
| `results/nist_report.txt` | Raw NIST SP 800-22 test output |

`results/*.bin` and `results/*.key` are excluded from version control via `.gitignore`.

---

## Security Considerations

**Behavioural entropy is supplemental, not the sole root of trust.**  
Fresh-mode key generation always XORs behavioural entropy with OS CSPRNG bytes (`os.urandom`). Predictable or zero mouse/keyboard input does not weaken the cryptographic output in fresh mode.

**Static-chain mode is intentionally deterministic.**  
The same captured movement sequence reproduces the same key. Use it for offline encryption workflows and demos. Use fresh mode when replay resistance is required.

**Vault shards carry per-shard Argon2id hardening.**  
Compromising one shard does not reveal the master secret or any other shard's content. Recovery requires at least `threshold` shards and the correct master password.

**MITM Shield replay window is ±5 minutes with monotonic sequence counters.**  
Packets outside the timestamp window or with a non-monotonic sequence are rejected before decryption.

**Threat detection blocks encryption, not just alerts.**  
Sessions scoring above the block threshold are denied at the `RotatingKeyEnvelope.encrypt()` call site, before any key material is derived.

**Rotating keys expire at epoch boundaries.**  
Decryption is only possible within the key epoch (0.3 seconds by default) plus any explicit clock-skew allowance. Intercepted ciphertext cannot be decrypted after epoch expiry.

**Phone/email OTP and NFC references in the fallback module are sandbox simulations.**  
Production OTP requires a provider integration with replay prevention, rate limiting, and short TTL. Production NFC should use FIDO2/WebAuthn or smart-card semantics.

**NIST SP 800-22 results assess statistical characteristics only.**  
This project is not a FIPS 140-validated cryptographic module and has not undergone formal entropy source certification under SP 800-90B.

---

## License

This project uses a **dual-license model**.

**Part A — Proprietary (All Rights Reserved)**  
`vault.py` · `crypto_tools.py` · `advanced_security.py` · `threat_model.py` · `crypto_benchmark.py`

These files are the exclusive property of Soumodeep Guha (rock4007). Copying, modification, distribution, sublicensing, or use in any form — commercial or non-commercial — is strictly prohibited without prior written permission.

**Part B — MIT License**  
All other files in this repository.

Copyright (c) 2026 Soumodeep Guha (rock4007)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

*Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved (proprietary modules).*
