# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning 2.0.0](https://semver.org).

---

## [1.0.0] — 2026-06-06

### Added

**Core cryptography (Stack A)**
- `SumitKey` class with AES-256-GCM encrypt/decrypt and HKDF-SHA3-256 key derivation
- `pool_entropy()` — behavioural feature extraction from mouse velocity, micro-tremor, keystroke dwell/flight time, and per-key-pair bigrams
- `new_shared_secret()` — 256-bit random secret for channel bootstrap
- Envelope format `{"magic":"SUMK","v":1,"nonce":…,"ct":…,"fp":…}`
- File encryption with filename-bound AAD (`decrypt_file(expected_name=)` — rename attacks raise `ValueError`)
- `MITMShield` — HMAC-SHA3-512 associated-data binding; `hmac.compare_digest` on verify

**Per-user identity (Stack A extension)**
- `UserIdentity(user_id, platform, device_secret, behaviour)` — per-user, per-platform cryptographic identity
- `Channel` — symmetric key context derived from `HKDF-SHA3-256(sorted(alice_pid, bob_pid) ‖ platform ‖ shared_secret)`
- Platform isolation: WhatsApp, Telegram, Gmail, Instagram, Twitter/X, Google Drive
- Individual integrations in `sdk/integrations/` — phone-number, username, and handle binding

**Quantum-safe (Stack B)**
- ML-KEM-1024 key encapsulation (NIST FIPS 203) via `kyber-py`
- Argon2id 64 MB memory-hard KDF (RFC 9106) for session key hardening
- HKDF-SHA3-512 session key derivation on top of KEM shared secret

**Zero-knowledge & vault (Stack C)**
- Schnorr/Fiat-Shamir ZKP for identity proof
- Shamir Secret Sharing GF(2⁸) for threshold key recovery
- Ghost package (burn-after-read): `ARMED → HOT → BURNED` state machine with configurable TTL
- Key zeroization via `bytearray` overwrite on use or expiry

**Rotating keys (Stack D)**
- 0.3-second epoch key rotation
- Threat detection pre-derivation with automated block
- Self-healing failover service (`self_healing.py`)
- Identity binding: `user + session + device`

**API surface**
- Full REST API (`api.py`) — 30+ endpoints including `/benchmark`, `/threat-model`, `/nist/experiments`
- Lightweight SDK server (`sdk/server.py`) — 4 endpoints, 1 runtime dependency (`cryptography`)
- Chrome MV3 browser extension with Web Crypto API (`browser_extension/`)
- JavaScript browser SDK (`sdk/sumitkey.js`) — zero dependencies

**Platform integrations**
- WhatsApp (phone-number bound), Telegram (username bound), Gmail + Google Drive (email bound), Instagram + Twitter/X (handle bound)

**Entropy pipeline**
- Mouse event capture (`capture.py`, `pynput`)
- Feature extraction and entropy pooling (`entropy_engine.py`)
- HKDF-SHA3-256 key derivation from entropy pool (`key_generator.py`)
- NIST SP 800-22 statistical test battery (`nist_validator.py`, `nistrng`)

**Security infrastructure**
- Rate limiting: 10 req/min, 100 req/hr per IP (`security.py`)
- Threat logger with monotonic timestamp, IP, and LAN MAC resolution
- API key authentication (opt-in via `SUMITKEY_API_KEY`)

**Test suite — 318 passing**
- `test_identity.py` — 28 tests: per-user identity, channel key derivation, all-platform isolation
- `test_connectivity.py` — 53 tests: cross-stack connectivity (8 stacks × all interfaces)
- `test_logical_fixes.py` — 17 tests: vault password guard, AAD, serverless POST body
- `test_file_decrypt_aad.py` — 14 tests: filename AAD binding and rename-attack detection
- Black-box, adversarial, deep-audit, and sandbox test modules

**Documentation**
- README with SVG architecture diagrams, Mermaid flowcharts, full API reference
- Interactive system flow visualisation (`flow.html`, 8 tabs including Social Media Safety)
- SECURITY.md, CHANGELOG.md, GitHub issue templates

**Deployment**
- `Dockerfile` — `python:3.11-slim`, 3 dependencies, exposes `:8001`
- Kubernetes deployment manifest (`k8s/deployment.yaml`)

---

## Versioning policy

| Version component | Changed when |
|---|---|
| Major (`X.0.0`) | Breaking changes to the public API surface |
| Minor (`1.X.0`) | New backwards-compatible features |
| Patch (`1.0.X`) | Backwards-compatible bug fixes and security patches |

The public API surface is: `sdk/core.py`, `sdk/identity.py`, `sdk/server.py`, `sdk/sumitkey.js`.

Internal modules marked `⬤` are private — they may change in any version.
