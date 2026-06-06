# SUMIT KEY — Dissertation Speaking Notes

## 1. Opening (1–2 min)

**What problem does this solve?**

Most cryptographic keys are generated from a random number generator — strong, but identical in nature. They carry no identity. SUMIT KEY asks: what if the randomness came from *you*? From the way you move your mouse, the rhythm of your keystrokes?

That is the core idea. Human behavioural patterns are chaotic, biometric, and non-repeatable. SUMIT KEY harvests that chaos as an additional entropy source, mixes it with OS-level randomness, and produces keys that are tied to both the hardware *and* the human using it.

This is not a replacement for system randomness — it is entropy enrichment with a human fingerprint.

---

## 2. Architecture overview (3–4 min)

**Five-stage pipeline:**

```
Mouse + Keyboard
      │
      ▼
 [Capture Layer]        pynput / evdev / Chrome extension Web Crypto
      │
      ▼
 [Feature Extraction]   velocity, direction-change rate, micro-tremor,
                        dwell time, flight time, bigram timing
      │
      ▼
 [Entropy Pooling]      SHA3-256(len(mouse) ‖ mouse ‖ len(keys) ‖ keys)
      │
      ▼
 [Key Derivation]       HKDF-SHA3 + OS urandom + personalization
      │
      ▼
 [Cryptographic Use]    AES-256-GCM  /  ML-KEM-1024 hybrid  /  Vault
```

**Key design decisions worth explaining:**

- **Length-prefixed hashing** at every boundary prevents concatenation collisions.
- **OS randomness is always mixed in** — even if behavioural capture is weak, the key is still cryptographically strong.
- **Health checks** (NIST SP 800-90B inspired) reject constant, dominated, or short-run inputs before key derivation.

---

## 3. Entropy features (2 min)

**Why these features carry entropy:**

| Feature | Why it is hard to reproduce |
|---------|----------------------------|
| Velocity σ | Motor jitter varies continuously; two captures are never identical |
| Direction change freq | Depends on path, not just speed |
| Micro-tremor (<3 px steps) | Involuntary neuromuscular noise — impossible to fake precisely |
| Keystroke dwell time | Physiological, person-specific, moment-specific |
| Keystroke flight time | Transition timing encodes rhythm |
| Bigram timings | Per-pair delays reveal fine motor control patterns |

The entropy is not astronomical — that is why OS randomness is always layered on top. The behavioural signal raises the cost of prediction beyond what a passive observer could replicate.

---

## 4. Cryptographic pipeline (4–5 min)

**Three independent stacks, one entropy pool:**

### Stack A — Classical (AES-256-GCM)
- HKDF-SHA3 extracts + expands behavioural entropy
- AES-256-GCM provides ~128-bit post-quantum security via Grover's algorithm
- 96-bit nonce generated fresh per operation via `os.urandom`
- File format: `MAGIC(9) + aad_len(2) + aad(N) + nonce(12) + ciphertext+tag`
- **Filename AAD binding**: `file:<original_name>` is bound into the GCM tag — renaming the encrypted file and decrypting with `expected_name=` raises `ValueError`

### Stack B — Quantum-safe Hybrid (ML-KEM-1024 + Argon2id + AES-256-GCM)
- **ML-KEM-1024 (FIPS 203)**: NIST Level 5 — resists Shor's algorithm
- **Argon2id hardening**: behavioural entropy is memory-hard hardened before use
- **HKDF-SHA3-512**: derives session key from KEM shared secret + Argon2id output
- Defense in depth: breaking KEM alone does not reveal the plaintext (Argon2id blob also required); reproducing behaviour alone is not enough (ML-KEM dk also required)

### Stack C — Zero-Knowledge + Vault
- **Schnorr ZKP** (Fiat-Shamir, RFC 3526 Group 14): proves knowledge of behavioural-derived secret without revealing it
- **Shamir Secret Sharing** over GF(2⁸): splits key into N shards, requires threshold T to reconstruct
- **High-Voltage Vault**: burn-after-read, TTL dead-man switch, ARMED → HOT → BURNED states
- **MITM Shield**: ML-KEM session key + AES-GCM payload + HMAC-SHA3-512 envelope, ±5-minute replay window + monotonic sequence counter

---

## 5. Security design decisions (3 min)

**Three fixes made during development that are worth highlighting in Q&A:**

1. **Key material never written to disk** — `results/latest_generation.json` stores only a fingerprint (`sha256[:16]`), never the raw `key_hex`. The key stays in memory only.

2. **Sensitive data kept out of URLs** — `/generate-and-encrypt`, `/encrypt/rotating-message`, `/decrypt/rotating-message`, and `/encrypt/self-healing-message` all use POST body models. Query parameters appear in server access logs, browser history, and HTTP Referer headers — none of those should contain plaintext messages or device secrets.

3. **`/generate` endpoint redacts key by default** — the full `key_hex` is only returned when the caller passes `include_key=true`. The default response returns a fingerprint, so accidental logging at a proxy or load balancer does not expose key material.

---

## 6. NIST SP 800-22 validation (2 min)

Three experiments (A, B, C) compare entropy sources:

| Experiment | Source | Question |
|-----------|--------|----------|
| A | Mouse only | Is mouse movement alone statistically random? |
| B | Keystroke only | Is typing rhythm alone statistically random? |
| C | Mouse + Keystroke | Does combination beat either source alone? |

Each experiment generates 4,000 keys (configurable up to 20,000). NIST tests run on the concatenated bit stream.

**Expected result**: Experiment C (combined) should equal or exceed A and B on pass rate because entropy fusion strengthens the pooled signal.

**Calibration note**: Some NIST tests (e.g., longest run, non-overlapping templates) require large bit counts to become eligible. Report the calibrated pass rate (excluding tests that also fail on `os.urandom` in the test environment) alongside the raw score.

---

## 7. Browser Extension (2 min)

The Chrome MV3 extension demonstrates SUMIT KEY with zero server requirements:

- **Self-contained AES-256-GCM** using `crypto.subtle` (Web Crypto API, no third-party JS)
- **PBKDF2-SHA-256, 210,000 iterations** for ghost code key derivation
- **Presence gating**: user must accumulate score ≥ 40 from mouse/keystroke activity before decryption; bot-like flat motion cannot pass
- **Ghost code security**: 40-bit random secret travels via a separate channel from the ciphertext — intercepting the package JSON alone decrypts nothing
- **Burn-after-read**: decrypted plaintext stored only in `chrome.storage.session`, cleared after display

**Key threat model for the extension:**
- Extension is safe-by-default on offline installs — no network requests unless an API URL is configured
- `manifest.json` uses strict CSP: `script-src 'self'`; no remote scripts
- The presence score is a UI gate, not a cryptographic commitment (stated limitation)

---

## 8. Limitations (2 min — important for Q&A)

These are documented openly in `SECURITY_LIMITATIONS.md`:

1. **Pre-encryption malware** — software with kernel or browser access can intercept plaintext before the crypto layer. No key derivation system defends against this.

2. **Presence score is not cryptographically bound** (local mode) — a determined attacker who also controls the browser cannot be stopped by mouse-count gating alone.

3. **40-bit ghost code** — provides ~40 bits of security. Strong for a demo channel; not suitable as the sole authentication factor for high-value secrets.

4. **ARP MAC lookup is LAN-only** — `security.py` logs attacker MAC addresses from the OS ARP table, but this only works on the same LAN segment. Remote attackers show "unknown".

5. **NIST tests are statistical, not FIPS-certified** — the `nist_validator.py` is an engineering check, not a formal NIST/FIPS 140 validation.

6. **Behavioural entropy degrades under observation** — if an adversary records mouse/keystroke timing precisely, they could partially reproduce the features. OS randomness prevents this from being a full key recovery.

---

## 9. Q&A Prep

**"Why not just use os.urandom?"**
We do — it is always mixed in. Behavioural entropy is an *additional* layer that binds keys to a specific human + device session. The value is in the threat model: a stolen key file derived from pure CSPRNG has no identity; one derived from CSPRNG + behavioural entropy required the attacker to also replicate the exact capture session.

**"How do you validate the entropy quality?"**
Three ways: (1) NIST SP 800-22 statistical tests on 4,000 keys, (2) Shannon entropy + chi-squared + autocorrelation in the benchmark endpoint, (3) NIST SP 800-90B-inspired health checks that reject constant, dominated, or short-run inputs at ingestion time.

**"Is the ghost code secure enough?"**
For the dissertation demo: yes. The ghost code is 10 hex characters (40 bits) derived from `crypto.getRandomValues`, PBKDF2-hardened at 210,000 SHA-256 iterations, and travels out-of-band from the ciphertext. An attacker intercepting only one channel learns nothing. For production: we document that FIDO2/WebAuthn is the right second factor for high-value secrets.

**"What happens if mouse data is spoofed?"**
The health checks in `KeyGenerator.health_check_entropy` reject constant and dominated streams. Synthetic mouse events that repeat the same (x, y) produce a degenerate entropy pool. The OS randomness component means even a spoofed capture still produces a secure key — just one without the human identity component.

**"Why Schnorr ZKP over simpler password auth?"**
The ZKP proves knowledge of the behavioural-derived secret without ever transmitting it. A verifier learns only that the prover knows the secret — nothing about its value. This is useful for scenarios where the secret cannot be hashed and compared server-side without first being transmitted.

---

## 10. One-slide summary

> SUMIT KEY generates cryptographic keys by extracting entropy from mouse micro-tremors and keystroke timing, enriching OS randomness with a biometric signal. The system provides three independent cryptographic stacks (classical AES-256-GCM, quantum-safe ML-KEM-1024 hybrid, and zero-knowledge Schnorr + Shamir vault), validated against NIST SP 800-22 across three entropy-source experiments. A self-contained Chrome extension demonstrates the ghost message handoff protocol on any device with no server, using only the browser's Web Crypto API.
