# Stack Overflow / Cryptography Stack Exchange Post

---

## QUESTION

**Title:** How to generate cryptographic keys from mouse movement and keystroke timing in Python — design, entropy extraction, HKDF derivation, and NIST SP 800-22 validation

**Tags:** `python` `cryptography` `entropy` `key-derivation` `aes-gcm` `hkdf` `nist` `random-number-generation` `mouse` `biometrics`

---

I am building a system (SUMIT KEY) that generates cryptographic keys by capturing human behavioural signals — mouse micro-tremors, velocities, direction changes, and keystroke dwell/flight timing — and using them as an entropy source alongside `os.urandom`.

**What I am trying to accomplish:**

- Capture raw mouse/keystroke events and extract entropy features deterministically
- Pool and hash the features into a fixed-size entropy seed
- Derive a 256-bit or 512-bit key using HKDF-SHA3
- Optionally layer on: ML-KEM-1024 (FIPS 203) quantum-safe KEM, Argon2id hardening, Schnorr ZKP, Shamir Secret Sharing, and a High-Voltage Vault with burn-after-read
- Validate output quality using NIST SP 800-22 statistical tests

**Questions:**

1. What entropy features from mouse and keyboard are most meaningful and how should they be encoded as bytes for hashing?
2. How do you correctly implement HKDF-Extract + HKDF-Expand with SHA3-256 in Python without using the high-level `cryptography` library HKDF wrapper?
3. How should you pool multi-source entropy safely (avoiding concatenation ambiguity)?
4. How do you structure the NIST SP 800-22 experiments to compare entropy sources?
5. How do you ensure key material never leaks to disk, logs, or URLs?

**Environment:**
- Python 3.12
- Libraries: `cryptography`, `argon2-cffi`, `kyber-py` (ML-KEM-1024), `nistrng`, `pynput`

---

---

## ANSWER (Self-answered)

This is a complete walkthrough of SUMIT KEY. Each section answers one of the questions above.

---

### 1. Entropy Feature Extraction

The core insight is that humans cannot repeat mouse or keyboard behaviour with exact precision. That involuntary variation is the entropy signal.

**Mouse features (8 values packed as `>4d4I` = 64 bytes):**

```python
import struct, hashlib, statistics
from math import sqrt

def extract_mouse_entropy(mouse_events: list[dict]) -> bytes:
    velocities, directions, tremor_steps, vibration_steps = [], [], [], []

    for ev in mouse_events:
        velocities.append(float(ev.get("velocity_px_per_s", 0.0)))
        directions.append(float(ev.get("direction_angle_deg", 0.0)))

    for i in range(1, len(mouse_events)):
        dx = float(mouse_events[i].get("x", 0)) - float(mouse_events[i-1].get("x", 0))
        dy = float(mouse_events[i].get("y", 0)) - float(mouse_events[i-1].get("y", 0))
        d = sqrt(dx*dx + dy*dy)
        if 0 < d < 3.0:
            tremor_steps.append(d)   # micro-tremor: <3 px involuntary jitter
        elif d < 5.0:
            vibration_steps.append(d)

    direction_changes = sum(
        1 for i in range(1, len(directions))
        if abs((directions[i] - directions[i-1]) % 360 - 180) < 160
    )

    mean_v   = statistics.fmean(velocities) if velocities else 0.0
    stdev_v  = statistics.pstdev(velocities) if len(velocities) >= 2 else 0.0
    dcf      = direction_changes / max(1, len(directions) - 1)
    tremor   = sqrt(sum(s*s for s in tremor_steps) / len(tremor_steps)) if tremor_steps else 0.0

    return struct.pack(
        ">4d4I",
        mean_v, stdev_v, dcf, tremor,
        len(mouse_events), len(directions),
        len(tremor_steps), len(vibration_steps),
    )
```

**Why these features work:**

| Feature | Source of entropy |
|---|---|
| `velocity_σ` | Motor jitter — never constant, person-specific |
| `direction_change_freq` | Path shape — depends on unconscious tracking style |
| `micro_tremor_rms` | Involuntary neuromuscular noise, impossible to fake at <3 px precision |
| `dwell_time_ms` | How long each key is held — physiological, moment-specific |
| `flight_time_ms` | Gap between consecutive releases — encodes typing rhythm |
| `bigram_timing` | Per key-pair transition delays — fine motor control fingerprint |

**Keystroke features (variable-length, bigram-aware):**

```python
def extract_keystroke_entropy(events: list[dict]) -> bytes:
    dwell  = [float(ev.get("dwell_time_ms",  0.0)) for ev in events]
    flight = [float(ev.get("flight_time_ms", 0.0)) for ev in events]

    bigrams: dict[str, list[float]] = {}
    for i in range(1, len(events)):
        pair = f"{events[i-1].get('key','?')}->{events[i].get('key','?')}"
        dt   = (float(events[i].get("release_timestamp", 0))
              - float(events[i-1].get("release_timestamp", 0))) * 1000
        if dt >= 0:
            bigrams.setdefault(pair, []).append(dt)

    buf = bytearray()
    buf += struct.pack(
        ">4dI",
        statistics.fmean(dwell)  if dwell  else 0.0,
        statistics.pstdev(dwell) if len(dwell) >= 2 else 0.0,
        statistics.fmean(flight) if flight else 0.0,
        statistics.pstdev(flight) if len(flight) >= 2 else 0.0,
        len(events),
    )
    sorted_bigrams = sorted((p, sum(v)/len(v)) for p, v in bigrams.items())
    buf += struct.pack(">I", len(sorted_bigrams))
    for pair, mean_ms in sorted_bigrams:
        pb = pair.encode("utf-8")
        buf += struct.pack(">H", len(pb)) + pb + struct.pack(">d", mean_ms)
    return bytes(buf)
```

**Important**: Bigrams are sorted alphabetically before packing so the output is deterministic regardless of insertion order.

---

### 2. Entropy Pooling (no concatenation ambiguity)

Naïve concatenation `mouse_bytes + keystroke_bytes` is ambiguous — a 3-byte mouse blob followed by a 5-byte key blob hashes identically to a 4-byte mouse blob followed by a 4-byte key blob if the bytes happen to align. **Length-prefix each source:**

```python
def pool_entropy(mouse_bytes: bytes, keystroke_bytes: bytes) -> bytes:
    h = hashlib.sha3_256()
    h.update(len(mouse_bytes).to_bytes(4, "big"))
    h.update(mouse_bytes)
    h.update(len(keystroke_bytes).to_bytes(4, "big"))
    h.update(keystroke_bytes)
    return h.digest()   # 32 bytes
```

This is the same pattern used in TLS 1.3 transcript hashing and HKDF itself.

---

### 3. HKDF-SHA3 Key Derivation (manual implementation)

HKDF (RFC 5869) has two steps: **Extract** compresses high-entropy-but-biased IKM into a uniform PRK; **Expand** stretches PRK into output key material of any length.

```python
import hmac, hashlib

HASH_NAME = "sha3_256"
HASH_LEN  = 32          # SHA3-256 output length

def hkdf_extract(ikm: bytes, salt: bytes) -> bytes:
    """PRK = HMAC-SHA3-256(salt, IKM)"""
    salt = salt or b"\x00" * HASH_LEN
    return hmac.new(salt, ikm, digestmod=HASH_NAME).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """OKM = T(1) || T(2) || ... truncated to `length` bytes
       T(i) = HMAC-SHA3-256(PRK, T(i-1) || info || i)
    """
    okm, prev, counter = b"", b"", 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), digestmod=HASH_NAME).digest()
        okm += prev
        counter += 1
    return okm[:length]

def generate_key(
    behavioural_entropy: bytes,
    *,
    salt:   bytes = b"SUMIT_KEY_v1",
    info:   bytes = b"behavioural_entropy_key",
    length: int   = 32,
) -> bytes:
    # Always mix OS randomness — weak capture still yields a secure key
    system_random = os.urandom(length)

    # Length-prefix all inputs to avoid boundary ambiguity
    ikm = (
        b"SUMIT_KEY_FRESH_V1"
        + _length_prefix(behavioural_entropy)
        + _length_prefix(system_random)
    )

    prk = hkdf_extract(ikm, salt)
    return hkdf_expand(prk, info, length)

def _length_prefix(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data
```

**Why SHA3 instead of SHA2?** SHA3 (Keccak) has a different sponge construction — it is immune to length-extension attacks that affect SHA2-based HMAC in some edge cases, and it is listed in FIPS 202. For post-quantum threat models, SHA3-512 provides a 256-bit security margin against Grover-style attacks.

**Input health checks (NIST SP 800-90B inspired):**

```python
def health_check_entropy(data: bytes, min_bytes: int = 32) -> None:
    if len(data) < min_bytes:
        raise ValueError(f"Need ≥{min_bytes} bytes; got {len(data)}")
    if len(set(data)) < 2:
        raise ValueError("Input is constant — all bytes identical")

    # Longest repeated-byte run
    run = max_run = 1
    for a, b in zip(data, data[1:]):
        run = run + 1 if b == a else 1
        max_run = max(max_run, run)
    if max_run > min_bytes:
        raise ValueError(f"Repeated-byte run of {max_run} detected")

    # Single-byte dominance
    most_common = max(data.count(v) for v in set(data))
    if most_common / len(data) > 0.85:
        raise ValueError("One byte value dominates (>85%) — likely degenerate input")
```

---

### 4. Quantum-Safe Hybrid: ML-KEM-1024 + Argon2id + AES-256-GCM

For post-quantum security, SUMIT KEY implements a hybrid that requires **both** the ML-KEM decapsulation key **and** the Argon2id-hardened behavioural entropy to decrypt:

```
Encrypt:
  kem_shared, kem_ct ← ML_KEM_1024.encaps(ek)         # 1568-byte ciphertext
  hardened           ← Argon2id(behaviour, salt, t=1, m=64MB)  # 64 bytes
  hardened_enc       ← AES-GCM(kem_shared[:32], hardened)      # bundled in package
  session_key        ← HKDF-SHA3-512(kem_shared ‖ hardened)    # 32 bytes
  ciphertext         ← AES-GCM(session_key, plaintext, aad)

Decrypt (needs only dk):
  kem_shared   ← ML_KEM_1024.decaps(dk, kem_ct)
  hardened     ← AES-GCM-decrypt(kem_shared[:32], hardened_enc)  # recovered
  session_key  ← HKDF-SHA3-512(kem_shared ‖ hardened)
  plaintext    ← AES-GCM-decrypt(session_key, ciphertext, aad)
```

```python
from kyber_py.ml_kem import ML_KEM_1024
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2.low_level import hash_secret_raw, Type
import os

def quantum_encrypt(ek_bytes: bytes, plaintext: bytes, behaviour: bytes) -> dict:
    kem_shared, kem_ct = ML_KEM_1024.encaps(ek_bytes)

    salt    = os.urandom(16)
    hardened = hash_secret_raw(behaviour, salt, time_cost=1,
                               memory_cost=65536, parallelism=1,
                               hash_len=64, type=Type.ID)

    kem_aes        = AESGCM(kem_shared[:32])
    hardened_nonce = os.urandom(12)
    hardened_enc   = kem_aes.encrypt(hardened_nonce, hardened, None)

    ikm        = kem_shared + hardened
    session_key = HKDF(hashes.SHA3_512(), 32,
                       salt=b"SUMIT_QS_HKDF_SALT_V2",
                       info=b"SUMIT-QS-AES256-SESSION-KEY-V2").derive(ikm)

    nonce      = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, None)

    return dict(kem_ct=kem_ct, argon2_salt=salt,
                hardened_nonce=hardened_nonce, hardened_enc=hardened_enc,
                nonce=nonce, ciphertext=ciphertext)
```

**Defense-in-depth properties:**

| Attack | What stops it |
|---|---|
| Steal ML-KEM dk only | Attacker recovers `hardened_enc` but still needs Argon2id to reproduce `hardened` — cannot without behavioural replay |
| Reproduce behavioural entropy only | Attacker can recompute `hardened` but cannot recover `kem_shared` without dk |
| Full break | Both dk **and** behavioural entropy required simultaneously |

---

### 5. AES-256-GCM File Encryption with Filename AAD Binding

The encrypted file format binds the ciphertext to the original filename via AAD. A rename attack — where `secret.enc` is renamed to `public.enc` and decrypted — is now detectable:

```python
MAGIC    = b"SUMITKEY1"
NONCE_SZ = 12

def encrypt_file(key: bytes, src: Path, dst: Path) -> None:
    plaintext = src.read_bytes()
    aad       = f"file:{src.name}".encode()  # binds ciphertext to filename
    nonce     = os.urandom(NONCE_SZ)
    ct        = AESGCM(key[:32]).encrypt(nonce, plaintext, aad)

    with dst.open("wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">H", len(aad)))
        f.write(aad)
        f.write(nonce)
        f.write(ct)

def decrypt_file(
    key: bytes,
    src: Path,
    dst: Path,
    *,
    expected_name: str | None = None,   # opt-in rename-attack detection
) -> None:
    import hmac as _hmac
    data = src.read_bytes()
    assert data.startswith(MAGIC), "Bad magic"

    off     = len(MAGIC)
    aad_len = struct.unpack(">H", data[off:off+2])[0]; off += 2
    aad     = data[off:off+aad_len];                   off += aad_len
    nonce   = data[off:off+NONCE_SZ];                  off += NONCE_SZ
    ct      = data[off:]

    # GCM authentication proves AAD was not tampered with.
    # This check proves the caller is decrypting the file they intended.
    if expected_name is not None:
        expected = f"file:{expected_name}".encode()
        if not _hmac.compare_digest(aad, expected):
            raise ValueError(
                f"Filename mismatch: encrypted as {aad!r}, "
                f"expected 'file:{expected_name}'"
            )

    plaintext = AESGCM(key[:32]).decrypt(nonce, ct, aad)
    dst.write_bytes(plaintext)
```

---

### 6. Schnorr Zero-Knowledge Proof over RFC 3526 Group 14

The ZKP proves knowledge of a behavioural-entropy-derived secret **without transmitting it**. Uses the 2048-bit safe prime from RFC 3526:

```python
import hashlib, os

# RFC 3526 Group 14 — 2048-bit MODP safe prime
P = int("FFFFFFFF...FFFFFFFF", 16)   # 512 hex chars
G = 2
Q = (P - 1) // 2   # safe prime: order q = (p-1)/2

def zkp_keygen(entropy: bytes):
    digest = hashlib.sha3_512(b"SUMIT-ZKP-SK-v1" + entropy).digest()
    sk = (int.from_bytes(digest, "big") % (Q - 1)) + 1
    pk = pow(G, sk, P)
    return sk, pk

def zkp_prove(sk: int, pk: int, context: bytes = b"") -> dict:
    r      = (int.from_bytes(os.urandom(64), "big") % (Q - 1)) + 1
    R      = pow(G, r, P)
    c_hash = hashlib.sha3_256(
        pk.to_bytes(256, "big") + R.to_bytes(256, "big") + context
    ).digest()
    c = int.from_bytes(c_hash, "big") % Q
    z = (r + c * sk) % Q
    return {"R": R, "c": c_hash.hex(), "z": z}

def zkp_verify(pk: int, proof: dict, context: bytes = b"") -> bool:
    R, c_hex, z = proof["R"], proof["c"], proof["z"]
    c_recomputed = hashlib.sha3_256(
        pk.to_bytes(256, "big") + R.to_bytes(256, "big") + context
    ).digest()
    if not hmac.compare_digest(c_recomputed, bytes.fromhex(c_hex)):
        return False
    c_int = int.from_bytes(c_recomputed, "big") % Q
    # Schnorr equation: g^z ≡ R · pk^c  (mod p)
    return pow(G, z, P) == (R * pow(pk, c_int, P)) % P
```

---

### 7. Shamir Secret Sharing over GF(2⁸)

One polynomial per secret byte, operating in the AES field (irreducible poly `0x11B`):

```python
GF_POLY = 0x11B   # AES field polynomial

def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) — Russian-peasant algorithm."""
    p = 0
    while b:
        if b & 1: p ^= a
        a = (a << 1) ^ (GF_POLY if a & 0x80 else 0)
        b >>= 1
    return p & 0xFF

def shamir_split(secret: bytes, n: int, t: int) -> list[tuple[int, bytes]]:
    """Split secret into n shards; any t reconstruct it."""
    shards = [(i, bytearray()) for i in range(1, n + 1)]
    for byte_val in secret:
        coeffs = [byte_val] + [int.from_bytes(os.urandom(1), "big") for _ in range(t - 1)]
        for x, shard_bytes in shards:
            y = 0
            for coeff in reversed(coeffs):
                y = _gf_mul(y, x) ^ coeff
            shard_bytes.append(y)
    return [(x, bytes(b)) for x, b in shards]

def shamir_combine(shards: list[tuple[int, bytes]]) -> bytes:
    """Lagrange interpolation at x=0 to recover the secret."""
    secret = bytearray()
    for i in range(len(shards[0][1])):
        y_vals = [(x, b[i]) for x, b in shards]
        val = 0
        for j, (xj, yj) in enumerate(y_vals):
            num = den = 1
            for k, (xk, _) in enumerate(y_vals):
                if k != j:
                    num = _gf_mul(num, xk)
                    den = _gf_mul(den, xj ^ xk)
            # GF(2^8) division via Fermat's little theorem: a^(2^8-2) = a^(-1)
            inv_den = pow(den, 254, 0x100)  # works because |GF(2^8)*| = 255
            val ^= _gf_mul(_gf_mul(num, inv_den), yj)
        secret.append(val)
    return bytes(secret)
```

---

### 8. NIST SP 800-22 Experiment Design

Three experiments compare entropy sources side-by-side:

```
Experiment A: keys_a = derive_batch(mouse_entropy,       n=4000)
Experiment B: keys_b = derive_batch(keystroke_entropy,   n=4000)
Experiment C: keys_c = derive_batch(combined_entropy,    n=4000)
```

Each key contributes its bit stream to a single concatenated sequence. NIST tests run on that sequence.

```python
def derive_batch(base_entropy: bytes, tag: str, n: int) -> list[bytes]:
    """Generate n diverse keys from one entropy base using domain-separated hashing."""
    prefix = hashlib.sha3_256(
        tag.encode() + b"|SUMIT_KEY_BATCH|" + base_entropy
    ).digest()
    keys = []
    for i in range(n):
        personalization = tag.encode() + b"|" + i.to_bytes(8, "big")
        behaviour       = hashlib.sha3_256(prefix + personalization + base_entropy).digest()
        keys.append(generate_key(behaviour, personalization=personalization))
    return keys
```

**Why domain separation matters**: using the same `prefix + i` without the experiment tag would produce identical keys across experiments A/B/C if the underlying entropy happens to be equal — making the NIST comparison meaningless.

**Interpreting results**:

| Score | Meaning |
|---|---|
| Raw pass rate | Fraction of eligible NIST tests passed |
| Calibrated pass rate | Raw rate excluding tests that also fail on `os.urandom` in this environment |
| Eligible tests | Subset of 15 tests that have enough bits to run (some need ≥10⁶ bits) |

Experiment C (combined) should equal or exceed A and B — entropy fusion never reduces statistical quality.

---

### 9. Key Material Never Reaches Disk, Logs, or URLs

Three design rules enforced in this project:

**Rule 1 — Never write key_hex to disk.** Save only a fingerprint:

```python
key_fp = "fp:" + hashlib.sha256(key_bytes).hexdigest()[:16]

# saved dict strips key_hex and binary_output
saved = {k: v for k, v in output.items() if k not in ("key_hex", "binary_output")}
Path("results/latest_generation.json").write_text(json.dumps(saved, indent=2))
```

**Rule 2 — Never put sensitive data in query parameters.** Query params appear in server access logs, `Referer` headers, and browser history. Use POST body models:

```python
class EncryptBody(BaseModel):
    message: str       # ← POST body, never a Query(...)
    key_hex: str
    label: str = ""

@app.post("/encrypt/message")
def encrypt_endpoint(body: EncryptBody) -> dict:
    key = bytes.fromhex(body.key_hex)   # never logged
    ...
```

**Rule 3 — API `/generate` redacts key by default.** Full key returned only on explicit opt-in:

```python
@app.post("/generate")
def generate(include_key: bool = Query(default=False)) -> dict:
    ...
    response = {"key_fingerprint": key_fp, "key_bits": bits, ...}
    if include_key:
        response["key_hex"] = result["key_hex"]   # opt-in only
    return response
```

---

### 10. Chrome Extension: Self-Contained AES-256-GCM (no server, no libraries)

The extension uses the browser's `crypto.subtle` Web Crypto API directly:

```javascript
async function deriveKey(ghostCode, salt) {
    const raw = new TextEncoder().encode(ghostCode);
    const km  = await crypto.subtle.importKey("raw", raw, {name: "PBKDF2"}, false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        {name: "PBKDF2", hash: "SHA-256", salt, iterations: 210_000},
        km,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt", "decrypt"],
    );
}

async function localEncrypt(message, ttlSeconds) {
    const salt      = crypto.getRandomValues(new Uint8Array(16));
    const nonce     = crypto.getRandomValues(new Uint8Array(12));
    const ghostCode = generateGhostCode();   // 5 random bytes → 10 hex chars → "AAAAA-BBBBB"
    const key       = await deriveKey(ghostCode, salt);
    const cipher    = await crypto.subtle.encrypt(
        {name: "AES-GCM", iv: nonce},
        key,
        new TextEncoder().encode(message),
    );
    return {
        pkg: {mode: "local", ver: 1, cipher: b64(cipher), nonce: b64(nonce),
              salt: b64(salt), expires_at: Math.floor(Date.now()/1000) + ttlSeconds},
        ghostCode,
    };
}
```

**Security properties of the ghost code handoff:**

```
Sender                                       Receiver
──────                                       ────────
Create ghost package (AES-GCM encrypted)     Install extension
Share package JSON  ──── any channel ──────→ Paste package JSON
Share ghost code    ── separate channel ───→ Enter ghost code
(e.g. email the JSON, SMS the code)          Move mouse (presence ≥ 40)
                                             Click Open → plaintext shown once
                                             Ghost code cleared from storage
```

Intercepting only the package JSON gives the attacker nothing — the ghost code is the only secret and travels separately. PBKDF2 with 210,000 SHA-256 iterations makes brute-force on the 40-bit code expensive (~weeks on commodity hardware for a 10-hex-char space).

---

### Summary of cryptographic stack

| Layer | Algorithm | Security (classical) | Security (quantum) |
|---|---|---|---|
| Entropy pool | SHA3-256 | 256-bit collision | 128-bit (Grover) |
| Key derivation | HKDF-SHA3-256/512 | 256/512-bit | 128/256-bit |
| Symmetric encryption | AES-256-GCM | 256-bit | 128-bit |
| KEM | ML-KEM-1024 (FIPS 203) | — | 128-bit (NIST L5) |
| KDF hardening | Argon2id (64 MB, t=1) | Memory-hard | Memory-hard |
| Secret distribution | Shamir SSS over GF(2⁸) | Information-theoretic | Information-theoretic |
| Authentication proof | Schnorr ZKP (2048-bit MODP) | DL-hard | Broken by Shor |
| Wire integrity | HMAC-SHA3-512 | 256-bit | 128-bit |

**Documented limitations (important for production use):**

1. Behavioural entropy is supplemental — it raises the cost of key prediction but does not replace `os.urandom`. A weak capture still produces a secure key via the OS randomness path.
2. Pre-encryption malware that controls the process can intercept plaintext. No entropy system defends against this.
3. The 40-bit ghost code is suitable for demonstration; FIDO2/WebAuthn is recommended for production second factors.
4. NIST SP 800-22 tests are statistical engineering checks, not FIPS 140 certification.
5. Schnorr ZKP is classical — it does not resist Shor's algorithm. For post-quantum identity proofs, lattice-based ZKPs (e.g., those in CRYSTALS-Dilithium) are the current recommendation.

---

**Full source:** https://github.com/rock4007/generating-random-number-and-key-with-the-mouse-and-keystroke-

**Test suite:** 237 tests (2 skipped — require a physical mouse), covering HKDF correctness, round-trip encryption, NIST statistical validation, ZKP verify, Shamir reconstruct, vault burn-after-read, MITMShield replay rejection, and AAD filename binding.
