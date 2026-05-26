# Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved.
# PROPRIETARY AND CONFIDENTIAL — see LICENSE (Part A) for terms.
# Unauthorised copying, modification, distribution, or use is strictly prohibited.

"""threat_model.py — Comprehensive threat model for SUMIT KEY cryptography.

Analyses every algorithm and attack surface across:
  1. Classical attacks     — brute-force, birthday, meet-in-the-middle
  2. Quantum attacks       — Grover search, Shor factoring, BKZ lattice
  3. Side-channel attacks  — timing, power, cache, fault injection
  4. Protocol attacks      — nonce reuse, key reuse, downgrade, replay
  5. Implementation risks  — known CVEs, subtle API traps
  6. Entropy source risks  — behavioural entropy threat surface

Covered algorithms:
  AES-256-GCM        — current SUMIT KEY cipher
  ChaCha20-Poly1305  — alternative cipher
  HKDF-SHA3-256      — current KDF
  Argon2id           — hardened KDF
  ML-KEM-1024        — post-quantum KEM (FIPS 203)
  MAYO-5             — post-quantum signature (documented; needs liboqs)

Usage:
  python threat_model.py              # full report
  python threat_model.py --json       # machine-readable JSON output
  get_threat_model()                  # importable dict for API
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AttackVector:
    name: str
    attack_type: str          # classical / quantum / side-channel / protocol / implementation
    complexity: str           # bits of security broken (e.g. "2^128") or qualitative
    feasible_now: bool        # with today's technology
    feasible_quantum: bool    # with a large fault-tolerant quantum computer
    mitigation: str
    severity: str             # CRITICAL / HIGH / MEDIUM / LOW / NEGLIGIBLE


@dataclass
class AlgorithmProfile:
    algorithm: str
    category: str
    key_size_bits: int
    security_classical_bits: int
    security_quantum_bits: int
    nist_pqc_level: int | None         # None if classical
    standardisation: str               # e.g. "NIST FIPS 197", "IETF RFC 8439"
    known_attacks: list[AttackVector]
    overall_verdict: str               # RECOMMENDED / ACCEPTABLE / DEPRECATED / ANALYSIS_ONLY
    verdict_reason: str
    references: list[str]


@dataclass
class ThreatModelReport:
    title: str
    summary: str
    algorithms: list[AlgorithmProfile]
    recommended_stack: list[str]
    attack_surface_entropy: list[AttackVector]
    overall_quantum_readiness: str


# ---------------------------------------------------------------------------
# Algorithm profiles
# ---------------------------------------------------------------------------

def _profile_aes_256_gcm() -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm="AES-256-GCM",
        category="Authenticated Symmetric Encryption (AEAD)",
        key_size_bits=256,
        security_classical_bits=256,
        security_quantum_bits=128,
        nist_pqc_level=None,
        standardisation="NIST FIPS 197 + SP 800-38D (GCM mode)",
        known_attacks=[
            AttackVector(
                name="Brute-force key search",
                attack_type="classical",
                complexity="2^256",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="256-bit key; computationally infeasible even with all energy in the observable universe",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Grover quantum search on AES",
                attack_type="quantum",
                complexity="2^128 (effective with Grover)",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "128-bit post-quantum security is the NIST Level 1 baseline. "
                    "Migrate to 512-bit keys (SUMIT KEY quantum mode) or use ML-KEM for key agreement."
                ),
                severity="LOW",
            ),
            AttackVector(
                name="Nonce reuse (GCM catastrophic failure)",
                attack_type="protocol",
                complexity="0 (immediate key recovery with 2 same-nonce ciphertexts)",
                feasible_now=True,
                feasible_quantum=True,
                mitigation=(
                    "SUMIT KEY uses os.urandom(12) per operation — 96-bit random nonce. "
                    "Probability of collision: 2^{-48} after 2^{32} messages. "
                    "For >2^{32} messages use deterministic counter nonce or AES-256-SIV."
                ),
                severity="CRITICAL",
            ),
            AttackVector(
                name="Authentication tag truncation (>16B tag forgery)",
                attack_type="protocol",
                complexity="2^{tag_bits}",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="SUMIT KEY always uses the default 128-bit (16-byte) authentication tag.",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="AES-NI timing side-channel",
                attack_type="side-channel",
                complexity="Practical on shared hardware",
                feasible_now=True,
                feasible_quantum=True,
                mitigation=(
                    "Python `cryptography` library uses OpenSSL/BoringSSL AES-NI — "
                    "constant-time on hardware with AES-NI. "
                    "On systems without AES-NI, consider ChaCha20-Poly1305."
                ),
                severity="MEDIUM",
            ),
            AttackVector(
                name="Forbidden attack (tag reuse across different nonces with same key)",
                attack_type="protocol",
                complexity="O(1) if attacker controls nonce",
                feasible_now=True,
                feasible_quantum=True,
                mitigation="Never allow external control of the GCM nonce. SUMIT KEY generates nonces internally.",
                severity="HIGH",
            ),
        ],
        overall_verdict="RECOMMENDED",
        verdict_reason=(
            "AES-256-GCM is the current SUMIT KEY cipher. 256-bit keys, 128-bit post-quantum security. "
            "Hardware-accelerated on all modern CPUs. Primary risk is nonce reuse — fully mitigated "
            "by fresh random nonce generation per call."
        ),
        references=[
            "NIST FIPS 197",
            "NIST SP 800-38D",
            "Joux 2006: Authentication failures in NIST version of GCM",
            "Bock et al. 2016: Nonce-Disrespecting Adversaries",
        ],
    )


def _profile_chacha20_poly1305() -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm="ChaCha20-Poly1305",
        category="Authenticated Symmetric Encryption (AEAD)",
        key_size_bits=256,
        security_classical_bits=256,
        security_quantum_bits=128,
        nist_pqc_level=None,
        standardisation="IETF RFC 8439; TLS 1.3 (RFC 8446)",
        known_attacks=[
            AttackVector(
                name="Brute-force key search",
                attack_type="classical",
                complexity="2^256",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="256-bit key; same classical security as AES-256.",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Grover quantum search",
                attack_type="quantum",
                complexity="2^128",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="Same post-quantum security as AES-256-GCM.",
                severity="LOW",
            ),
            AttackVector(
                name="Nonce reuse",
                attack_type="protocol",
                complexity="Plaintext XOR recovery; Poly1305 key recovery",
                feasible_now=True,
                feasible_quantum=True,
                mitigation="Fresh 96-bit random nonce per operation. Same mitigation as AES-GCM.",
                severity="CRITICAL",
            ),
            AttackVector(
                name="Poly1305 authentication tag length",
                attack_type="protocol",
                complexity="2^128 forgery",
                feasible_now=False,
                feasible_quantum=True,
                mitigation="128-bit tag used; Grover reduces to ~2^64 — use with PQC KEM key agreement.",
                severity="LOW",
            ),
            AttackVector(
                name="Software timing side-channel on non-AES-NI hardware",
                attack_type="side-channel",
                complexity="Varies; less applicable than AES on non-NI hardware",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "ChaCha20 is designed to run in constant time in software — preferred "
                    "over AES on ARM/embedded without hardware AES support."
                ),
                severity="LOW",
            ),
        ],
        overall_verdict="RECOMMENDED",
        verdict_reason=(
            "ChaCha20-Poly1305 is a strong alternative to AES-256-GCM. "
            "Better software-side-channel properties. Preferred on ARM/mobile without AES-NI. "
            "On x86 with AES-NI, AES-256-GCM is typically faster."
        ),
        references=[
            "RFC 8439: ChaCha20 and Poly1305 for IETF Protocols",
            "Bernstein 2008: ChaCha, a variant of Salsa20",
            "RFC 8446: TLS 1.3",
        ],
    )


def _profile_hkdf_sha3() -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm="HKDF-SHA3-256",
        category="Key Derivation Function (KDF)",
        key_size_bits=512,
        security_classical_bits=256,
        security_quantum_bits=128,
        nist_pqc_level=None,
        standardisation="RFC 5869 (HKDF) + NIST FIPS 202 (SHA3)",
        known_attacks=[
            AttackVector(
                name="Preimage attack on SHA3-256",
                attack_type="classical",
                complexity="2^256",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="SHA3 (Keccak) has no known structural weaknesses. 256-bit output has 256-bit preimage resistance.",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Grover preimage on SHA3-256",
                attack_type="quantum",
                complexity="2^128",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="128-bit quantum preimage resistance. SUMIT KEY uses 512-bit derived keys (quantum mode).",
                severity="LOW",
            ),
            AttackVector(
                name="Weak entropy input (low-entropy mouse capture)",
                attack_type="implementation",
                complexity="Depends on actual entropy; may be much less than key size",
                feasible_now=True,
                feasible_quantum=True,
                mitigation=(
                    "HKDF does not stretch entropy — it only extracts and expands. "
                    "If mouse events are too few or predictable (e.g. 2-3 slow moves), "
                    "actual security is bounded by input entropy, not key size. "
                    "Mitigation: enforce minimum event counts; add Argon2id hardening."
                ),
                severity="HIGH",
            ),
            AttackVector(
                name="Salt reuse across sessions",
                attack_type="protocol",
                complexity="No direct attack; reduces domain separation",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="SUMIT KEY uses a fixed domain-separated salt (b'SUMIT_KEY_v2_QUANTUM'). Acceptable for non-password KDF usage.",
                severity="LOW",
            ),
        ],
        overall_verdict="ACCEPTABLE",
        verdict_reason=(
            "HKDF-SHA3 is cryptographically sound for key derivation. "
            "Main risk is that it does NOT harden weak entropy — a user capturing only "
            "2-3 mouse events gets a correctly-formatted key but with low actual entropy. "
            "Pair with Argon2id for hardening in security-sensitive deployments."
        ),
        references=[
            "RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)",
            "NIST FIPS 202: SHA-3 Standard (Keccak)",
            "Krawczyk 2010: Cryptographic extraction and key derivation",
        ],
    )


def _profile_argon2id() -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm="Argon2id",
        category="Memory-Hard Key Derivation Function",
        key_size_bits=512,
        security_classical_bits=256,
        security_quantum_bits=128,
        nist_pqc_level=None,
        standardisation="RFC 9106 (Argon2); PHC winner 2015",
        known_attacks=[
            AttackVector(
                name="GPU brute-force against low-cost configuration",
                attack_type="classical",
                complexity="Depends on cost parameters",
                feasible_now=True,
                feasible_quantum=False,
                mitigation=(
                    "Use sensitive config: time_cost=4, memory_cost=1GB. "
                    "This makes each attempt cost ~1 second + 1GB RAM, "
                    "limiting GPU farms to ~1-10 attempts/sec/GPU."
                ),
                severity="HIGH",
            ),
            AttackVector(
                name="ASIC / hardware accelerator",
                attack_type="classical",
                complexity="Memory bandwidth bound",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "Argon2id's hybrid mode (d+i) resists both TMTO (time-memory tradeoff) "
                    "and side-channel ASIC attacks. 1GB memory cost makes custom silicon expensive."
                ),
                severity="LOW",
            ),
            AttackVector(
                name="Quantum speedup (Grover on output)",
                attack_type="quantum",
                complexity="2^128 with 512-bit output and 256-bit input search space",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "Grover gives quadratic speedup. 256-bit input → 128-bit quantum security. "
                    "Memory hardness limits quantum parallelism: quantum computers still need "
                    "classical memory, so TMTO advantage is limited."
                ),
                severity="LOW",
            ),
            AttackVector(
                name="Salt reuse (dictionary attack enablement)",
                attack_type="protocol",
                complexity="Enables pre-computation if salt is known and reused",
                feasible_now=True,
                feasible_quantum=False,
                mitigation="Always use a fresh cryptographically random salt per derivation (os.urandom(16)).",
                severity="MEDIUM",
            ),
            AttackVector(
                name="Side-channel on password/entropy value",
                attack_type="side-channel",
                complexity="Timing of memory access pattern",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="Argon2id's i-phase provides data-independent memory access pattern.",
                severity="LOW",
            ),
        ],
        overall_verdict="RECOMMENDED",
        verdict_reason=(
            "Argon2id is the best available KDF for hardening potentially-weak entropy. "
            "Use when mouse/keystroke capture may be limited (few events, predictable user). "
            "At sensitive config (4 iterations, 1GB), GPU/ASIC brute-force is infeasible. "
            "PHC winner, standardised in RFC 9106."
        ),
        references=[
            "RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work",
            "Biryukov & Khovratovich 2016: Argon2: The Memory-Hard Function for Password Hashing",
            "PHC (Password Hashing Competition) winner 2015",
        ],
    )


def _profile_ml_kem_1024() -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm="ML-KEM-1024 (Kyber-1024 / FIPS 203)",
        category="Post-Quantum Key Encapsulation Mechanism (KEM)",
        key_size_bits=256,
        security_classical_bits=256,
        security_quantum_bits=128,
        nist_pqc_level=5,
        standardisation="NIST FIPS 203 (2024); CRYSTALS-Kyber family",
        known_attacks=[
            AttackVector(
                name="Classical lattice attacks (BKZ / BDGL sieving)",
                attack_type="classical",
                complexity="2^>256 for ML-KEM-1024 module lattice",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="ML-KEM-1024 parameters chosen to resist all known lattice attacks at 256-bit classical equivalent.",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Quantum lattice attack (quantum BKZ, QROM)",
                attack_type="quantum",
                complexity="~2^128 (NIST Level 5 target)",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "Proven secure in the Quantum Random Oracle Model (QROM). "
                    "128-bit post-quantum security remains strong even with "
                    "large fault-tolerant quantum computers."
                ),
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Decryption failure attack (probability 2^{-174})",
                attack_type="classical",
                complexity="Astronomically unlikely failure event",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="ML-KEM-1024 failure probability is 2^{-174} — negligible in practice.",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Side-channel: secret key recovery via timing",
                attack_type="side-channel",
                complexity="Practical against naive reference implementations",
                feasible_now=True,
                feasible_quantum=True,
                mitigation=(
                    "kyber-py is a pure-Python reference — NOT hardened against timing attacks. "
                    "For production: use liboqs C implementation or PQClean with constant-time code."
                ),
                severity="HIGH",
            ),
            AttackVector(
                name="Implicit rejection failure (decaps with wrong key)",
                attack_type="protocol",
                complexity="Ciphertext modification still produces a 'random' shared secret",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "ML-KEM uses implicit rejection: decaps always returns a value, "
                    "but it will be a random key if the ciphertext was tampered. "
                    "Always authenticate the ciphertext (e.g. with MAYO signature or HMAC)."
                ),
                severity="MEDIUM",
            ),
            AttackVector(
                name="Large public key storage / transmission",
                attack_type="implementation",
                complexity="ek=1568B dk=3168B ct=1568B — large vs classical RSA/ECC",
                feasible_now=True,
                feasible_quantum=True,
                mitigation=(
                    "Size overhead is a bandwidth/storage cost, not a security flaw. "
                    "Acceptable for key establishment; not for per-message encryption."
                ),
                severity="LOW",
            ),
        ],
        overall_verdict="RECOMMENDED",
        verdict_reason=(
            "ML-KEM-1024 is the NIST-standardised (FIPS 203, 2024) post-quantum KEM. "
            "Highest security level (NIST Level 5 = 256-bit classical / 128-bit quantum). "
            "Use for key establishment; combine with AES-256-GCM for bulk encryption. "
            "kyber-py is a correct but slow pure-Python reference — use liboqs for production speed."
        ),
        references=[
            "NIST FIPS 203 (2024): Module-Lattice-Based Key-Encapsulation Mechanism Standard",
            "Bos et al. 2018: CRYSTALS – Kyber: A CCA-Secure Module-Lattice-Based KEM",
            "Pessl & Prokop 2021: Fault Attacks on CCA-secure Lattice KEMs",
        ],
    )


def _profile_mayo5() -> AlgorithmProfile:
    return AlgorithmProfile(
        algorithm="MAYO-5",
        category="Post-Quantum Digital Signature (Multivariate)",
        key_size_bits=320,
        security_classical_bits=256,
        security_quantum_bits=128,
        nist_pqc_level=5,
        standardisation="NIST PQC Round 2 candidate (2023); not yet standardised",
        known_attacks=[
            AttackVector(
                name="Classical MQ problem solving (Groebner basis, XL algorithm)",
                attack_type="classical",
                complexity="2^>256 for MAYO-5 parameter set",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="MAYO-5 parameters are conservatively chosen against all known MQ solvers.",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Quantum speedup on MQ (quantum annealing, Grover)",
                attack_type="quantum",
                complexity="~2^128 (NIST Level 5 estimate)",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "Quantum speedup for MQ is modest. MAYO-5 provides ~128-bit quantum security "
                    "by choosing parameters with sufficient classical hardness margin."
                ),
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Oil-and-Vinegar structural attack (if whipping fails)",
                attack_type="classical",
                complexity="Depends on whipping map security",
                feasible_now=False,
                feasible_quantum=False,
                mitigation=(
                    "MAYO uses 'whipped' UOV (Unbalanced Oil-and-Vinegar) construction. "
                    "The whipping map prevents known UOV attacks on the full system."
                ),
                severity="LOW",
            ),
            AttackVector(
                name="Forgery via signature malleability",
                attack_type="protocol",
                complexity="Requires solving the MQ problem",
                feasible_now=False,
                feasible_quantum=False,
                mitigation="MAYO signatures are non-malleable by design (hash-and-sign paradigm).",
                severity="NEGLIGIBLE",
            ),
            AttackVector(
                name="Side-channel on whipping map computation",
                attack_type="side-channel",
                complexity="Practical against non-constant-time implementations",
                feasible_now=True,
                feasible_quantum=True,
                mitigation=(
                    "Only the MAYO-C reference implementation (C, AVX2-optimised) provides "
                    "timing-constant operations. Pure Python implementation would leak timing."
                ),
                severity="HIGH",
            ),
            AttackVector(
                name="Not yet fully standardised",
                attack_type="implementation",
                complexity="Possible parameter changes before final standard",
                feasible_now=True,
                feasible_quantum=False,
                mitigation=(
                    "MAYO is in NIST PQC Round 2 (2023). Not yet standardised. "
                    "Use ML-DSA (Dilithium, FIPS 204) for production signature until MAYO is finalised."
                ),
                severity="MEDIUM",
            ),
        ],
        overall_verdict="ANALYSIS_ONLY",
        verdict_reason=(
            "MAYO-5 provides strong post-quantum signature security at NIST Level 5. "
            "Key advantages: very short secret key (40B), competitive signature size (838B). "
            "Limitations: not yet standardised (still in Round 2); requires C implementation (liboqs) "
            "for timing safety; pure-Python not suitable for production. "
            "For production signatures now: use ML-DSA (FIPS 204, standardised 2024) as primary, "
            "MAYO as secondary when liboqs becomes available."
        ),
        references=[
            "Beullens et al. 2022: MAYO: Practical Post-Quantum Signatures from Oil-and-Vinegar Maps",
            "https://pqmayo.org/",
            "NIST PQC Round 2 submission (2023)",
            "Unbalanced Oil and Vinegar: Patarin 1997",
        ],
    )


# ---------------------------------------------------------------------------
# Entropy source threat surface
# ---------------------------------------------------------------------------

def _entropy_source_attacks() -> list[AttackVector]:
    return [
        AttackVector(
            name="Minimal mouse movement (user barely moves mouse)",
            attack_type="implementation",
            complexity="As low as ~20-40 bits of actual entropy from 2-3 slow moves",
            feasible_now=True,
            feasible_quantum=True,
            mitigation=(
                "Enforce minimum event count (>= 30 mouse events recommended). "
                "Add Argon2id post-processing to harden weak captures. "
                "Warn user if capture window yields < 20 events."
            ),
            severity="HIGH",
        ),
        AttackVector(
            name="Scripted / replay mouse movement",
            attack_type="classical",
            complexity="~0 bits entropy if attacker controls mouse driver",
            feasible_now=True,
            feasible_quantum=True,
            mitigation=(
                "Entropy source is the user's biological variation, not the computer. "
                "Replay attack requires physical access or full system compromise. "
                "In that scenario, key material is already exposed by other means."
            ),
            severity="MEDIUM",
        ),
        AttackVector(
            name="Cross-session entropy correlation (same user, same session type)",
            attack_type="classical",
            complexity="Reduces effective entropy pool if user behaviour is highly repetitive",
            feasible_now=False,
            feasible_quantum=False,
            mitigation=(
                "SHA3-256 pooling masks inter-session correlation. "
                "Random system noise (timestamps, scheduler jitter) adds session-unique bits. "
                "Argon2id further prevents exploitation of cross-session patterns."
            ),
            severity="LOW",
        ),
        AttackVector(
            name="Headless / automated environment (no physical mouse)",
            attack_type="implementation",
            complexity="Zero entropy if evdev mock or synthetic events used",
            feasible_now=True,
            feasible_quantum=True,
            mitigation=(
                "API /generate returns an error if no mouse device is detected. "
                "Synthetic events from debug_pipeline.py are for testing only — never use in production."
            ),
            severity="CRITICAL",
        ),
        AttackVector(
            name="Timing oracle on key generation latency",
            attack_type="side-channel",
            complexity="Could reveal number of mouse events if latency is measured",
            feasible_now=False,
            feasible_quantum=False,
            mitigation=(
                "Key derivation uses HKDF with fixed-length output regardless of input size. "
                "Capture duration is user-visible — no secret timing information leaks."
            ),
            severity="LOW",
        ),
        AttackVector(
            name="Network interception of generated key (API /generate response)",
            attack_type="protocol",
            complexity="Trivial if API runs over plain HTTP",
            feasible_now=True,
            feasible_quantum=True,
            mitigation=(
                "Always run the API over TLS (HTTPS). "
                "API is bound to localhost:8000 by default. "
                "HSTS header is set for any reverse-proxy deployments."
            ),
            severity="CRITICAL",
        ),
    ]


# ---------------------------------------------------------------------------
# Build the full report
# ---------------------------------------------------------------------------

def build_threat_model() -> ThreatModelReport:
    algorithms = [
        _profile_aes_256_gcm(),
        _profile_chacha20_poly1305(),
        _profile_hkdf_sha3(),
        _profile_argon2id(),
        _profile_ml_kem_1024(),
        _profile_mayo5(),
    ]

    recommended_stack = [
        "1. Entropy capture     : SUMIT KEY mouse + keystroke (>= 30 events each)",
        "2. Entropy hardening   : Argon2id(time=4, mem=1GB, parallelism=1)",
        "3. Key agreement       : ML-KEM-1024 (FIPS 203) — post-quantum safe",
        "4. Bulk encryption     : AES-256-GCM (primary) or ChaCha20-Poly1305 (ARM)",
        "5. Authentication      : HMAC-SHA3-256 on ciphertext (or GCM tag is sufficient)",
        "6. Signatures (future) : ML-DSA (FIPS 204) now; MAYO-5 when standardised",
        "7. Transport           : TLS 1.3 with ML-KEM hybrid mode (X25519+ML-KEM)",
    ]

    return ThreatModelReport(
        title="SUMIT KEY — Full Cryptographic Threat Model",
        summary=(
            "SUMIT KEY uses behavioural biometrics (mouse dynamics + keystroke timing) as an entropy "
            "source for cryptographic key generation. The pipeline is: capture → entropy extraction → "
            "SHA3 pooling → HKDF key derivation → AES-256-GCM encryption.\n\n"
            "Primary risks: (a) weak entropy from minimal mouse movement, mitigated by Argon2id hardening; "
            "(b) nonce reuse in GCM, fully mitigated by random nonce generation; "
            "(c) post-quantum: AES-256-GCM retains 128-bit quantum security which meets NIST Level 1. "
            "For NIST Level 5 post-quantum security, add ML-KEM-1024 key agreement.\n\n"
            "MAYO-5 analysis is included as documented reference — it is not yet standardised and "
            "requires the liboqs C library for production use."
        ),
        algorithms=algorithms,
        recommended_stack=recommended_stack,
        attack_surface_entropy=_entropy_source_attacks(),
        overall_quantum_readiness=(
            "PARTIAL. Current pipeline (AES-256-GCM + HKDF-SHA3) provides 128-bit post-quantum "
            "security for symmetric operations. Full post-quantum readiness requires adding "
            "ML-KEM-1024 for key agreement (replaces Diffie-Hellman / RSA / ECDH). "
            "Argon2id adds memory-hardness against quantum-enabled brute-force on weak entropy."
        ),
    )


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------

def _severity_icon(s: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "NEGLIGIBLE": "⚪"}.get(s, "?")


def print_threat_model(report: ThreatModelReport) -> None:
    print("\n" + "=" * 80)
    print(f"  {report.title}")
    print("=" * 80)
    print(f"\n{report.summary}\n")

    print(f"\nOverall quantum readiness: {report.overall_quantum_readiness}\n")

    for algo in report.algorithms:
        verdict_tag = {
            "RECOMMENDED": "[✓ RECOMMENDED]",
            "ACCEPTABLE": "[~ ACCEPTABLE]",
            "DEPRECATED": "[✗ DEPRECATED]",
            "ANALYSIS_ONLY": "[~ ANALYSIS ONLY]",
        }.get(algo.overall_verdict, algo.overall_verdict)

        print("─" * 80)
        print(f"  {algo.algorithm}  {verdict_tag}")
        print(f"  Category  : {algo.category}")
        print(f"  Standard  : {algo.standardisation}")
        print(f"  Security  : {algo.security_classical_bits}-bit classical | {algo.security_quantum_bits}-bit quantum | NIST PQC Level {algo.nist_pqc_level or 'N/A'}")
        print(f"  Verdict   : {algo.verdict_reason}")
        print(f"\n  Attack Vectors:")
        for av in algo.known_attacks:
            icon = _severity_icon(av.severity)
            print(f"    {icon} [{av.severity:<10}] {av.name}")
            print(f"              Complexity : {av.complexity}")
            print(f"              Now/Quantum: {av.feasible_now}/{av.feasible_quantum}")
            print(f"              Mitigation : {av.mitigation[:90]}")
        print()

    print("─" * 80)
    print("\n  ENTROPY SOURCE THREATS:")
    for av in report.attack_surface_entropy:
        icon = _severity_icon(av.severity)
        print(f"  {icon} [{av.severity:<10}] {av.name}")
        print(f"              Mitigation : {av.mitigation[:90]}")

    print("\n" + "=" * 80)
    print("  RECOMMENDED SECURE STACK:")
    print("=" * 80)
    for step in report.recommended_stack:
        print(f"  {step}")
    print()


# ---------------------------------------------------------------------------
# API-friendly dict export
# ---------------------------------------------------------------------------

def get_threat_model() -> dict[str, Any]:
    """Return the full threat model as a JSON-serialisable dict."""
    report = build_threat_model()

    def _av(v: AttackVector) -> dict:
        return {
            "name": v.name,
            "attack_type": v.attack_type,
            "complexity": v.complexity,
            "feasible_now": v.feasible_now,
            "feasible_quantum": v.feasible_quantum,
            "mitigation": v.mitigation,
            "severity": v.severity,
        }

    def _ap(p: AlgorithmProfile) -> dict:
        return {
            "algorithm": p.algorithm,
            "category": p.category,
            "key_size_bits": p.key_size_bits,
            "security_classical_bits": p.security_classical_bits,
            "security_quantum_bits": p.security_quantum_bits,
            "nist_pqc_level": p.nist_pqc_level,
            "standardisation": p.standardisation,
            "overall_verdict": p.overall_verdict,
            "verdict_reason": p.verdict_reason,
            "known_attacks": [_av(v) for v in p.known_attacks],
            "references": p.references,
        }

    return {
        "title": report.title,
        "summary": report.summary,
        "overall_quantum_readiness": report.overall_quantum_readiness,
        "algorithms": [_ap(p) for p in report.algorithms],
        "recommended_stack": report.recommended_stack,
        "entropy_source_attacks": [_av(v) for v in report.attack_surface_entropy],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="SUMIT KEY threat model")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of text")
    args = parser.parse_args()

    if args.json:
        print(json.dumps(get_threat_model(), indent=2))
    else:
        report = build_threat_model()
        print_threat_model(report)
