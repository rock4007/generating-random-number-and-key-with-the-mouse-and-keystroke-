# Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved.
# PROPRIETARY AND CONFIDENTIAL — see LICENSE (Part A) for terms.
# Unauthorised copying, modification, distribution, or use is strictly prohibited.

"""crypto_benchmark.py — Cryptographic speed and entropy quality benchmark for SUMIT KEY.

Tests and compares:
  1. Entropy quality   — Shannon entropy, chi-squared, autocorrelation, byte histogram
  2. Symmetric ciphers — AES-256-GCM vs ChaCha20-Poly1305 (MB/s, latency)
  3. Key derivation    — HKDF-SHA3 (current) vs Argon2id at various cost settings
  4. Post-quantum KEM  — ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 (FIPS 203 / Kyber)
  5. MAYO-5            — documented analysis; runnable benchmark requires liboqs

Usage:
  python crypto_benchmark.py              # full benchmark suite
  python crypto_benchmark.py --quick      # fast pass (small data sizes)

Python packages used:
  cryptography>=42   — AES-GCM, ChaCha20-Poly1305, HKDF
  argon2-cffi>=21    — Argon2id
  kyber-py>=1.2      — ML-KEM (FIPS 203 pure-Python reference)
"""

from __future__ import annotations

import hashlib
import math
import os
import statistics
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    algorithm: str
    category: str
    throughput_mb_s: float | None = None    # MB/s for cipher benchmarks
    latency_ms: float | None = None         # ms per operation
    ops_per_second: float | None = None     # for KEM/KDF
    key_size_bits: int | None = None
    ct_size_bytes: int | None = None        # ciphertext / KEM ciphertext
    memory_mb: float | None = None          # for Argon2
    security_classical_bits: int | None = None
    security_quantum_bits: int | None = None
    notes: str = ""
    available: bool = True
    error: str = ""


@dataclass
class EntropyQualityResult:
    source: str
    byte_count: int
    shannon_bits_per_byte: float
    chi_squared: float
    chi_squared_pass: bool       # p-value heuristic: chi² < 293.25 for 255 dof at 0.05
    max_autocorrelation: float   # max |r| for lags 1..16; should be < 0.05 for good RNG
    byte_distribution_uniformity: float   # 1.0 = perfect uniform, 0.0 = single byte
    verdict: str                 # EXCELLENT / GOOD / ACCEPTABLE / WEAK


@dataclass
class StaticChainBenchmark:
    mouse_events: int
    micro_vibration_steps: int
    direction_changes: int
    key_bits: int
    encryption_algorithm: str
    decrypt_verified: bool
    framework_passes: int
    framework_warnings: int
    key_preview_hex: str
    nonce_hex: str
    notes: str


@dataclass
class ScenarioFallbackBenchmark:
    scenario: str
    authenticated: bool
    method: str
    movement_verdict: str
    movement_score: float
    event_count: int
    direction_changes: int
    micro_vibration_steps: int
    decisions: list[str]


# ---------------------------------------------------------------------------
# Entropy quality analysis
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _chi_squared(data: bytes) -> float:
    """Chi-squared statistic against a uniform byte distribution."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    expected = len(data) / 256.0
    return sum((c - expected) ** 2 / expected for c in counts)


def _autocorrelation(data: bytes, max_lag: int = 16) -> float:
    """Maximum absolute autocorrelation across lags 1..max_lag."""
    n = len(data)
    if n < max_lag + 2:
        return 0.0
    vals = [b / 255.0 for b in data]
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    if var == 0:
        return 1.0
    max_corr = 0.0
    for lag in range(1, max_lag + 1):
        cov = sum((vals[i] - mean) * (vals[i + lag] - mean) for i in range(n - lag)) / (n - lag)
        r = abs(cov / var)
        if r > max_corr:
            max_corr = r
    return round(max_corr, 4)


def _uniformity(data: bytes) -> float:
    """Byte distribution uniformity: ratio of distinct bytes to 256."""
    return len(set(data)) / 256.0


def analyze_entropy_quality(data: bytes, source: str) -> EntropyQualityResult:
    """Run all entropy quality metrics on a byte sequence."""
    shannon = round(_shannon_entropy(data), 4)
    chi2 = round(_chi_squared(data), 2)
    chi2_pass = chi2 < 293.25            # 0.05 significance, 255 dof
    autocorr = _autocorrelation(data)
    uniformity = round(_uniformity(data), 4)

    if shannon >= 7.9 and chi2_pass and autocorr < 0.05:
        verdict = "EXCELLENT"
    elif shannon >= 7.5 and autocorr < 0.10:
        verdict = "GOOD"
    elif shannon >= 6.5:
        verdict = "ACCEPTABLE"
    else:
        verdict = "WEAK"

    return EntropyQualityResult(
        source=source,
        byte_count=len(data),
        shannon_bits_per_byte=shannon,
        chi_squared=chi2,
        chi_squared_pass=chi2_pass,
        max_autocorrelation=autocorr,
        byte_distribution_uniformity=uniformity,
        verdict=verdict,
    )


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------

def _timeit(fn: Callable, n_warmup: int = 2, n_runs: int = 10) -> tuple[float, float]:
    """Return (mean_ms, stdev_ms) for n_runs executions after n_warmup."""
    for _ in range(n_warmup):
        fn()
    times: list[float] = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    mean = statistics.mean(times)
    stdev = statistics.pstdev(times) if len(times) > 1 else 0.0
    return round(mean, 4), round(stdev, 4)


def _throughput_mb_s(fn: Callable, data_size_bytes: int, n_runs: int = 10) -> tuple[float, float]:
    """Return (throughput_mb_s, mean_latency_ms) for a cipher operating on data_size_bytes."""
    mean_ms, _ = _timeit(fn, n_warmup=3, n_runs=n_runs)
    mb_s = (data_size_bytes / 1e6) / (mean_ms / 1000) if mean_ms > 0 else 0.0
    return round(mb_s, 2), mean_ms


# ---------------------------------------------------------------------------
# 1. Symmetric cipher benchmarks
# ---------------------------------------------------------------------------

def _bench_aes_gcm(data_size_bytes: int) -> BenchmarkResult:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = os.urandom(data_size_bytes)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    enc_fn = lambda: aesgcm.encrypt(os.urandom(12), plaintext, None)
    dec_fn = lambda: aesgcm.decrypt(nonce, ciphertext, None)

    enc_tp, enc_lat = _throughput_mb_s(enc_fn, data_size_bytes)
    dec_tp, dec_lat = _throughput_mb_s(dec_fn, data_size_bytes)

    return BenchmarkResult(
        algorithm="AES-256-GCM",
        category="Symmetric Cipher",
        throughput_mb_s=(enc_tp + dec_tp) / 2,
        latency_ms=enc_lat,
        key_size_bits=256,
        ct_size_bytes=len(ciphertext),
        security_classical_bits=256,
        security_quantum_bits=128,
        notes=(
            f"encrypt {enc_tp} MB/s | decrypt {dec_tp} MB/s | "
            f"data={data_size_bytes//1024}KB | AEAD w/ 128-bit tag"
        ),
    )


def _bench_chacha20(data_size_bytes: int) -> BenchmarkResult:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = os.urandom(data_size_bytes)
    chacha = ChaCha20Poly1305(key)

    ciphertext = chacha.encrypt(nonce, plaintext, None)

    enc_fn = lambda: chacha.encrypt(os.urandom(12), plaintext, None)
    dec_fn = lambda: chacha.decrypt(nonce, ciphertext, None)

    enc_tp, enc_lat = _throughput_mb_s(enc_fn, data_size_bytes)
    dec_tp, dec_lat = _throughput_mb_s(dec_fn, data_size_bytes)

    return BenchmarkResult(
        algorithm="ChaCha20-Poly1305",
        category="Symmetric Cipher",
        throughput_mb_s=(enc_tp + dec_tp) / 2,
        latency_ms=enc_lat,
        key_size_bits=256,
        ct_size_bytes=len(ciphertext),
        security_classical_bits=256,
        security_quantum_bits=128,
        notes=(
            f"encrypt {enc_tp} MB/s | decrypt {dec_tp} MB/s | "
            f"data={data_size_bytes//1024}KB | no AES-NI dependency"
        ),
    )


# ---------------------------------------------------------------------------
# 2. Key derivation benchmarks
# ---------------------------------------------------------------------------

def _bench_hkdf_sha3(entropy: bytes) -> BenchmarkResult:
    from key_generator import KeyGenerator, HKDFConfig

    cfg = HKDFConfig.quantum_hardened()

    mean_ms, _ = _timeit(
        lambda: KeyGenerator.derive_key([entropy], cfg),
        n_warmup=5, n_runs=200,
    )
    ops = 1000 / mean_ms if mean_ms > 0 else 0

    return BenchmarkResult(
        algorithm="HKDF-SHA3-256",
        category="Key Derivation",
        latency_ms=mean_ms,
        ops_per_second=round(ops),
        key_size_bits=512,
        security_classical_bits=256,
        security_quantum_bits=128,
        notes="Current SUMIT KEY KDF; fast, no memory hardening",
    )


def _bench_argon2id(entropy: bytes, time_cost: int, memory_cost_kb: int, label: str) -> BenchmarkResult:
    from argon2.low_level import hash_secret_raw, Type

    salt = os.urandom(16)

    def run():
        hash_secret_raw(
            entropy,
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost_kb,
            parallelism=1,
            hash_len=64,
            type=Type.ID,
        )

    mean_ms, _ = _timeit(run, n_warmup=1, n_runs=5)
    ops = 1000 / mean_ms if mean_ms > 0 else 0
    memory_mb = memory_cost_kb / 1024

    return BenchmarkResult(
        algorithm=f"Argon2id ({label})",
        category="Key Derivation",
        latency_ms=round(mean_ms, 1),
        ops_per_second=round(ops, 2),
        key_size_bits=512,
        memory_mb=round(memory_mb, 1),
        security_classical_bits=256,
        security_quantum_bits=128,
        notes=(
            f"time_cost={time_cost} memory={memory_cost_kb}KB ({memory_mb:.0f}MB) | "
            f"memory-hard → GPU/ASIC resistant"
        ),
    )


# ---------------------------------------------------------------------------
# 3. ML-KEM (Kyber) benchmarks
# ---------------------------------------------------------------------------

def _bench_ml_kem(variant: str) -> BenchmarkResult:
    try:
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
        kem_map = {
            "ML-KEM-512": ML_KEM_512,
            "ML-KEM-768": ML_KEM_768,
            "ML-KEM-1024": ML_KEM_1024,
        }
        kem = kem_map[variant]

        # Warm-up + measure keygen
        ek, dk = kem.keygen()
        keygen_ms, _ = _timeit(lambda: kem.keygen(), n_warmup=2, n_runs=20)

        # Encaps
        key_ref, ct = kem.encaps(ek)
        encaps_ms, _ = _timeit(lambda: kem.encaps(ek), n_warmup=2, n_runs=20)

        # Decaps
        decaps_ms, _ = _timeit(lambda: kem.decaps(dk, ct), n_warmup=2, n_runs=20)

        total_ms = keygen_ms + encaps_ms + decaps_ms
        ops = 1000 / total_ms if total_ms > 0 else 0

        sec_bits = {"ML-KEM-512": (128, 64), "ML-KEM-768": (192, 96), "ML-KEM-1024": (256, 128)}
        cl_bits, q_bits = sec_bits[variant]

        return BenchmarkResult(
            algorithm=variant,
            category="Post-Quantum KEM (FIPS 203)",
            latency_ms=round(total_ms, 2),
            ops_per_second=round(ops, 1),
            key_size_bits=256,
            ct_size_bytes=len(ct),
            security_classical_bits=cl_bits,
            security_quantum_bits=q_bits,
            notes=(
                f"keygen={keygen_ms:.1f}ms encaps={encaps_ms:.1f}ms decaps={decaps_ms:.1f}ms | "
                f"ek={len(ek)}B dk={len(dk)}B ct={len(ct)}B | pure-Python (slower than C impl)"
            ),
        )
    except Exception as exc:
        return BenchmarkResult(
            algorithm=variant, category="Post-Quantum KEM",
            available=False, error=str(exc),
        )


# ---------------------------------------------------------------------------
# 4. MAYO — documented analysis (no runnable impl available without liboqs)
# ---------------------------------------------------------------------------

def _mayo_documented_analysis() -> list[BenchmarkResult]:
    """
    MAYO (Multivariate quadrAtic cOde-based signatures) documented analysis.

    MAYO is a NIST PQC signature scheme based on the hardness of solving systems
    of multivariate quadratic equations over finite fields (MQ problem).

    Security levels (MAYO specification, 2023):
      MAYO-1: NIST Level 1 (AES-128 equivalent classical, ~64-bit quantum via Grover)
      MAYO-2: NIST Level 1 (optimised for short signatures)
      MAYO-3: NIST Level 3 (AES-192 equivalent)
      MAYO-5: NIST Level 5 (AES-256 equivalent, ~128-bit quantum)

    Reference: https://pqmayo.org/
    Reference impl: https://github.com/PQCMayo/MAYO-C

    Note: MAYO is a *signature* scheme (sign/verify), NOT a KEM or cipher.
    For SUMIT KEY: use ML-KEM for key agreement, MAYO for signing the public key
    to prove identity/authenticity.

    Benchmark figures from MAYO-C reference implementation on ARM Cortex-M4:
      MAYO-5 keygen:  ~1.8ms  (ARM M4 @ 168MHz)
      MAYO-5 sign:    ~6.2ms
      MAYO-5 verify:  ~1.1ms
    Desktop (x86-64 AVX2) figures are ~5-10x faster.
    """
    variants = [
        {
            "name": "MAYO-1",
            "nist_level": 1,
            "classical_bits": 128,
            "quantum_bits": 64,
            "pk_bytes": 1168,
            "sk_bytes": 24,
            "sig_bytes": 321,
            "note": "Level 1; smallest signature in MAYO family",
        },
        {
            "name": "MAYO-2",
            "nist_level": 1,
            "classical_bits": 128,
            "quantum_bits": 64,
            "pk_bytes": 5488,
            "sk_bytes": 24,
            "sig_bytes": 180,
            "note": "Level 1; shorter signatures than MAYO-1 via larger public key",
        },
        {
            "name": "MAYO-3",
            "nist_level": 3,
            "classical_bits": 192,
            "quantum_bits": 96,
            "pk_bytes": 2656,
            "sk_bytes": 32,
            "sig_bytes": 577,
            "note": "Level 3; 192-bit classical equivalent",
        },
        {
            "name": "MAYO-5",
            "nist_level": 5,
            "classical_bits": 256,
            "quantum_bits": 128,
            "pk_bytes": 5008,
            "sk_bytes": 40,
            "sig_bytes": 838,
            "note": "Level 5; matches AES-256 classical security; requires liboqs C impl",
        },
    ]

    results = []
    for v in variants:
        results.append(BenchmarkResult(
            algorithm=v["name"],
            category="Post-Quantum Signature (MAYO — documented)",
            available=False,
            latency_ms=None,
            key_size_bits=v["sk_bytes"] * 8,
            ct_size_bytes=v["sig_bytes"],
            security_classical_bits=v["classical_bits"],
            security_quantum_bits=v["quantum_bits"],
            notes=(
                f"NIST Level {v['nist_level']} | "
                f"pk={v['pk_bytes']}B sk={v['sk_bytes']}B sig={v['sig_bytes']}B | "
                f"{v['note']} | install: pip install liboqs-python (needs C build)"
            ),
            error="liboqs not available on this system — documented analysis only",
        ))
    return results


# ---------------------------------------------------------------------------
# Entropy quality on SUMIT KEY outputs
# ---------------------------------------------------------------------------

def _bench_sumit_key_entropy() -> list[EntropyQualityResult]:
    """Analyse entropy quality of SUMIT KEY-generated keys."""
    from debug_pipeline import make_synthetic_mouse_events, make_synthetic_keystroke_events
    from entropy_engine import extract_keystroke_entropy, extract_mouse_entropy, pool_entropy
    from key_generator import KeyGenerator

    mouse_events = make_synthetic_mouse_events(50)
    keystroke_events = make_synthetic_keystroke_events(15)

    m_bytes = extract_mouse_entropy(mouse_events)
    k_bytes = extract_keystroke_entropy(keystroke_events)
    pooled = pool_entropy(m_bytes, k_bytes)
    std_key = KeyGenerator.generate_key(pooled)
    quantum_key = KeyGenerator.generate_quantum_hardened_key(pooled)

    # Generate a batch to test distribution across many keys
    batch_keys = b"".join(
        KeyGenerator.generate_quantum_hardened_key(
            hashlib.sha3_256(pooled + i.to_bytes(4, "big")).digest()
        )
        for i in range(50)
    )

    # Also test raw OS random as a quality baseline
    os_random = os.urandom(3200)

    return [
        analyze_entropy_quality(m_bytes,      "Mouse entropy bytes (48B)"),
        analyze_entropy_quality(k_bytes,      "Keystroke entropy bytes"),
        analyze_entropy_quality(pooled,       "SHA3-256 pooled entropy (32B)"),
        analyze_entropy_quality(std_key,      "HKDF-SHA3 key (256-bit)"),
        analyze_entropy_quality(quantum_key,  "HKDF-SHA3 quantum key (512-bit)"),
        analyze_entropy_quality(batch_keys,   "Batch of 50 quantum keys (3200B)"),
        analyze_entropy_quality(os_random,    "OS urandom baseline (3200B)"),
    ]


def _bench_static_mouse_chain() -> StaticChainBenchmark:
    """Run the full static mouse-turn/vibration -> key -> encryption chain."""

    from debug_pipeline import make_turn_vibration_mouse_events, run_static_encryption_chain

    mouse_events = make_turn_vibration_mouse_events(turns=4, samples_per_turn=12)
    chain = run_static_encryption_chain(
        mouse_events,
        "SUMIT KEY benchmark static-chain message",
        security_level="quantum",
        label="benchmark-static-chain",
    )
    checks = chain["framework_checks"]
    passes = sum(1 for check in checks if check["status"] == "PASS")
    warnings = sum(1 for check in checks if check["status"] == "WARN")

    return StaticChainBenchmark(
        mouse_events=chain["mouse_event_count"],
        micro_vibration_steps=chain["micro_vibration_steps"],
        direction_changes=chain["turn_direction_changes"],
        key_bits=chain["static_key_bits"],
        encryption_algorithm=chain["encryption"]["algorithm"],
        decrypt_verified=bool(chain["encryption"]["decrypt_verified"]),
        framework_passes=passes,
        framework_warnings=warnings,
        key_preview_hex=chain["static_key_hex"][:48] + "...",
        nonce_hex=chain["encryption"]["nonce_hex"],
        notes=chain["certification_note"],
    )


def _bench_game_fallback_scenarios() -> list[ScenarioFallbackBenchmark]:
    """Run chess/game authentication scenarios with OTP and NFC fallback."""

    from fallback_auth import (
        SimulatedNFCProvider,
        SimulatedOTPProvider,
        authenticate_game_scenario,
        make_chess_like_mouse_events,
    )

    otp_provider = SimulatedOTPProvider(secret=b"benchmark-otp-secret-32-bytes!!")
    nfc_provider = SimulatedNFCProvider()
    nfc_provider.register_token("phone-nfc-token-001")
    destination = "+15551234567"
    otp = otp_provider.issue(destination)

    scenarios = [
        authenticate_game_scenario(
            scenario="chess_good_mouse_direct",
            mouse_events=make_chess_like_mouse_events(good=True, moves=8),
            otp_provider=otp_provider,
            nfc_provider=nfc_provider,
        ),
        authenticate_game_scenario(
            scenario="chess_weak_mouse_otp_backup",
            mouse_events=make_chess_like_mouse_events(good=False, moves=4),
            otp_destination=destination,
            provided_otp=otp,
            otp_provider=otp_provider,
            nfc_provider=nfc_provider,
        ),
        authenticate_game_scenario(
            scenario="game_bad_mouse_bad_otp_nfc_backup",
            mouse_events=make_chess_like_mouse_events(good=False, moves=3),
            otp_destination=destination,
            provided_otp="000000",
            nfc_token_uid="phone-nfc-token-001",
            otp_provider=otp_provider,
            nfc_provider=nfc_provider,
        ),
        authenticate_game_scenario(
            scenario="game_all_factors_fail",
            mouse_events=make_chess_like_mouse_events(good=False, moves=2),
            otp_destination=destination,
            provided_otp="111111",
            nfc_token_uid="unknown-token",
            otp_provider=otp_provider,
            nfc_provider=nfc_provider,
        ),
    ]

    return [
        ScenarioFallbackBenchmark(
            scenario=item.scenario,
            authenticated=item.authenticated,
            method=item.method,
            movement_verdict=item.movement_profile.verdict,
            movement_score=item.movement_profile.score,
            event_count=item.movement_profile.event_count,
            direction_changes=item.movement_profile.direction_changes,
            micro_vibration_steps=item.movement_profile.micro_vibration_steps,
            decisions=[
                f"{decision.step}:{decision.status}"
                for decision in item.decisions
            ],
        )
        for item in scenarios
    ]


# ---------------------------------------------------------------------------
# 5. Full quantum-safe hybrid pipeline benchmark
# ---------------------------------------------------------------------------

def _bench_quantum_full_pipeline() -> BenchmarkResult:
    """Benchmark the complete hybrid pipeline: keygen + encrypt + decrypt."""
    try:
        from crypto_tools import quantum_keygen, quantum_encrypt_message, quantum_decrypt_message

        plaintext = b"SUMIT KEY quantum pipeline benchmark payload - 64 bytes!!"
        entropy = os.urandom(64)

        # Warm-up pass
        _session = quantum_keygen()
        _pkg = quantum_encrypt_message(_session, plaintext, entropy)
        quantum_decrypt_message(_session, _pkg)

        keygen_ms, _ = _timeit(lambda: quantum_keygen(), n_warmup=1, n_runs=5)

        session = quantum_keygen()
        encrypt_ms, _ = _timeit(
            lambda: quantum_encrypt_message(session, plaintext, os.urandom(64)),
            n_warmup=1, n_runs=5,
        )

        pkg = quantum_encrypt_message(session, plaintext, os.urandom(64))
        decrypt_ms, _ = _timeit(
            lambda: quantum_decrypt_message(session, pkg),
            n_warmup=1, n_runs=5,
        )

        total_ms = keygen_ms + encrypt_ms + decrypt_ms
        ops = 1000 / total_ms if total_ms > 0 else 0

        return BenchmarkResult(
            algorithm="SUMIT-KEY Quantum Hybrid",
            category="Full Pipeline (ML-KEM-1024 + Argon2id + AES-256-GCM)",
            latency_ms=round(total_ms, 2),
            ops_per_second=round(ops, 2),
            key_size_bits=256,
            ct_size_bytes=1568 + 80 + len(plaintext) + 16,
            security_classical_bits=256,
            security_quantum_bits=128,
            notes=(
                f"keygen={keygen_ms:.1f}ms encrypt={encrypt_ms:.1f}ms "
                f"decrypt={decrypt_ms:.1f}ms | NIST Level 5 end-to-end"
            ),
        )
    except Exception as exc:
        return BenchmarkResult(
            algorithm="SUMIT-KEY Quantum Hybrid",
            category="Full Pipeline",
            available=False,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Full benchmark runner
# ---------------------------------------------------------------------------

def run_benchmarks(quick: bool = False) -> dict[str, Any]:
    """Run the complete benchmark suite and return structured results."""

    data_size = 64 * 1024 if quick else 1024 * 1024   # 64KB or 1MB

    print("\n" + "=" * 76)
    print("  SUMIT KEY — Cryptographic Benchmark Suite")
    print("=" * 76)

    results: dict[str, Any] = {}

    # ── Entropy quality ──────────────────────────────────────────────────────
    print("\n[1/8] Entropy Quality Analysis...")
    eq_results = _bench_sumit_key_entropy()
    results["entropy_quality"] = eq_results
    _print_entropy_table(eq_results)

    # ── Full static chain ───────────────────────────────────────────────────
    print("\n[2/8] Static Mouse-Turn/Vibration → Key → AES-GCM Chain...")
    chain_result = _bench_static_mouse_chain()
    results["static_chain"] = chain_result
    _print_static_chain(chain_result)

    # ── Game fallback auth scenarios ────────────────────────────────────────
    print("\n[3/8] Game/Chess Scenario Fallback Auth...")
    fallback_results = _bench_game_fallback_scenarios()
    results["game_fallback_scenarios"] = fallback_results
    _print_fallback_table(fallback_results)

    # ── Symmetric ciphers ────────────────────────────────────────────────────
    print(f"\n[4/8] Symmetric Cipher Speed ({data_size//1024}KB payload)...")
    ciphers = [
        _bench_aes_gcm(data_size),
        _bench_chacha20(data_size),
    ]
    results["symmetric_ciphers"] = ciphers
    _print_benchmark_table(ciphers)

    # ── Key derivation ───────────────────────────────────────────────────────
    print("\n[5/8] Key Derivation Speed...")
    entropy_sample = os.urandom(64)
    kdf_results = [
        _bench_hkdf_sha3(entropy_sample),
        _bench_argon2id(entropy_sample, time_cost=1,  memory_cost_kb=65536,  label="interactive"),
        _bench_argon2id(entropy_sample, time_cost=3,  memory_cost_kb=262144, label="moderate"),
        _bench_argon2id(entropy_sample, time_cost=4,  memory_cost_kb=1048576, label="sensitive"),
    ]
    results["key_derivation"] = kdf_results
    _print_benchmark_table(kdf_results)

    # ── ML-KEM (Kyber) ───────────────────────────────────────────────────────
    print("\n[6/8] Post-Quantum KEM: ML-KEM / Kyber (FIPS 203)...")
    kem_results = [
        _bench_ml_kem("ML-KEM-512"),
        _bench_ml_kem("ML-KEM-768"),
        _bench_ml_kem("ML-KEM-1024"),
    ]
    results["ml_kem"] = kem_results
    _print_benchmark_table(kem_results)

    # ── MAYO documented ──────────────────────────────────────────────────────
    print("\n[7/8] MAYO Post-Quantum Signatures (documented analysis)...")
    mayo_results = _mayo_documented_analysis()
    results["mayo"] = mayo_results
    _print_mayo_table(mayo_results)

    # ── Full quantum hybrid pipeline ─────────────────────────────────────────
    print("\n[8/8] Full Quantum-Safe Hybrid Pipeline (ML-KEM-1024 + Argon2id + AES-256-GCM)...")
    qs_result = _bench_quantum_full_pipeline()
    results["quantum_pipeline"] = qs_result
    _print_benchmark_table([qs_result])

    # ── Recommendation ───────────────────────────────────────────────────────
    _print_recommendation(ciphers, kdf_results, kem_results)

    return results


# ---------------------------------------------------------------------------
# Pretty printers
# ---------------------------------------------------------------------------

def _print_entropy_table(results: list[EntropyQualityResult]) -> None:
    print(f"\n  {'Source':<38} {'Bytes':>6}  {'H(bits/B)':>9}  {'χ²':>8}  {'χ²OK':>5}  {'AutoC':>6}  {'Verdict':>10}")
    print("  " + "-" * 92)
    for r in results:
        ok = "✓" if r.chi_squared_pass else "✗"
        print(
            f"  {r.source:<38} {r.byte_count:>6}  {r.shannon_bits_per_byte:>9.4f}"
            f"  {r.chi_squared:>8.1f}  {ok:>5}  {r.max_autocorrelation:>6.4f}  {r.verdict:>10}"
        )


def _print_benchmark_table(results: list[BenchmarkResult]) -> None:
    print(f"\n  {'Algorithm':<28} {'Throughput':>12}  {'Latency':>10}  {'Ops/s':>8}  {'Classical':>9}  {'Quantum':>7}  {'Notes'}")
    print("  " + "-" * 110)
    for r in results:
        if not r.available:
            print(f"  {r.algorithm:<28}  N/A (not available: {r.error[:40]})")
            continue
        tp = f"{r.throughput_mb_s:.1f} MB/s" if r.throughput_mb_s else "—"
        lat = f"{r.latency_ms:.2f}ms" if r.latency_ms else "—"
        ops = f"{r.ops_per_second:.0f}" if r.ops_per_second else "—"
        cl = f"{r.security_classical_bits}b" if r.security_classical_bits else "—"
        qt = f"{r.security_quantum_bits}b" if r.security_quantum_bits else "—"
        print(
            f"  {r.algorithm:<28} {tp:>12}  {lat:>10}  {ops:>8}  {cl:>9}  {qt:>7}  {r.notes[:55]}"
        )


def _print_static_chain(result: StaticChainBenchmark) -> None:
    print("\n  Full-chain static key demo")
    print("  " + "-" * 72)
    print(f"  Mouse events              : {result.mouse_events}")
    print(f"  Direction changes         : {result.direction_changes}")
    print(f"  Micro-vibration steps     : {result.micro_vibration_steps}")
    print(f"  Static key bits           : {result.key_bits}")
    print(f"  Static key preview        : {result.key_preview_hex}")
    print(f"  Encryption                : {result.encryption_algorithm}")
    print(f"  AES-GCM nonce             : {result.nonce_hex}")
    print(f"  Decrypt verified          : {result.decrypt_verified}")
    print(f"  Framework PASS/WARN       : {result.framework_passes}/{result.framework_warnings}")
    print(f"  Note                      : {result.notes}")


def _print_fallback_table(results: list[ScenarioFallbackBenchmark]) -> None:
    print(f"\n  {'Scenario':<34} {'Auth':>5}  {'Method':<18} {'Move':>5} {'Score':>5} {'Events':>6} {'Turns':>5} {'Vib':>5} Decisions")
    print("  " + "-" * 118)
    for result in results:
        auth = "YES" if result.authenticated else "NO"
        decisions = " -> ".join(result.decisions)
        print(
            f"  {result.scenario:<34} {auth:>5}  {result.method:<18} "
            f"{result.movement_verdict:>5} {result.movement_score:>5.2f} "
            f"{result.event_count:>6} {result.direction_changes:>5} "
            f"{result.micro_vibration_steps:>5} {decisions}"
        )


def _print_mayo_table(results: list[BenchmarkResult]) -> None:
    print(f"\n  {'Algorithm':<10} {'Class':>9}  {'Quantum':>7}  {'pk':>6}  {'sig':>5}  {'Notes'}")
    print("  " + "-" * 90)
    for r in results:
        cl = f"{r.security_classical_bits}b" if r.security_classical_bits else "—"
        qt = f"{r.security_quantum_bits}b" if r.security_quantum_bits else "—"
        # Extract pk/sig from notes
        parts = {p.split("=")[0].strip(): p.split("=")[1] for p in r.notes.split("|") if "=" in p}
        pk = parts.get("pk", "?").replace("B", "")
        sig = parts.get("sig", "?").replace("B", "")
        note_short = r.notes.split("|")[-1].strip()[:50]
        print(f"  {r.algorithm:<10} {cl:>9}  {qt:>7}  {pk:>6}  {sig:>5}  {note_short}")


def _print_recommendation(
    ciphers: list[BenchmarkResult],
    kdfs: list[BenchmarkResult],
    kems: list[BenchmarkResult],
) -> None:
    print("\n" + "=" * 76)
    print("  RECOMMENDATION: Most Secure Configuration for SUMIT KEY")
    print("=" * 76)

    # Find fastest cipher
    best_cipher = max((r for r in ciphers if r.available and r.throughput_mb_s), key=lambda r: r.throughput_mb_s)

    print(f"""
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Layer          │  Algorithm              │  Why                     │
  ├──────────────────────────────────────────────────────────────────────┤
  │  Entropy        │  SUMIT KEY mouse+key    │  ~158 bits Shannon       │
  │  Key hardening  │  Argon2id (sensitive)   │  Memory-hard, GPU-proof  │
  │  Symmetric enc  │  {best_cipher.algorithm:<22} │  Fastest + 256-bit AEAD  │
  │  Post-Q KEM     │  ML-KEM-1024 (FIPS 203) │  128-bit quantum KEM     │
  │  Post-Q Sig     │  MAYO-5 (needs liboqs)  │  128-bit quantum sign    │
  │  Key size       │  512-bit (quantum mode) │  Grover margin           │
  └──────────────────────────────────────────────────────────────────────┘

  Full pipeline recommendation:
    1. Capture mouse + keystroke entropy  (SUMIT KEY)
    2. Argon2id(time=4, mem=1GB)          (harden against low-entropy capture)
    3. ML-KEM-1024 encapsulation          (post-quantum key agreement)
    4. {best_cipher.algorithm} encryption     (fast authenticated encryption)
    5. MAYO-5 signature                   (authenticate the public key)

  Classical security   : 256-bit (AES-256 equivalent)
  Post-quantum security: 128-bit (NIST Level 5)
  Memory hardness      : 1GB Argon2id — GPU/ASIC brute-force infeasible
""")
    print("=" * 76)


# ---------------------------------------------------------------------------
# Return structured dict for API / test use
# ---------------------------------------------------------------------------

def get_benchmark_summary(quick: bool = True) -> dict[str, Any]:
    """Return a JSON-serialisable benchmark summary."""
    data_size = 64 * 1024 if quick else 1024 * 1024

    entropy_sample = os.urandom(64)

    ciphers = [_bench_aes_gcm(data_size), _bench_chacha20(data_size)]
    kdfs = [
        _bench_hkdf_sha3(entropy_sample),
        _bench_argon2id(entropy_sample, 1, 65536, "interactive"),
        _bench_argon2id(entropy_sample, 3, 262144, "moderate"),
    ]
    kems = [_bench_ml_kem("ML-KEM-1024")]
    mayo = _mayo_documented_analysis()[-1]  # MAYO-5 only

    def _r(r: BenchmarkResult) -> dict:
        return {
            "algorithm": r.algorithm,
            "category": r.category,
            "available": r.available,
            "throughput_mb_s": r.throughput_mb_s,
            "latency_ms": r.latency_ms,
            "ops_per_second": r.ops_per_second,
            "key_size_bits": r.key_size_bits,
            "ct_size_bytes": r.ct_size_bytes,
            "memory_mb": r.memory_mb,
            "security_classical_bits": r.security_classical_bits,
            "security_quantum_bits": r.security_quantum_bits,
            "notes": r.notes,
            "error": r.error or None,
        }

    eq_results = _bench_sumit_key_entropy()
    chain_result = _bench_static_mouse_chain()
    fallback_results = _bench_game_fallback_scenarios()

    def _eq(r: EntropyQualityResult) -> dict:
        return {
            "source": r.source,
            "byte_count": r.byte_count,
            "shannon_bits_per_byte": r.shannon_bits_per_byte,
            "chi_squared": r.chi_squared,
            "chi_squared_pass": r.chi_squared_pass,
            "max_autocorrelation": r.max_autocorrelation,
            "byte_distribution_uniformity": r.byte_distribution_uniformity,
            "verdict": r.verdict,
        }

    qs_result = _bench_quantum_full_pipeline()

    return {
        "entropy_quality": [_eq(r) for r in eq_results],
        "static_chain": {
            "mouse_events": chain_result.mouse_events,
            "micro_vibration_steps": chain_result.micro_vibration_steps,
            "direction_changes": chain_result.direction_changes,
            "key_bits": chain_result.key_bits,
            "encryption_algorithm": chain_result.encryption_algorithm,
            "decrypt_verified": chain_result.decrypt_verified,
            "framework_passes": chain_result.framework_passes,
            "framework_warnings": chain_result.framework_warnings,
            "key_preview_hex": chain_result.key_preview_hex,
            "nonce_hex": chain_result.nonce_hex,
            "notes": chain_result.notes,
        },
        "game_fallback_scenarios": [
            {
                "scenario": result.scenario,
                "authenticated": result.authenticated,
                "method": result.method,
                "movement_verdict": result.movement_verdict,
                "movement_score": result.movement_score,
                "event_count": result.event_count,
                "direction_changes": result.direction_changes,
                "micro_vibration_steps": result.micro_vibration_steps,
                "decisions": result.decisions,
            }
            for result in fallback_results
        ],
        "symmetric_ciphers": [_r(r) for r in ciphers],
        "key_derivation": [_r(r) for r in kdfs],
        "ml_kem": [_r(r) for r in kems],
        "mayo_documented": _r(mayo),
        "quantum_pipeline": _r(qs_result),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import hashlib

    parser = argparse.ArgumentParser(description="SUMIT KEY cryptographic benchmark")
    parser.add_argument("--quick", action="store_true", help="Use 64KB payload instead of 1MB")
    args = parser.parse_args()

    run_benchmarks(quick=args.quick)
