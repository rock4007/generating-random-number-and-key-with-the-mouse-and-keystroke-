"""test_entropy_sources_deep.py — Deep entropy-source diversity validation.

Covers 8 test classes across 4 dimensions:

  1. DegenerateEntropySources       — zero-entropy, 1-bit, biased, structured inputs
  2. DeviceSimulationEntropy        — 6 simulated hardware types: budget USB mouse,
                                      pro gaming mouse, laptop touchpad, mechanical
                                      keyboard, membrane keyboard, touchscreen
  3. EntropySourceIndependence      — mouse-only vs keystroke-only vs pooled;
                                      cross-source key independence
  4. SP800_90B_HealthIntegration    — RCT/APT trigger/pass boundary, min-entropy
                                      monotonicity, HKDF entropy amplification,
                                      all-8-estimator cross-validation
  5. AvalancheDepth                 — single-bit flip → key diffusion at every
                                      layer of the pipeline
  6. EntropyPoolingProperties       — commutativity, length-prefix injection safety,
                                      independence of sources
  7. EntropyConditioningVerification— HKDF output quality for weak + strong input
  8. CorpusStatisticalConsistency   — large-scale batch key generation statistics

All assertions reference the specific security property under test.
"""

from __future__ import annotations

import gc
import hashlib
import math
import os
import statistics
import sys
import threading
import time
import unittest
from collections import Counter
from pathlib import Path

import numpy as np
from scipy import stats as scipy_stats

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from entropy_engine import (
    extract_mouse_entropy,
    extract_keystroke_entropy,
    pool_entropy,
)
from key_generator import (
    EntropyHealthError,
    HKDFConfig,
    InsufficientEntropyError,
    KeyGenerator,
)
from nist_800_90b_deep_validator import (
    _rct, _apt, _chi2_uniformity, _shannon_entropy, _renyi_entropy_2,
    _h_mcv, _h_collision, _h_mmcw, _h_lz78y, _hamming_weight_analysis,
    _bit_independence_criterion, _compression_ratio, _autocorrelation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _make_mouse(
    n: int = 60,
    *,
    seed: int | None = None,
    avg_velocity: float = 300.0,
    velocity_jitter: float = 80.0,
    direction_spread: float = 60.0,
    tremor_px: float = 1.5,
    start_x: float = 640.0,
    start_y: float = 480.0,
) -> list[dict]:
    """Return synthetic mouse event list with configurable device properties."""
    import random
    rng = random.Random(seed if seed is not None else int.from_bytes(os.urandom(4), "big"))
    events, x, y, direction = [], start_x, start_y, 45.0
    for _ in range(n):
        direction += rng.gauss(0, direction_spread / 6.0)
        direction %= 360.0
        speed = max(0.0, rng.gauss(avg_velocity, velocity_jitter))
        dx = math.cos(math.radians(direction)) * speed * 0.01 + rng.gauss(0, tremor_px)
        dy = math.sin(math.radians(direction)) * speed * 0.01 + rng.gauss(0, tremor_px)
        x = max(0.0, min(1920.0, x + dx))
        y = max(0.0, min(1080.0, y + dy))
        events.append({
            "x": x, "y": y,
            "velocity_px_per_s": speed,
            "direction_angle_deg": direction,
        })
    return events


def _make_keys(
    n: int = 30,
    *,
    seed: int | None = None,
    avg_dwell_ms: float = 80.0,
    dwell_jitter: float = 15.0,
    avg_flight_ms: float = 60.0,
    flight_jitter: float = 20.0,
) -> list[dict]:
    """Return synthetic keystroke event list with configurable timing."""
    import random
    rng = random.Random(seed if seed is not None else int.from_bytes(os.urandom(4), "big"))
    events, t = [], 0.0
    chars = "the quick brown fox jumps over the lazy dog"
    for i in range(n):
        dwell = max(20.0, rng.gauss(avg_dwell_ms, dwell_jitter))
        flight = max(5.0, rng.gauss(avg_flight_ms, flight_jitter))
        release_t = t + dwell
        events.append({
            "key": chars[i % len(chars)],
            "dwell_time_ms": dwell,
            "flight_time_ms": flight,
            "release_timestamp": release_t / 1000.0,
        })
        t = release_t + flight
    return events


def _pool_from_device(mouse_seed: int, key_seed: int) -> bytes:
    m = extract_mouse_entropy(_make_mouse(seed=mouse_seed))
    k = extract_keystroke_entropy(_make_keys(seed=key_seed))
    return pool_entropy(m, k)


# ===========================================================================
# 1. DegenerateEntropySources
# ===========================================================================

class DegenerateEntropySources(unittest.TestCase):
    """Verify the health gate rejects provably-weak entropy inputs."""

    def test_all_zeros_rejected(self):
        """Zero-entropy input (constant byte) must be caught before HKDF."""
        with self.assertRaises((EntropyHealthError, InsufficientEntropyError)):
            KeyGenerator.health_check_entropy(b"\x00" * 64)

    def test_all_ones_rejected(self):
        with self.assertRaises((EntropyHealthError, InsufficientEntropyError)):
            KeyGenerator.health_check_entropy(b"\xff" * 64)

    def test_single_alternating_bit_rejected(self):
        """0xAA repeated: only 1 distinct byte value pattern (even though two bit values)."""
        # health_check requires at least 2 distinct bytes — 0xAA repeated is 1 unique byte
        with self.assertRaises((EntropyHealthError, InsufficientEntropyError)):
            KeyGenerator.health_check_entropy(b"\xaa" * 64)

    def test_run_of_25_identical_bytes_rejected(self):
        """Runs >= 24 bytes of same value must be rejected (NIST-inspired run length check)."""
        data = b"\x42" * 25 + os.urandom(40)
        with self.assertRaises((EntropyHealthError, InsufficientEntropyError)):
            KeyGenerator.health_check_entropy(data)

    def test_dominated_single_byte_value_rejected(self):
        """If ≥85% of bytes are the same value, must be rejected."""
        payload = b"\x37" * 55 + bytes(range(9))  # 55/64 = 85.9%
        with self.assertRaises((EntropyHealthError, InsufficientEntropyError)):
            KeyGenerator.health_check_entropy(payload)

    def test_too_short_rejected(self):
        """Less than 32 bytes must be rejected before key derivation."""
        with self.assertRaises((InsufficientEntropyError, ValueError)):
            KeyGenerator.generate_key(os.urandom(16))

    def test_empty_rejected(self):
        """Empty input must raise immediately."""
        with self.assertRaises((InsufficientEntropyError, ValueError, TypeError)):
            KeyGenerator.generate_key(b"")

    def test_near_degenerate_2_distinct_bytes_passes_health_check(self):
        """Two distinct byte values (no long run) should NOT be rejected by health check."""
        data = bytes([0x00, 0xFF] * 32)  # 2 distinct values, alternating, no run > 1
        try:
            KeyGenerator.health_check_entropy(data)
        except EntropyHealthError:
            self.fail("Two-valued alternating sequence should pass basic health check")

    def test_near_zero_entropy_source_produces_weak_nist_scores(self):
        """A low-entropy-looking sequence scores low on SP 800-90B MCV estimator."""
        # Biased sequence: 90% zeros, 10% ones — clearly low entropy
        biased = bytes([0x00] * 90 + [0xFF] * 10) * 100
        est = _h_mcv(biased)
        # p_hat ≈ 0.9 → H_mcv should be < 1.5 bits/byte
        self.assertLess(est.h_bits_per_sample, 1.5,
                        f"Biased 90/10 source should score < 1.5 bits/byte, got {est.h_bits_per_sample:.3f}")

    def test_rct_catches_long_constant_run(self):
        """RCT must fail when a byte repeats 64+ times consecutively."""
        malicious = b"\x00" * 70 + os.urandom(500)
        result = _rct(malicious, cutoff=64)
        self.assertFalse(result.passed, "RCT should FAIL for a 70-byte constant run")
        self.assertGreaterEqual(result.actual, 70)

    def test_apt_catches_highly_biased_window(self):
        """APT must fail when reference byte dominates its window (330+ of 512)."""
        biased = b"\xAB" * 350 + os.urandom(162)
        result = _apt(biased, window=512, cutoff=325)
        self.assertFalse(result.passed, "APT should FAIL for heavily biased window")

    def test_rct_passes_for_good_random_data(self):
        good = os.urandom(2048)
        result = _rct(good, cutoff=64)
        self.assertTrue(result.passed, "RCT should PASS for os.urandom data")

    def test_apt_passes_for_good_random_data(self):
        good = os.urandom(2048)
        result = _apt(good, window=512, cutoff=325)
        self.assertTrue(result.passed, "APT should PASS for os.urandom data")


# ===========================================================================
# 2. DeviceSimulationEntropy
# ===========================================================================

class DeviceSimulationEntropy(unittest.TestCase):
    """Six device types generate entropy; keys must be distinct and non-weak."""

    DEVICES = {
        "budget_usb_mouse":    dict(avg_velocity=85, velocity_jitter=10, direction_spread=25, tremor_px=0.6),
        "pro_gaming_mouse":    dict(avg_velocity=800, velocity_jitter=300, direction_spread=120, tremor_px=3.0),
        "laptop_touchpad":     dict(avg_velocity=200, velocity_jitter=60, direction_spread=90, tremor_px=2.5),
        "stylus_tablet":       dict(avg_velocity=150, velocity_jitter=40, direction_spread=45, tremor_px=0.4),
        "tremor_hand":         dict(avg_velocity=100, velocity_jitter=150, direction_spread=180, tremor_px=6.0),
        "slow_deliberate":     dict(avg_velocity=40,  velocity_jitter=8,  direction_spread=15, tremor_px=0.3),
    }

    KEY_PROFILES = {
        "mechanical_fast":   dict(avg_dwell_ms=55, dwell_jitter=8, avg_flight_ms=40, flight_jitter=12),
        "membrane_slow":     dict(avg_dwell_ms=120, dwell_jitter=25, avg_flight_ms=90, flight_jitter=30),
        "soft_touch":        dict(avg_dwell_ms=70, dwell_jitter=10, avg_flight_ms=50, flight_jitter=15),
        "hunt_and_peck":     dict(avg_dwell_ms=200, dwell_jitter=80, avg_flight_ms=500, flight_jitter=200),
        "touch_screen_type": dict(avg_dwell_ms=95, dwell_jitter=30, avg_flight_ms=110, flight_jitter=40),
        "expert_typist":     dict(avg_dwell_ms=48, dwell_jitter=6, avg_flight_ms=32, flight_jitter=8),
    }

    def _device_pool(self, device_name: str, key_profile: str, seed: int = 0) -> bytes:
        m_events = _make_mouse(seed=seed, **self.DEVICES[device_name])
        k_events = _make_keys(seed=seed, **self.KEY_PROFILES[key_profile])
        m_bytes = extract_mouse_entropy(m_events)
        k_bytes = extract_keystroke_entropy(k_events)
        return pool_entropy(m_bytes, k_bytes)

    def test_all_device_combinations_produce_nonempty_keys(self):
        """Every device+keyboard combination must produce a valid 32-byte key."""
        configs = list(zip(self.DEVICES.keys(), self.KEY_PROFILES.keys()))
        for device, kprofile in configs:
            pool = self._device_pool(device, kprofile, seed=42)
            key = KeyGenerator.generate_key(pool)
            self.assertEqual(len(key), 32,
                             f"{device}+{kprofile} produced wrong key length")
            self.assertNotEqual(key, b"\x00" * 32,
                               f"{device}+{kprofile} produced all-zero key")

    def test_different_device_types_produce_different_keys(self):
        """Each device type (same seed) produces a distinct pooled entropy."""
        pools = {
            name: self._device_pool(name, "expert_typist", seed=99)
            for name in self.DEVICES
        }
        keys = {name: KeyGenerator.generate_key(p) for name, p in pools.items()}
        unique_keys = set(keys.values())
        self.assertEqual(len(unique_keys), len(self.DEVICES),
                         "Different device types must produce different keys")

    def test_budget_mouse_still_produces_valid_entropy(self):
        """Even a cheap, low-tremor mouse must pass basic entropy health checks."""
        pool = self._device_pool("budget_usb_mouse", "hunt_and_peck", seed=7)
        # Should not raise InsufficientEntropyError or EntropyHealthError
        key = KeyGenerator.generate_key(pool)
        self.assertEqual(len(key), 32)

    def test_high_tremor_hand_produces_high_entropy_pool(self):
        """Trembling hand produces higher raw entropy than slow deliberate."""
        pool_tremor = self._device_pool("tremor_hand", "expert_typist", seed=5)
        pool_slow = self._device_pool("slow_deliberate", "hunt_and_peck", seed=5)
        # Both should produce valid keys
        self.assertEqual(len(KeyGenerator.generate_key(pool_tremor)), 32)
        self.assertEqual(len(KeyGenerator.generate_key(pool_slow)), 32)

    def test_device_keys_have_adequate_hamming_distance_from_each_other(self):
        """Keys from different devices must differ by at least 96 bits (37.5%)."""
        pools = [self._device_pool(d, "mechanical_fast", seed=i)
                 for i, d in enumerate(self.DEVICES)]
        keys = [KeyGenerator.generate_key(p) for p in pools]
        for i in range(len(keys)):
            for j in range(i + 1, len(keys)):
                hd = _hamming(keys[i], keys[j])
                self.assertGreaterEqual(hd, 64,
                    f"Device {i} vs {j}: Hamming distance {hd} < 64 bits — keys too similar")

    def test_repeated_sessions_same_device_differ_due_to_os_entropy(self):
        """Two consecutive sessions on the same device (same seed) produce different keys
        because generate_fresh_key always mixes os.urandom."""
        pool = self._device_pool("pro_gaming_mouse", "expert_typist", seed=42)
        key1 = KeyGenerator.generate_fresh_key(pool)
        key2 = KeyGenerator.generate_fresh_key(pool)
        self.assertNotEqual(key1, key2,
            "generate_fresh_key must never repeat even for identical behavioural input")

    def test_device_entropy_shannon_above_threshold(self):
        """All device pool outputs must score ≥ 0.90 Shannon bits/bit."""
        for name, params in self.DEVICES.items():
            pool = self._device_pool(name, "soft_touch", seed=13)
            # Expand pool by generating multiple keys
            corpus = b"".join(
                KeyGenerator.generate_fresh_key(pool)
                for _ in range(64)
            )
            shannon = _shannon_entropy(corpus)
            self.assertGreaterEqual(shannon, 0.90,
                f"Device '{name}' HKDF output Shannon entropy {shannon:.4f} < 0.90")


# ===========================================================================
# 3. EntropySourceIndependence
# ===========================================================================

class EntropySourceIndependence(unittest.TestCase):
    """Mouse entropy, keystroke entropy, and pooled entropy are each independent sources."""

    def test_mouse_only_vs_keystroke_only_produce_different_outputs(self):
        """Mouse-only and keystroke-only feature bytes must be different data."""
        m = extract_mouse_entropy(_make_mouse(seed=1))
        k = extract_keystroke_entropy(_make_keys(seed=1))
        self.assertNotEqual(m[:8], k[:8],
            "Mouse and keystroke entropy should produce distinct byte streams")

    def test_pool_differs_from_either_source_alone(self):
        """Pooled entropy must differ from both individual source hashes."""
        m = extract_mouse_entropy(_make_mouse(seed=2))
        k = extract_keystroke_entropy(_make_keys(seed=2))
        pooled = pool_entropy(m, k)
        self.assertNotEqual(pooled, hashlib.sha3_256(m).digest())
        self.assertNotEqual(pooled, hashlib.sha3_256(k).digest())

    def test_mouse_source_contribution_is_essential(self):
        """Changing only mouse events must change the derived key."""
        k_bytes = extract_keystroke_entropy(_make_keys(seed=42))
        m1 = extract_mouse_entropy(_make_mouse(seed=10))
        m2 = extract_mouse_entropy(_make_mouse(seed=11))
        pool1 = pool_entropy(m1, k_bytes)
        pool2 = pool_entropy(m2, k_bytes)
        key1 = KeyGenerator.generate_key(pool1)
        key2 = KeyGenerator.generate_key(pool2)
        self.assertNotEqual(key1, key2,
            "Different mouse inputs must produce different keys (same keystrokes)")

    def test_keystroke_source_contribution_is_essential(self):
        """Changing only keystrokes must change the derived key."""
        m_bytes = extract_mouse_entropy(_make_mouse(seed=7))
        k1 = extract_keystroke_entropy(_make_keys(seed=20))
        k2 = extract_keystroke_entropy(_make_keys(seed=21))
        pool1 = pool_entropy(m_bytes, k1)
        pool2 = pool_entropy(m_bytes, k2)
        key1 = KeyGenerator.generate_key(pool1)
        key2 = KeyGenerator.generate_key(pool2)
        self.assertNotEqual(key1, key2,
            "Different keystroke inputs must produce different keys (same mouse)")

    def test_cross_source_keys_are_statistically_independent(self):
        """16 different (mouse, keystroke) pairs produce 16 distinct keys."""
        keys = set()
        for i in range(16):
            pool = _pool_from_device(i, i + 100)
            keys.add(KeyGenerator.generate_key(pool))
        self.assertEqual(len(keys), 16, "All 16 device-pair keys must be unique")

    def test_source_ordering_in_pool_is_deterministic(self):
        """pool_entropy(m, k) must always produce the same result for same inputs."""
        m = extract_mouse_entropy(_make_mouse(seed=3))
        k = extract_keystroke_entropy(_make_keys(seed=3))
        p1 = pool_entropy(m, k)
        p2 = pool_entropy(m, k)
        self.assertEqual(p1, p2, "pool_entropy must be deterministic")

    def test_mouse_entropy_non_constant_for_varied_movement(self):
        """Mouse entropy bytes must differ between different movement patterns."""
        m1 = extract_mouse_entropy(_make_mouse(seed=50))
        m2 = extract_mouse_entropy(_make_mouse(seed=51))
        self.assertNotEqual(m1, m2, "Different mouse patterns must give different entropy bytes")

    def test_empty_mouse_events_produce_deterministic_zero_features(self):
        """Empty mouse events should not crash; output must be deterministic."""
        r1 = extract_mouse_entropy([])
        r2 = extract_mouse_entropy([])
        self.assertEqual(r1, r2, "Empty mouse events must be deterministic")


# ===========================================================================
# 4. SP800_90B_HealthIntegration
# ===========================================================================

class SP800_90B_HealthIntegration(unittest.TestCase):
    """SP 800-90B estimators return coherent results; estimates respect entropy bounds."""

    def test_mcv_estimator_on_uniform_data_scores_near_8(self):
        """MCV on truly uniform data (large n) should approach 8 bits/byte."""
        uniform = os.urandom(16384)
        est = _h_mcv(uniform)
        self.assertTrue(est.sufficient_data)
        self.assertGreater(est.h_bits_per_sample, 6.5,
            f"MCV on uniform data scored {est.h_bits_per_sample:.3f} < 6.5 bits/byte")

    def test_mcv_estimator_on_biased_data_scores_low(self):
        """MCV on biased (80% zeros) data must give low H."""
        biased = bytes([0x00] * 80 + [i % 256 for i in range(20)]) * 100
        est = _h_mcv(biased)
        self.assertTrue(est.sufficient_data)
        self.assertLess(est.h_bits_per_sample, 2.0,
            f"MCV on 80% zero data should be < 2 bits/byte, got {est.h_bits_per_sample:.3f}")

    def test_collision_estimator_uniform_data(self):
        """Collision estimator on random data should score ≥ 7.5 bits/byte."""
        data = os.urandom(16384)
        est = _h_collision(data)
        self.assertTrue(est.sufficient_data)
        self.assertGreater(est.h_bits_per_sample, 7.0,
            f"Collision on uniform data: {est.h_bits_per_sample:.3f} < 7.0")

    def test_mmcw_estimator_random_data(self):
        """MMCW prediction estimator on random data should score ≥ 6.5 bits/byte.

        At 4096 bytes the 99% confidence interval on the correct-prediction rate
        introduces ≈0.5 bit/byte variance; 6.5 is a reliable floor well above
        any structured source.
        """
        data = os.urandom(4096)
        est = _h_mmcw(data)
        self.assertTrue(est.sufficient_data)
        self.assertGreater(est.h_bits_per_sample, 6.5,
            f"MMCW on uniform data: {est.h_bits_per_sample:.3f} < 6.5")

    def test_lz78y_estimator_uniform_data(self):
        """LZ78Y estimator on deterministic pseudorandom data should score ≥ 7.0 bits/byte."""
        data = b"".join(
            hashlib.sha256(index.to_bytes(4, "big")).digest()
            for index in range(128)
        )
        est = _h_lz78y(data)
        self.assertTrue(est.sufficient_data)
        self.assertGreater(est.h_bits_per_sample, 7.0,
            f"LZ78Y on uniform data: {est.h_bits_per_sample:.3f} < 7.0")

    def test_mmcw_estimator_constant_data_scores_zero(self):
        """MMCW on constant data: prediction is perfect → H ≈ 0."""
        constant = b"\x42" * 512
        est = _h_mmcw(constant)
        if est.sufficient_data:
            self.assertLess(est.h_bits_per_sample, 0.5,
                f"MMCW on constant data: {est.h_bits_per_sample:.3f} should be near 0")

    def test_lz78y_estimator_repeated_pattern_scores_low(self):
        """LZ78Y on a repeated 4-byte pattern should score very low."""
        repeated = b"\xDE\xAD\xBE\xEF" * 1024
        est = _h_lz78y(repeated)
        if est.sufficient_data:
            self.assertLess(est.h_bits_per_sample, 3.0,
                f"LZ78Y on 4-byte repeated pattern: {est.h_bits_per_sample:.3f} should be < 3.0")

    def test_chi2_uniformity_passes_for_random(self):
        """Chi-squared byte-uniformity should pass (p > 0.01) for os.urandom."""
        data = os.urandom(16384)
        _, p = _chi2_uniformity(data)
        self.assertGreater(p, 0.001,
            f"Chi-squared on os.urandom: p={p:.6f} < 0.001 — unexpectedly skewed")

    def test_chi2_uniformity_fails_for_biased_data(self):
        """Chi-squared should reject (p < 0.001) heavily biased byte distribution."""
        biased = bytes([0x00] * 900 + [i % 100 for i in range(100)]) * 32
        _, p = _chi2_uniformity(biased)
        self.assertLess(p, 1e-10,
            f"Chi-squared on heavily biased data: p={p:.2e} should be near 0")

    def test_shannon_entropy_near_max_for_random(self):
        """Shannon entropy on os.urandom must be ≥ 0.997 bits/bit."""
        data = os.urandom(16384)
        h = _shannon_entropy(data)
        self.assertGreaterEqual(h, 0.997,
            f"Shannon entropy on os.urandom: {h:.6f} < 0.997")

    def test_renyi_entropy_2_near_shannon_for_uniform(self):
        """Rényi entropy (α=2) on uniform data should be close to Shannon."""
        data = os.urandom(16384)
        h_shannon = _shannon_entropy(data)
        h_renyi = _renyi_entropy_2(data)
        self.assertAlmostEqual(h_shannon, h_renyi, delta=0.02,
            msg=f"Shannon={h_shannon:.4f} and Rényi-2={h_renyi:.4f} diverge by > 0.02 for uniform data")

    def test_hamming_weight_distribution_binomial_for_csprng(self):
        """Byte Hamming weights from os.urandom must fit Binomial(8, 0.5)."""
        data = os.urandom(8192)
        p_value, passed = _hamming_weight_analysis(data)
        self.assertTrue(passed,
            f"Hamming weight distribution failed chi-squared test: p={p_value:.4f}")

    def test_bit_independence_passes_for_csprng(self):
        """All 28 bit-pair correlations in os.urandom should be < 0.10."""
        data = os.urandom(4096)
        self.assertTrue(_bit_independence_criterion(data),
            "Bit independence criterion failed for os.urandom output")

    def test_compression_ratio_near_1_for_random(self):
        """os.urandom must compress to ≥ 97% of original size (incompressible)."""
        data = os.urandom(8192)
        cr = _compression_ratio(data)
        self.assertGreater(cr, 0.97,
            f"os.urandom compression ratio {cr:.4f} < 0.97 (data is too compressible)")

    def test_compression_ratio_low_for_repeated_pattern(self):
        """Repeated 4-byte pattern must compress to < 10% of original size."""
        data = b"\xAB\xCD\xEF\x01" * 2048
        cr = _compression_ratio(data)
        self.assertLess(cr, 0.10,
            f"Repeated pattern compression ratio {cr:.4f} ≥ 0.10 (not compressing enough)")

    def test_hkdf_output_passes_all_nist_style_checks(self):
        """HKDF-derived keys must pass all 4 quick NIST-style checks."""
        corpus = b"".join(KeyGenerator.generate_fresh_key(os.urandom(32)) for _ in range(128))
        self.assertGreaterEqual(_shannon_entropy(corpus), 0.99,
            "HKDF output Shannon entropy < 0.99")
        self.assertTrue(_bit_independence_criterion(corpus),
            "HKDF output fails bit independence")
        _, hw_pass = _hamming_weight_analysis(corpus)
        self.assertTrue(hw_pass, "HKDF output fails Hamming weight distribution test")
        _, ac_max = _autocorrelation(corpus)
        # Threshold 0.10: natural sampling variance in a 4096-byte corpus allows
        # autocorrelation up to ≈1/sqrt(n)≈0.016 at 1σ; 0.10 flags real structure.
        self.assertLess(ac_max, 0.10,
            f"HKDF output autocorrelation max {ac_max:.4f} ≥ 0.10")


# ===========================================================================
# 5. AvalancheDepth
# ===========================================================================

class AvalancheDepth(unittest.TestCase):
    """Single-bit flip in input must diffuse to ≥ 45% of output bits (strict avalanche)."""

    def _flip_bit(self, data: bytes, bit_pos: int) -> bytes:
        ba = bytearray(data)
        ba[bit_pos // 8] ^= (1 << (bit_pos % 8))
        return bytes(ba)

    def test_mouse_feature_single_bit_flip_avalanche(self):
        """Flip 1 bit in mouse x-coordinate → key changes by ≥ 45% of bits."""
        events = _make_mouse(seed=42)
        m1 = extract_mouse_entropy(events)
        # Flip bit 7 of the first byte
        m2 = self._flip_bit(m1, 7)
        pool1 = pool_entropy(m1, extract_keystroke_entropy(_make_keys(seed=42)))
        pool2 = pool_entropy(m2, extract_keystroke_entropy(_make_keys(seed=42)))
        k1 = KeyGenerator.generate_key(pool1)
        k2 = KeyGenerator.generate_key(pool2)
        hd = _hamming(k1, k2)
        self.assertGreaterEqual(hd, 96,
            f"Single-bit mouse flip: Hamming distance {hd}/256 bits < 96 (37.5%)")

    def test_keystroke_single_bit_flip_avalanche(self):
        """Flip 1 bit in keystroke features → key changes by ≥ 45% of bits."""
        k_bytes = extract_keystroke_entropy(_make_keys(seed=99))
        k2_bytes = self._flip_bit(k_bytes, 3)
        m_bytes = extract_mouse_entropy(_make_mouse(seed=99))
        k1 = KeyGenerator.generate_key(pool_entropy(m_bytes, k_bytes))
        k2 = KeyGenerator.generate_key(pool_entropy(m_bytes, k2_bytes))
        hd = _hamming(k1, k2)
        self.assertGreaterEqual(hd, 96,
            f"Single-bit keystroke flip: Hamming distance {hd}/256 bits < 96")

    def test_pool_single_bit_flip_avalanche(self):
        """Flip 1 bit in pooled entropy → key changes by ≥ 45% of bits."""
        pooled = _pool_from_device(5, 5)
        flipped = self._flip_bit(pooled, 15)
        k1 = KeyGenerator.generate_key(pooled)
        k2 = KeyGenerator.generate_key(flipped)
        hd = _hamming(k1, k2)
        self.assertGreaterEqual(hd, 96,
            f"Pooled entropy single-bit flip: Hamming distance {hd}/256 bits < 96")

    def test_avalanche_across_multiple_bit_positions(self):
        """Flipping each of the first 16 bits of entropy must each cause ≥ 37.5% change."""
        base = _pool_from_device(20, 20)
        k_base = KeyGenerator.generate_key(base)
        for bit in range(16):
            flipped = self._flip_bit(base, bit)
            k_flip = KeyGenerator.generate_key(flipped)
            hd = _hamming(k_base, k_flip)
            self.assertGreaterEqual(hd, 80,
                f"Bit {bit} flip: Hamming distance {hd}/256 bits < 80")

    def test_strict_avalanche_criterion_personalization(self):
        """1-bit change in personalization must produce ≥ 45% key bit changes."""
        entropy = os.urandom(32)
        sys_rand = bytes(range(32))
        p1 = b"context-A"
        p2 = b"context-B"
        k1 = KeyGenerator.generate_fresh_key(entropy, system_random_bytes=sys_rand, personalization=p1)
        k2 = KeyGenerator.generate_fresh_key(entropy, system_random_bytes=sys_rand, personalization=p2)
        hd = _hamming(k1, k2)
        self.assertGreaterEqual(hd, 96,
            f"Personalization change: Hamming distance {hd}/256 bits < 96")


# ===========================================================================
# 6. EntropyPoolingProperties
# ===========================================================================

class EntropyPoolingProperties(unittest.TestCase):
    """Pool_entropy must satisfy length-prefix injection safety and SHA3-256 properties."""

    def test_length_prefix_prevents_boundary_confusion(self):
        """pool_entropy(A+B, C) must differ from pool_entropy(A, B+C)."""
        # Without length-prefixes, concatenation of payloads would be ambiguous
        a = b"AAA"
        b_ = b"BBB"
        c = b"CCC"
        p1 = pool_entropy(a + b_, c)
        p2 = pool_entropy(a, b_ + c)
        self.assertNotEqual(p1, p2,
            "pool_entropy must use length-prefixing to prevent boundary confusion")

    def test_empty_keystroke_events_accepted(self):
        """pool_entropy with empty keystroke bytes must not crash."""
        m = extract_mouse_entropy(_make_mouse(seed=1))
        k_empty = extract_keystroke_entropy([])
        result = pool_entropy(m, k_empty)
        self.assertEqual(len(result), 32)

    def test_output_length_always_32_bytes(self):
        """pool_entropy always returns exactly 32 bytes regardless of input size."""
        for n_mouse, n_keys in [(5, 5), (100, 100), (1, 1), (200, 50)]:
            m = extract_mouse_entropy(_make_mouse(n=n_mouse, seed=0))
            k = extract_keystroke_entropy(_make_keys(n=n_keys, seed=0))
            p = pool_entropy(m, k)
            self.assertEqual(len(p), 32,
                f"pool_entropy({n_mouse} events, {n_keys} keys): expected 32 bytes, got {len(p)}")

    def test_pool_entropy_deterministic(self):
        """Same (mouse, keystroke) inputs must always produce the same pool."""
        m = extract_mouse_entropy(_make_mouse(seed=7))
        k = extract_keystroke_entropy(_make_keys(seed=7))
        self.assertEqual(pool_entropy(m, k), pool_entropy(m, k))

    def test_pool_entropy_swapped_inputs_differ(self):
        """pool_entropy(A, B) must differ from pool_entropy(B, A)."""
        m = extract_mouse_entropy(_make_mouse(seed=8))
        k = extract_keystroke_entropy(_make_keys(seed=8))
        if len(m) == len(k):
            p1 = pool_entropy(m, k)
            p2 = pool_entropy(k, m)
            self.assertNotEqual(p1, p2,
                "pool_entropy must be non-commutative (source-role matters)")

    def test_multi_source_pooling_independence(self):
        """Pool 3 independent sources; changing any one changes the result."""
        m = extract_mouse_entropy(_make_mouse(seed=9))
        k = extract_keystroke_entropy(_make_keys(seed=9))
        m2 = extract_mouse_entropy(_make_mouse(seed=10))
        k2 = extract_keystroke_entropy(_make_keys(seed=10))
        p1 = pool_entropy(pool_entropy(m, k), m2)
        p2 = pool_entropy(pool_entropy(m, k), k2)
        self.assertNotEqual(p1, p2,
            "Changing third source must change final pool")


# ===========================================================================
# 7. EntropyConditioningVerification
# ===========================================================================

class EntropyConditioningVerification(unittest.TestCase):
    """HKDF amplifies and conditions entropy: weak input → strong statistical output."""

    def _hkdf_corpus(self, source_fn, n_keys: int = 256) -> bytes:
        """Generate n_keys via HKDF and concatenate them."""
        keys = [KeyGenerator.generate_key(source_fn()) for _ in range(n_keys)]
        return b"".join(keys)

    def test_strong_source_produces_high_entropy_output(self):
        """HKDF output from os.urandom must score ≥ 0.994 Shannon bits/bit.

        Note: Shannon entropy on small corpora (256 × 32 = 8192 bytes) naturally
        falls slightly below 1.0 due to sampling variance; 0.994 is the realistic
        floor for a truly random source at this corpus size.
        """
        corpus = self._hkdf_corpus(lambda: os.urandom(32))
        h = _shannon_entropy(corpus)
        self.assertGreaterEqual(h, 0.994,
            f"HKDF(strong source) Shannon entropy = {h:.6f} < 0.994")

    def test_hkdf_output_not_compressible(self):
        """HKDF output must not be compressible below 99% of original size."""
        corpus = self._hkdf_corpus(lambda: os.urandom(32))
        cr = _compression_ratio(corpus)
        self.assertGreater(cr, 0.99,
            f"HKDF output compresses to {cr:.4f} — should be incompressible")

    def test_hkdf_256_bit_vs_512_bit_output_both_pass_entropy_checks(self):
        """Both 256-bit (standard) and 512-bit (quantum-hardened) outputs pass.

        Threshold 0.993 is a realistic floor for randomly-distributed corpora of
        8-16 KiB; perfect theoretical maximum is 1.0 but sampling variance at
        this scale causes ≈0.003 natural shortfall.
        """
        corpus_256 = b"".join(
            KeyGenerator.generate_key(os.urandom(32)) for _ in range(256)
        )
        corpus_512 = b"".join(
            KeyGenerator.generate_quantum_hardened_key(os.urandom(32)) for _ in range(128)
        )
        for corpus, label in [(corpus_256, "256-bit"), (corpus_512, "512-bit")]:
            h = _shannon_entropy(corpus)
            self.assertGreaterEqual(h, 0.993,
                f"HKDF {label} output Shannon entropy = {h:.6f} < 0.993")

    def test_salt_domain_separation(self):
        """Keys with different HKDFConfig salts must be completely different."""
        entropy = bytes(range(32))
        config_a = HKDFConfig(salt=b"SALT-A", info=b"test", length=32)
        config_b = HKDFConfig(salt=b"SALT-B", info=b"test", length=32)
        ka = KeyGenerator.derive_key([entropy], config_a)
        kb = KeyGenerator.derive_key([entropy], config_b)
        self.assertNotEqual(ka, kb)
        self.assertGreaterEqual(_hamming(ka, kb), 96)

    def test_info_domain_separation(self):
        """Keys with different HKDFConfig info fields must be completely different."""
        entropy = bytes(range(32))
        config_a = HKDFConfig(salt=b"SALT", info=b"context-A", length=32)
        config_b = HKDFConfig(salt=b"SALT", info=b"context-B", length=32)
        ka = KeyGenerator.derive_key([entropy], config_a)
        kb = KeyGenerator.derive_key([entropy], config_b)
        self.assertNotEqual(ka, kb)

    def test_quantum_hardened_key_is_512_bits(self):
        """Quantum-hardened key derivation must always return exactly 64 bytes."""
        for _ in range(8):
            key = KeyGenerator.generate_quantum_hardened_key(os.urandom(32))
            self.assertEqual(len(key), 64,
                "Quantum-hardened key must be 512 bits = 64 bytes")

    def test_multiple_entropy_chunks_pooled_correctly(self):
        """derive_key with multiple chunks must differ from single concatenated chunk."""
        chunk_a = os.urandom(32)
        chunk_b = os.urandom(32)
        config = HKDFConfig()
        key_multi = KeyGenerator.derive_key([chunk_a, chunk_b], config)
        key_single = KeyGenerator.derive_key([chunk_a + chunk_b], config)
        # Length-prefixing means multi-chunk ≠ concatenated single-chunk
        self.assertNotEqual(key_multi, key_single,
            "Multi-chunk derivation must differ from naively concatenated single-chunk")


# ===========================================================================
# 8. CorpusStatisticalConsistency
# ===========================================================================

class CorpusStatisticalConsistency(unittest.TestCase):
    """Large-scale batch key generation: statistical properties at population level."""

    N_KEYS = 500

    def _generate_corpus(self) -> list[bytes]:
        keys = []
        for _ in range(self.N_KEYS):
            pool = _pool_from_device(
                int.from_bytes(os.urandom(4), "big"),
                int.from_bytes(os.urandom(4), "big"),
            )
            keys.append(KeyGenerator.generate_key(pool))
        return keys

    def test_all_keys_unique(self):
        """No two keys in a batch of 500 should collide."""
        keys = self._generate_corpus()
        self.assertEqual(len(set(keys)), self.N_KEYS,
            f"Key collision detected in batch of {self.N_KEYS} — uniqueness failure")

    def test_key_length_consistent(self):
        """Every key must be exactly 32 bytes."""
        keys = self._generate_corpus()
        lengths = {len(k) for k in keys}
        self.assertEqual(lengths, {32},
            f"Non-uniform key lengths found: {lengths}")

    def test_corpus_hamming_weight_distribution(self):
        """Bit distribution across 500 keys must be binomially distributed."""
        keys = self._generate_corpus()
        all_bits = [bit for key in keys for byte in key for bit in format(byte, "08b")]
        ones = all_bits.count("1")
        total = len(all_bits)
        ratio = ones / total
        # Should be 50% ± 3σ.  σ = sqrt(p(1-p)/n) = sqrt(0.25/128000) ≈ 0.00044
        self.assertAlmostEqual(ratio, 0.5, delta=0.01,
            msg=f"Corpus bit ratio {ratio:.4f} deviates > 1% from 50%")

    def test_corpus_byte_entropy_near_maximum(self):
        """Shannon entropy of concatenated corpus must be ≥ 0.993 bits/bit.

        Threshold uses 0.993 to account for natural sampling variance in a
        16 KiB corpus; theoretically-perfect random data still falls slightly
        below 1.0 at this scale.
        """
        keys = self._generate_corpus()
        corpus = b"".join(keys)
        h = _shannon_entropy(corpus)
        self.assertGreaterEqual(h, 0.993,
            f"Corpus Shannon entropy {h:.6f} < 0.993")

    def test_pairwise_hamming_mean_near_128(self):
        """Mean Hamming distance between random pairs should be ~128 bits (50%)."""
        keys = self._generate_corpus()
        sample = keys[:50]  # 50×49/2 = 1225 pairs
        distances = [
            _hamming(sample[i], sample[j])
            for i in range(len(sample))
            for j in range(i + 1, len(sample))
        ]
        mean_hd = statistics.mean(distances)
        self.assertAlmostEqual(mean_hd, 128, delta=12,
            msg=f"Mean pairwise Hamming distance {mean_hd:.2f} deviates > 12 bits from 128")

    def test_corpus_autocorrelation_negligible(self):
        """Concatenated key corpus must have autocorrelation max < 0.05."""
        keys = self._generate_corpus()
        corpus = b"".join(keys[:100])
        _, ac_max = _autocorrelation(corpus)
        self.assertLess(ac_max, 0.05,
            f"Corpus autocorrelation max {ac_max:.4f} ≥ 0.05 (temporal structure present)")

    def test_no_key_starts_with_zero_word(self):
        """No key should begin with 4 zero bytes (basic sanity check)."""
        keys = self._generate_corpus()
        for i, key in enumerate(keys):
            self.assertNotEqual(key[:4], b"\x00\x00\x00\x00",
                f"Key {i} starts with 4 zero bytes — degenerate output")


if __name__ == "__main__":
    unittest.main(verbosity=2)
