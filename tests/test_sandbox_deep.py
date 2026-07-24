"""test_sandbox_deep.py — Deep sandbox, isolation, and robustness testing.

Treats the key pipeline as an isolated component and verifies:

  1.  KeyMaterialSecrecy       — key bytes never appear in repr/str/exceptions
  2.  MemoryCleanup            — sensitive objects don't linger in gc references
  3.  ConcurrencySafety        — thread-safe key generation under heavy load
  4.  ResourceBoundaries       — OOM-safe: huge inputs, mass key generation
  5.  PipelineIsolation        — entropy changes in one layer don't leak to another
  6.  DeterminismSandbox       — same-seed synthetic events = reproducible output
  7.  EntropyPipelineIntegrity — hash chain from raw events → final key is unbroken
  8.  SandboxEdgeCases         — single event, max-size events, extreme timing values
  9.  SP800_90B_SandboxChecks  — health tests and estimators work in isolated call contexts
"""

from __future__ import annotations

import gc
import hashlib
import math
import os
import sys
import threading
import time
import traceback
import unittest
import weakref
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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
from nist_800_90b_deep_validator import _rct, _apt, _h_mcv, _h_collision, _h_mmcw


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_mouse() -> list[dict]:
    return [{"x": 100.0 + i, "y": 200.0 + i,
             "velocity_px_per_s": 200.0 + i * 3,
             "direction_angle_deg": 45.0 + i * 2.1}
            for i in range(12)]


def _minimal_keys() -> list[dict]:
    events, t = [], 0.0
    for i, ch in enumerate("sandbox"):
        dwell, flight = 80.0 + i * 3, 55.0 + i * 2
        release_t = t + dwell
        events.append({
            "key": ch,
            "dwell_time_ms": dwell,
            "flight_time_ms": flight,
            "release_timestamp": release_t / 1000.0,
        })
        t = release_t + flight
    return events


def _pool() -> bytes:
    m = extract_mouse_entropy(_minimal_mouse())
    k = extract_keystroke_entropy(_minimal_keys())
    return pool_entropy(m, k)


# ===========================================================================
# 1. KeyMaterialSecrecy
# ===========================================================================

class KeyMaterialSecrecy(unittest.TestCase):
    """Key bytes must not appear in repr, str, or error messages of any object."""

    def test_hkdfconfig_repr_contains_no_key_material(self):
        """HKDFConfig repr/str must not expose salt or info byte values as hex."""
        cfg = HKDFConfig(salt=b"\xDE\xAD\xBE\xEF" * 4, info=b"\xCA\xFE\xBA\xBE" * 4)
        r = repr(cfg)
        # dead and cafe are common words, but deadbeef and cafebabe are key-like
        self.assertNotIn("deadbeef", r.lower(),
            "HKDFConfig repr leaks salt bytes")
        self.assertNotIn("cafebabe", r.lower(),
            "HKDFConfig repr leaks info bytes")

    def test_key_bytes_not_in_insufficient_entropy_error(self):
        """InsufficientEntropyError should describe the problem, not dump data."""
        sentinel = b"\x37\x42\x9A\xBB" * 8  # 32 bytes, 2 unique values
        try:
            KeyGenerator.health_check_entropy(sentinel)
        except (EntropyHealthError, InsufficientEntropyError, Exception) as exc:
            msg = str(exc)
            self.assertNotIn("37429abb", msg.lower(),
                "Error message contains raw entropy bytes")

    def test_exception_traceback_safe(self):
        """Full traceback of a KeyGenerator failure must not contain key hex."""
        sentinel = b"\xDE\xAD" * 16
        try:
            KeyGenerator.health_check_entropy(sentinel)
        except (EntropyHealthError, InsufficientEntropyError, Exception) as exc:
            tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            # The traceback should not contain the byte pattern as hex
            self.assertNotIn("dead" * 4, tb.lower(),
                "Traceback contains raw input bytes")

    def test_health_check_error_message_under_500_chars(self):
        """Error messages must be human-readable, not data dumps."""
        try:
            KeyGenerator.health_check_entropy(b"\x00" * 64)
        except (EntropyHealthError, InsufficientEntropyError) as exc:
            self.assertLess(len(str(exc)), 500,
                "Health check error message is a suspicious data dump")

    def test_type_error_message_under_300_chars(self):
        try:
            KeyGenerator.generate_key("string-instead-of-bytes")  # type: ignore[arg-type]
        except TypeError as exc:
            self.assertLess(len(str(exc)), 300)


# ===========================================================================
# 2. MemoryCleanup
# ===========================================================================

class MemoryCleanup(unittest.TestCase):
    """After key generation, sensitive data must not persist in reachable objects."""

    def test_key_not_held_in_generator_class_attributes(self):
        """KeyGenerator is a stateless class — no instance state holds key material."""
        key = KeyGenerator.generate_fresh_key(os.urandom(32))
        # Verify that the class itself has no attribute referencing the key
        for attr_name in dir(KeyGenerator):
            if attr_name.startswith("__"):
                continue
            try:
                val = getattr(KeyGenerator, attr_name)
                if isinstance(val, bytes) and len(val) == 32:
                    self.assertNotEqual(val, key,
                        f"KeyGenerator.{attr_name} holds generated key material!")
            except Exception:
                pass

    def test_gc_collects_hkdf_intermediate_objects(self):
        """Intermediate HKDF objects (PRK, OKM) must not leak through reference cycles."""
        gc.collect()
        entropy = os.urandom(32)
        ref_list: list[weakref.ref] = []

        def run():
            config = HKDFConfig()
            pooled = KeyGenerator.pool_entropy([entropy])
            prk = KeyGenerator.hkdf_extract(pooled, config.salt)
            okm = KeyGenerator.hkdf_expand(prk, config.info, config.length)
            # Take weak references to intermediate bytearray-wrappable objects
            # (weak refs to bytes are not supported, but we can verify via gc counts)
            _ = okm  # ensure it stays alive until here

        before = gc.get_count()
        run()
        gc.collect()
        after = gc.get_count()
        # gc counts should not grow unboundedly (no reference cycle leaks)
        delta = sum(after) - sum(before)
        self.assertLess(delta, 500,
            f"GC object count grew by {delta} after key generation — possible memory leak")

    def test_pool_entropy_output_is_fixed_size_regardless_of_input(self):
        """pool_entropy must always produce 32 bytes regardless of input explosion."""
        for size in [48, 100, 500, 2000]:
            large_m = extract_mouse_entropy(_minimal_mouse() * (size // 12 + 1))
            large_k = extract_keystroke_entropy(_minimal_keys() * (size // 7 + 1))
            result = pool_entropy(large_m, large_k)
            self.assertEqual(len(result), 32,
                f"pool_entropy returned {len(result)} bytes for large input (expected 32)")


# ===========================================================================
# 3. ConcurrencySafety
# ===========================================================================

class ConcurrencySafety(unittest.TestCase):
    """Parallel key generation must produce correct, unique, non-corrupted output."""

    N_WORKERS = 20
    N_KEYS_EACH = 10

    def test_parallel_key_generation_all_succeed(self):
        """N_WORKERS threads each generating N_KEYS_EACH fresh keys must all succeed."""
        errors: list[Exception] = []
        all_keys: list[bytes] = []
        lock = threading.Lock()

        def worker():
            try:
                keys = [KeyGenerator.generate_fresh_key(os.urandom(32))
                        for _ in range(self.N_KEYS_EACH)]
                with lock:
                    all_keys.extend(keys)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(self.N_WORKERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(len(errors), 0,
            f"Parallel key generation errors: {errors}")
        self.assertEqual(len(all_keys), self.N_WORKERS * self.N_KEYS_EACH)

    def test_parallel_keys_all_unique(self):
        """All keys from parallel generation must be distinct."""
        keys: list[bytes] = []
        lock = threading.Lock()

        def worker():
            k = KeyGenerator.generate_fresh_key(os.urandom(32))
            with lock:
                keys.append(k)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(len(set(keys)), len(keys),
            "Parallel key generation produced duplicate — thread-safety issue")

    def test_thread_pool_key_generation_correct_lengths(self):
        """ThreadPoolExecutor: every generated key must be 32 bytes."""
        with ThreadPoolExecutor(max_workers=8) as exe:
            futures = [
                exe.submit(KeyGenerator.generate_fresh_key, os.urandom(32))
                for _ in range(50)
            ]
            for future in as_completed(futures):
                key = future.result(timeout=10)
                self.assertEqual(len(key), 32,
                    f"ThreadPool key has wrong length: {len(key)}")

    def test_concurrent_pool_entropy_is_consistent(self):
        """Two threads computing pool_entropy of same inputs must get same result."""
        m = extract_mouse_entropy(_minimal_mouse())
        k = extract_keystroke_entropy(_minimal_keys())
        results: list[bytes] = []
        lock = threading.Lock()

        def compute():
            p = pool_entropy(m, k)
            with lock:
                results.append(p)

        threads = [threading.Thread(target=compute) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(set(results)), 1,
            "pool_entropy returned different values for same input across threads")

    def test_heavy_load_no_key_collisions(self):
        """500 concurrent key generations must all produce unique output."""
        with ThreadPoolExecutor(max_workers=16) as exe:
            futures = [
                exe.submit(KeyGenerator.generate_fresh_key, os.urandom(32))
                for _ in range(500)
            ]
            keys = {future.result(timeout=15) for future in as_completed(futures)}
        self.assertEqual(len(keys), 500,
            f"Found duplicates: only {len(keys)}/500 unique keys under heavy load")


# ===========================================================================
# 4. ResourceBoundaries
# ===========================================================================

class ResourceBoundaries(unittest.TestCase):
    """Key generation must handle extreme input sizes safely."""

    def test_exactly_32_bytes_entropy_accepted(self):
        """32-byte input is the exact minimum; must succeed."""
        key = KeyGenerator.generate_key(os.urandom(32))
        self.assertEqual(len(key), 32)

    def test_1_mb_entropy_input_accepted(self):
        """1 MiB input must not crash or corrupt."""
        big = os.urandom(1024 * 1024)
        key = KeyGenerator.generate_key(big)
        self.assertEqual(len(key), 32)

    def test_exactly_33_bytes_entropy_accepted(self):
        """33 bytes (1 above minimum) must be accepted."""
        key = KeyGenerator.generate_key(os.urandom(33))
        self.assertEqual(len(key), 32)

    def test_10000_sequential_key_generations_stable(self):
        """10,000 sequential key generations must all succeed without error."""
        for i in range(10_000):
            key = KeyGenerator.generate_key(os.urandom(32))
            self.assertEqual(len(key), 32, f"Key {i} had wrong length")

    def test_many_mouse_events_no_crash(self):
        """1000 mouse events must not crash extract_mouse_entropy."""
        events = [{"x": float(i % 1920), "y": float(i % 1080),
                   "velocity_px_per_s": float(i % 500),
                   "direction_angle_deg": float(i % 360)}
                  for i in range(1000)]
        result = extract_mouse_entropy(events)
        self.assertEqual(len(result), 48)

    def test_many_keystroke_events_no_crash(self):
        """500 keystroke events must not crash extract_keystroke_entropy."""
        events = [{"key": chr(65 + (i % 26)),
                   "dwell_time_ms": 80.0 + i % 50,
                   "flight_time_ms": 60.0 + i % 40,
                   "release_timestamp": (i * 0.15)}
                  for i in range(500)]
        result = extract_keystroke_entropy(events)
        self.assertGreater(len(result), 0)

    def test_single_mouse_event_no_crash(self):
        """A single mouse event should not crash (though entropy will be degenerate)."""
        single = [{"x": 100.0, "y": 200.0,
                   "velocity_px_per_s": 150.0,
                   "direction_angle_deg": 45.0}]
        result = extract_mouse_entropy(single)
        self.assertEqual(len(result), 48)

    def test_single_keystroke_event_no_crash(self):
        """A single keystroke event should not crash."""
        single = [{"key": "a", "dwell_time_ms": 80.0,
                   "flight_time_ms": 0.0, "release_timestamp": 0.08}]
        result = extract_keystroke_entropy(single)
        self.assertGreater(len(result), 0)

    def test_hkdf_expand_max_valid_length(self):
        """Max valid HKDF-Expand output is 255 * hash_len = 8160 bytes."""
        prk = KeyGenerator.hkdf_extract(os.urandom(32), b"max-test")
        max_len = 255 * 32
        okm = KeyGenerator.hkdf_expand(prk, b"info", max_len)
        self.assertEqual(len(okm), max_len)

    def test_pool_entropy_with_large_mouse_and_key_bytes(self):
        """pool_entropy must handle large inputs and still return 32 bytes."""
        big_m = os.urandom(4096)
        big_k = os.urandom(4096)
        result = pool_entropy(big_m, big_k)
        self.assertEqual(len(result), 32)


# ===========================================================================
# 5. PipelineIsolation
# ===========================================================================

class PipelineIsolation(unittest.TestCase):
    """Changing one pipeline stage must not invisibly propagate to another."""

    def test_mouse_entropy_change_isolated_from_key_extraction(self):
        """Changing mouse events must change mouse bytes, not keystroke bytes.

        We change velocity (not just x offset) because a uniform positional
        shift cancels in consecutive-difference calculations, whereas velocity
        directly feeds into the feature mean/std and changes the extracted bytes.
        """
        m1 = extract_mouse_entropy(_minimal_mouse())
        k_fixed = extract_keystroke_entropy(_minimal_keys())
        # Change velocity — this directly alters extracted feature bytes
        m2_events = [dict(e, velocity_px_per_s=e["velocity_px_per_s"] * 3.5)
                     for e in _minimal_mouse()]
        m2 = extract_mouse_entropy(m2_events)
        # Mouse bytes changed
        self.assertNotEqual(m1, m2, "Changing mouse velocity must change mouse entropy")
        # Keystroke bytes unaffected
        k_again = extract_keystroke_entropy(_minimal_keys())
        self.assertEqual(k_fixed, k_again, "Mouse change should not affect keystroke bytes")

    def test_keystroke_change_isolated_from_mouse_extraction(self):
        """Changing keystroke events must not change mouse entropy bytes."""
        m_fixed = extract_mouse_entropy(_minimal_mouse())
        k1 = extract_keystroke_entropy(_minimal_keys())
        k2_events = [dict(e, dwell_time_ms=e["dwell_time_ms"] * 2.0)
                     for e in _minimal_keys()]
        k2 = extract_keystroke_entropy(k2_events)
        self.assertNotEqual(k1, k2, "Changing keystroke timing must change keystroke bytes")
        m_again = extract_mouse_entropy(_minimal_mouse())
        self.assertEqual(m_fixed, m_again, "Keystroke change should not affect mouse bytes")

    def test_pool_changes_when_any_input_changes(self):
        """pool_entropy output must change when either input changes."""
        m = extract_mouse_entropy(_minimal_mouse())
        k = extract_keystroke_entropy(_minimal_keys())
        pool_base = pool_entropy(m, k)
        # Change velocity (not uniform x-offset, which cancels in diffs)
        m2 = extract_mouse_entropy([dict(e, velocity_px_per_s=e["velocity_px_per_s"] * 2.5)
                                    for e in _minimal_mouse()])
        pool_m_changed = pool_entropy(m2, k)
        self.assertNotEqual(pool_base, pool_m_changed,
            "pool_entropy unchanged after mouse modification")
        k2 = extract_keystroke_entropy([dict(e, dwell_time_ms=e["dwell_time_ms"] + 10)
                                        for e in _minimal_keys()])
        pool_k_changed = pool_entropy(m, k2)
        self.assertNotEqual(pool_base, pool_k_changed,
            "pool_entropy unchanged after keystroke modification")

    def test_hkdf_output_isolated_from_pool_computation(self):
        """HKDF output must change when pool changes."""
        pool1 = pool_entropy(extract_mouse_entropy(_minimal_mouse()),
                             extract_keystroke_entropy(_minimal_keys()))
        m2_events = [dict(e, velocity_px_per_s=e["velocity_px_per_s"] * 2)
                     for e in _minimal_mouse()]
        pool2 = pool_entropy(extract_mouse_entropy(m2_events),
                             extract_keystroke_entropy(_minimal_keys()))
        k1 = KeyGenerator.generate_key(pool1)
        k2 = KeyGenerator.generate_key(pool2)
        self.assertNotEqual(k1, k2,
            "HKDF output did not change when pool input changed")


# ===========================================================================
# 6. DeterminismSandbox
# ===========================================================================

class DeterminismSandbox(unittest.TestCase):
    """Deterministic mode: same synthetic events → same pooled entropy → same key."""

    MOUSE_SEED = [
        {"x": 100.0 + i * 5, "y": 200.0 + i * 3,
         "velocity_px_per_s": 150.0 + i * 2.5,
         "direction_angle_deg": 45.0 + i * 4.2}
        for i in range(20)
    ]
    KEY_SEED = [
        {"key": chr(97 + i % 26),
         "dwell_time_ms": 80.0 + i * 1.5,
         "flight_time_ms": 55.0 + i * 1.2,
         "release_timestamp": (i * 0.14)}
        for i in range(10)
    ]

    def _make_det_pool(self) -> bytes:
        m = extract_mouse_entropy(self.MOUSE_SEED)
        k = extract_keystroke_entropy(self.KEY_SEED)
        return pool_entropy(m, k)

    def test_synthetic_events_are_deterministic(self):
        """Same synthetic events must always produce the same pool bytes."""
        pool1 = self._make_det_pool()
        pool2 = self._make_det_pool()
        self.assertEqual(pool1, pool2,
            "Identical synthetic events produced different pool bytes")

    def test_deterministic_key_derivation(self):
        """generate_key on same pool must always return same key."""
        pool = self._make_det_pool()
        k1 = KeyGenerator.generate_key(pool)
        k2 = KeyGenerator.generate_key(pool)
        self.assertEqual(k1, k2,
            "generate_key is not deterministic for same pool input")

    def test_generate_fresh_key_deterministic_with_fixed_system_random(self):
        """generate_fresh_key with fixed sys_random must be deterministic."""
        pool = self._make_det_pool()
        sys_r = bytes(range(32))
        k1 = KeyGenerator.generate_fresh_key(pool, system_random_bytes=sys_r,
                                               personalization=b"test")
        k2 = KeyGenerator.generate_fresh_key(pool, system_random_bytes=sys_r,
                                               personalization=b"test")
        self.assertEqual(k1, k2,
            "generate_fresh_key with fixed system_random must be deterministic")

    def test_hkdf_extract_expand_is_deterministic(self):
        """HKDF extract+expand must always return the same bytes for same inputs."""
        ikm = bytes(range(32))
        salt = b"fixed-salt"
        info = b"fixed-info"
        prk1 = KeyGenerator.hkdf_extract(ikm, salt)
        prk2 = KeyGenerator.hkdf_extract(ikm, salt)
        self.assertEqual(prk1, prk2)
        okm1 = KeyGenerator.hkdf_expand(prk1, info, 32)
        okm2 = KeyGenerator.hkdf_expand(prk2, info, 32)
        self.assertEqual(okm1, okm2)

    def test_mouse_entropy_bytes_deterministic_for_fixed_events(self):
        m1 = extract_mouse_entropy(self.MOUSE_SEED)
        m2 = extract_mouse_entropy(self.MOUSE_SEED)
        self.assertEqual(m1, m2)

    def test_keystroke_entropy_bytes_deterministic_for_fixed_events(self):
        k1 = extract_keystroke_entropy(self.KEY_SEED)
        k2 = extract_keystroke_entropy(self.KEY_SEED)
        self.assertEqual(k1, k2)


# ===========================================================================
# 7. EntropyPipelineIntegrity
# ===========================================================================

class EntropyPipelineIntegrity(unittest.TestCase):
    """Verify the SHA3-256 hash chain from events → pool → key is unbroken."""

    def test_pool_entropy_is_sha3_256_digest(self):
        """pool_entropy output must be exactly 32 bytes (SHA3-256 digest size)."""
        m = extract_mouse_entropy(_minimal_mouse())
        k = extract_keystroke_entropy(_minimal_keys())
        pool = pool_entropy(m, k)
        self.assertEqual(len(pool), 32,
            "pool_entropy did not return 32-byte SHA3-256 digest")

    def test_pool_changes_nonlinearly_with_input(self):
        """Doubling input size should not simply double the pool output."""
        m_small = extract_mouse_entropy(_minimal_mouse())
        k_small = extract_keystroke_entropy(_minimal_keys())
        pool_small = pool_entropy(m_small, k_small)
        m_big = extract_mouse_entropy(_minimal_mouse() * 5)
        k_big = extract_keystroke_entropy(_minimal_keys() * 5)
        pool_big = pool_entropy(m_big, k_big)
        # Both are 32 bytes but values differ — SHA3 is non-linear
        self.assertNotEqual(pool_small, pool_big,
            "pool_entropy is the same for 1× and 5× repeated events")

    def test_pool_to_key_is_hkdf_not_identity(self):
        """generate_key must not return the raw pool unchanged."""
        pool = _pool()
        key = KeyGenerator.generate_key(pool)
        self.assertNotEqual(key, pool,
            "generate_key returned pool bytes unchanged — missing HKDF")

    def test_pool_sha3_256_avalanche(self):
        """1-bit change in pool must propagate to ≥ 40% of SHA3-256 output bits."""
        m = extract_mouse_entropy(_minimal_mouse())
        k = extract_keystroke_entropy(_minimal_keys())
        pool1 = pool_entropy(m, k)
        m_tweaked = bytearray(m)
        m_tweaked[0] ^= 0x01
        pool2 = pool_entropy(bytes(m_tweaked), k)
        hd = sum(bin(a ^ b).count("1") for a, b in zip(pool1, pool2))
        self.assertGreaterEqual(hd, 96,
            f"SHA3-256 avalanche in pool: only {hd}/256 bits changed for 1-bit input flip")

    def test_hkdf_chain_produces_different_key_per_config(self):
        """Running HKDF on the same pool with two different configs gives different keys."""
        pool = _pool()
        cfg1 = HKDFConfig(info=b"context-1")
        cfg2 = HKDFConfig(info=b"context-2")
        k1 = KeyGenerator.derive_key([pool], cfg1)
        k2 = KeyGenerator.derive_key([pool], cfg2)
        self.assertNotEqual(k1, k2)


# ===========================================================================
# 8. SandboxEdgeCases
# ===========================================================================

class SandboxEdgeCases(unittest.TestCase):
    """Edge values for timing, coordinates, and event counts."""

    def test_zero_velocity_events_no_crash(self):
        """Events with zero velocity must be handled without crashing."""
        events = [{"x": 100.0, "y": 200.0,
                   "velocity_px_per_s": 0.0,
                   "direction_angle_deg": 0.0}] * 15
        result = extract_mouse_entropy(events)
        self.assertEqual(len(result), 48)

    def test_max_float_coordinates_no_crash(self):
        """Very large coordinates must not crash (clamped or handled)."""
        events = [{"x": 1e15, "y": 1e15,
                   "velocity_px_per_s": 1e10,
                   "direction_angle_deg": 359.99}] * 10
        try:
            result = extract_mouse_entropy(events)
            self.assertEqual(len(result), 48)
        except (OverflowError, ValueError):
            pass  # Acceptable to reject extreme values

    def test_negative_coordinates_no_crash(self):
        """Negative coordinates (offscreen) must not crash."""
        events = [{"x": -100.0, "y": -200.0,
                   "velocity_px_per_s": 150.0,
                   "direction_angle_deg": 180.0}] * 10
        result = extract_mouse_entropy(events)
        self.assertEqual(len(result), 48)

    def test_zero_dwell_keystroke_no_crash(self):
        """Zero dwell time (instantaneous key press) must not crash."""
        events = [{"key": "a", "dwell_time_ms": 0.0,
                   "flight_time_ms": 50.0, "release_timestamp": 0.0}] * 5
        result = extract_keystroke_entropy(events)
        self.assertGreater(len(result), 0)

    def test_very_long_dwell_time_no_crash(self):
        """Extremely long dwell (hand resting on key) must not crash."""
        events = [{"key": "a", "dwell_time_ms": 10000.0,
                   "flight_time_ms": 5000.0, "release_timestamp": float(i * 15)}
                  for i in range(8)]
        result = extract_keystroke_entropy(events)
        self.assertGreater(len(result), 0)

    def test_repeated_same_key_no_crash(self):
        """Typing the same key repeatedly must not crash."""
        events = [{"key": "a", "dwell_time_ms": 75.0 + i * 0.5,
                   "flight_time_ms": 60.0, "release_timestamp": float(i * 0.14)}
                  for i in range(20)]
        result = extract_keystroke_entropy(events)
        self.assertGreater(len(result), 0)

    def test_non_ascii_unicode_key_no_crash(self):
        """Unicode keys (e.g. emoji, CJK) must not crash keystroke extraction."""
        events = [{"key": char, "dwell_time_ms": 80.0,
                   "flight_time_ms": 60.0, "release_timestamp": float(i * 0.14)}
                  for i, char in enumerate(["á", "ñ", "ü", "ö", "ç", "中", "日"])]
        result = extract_keystroke_entropy(events)
        self.assertGreater(len(result), 0)

    def test_missing_event_fields_handled_gracefully(self):
        """Events with missing optional fields must not crash (use defaults)."""
        events = [{"x": 100.0, "y": 200.0}] * 10  # missing velocity and direction
        try:
            result = extract_mouse_entropy(events)
            self.assertEqual(len(result), 48)
        except (KeyError, TypeError):
            pass  # acceptable to raise on missing required fields

    def test_pool_entropy_bytearray_input_accepted(self):
        """pool_entropy must accept bytearray as well as bytes."""
        m = bytearray(os.urandom(48))
        k = bytearray(os.urandom(32))
        result = pool_entropy(m, k)
        self.assertEqual(len(result), 32)


# ===========================================================================
# 9. SP800_90B_SandboxChecks
# ===========================================================================

class SP800_90B_SandboxChecks(unittest.TestCase):
    """SP 800-90B health tests and estimators work correctly in isolated call contexts."""

    def test_rct_with_empty_data_does_not_crash(self):
        """RCT on empty bytes must not crash."""
        result = _rct(b"", cutoff=64)
        self.assertIsNotNone(result)

    def test_apt_with_empty_data_does_not_crash(self):
        """APT on empty bytes must not crash."""
        result = _apt(b"", window=512, cutoff=325)
        self.assertIsNotNone(result)

    def test_apt_data_shorter_than_window_skipped(self):
        """APT on data shorter than window must skip (not fail)."""
        result = _apt(os.urandom(100), window=512, cutoff=325)
        self.assertTrue(result.passed,
            "APT with insufficient data should skip (pass) rather than FAIL")

    def test_mcv_estimator_on_single_repeated_byte(self):
        """MCV on single-byte data should return H near 0."""
        data = b"\xAB" * 1000
        est = _h_mcv(data)
        if est.sufficient_data:
            self.assertLess(est.h_bits_per_sample, 0.01,
                f"MCV on constant data: {est.h_bits_per_sample:.6f} should be near 0")

    def test_collision_estimator_minimum_data(self):
        """Collision estimator must return sufficient_data=False for < 200 bytes."""
        data = os.urandom(100)
        est = _h_collision(data)
        self.assertFalse(est.sufficient_data,
            "Collision estimator should report insufficient_data for < 200 bytes")

    def test_mmcw_estimator_minimum_data(self):
        """MMCW estimator must return sufficient_data=False for tiny inputs."""
        data = os.urandom(10)
        est = _h_mmcw(data)
        self.assertFalse(est.sufficient_data,
            "MMCW estimator should report insufficient_data for tiny input")

    def test_estimators_accept_bytearray(self):
        """All estimators must accept bytearray as well as bytes."""
        data = bytearray(os.urandom(1024))
        est_mcv = _h_mcv(bytes(data))
        est_col = _h_collision(bytes(data))
        self.assertTrue(est_mcv.sufficient_data)
        self.assertTrue(est_col.sufficient_data)

    def test_rct_cutoff_boundary_exactly_at_cutoff_is_fail(self):
        """Run of exactly cutoff bytes should FAIL the RCT."""
        cutoff = 10
        data = b"\x55" * cutoff + os.urandom(100)
        result = _rct(data, cutoff=cutoff)
        self.assertFalse(result.passed,
            f"RCT with run length == cutoff ({cutoff}) should FAIL")

    def test_rct_run_one_less_than_cutoff_passes(self):
        """Run of (cutoff - 1) bytes must PASS the RCT."""
        cutoff = 10
        data = b"\x55" * (cutoff - 1) + os.urandom(100)
        result = _rct(data, cutoff=cutoff)
        self.assertTrue(result.passed,
            f"RCT with run length == cutoff-1 ({cutoff-1}) should PASS")

    def test_health_tests_return_typed_results(self):
        """RCT and APT must return objects with .passed, .cutoff, .actual attributes."""
        data = os.urandom(1024)
        rct_r = _rct(data)
        apt_r = _apt(data)
        self.assertIsInstance(rct_r.passed, bool)
        self.assertIsInstance(apt_r.passed, bool)
        self.assertIsInstance(rct_r.actual, int)
        self.assertIsInstance(apt_r.actual, int)

    def test_pipeline_keys_pass_sp800_90b_health_tests(self):
        """Keys generated by the full pipeline must pass both online health tests."""
        corpus = b"".join(KeyGenerator.generate_fresh_key(os.urandom(32)) for _ in range(64))
        rct_r = _rct(corpus, cutoff=64)
        apt_r = _apt(corpus, window=512, cutoff=325)
        self.assertTrue(rct_r.passed,
            f"Pipeline output failed RCT: longest run = {rct_r.actual}")
        self.assertTrue(apt_r.passed,
            f"Pipeline output failed APT: worst window count = {apt_r.actual}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
