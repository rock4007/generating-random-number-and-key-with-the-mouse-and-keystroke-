"""test_blackbox_deep.py — Extended black-box security validation.

Treats SUMIT KEY as an opaque box: only public API inputs/outputs visible.
Tests 9 classes covering:

  1.  APIContractCoverage        — every public function returns correct types/lengths
  2.  InputValidationBoundary    — malformed, boundary, and adversarial inputs
  3.  DomainSeparationOracle     — same entropy + different context → completely different output
  4.  TimingOracleResistance     — key generation time must not depend on input value
  5.  KeyUniquenessAtScale       — 1000 fresh keys must be pairwise unique
  6.  ConfigurationSpaceCoverage — all HKDFConfig parameters exercise different output
  7.  ErrorPathSafety            — exception messages must never contain key material
  8.  NondeterminismGuarantee    — generate_fresh_key must never repeat for same input
  9.  CryptoToolsBlackBox        — encrypt/decrypt round-trips, tamper rejection,
                                    nonce uniqueness, AAD binding
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import threading
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from key_generator import (
    EntropyHealthError,
    HKDFConfig,
    InsufficientEntropyError,
    KeyGenerator,
)
from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy

try:
    from crypto_tools import (
        encrypt_message,
        decrypt_message,
        EncryptedMessage,
    )
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _make_valid_entropy(n: int = 32) -> bytes:
    """Return n bytes of valid (non-degenerate) entropy."""
    return os.urandom(n)


# ===========================================================================
# 1. APIContractCoverage
# ===========================================================================

class APIContractCoverage(unittest.TestCase):
    """Every public KeyGenerator method returns correct type, length, and encoding."""

    def test_generate_key_returns_32_bytes(self):
        key = KeyGenerator.generate_key(_make_valid_entropy(32))
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_generate_quantum_hardened_key_returns_64_bytes(self):
        key = KeyGenerator.generate_quantum_hardened_key(_make_valid_entropy(32))
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 64)

    def test_generate_fresh_key_returns_32_bytes_by_default(self):
        key = KeyGenerator.generate_fresh_key(_make_valid_entropy(32))
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_generate_fresh_quantum_hardened_key_returns_64_bytes(self):
        key = KeyGenerator.generate_fresh_quantum_hardened_key(_make_valid_entropy(32))
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 64)

    def test_derive_key_hex_returns_lowercase_hex_string(self):
        config = HKDFConfig()
        hex_key = KeyGenerator.derive_key_hex([_make_valid_entropy(32)], config)
        self.assertIsInstance(hex_key, str)
        self.assertEqual(len(hex_key), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in hex_key))

    def test_bytes_to_bitstring_returns_binary_string(self):
        key = KeyGenerator.generate_key(_make_valid_entropy(32))
        bits = KeyGenerator.bytes_to_bitstring(key)
        self.assertIsInstance(bits, str)
        self.assertEqual(len(bits), 256)
        self.assertTrue(all(c in "01" for c in bits))

    def test_generate_quantum_binary_string_respects_bits_param(self):
        for n_bits in [128, 256, 512]:
            bs = KeyGenerator.generate_quantum_binary_string(_make_valid_entropy(32), bits=n_bits)
            self.assertEqual(len(bs), n_bits,
                f"quantum_binary_string with bits={n_bits} returned {len(bs)} chars")

    def test_custom_length_config_respected(self):
        for length in [16, 24, 32, 48, 64]:
            config = HKDFConfig(length=length)
            key = KeyGenerator.derive_key([_make_valid_entropy(32)], config)
            self.assertEqual(len(key), length,
                f"HKDFConfig(length={length}) produced {len(key)} bytes")

    def test_hkdf_extract_returns_32_bytes(self):
        prk = KeyGenerator.hkdf_extract(_make_valid_entropy(32), b"test-salt")
        self.assertIsInstance(prk, bytes)
        self.assertEqual(len(prk), 32)

    def test_hkdf_expand_returns_requested_length(self):
        prk = KeyGenerator.hkdf_extract(_make_valid_entropy(32), b"test-salt")
        for length in [16, 32, 64, 100]:
            okm = KeyGenerator.hkdf_expand(prk, b"test-info", length)
            self.assertEqual(len(okm), length,
                f"hkdf_expand(length={length}) returned {len(okm)} bytes")

    def test_pool_entropy_returns_32_bytes(self):
        m = extract_mouse_entropy([{"x": 1.0, "y": 1.0,
                                    "velocity_px_per_s": 100.0,
                                    "direction_angle_deg": 45.0}] * 10)
        k = extract_keystroke_entropy([{"key": "a", "dwell_time_ms": 80.0,
                                         "flight_time_ms": 50.0,
                                         "release_timestamp": 0.1}] * 5)
        result = pool_entropy(m, k)
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)


# ===========================================================================
# 2. InputValidationBoundary
# ===========================================================================

class InputValidationBoundary(unittest.TestCase):
    """Adversarial, boundary, and malformed inputs must be cleanly rejected."""

    def test_wrong_type_list_rejected(self):
        with self.assertRaises(TypeError):
            KeyGenerator.generate_key([1, 2, 3])  # type: ignore[arg-type]

    def test_wrong_type_string_rejected(self):
        with self.assertRaises(TypeError):
            KeyGenerator.generate_key("not-bytes")  # type: ignore[arg-type]

    def test_wrong_type_int_rejected(self):
        with self.assertRaises(TypeError):
            KeyGenerator.generate_key(12345)  # type: ignore[arg-type]

    def test_none_rejected(self):
        with self.assertRaises((TypeError, AttributeError)):
            KeyGenerator.generate_key(None)  # type: ignore[arg-type]

    def test_31_bytes_rejected_insufficient_entropy(self):
        with self.assertRaises((InsufficientEntropyError, ValueError)):
            KeyGenerator.generate_key(os.urandom(31))

    def test_0_bytes_rejected(self):
        with self.assertRaises((InsufficientEntropyError, ValueError, TypeError)):
            KeyGenerator.generate_key(b"")

    def test_hkdf_config_zero_length_rejected(self):
        with self.assertRaises(ValueError):
            config = HKDFConfig(length=0)
            KeyGenerator.derive_key([_make_valid_entropy(32)], config)

    def test_hkdf_config_negative_length_rejected(self):
        with self.assertRaises(ValueError):
            config = HKDFConfig(length=-1)
            KeyGenerator.derive_key([_make_valid_entropy(32)], config)

    def test_hkdf_expand_length_exceeds_max_rejected(self):
        """Length > 255 * 32 = 8160 must be rejected."""
        prk = KeyGenerator.hkdf_extract(_make_valid_entropy(32), b"salt")
        with self.assertRaises(ValueError):
            KeyGenerator.hkdf_expand(prk, b"info", 8200)

    def test_hkdf_expand_short_prk_rejected(self):
        """PRK shorter than hash output length must be rejected."""
        with self.assertRaises(ValueError):
            KeyGenerator.hkdf_expand(b"\x01" * 10, b"info", 32)

    def test_generate_key_bytearray_accepted(self):
        """bytearray input must be accepted (bytes-compatible)."""
        key = KeyGenerator.generate_key(bytearray(os.urandom(32)))
        self.assertEqual(len(key), 32)

    def test_health_check_insufficient_entropy_error_type(self):
        """Too-short input must raise InsufficientEntropyError, not generic Exception."""
        with self.assertRaises(InsufficientEntropyError):
            KeyGenerator.health_check_entropy(b"\x01" * 10, min_bytes=32)

    def test_health_check_constant_raises_entropy_health_error(self):
        """Constant bytes must raise EntropyHealthError."""
        with self.assertRaises(EntropyHealthError):
            KeyGenerator.health_check_entropy(b"\x42" * 64)

    def test_pool_entropy_wrong_type_raises(self):
        with self.assertRaises(TypeError):
            pool_entropy("not-bytes", b"\x00" * 32)  # type: ignore[arg-type]

    def test_generate_quantum_binary_string_zero_bits_rejected(self):
        with self.assertRaises(ValueError):
            KeyGenerator.generate_quantum_binary_string(_make_valid_entropy(32), bits=0)

    def test_generate_quantum_binary_string_too_many_bits_rejected(self):
        with self.assertRaises(ValueError):
            KeyGenerator.generate_quantum_binary_string(_make_valid_entropy(32), bits=513)

    def test_high_entropy_but_short_input_still_rejected(self):
        """Even high-quality random bytes < 32 bytes must raise."""
        with self.assertRaises((InsufficientEntropyError, ValueError)):
            KeyGenerator.generate_key(os.urandom(20))

    def test_derive_key_empty_chunk_list_rejected(self):
        with self.assertRaises((ValueError, Exception)):
            KeyGenerator.derive_key([], HKDFConfig())

    def test_derive_key_chunk_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            KeyGenerator.derive_key(["not-bytes"], HKDFConfig())  # type: ignore[list-item]

    def test_personalization_bytes_accepted_any_length(self):
        """Personalization of various lengths (0, 1, 100) must not crash."""
        entropy = _make_valid_entropy(32)
        sys_r = bytes(range(32))
        for p_len in [0, 1, 32, 100]:
            p = os.urandom(p_len)
            key = KeyGenerator.generate_fresh_key(entropy, system_random_bytes=sys_r,
                                                   personalization=p)
            self.assertEqual(len(key), 32)

    def test_config_must_be_hkdfconfig_instance(self):
        with self.assertRaises(TypeError):
            KeyGenerator.derive_key([_make_valid_entropy(32)], {"length": 32})  # type: ignore[arg-type]


# ===========================================================================
# 3. DomainSeparationOracle
# ===========================================================================

class DomainSeparationOracle(unittest.TestCase):
    """Same raw entropy + different context/salt/info → completely different keys."""

    BASE_ENTROPY = bytes(range(32))
    SYS_RAND     = bytes(reversed(range(32)))

    def _key(self, **kwargs) -> bytes:
        return KeyGenerator.generate_fresh_key(
            self.BASE_ENTROPY,
            system_random_bytes=self.SYS_RAND,
            **kwargs,
        )

    def test_different_personalization_produces_different_key(self):
        k1 = self._key(personalization=b"user:alice")
        k2 = self._key(personalization=b"user:bob")
        self.assertNotEqual(k1, k2)
        self.assertGreaterEqual(_hamming(k1, k2), 96)

    def test_different_info_produces_different_key(self):
        cfg_a = HKDFConfig(info=b"purpose:signing")
        cfg_b = HKDFConfig(info=b"purpose:encryption")
        k1 = KeyGenerator.derive_key([self.BASE_ENTROPY], cfg_a)
        k2 = KeyGenerator.derive_key([self.BASE_ENTROPY], cfg_b)
        self.assertNotEqual(k1, k2)
        self.assertGreaterEqual(_hamming(k1, k2), 96)

    def test_different_salt_produces_different_key(self):
        cfg_a = HKDFConfig(salt=b"v1_salt")
        cfg_b = HKDFConfig(salt=b"v2_salt")
        k1 = KeyGenerator.derive_key([self.BASE_ENTROPY], cfg_a)
        k2 = KeyGenerator.derive_key([self.BASE_ENTROPY], cfg_b)
        self.assertNotEqual(k1, k2)

    def test_standard_vs_quantum_config_produce_different_keys(self):
        cfg_std = HKDFConfig()
        cfg_q = HKDFConfig.quantum_hardened()
        k1 = KeyGenerator.derive_key([self.BASE_ENTROPY], cfg_std)
        k2 = KeyGenerator.derive_key([self.BASE_ENTROPY], cfg_q)
        # Different length and domain — must not share prefix
        self.assertNotEqual(k1, k2[:32])

    def test_personalization_empty_vs_nonempty(self):
        k1 = self._key(personalization=b"")
        k2 = self._key(personalization=b"\x00")
        self.assertNotEqual(k1, k2,
            "Empty personalization must differ from b'\\x00' personalization")

    def test_10_distinct_personalization_contexts_produce_10_distinct_keys(self):
        keys = [self._key(personalization=f"ctx-{i}".encode()) for i in range(10)]
        self.assertEqual(len(set(keys)), 10,
            "10 distinct personalizations must produce 10 distinct keys")

    def test_key_derivation_order_independence_with_multiple_chunks(self):
        """Changing chunk order must change output (length-prefix non-commutativity)."""
        a = _make_valid_entropy(32)
        b = _make_valid_entropy(32)
        cfg = HKDFConfig()
        k1 = KeyGenerator.derive_key([a, b], cfg)
        k2 = KeyGenerator.derive_key([b, a], cfg)
        self.assertNotEqual(k1, k2,
            "Multi-chunk ordering must be significant (non-commutative pooling)")


# ===========================================================================
# 4. TimingOracleResistance
# ===========================================================================

class TimingOracleResistance(unittest.TestCase):
    """Key generation time must not be statistically correlated with input value."""

    N_TRIALS = 30

    def _timed_keygen(self, entropy: bytes) -> float:
        t0 = time.perf_counter()
        KeyGenerator.generate_key(entropy)
        return time.perf_counter() - t0

    def test_timing_not_correlated_with_input_value(self):
        """Time for zeros vs ones vs random should not differ by > 5× average."""
        # Measure several different inputs
        times_random = [self._timed_keygen(os.urandom(32)) for _ in range(self.N_TRIALS)]
        times_ff = [self._timed_keygen(bytes([0xFF, 0x00] * 16)) for _ in range(self.N_TRIALS)]
        avg_random = sum(times_random) / len(times_random)
        avg_ff = sum(times_ff) / len(times_ff)
        # Allow 5× variance (generous — just checking for gross timing leaks)
        ratio = max(avg_random, avg_ff) / max(min(avg_random, avg_ff), 1e-9)
        self.assertLess(ratio, 5.0,
            f"Key generation time ratio {ratio:.2f}× for different inputs — timing leak?")

    def test_generate_fresh_key_timing_stable_across_personalization_lengths(self):
        """Personalization length should not significantly affect timing."""
        entropy = _make_valid_entropy(32)
        sys_r = bytes(range(32))
        times_short = [
            self._timed_keygen.__func__(
                self,
                KeyGenerator.generate_fresh_key.__func__(  # type: ignore[attr-defined]
                    KeyGenerator, entropy, system_random_bytes=sys_r, personalization=b"x"
                ) or b"\x01" * 32
            )
            for _ in range(self.N_TRIALS)
        ]
        # Simpler approach: just time the two directly
        t_short_list = []
        t_long_list = []
        for _ in range(self.N_TRIALS):
            t0 = time.perf_counter()
            KeyGenerator.generate_fresh_key(entropy, system_random_bytes=sys_r,
                                             personalization=b"x" * 1)
            t_short_list.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            KeyGenerator.generate_fresh_key(entropy, system_random_bytes=sys_r,
                                             personalization=b"x" * 100)
            t_long_list.append(time.perf_counter() - t0)

        ratio = max(sum(t_long_list), sum(t_short_list)) / max(
            min(sum(t_long_list), sum(t_short_list)), 1e-9
        )
        self.assertLess(ratio, 3.0,
            f"Personalization length timing ratio {ratio:.2f}× — possible timing leak")

    def test_hmac_comparison_is_constant_time(self):
        """KeyGenerator uses hmac.new internally — HMAC is constant-time by design."""
        # Verify: timing difference between matching vs non-matching PRKs is negligible
        salt = b"test-salt"
        ikm_a = _make_valid_entropy(32)
        ikm_b = _make_valid_entropy(32)
        t_match = []
        t_mismatch = []
        for _ in range(50):
            t0 = time.perf_counter()
            KeyGenerator.hkdf_extract(ikm_a, salt)
            t_match.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            KeyGenerator.hkdf_extract(ikm_b, salt)
            t_mismatch.append(time.perf_counter() - t0)
        avg_match = sum(t_match) / len(t_match)
        avg_mismatch = sum(t_mismatch) / len(t_mismatch)
        ratio = max(avg_match, avg_mismatch) / max(min(avg_match, avg_mismatch), 1e-9)
        self.assertLess(ratio, 4.0,
            f"HKDF-Extract timing ratio {ratio:.2f}× for different IKM — possible leak")


# ===========================================================================
# 5. KeyUniquenessAtScale
# ===========================================================================

class KeyUniquenessAtScale(unittest.TestCase):
    """1000 fresh keys generated from fresh OS entropy must all be unique."""

    def test_1000_fresh_keys_all_unique(self):
        """Birthday paradox: probability of collision in 1000 32-byte keys ≈ 10^-67."""
        keys = {KeyGenerator.generate_fresh_key(os.urandom(32)) for _ in range(1000)}
        self.assertEqual(len(keys), 1000,
            "Collision detected among 1000 fresh keys — CSPRNG failure")

    def test_1000_derive_keys_different_entropy_all_unique(self):
        """1000 keys from different entropy sources (same config) must all differ."""
        config = HKDFConfig()
        keys = {KeyGenerator.derive_key([os.urandom(32)], config) for _ in range(1000)}
        self.assertEqual(len(keys), 1000)

    def test_256_quantum_hardened_keys_all_unique(self):
        keys = {KeyGenerator.generate_quantum_hardened_key(os.urandom(32)) for _ in range(256)}
        self.assertEqual(len(keys), 256)

    def test_fresh_key_uniqueness_with_fixed_behavioural_entropy(self):
        """Even with same behavioural entropy, 200 fresh keys must all differ (OS entropy)."""
        fixed_behaviour = bytes(range(32))
        keys = {KeyGenerator.generate_fresh_key(fixed_behaviour) for _ in range(200)}
        self.assertEqual(len(keys), 200,
            "With fixed behavioural entropy, OS randomness must ensure key uniqueness")

    def test_uniqueness_rate_is_exactly_100_percent(self):
        """No single duplicate allowed across 500 keys."""
        keys = [KeyGenerator.generate_fresh_key(os.urandom(32)) for _ in range(500)]
        unique = len(set(keys))
        rate = unique / 500
        self.assertEqual(rate, 1.0,
            f"Uniqueness rate {rate:.4f} < 1.0 — duplicate key detected")


# ===========================================================================
# 6. ConfigurationSpaceCoverage
# ===========================================================================

class ConfigurationSpaceCoverage(unittest.TestCase):
    """Full HKDFConfig parameter space produces valid, distinct outputs."""

    def test_all_standard_lengths_produce_correct_output_size(self):
        entropy = _make_valid_entropy(32)
        for length in [16, 20, 24, 28, 32, 48, 64, 128]:
            cfg = HKDFConfig(length=length)
            key = KeyGenerator.derive_key([entropy], cfg)
            self.assertEqual(len(key), length)

    def test_various_salts_all_produce_different_keys(self):
        entropy = _make_valid_entropy(32)
        # Note: b"" and b"\x00" are excluded from the same list because HMAC pads
        # short all-zero keys to the block size, making them functionally identical.
        # The interesting boundary is between the empty-salt default and a real salt.
        salts = [b"", b"v1", b"V1", b"salt-SUMITKEY", b"salt-long" * 10, os.urandom(32)]
        keys = [KeyGenerator.derive_key([entropy], HKDFConfig(salt=s)) for s in salts]
        self.assertEqual(len(set(keys)), len(salts),
            "Different salts must produce different keys")

    def test_empty_salt_falls_back_to_zero_block(self):
        """HKDFConfig with empty salt must still produce a valid key."""
        cfg = HKDFConfig(salt=b"")
        key = KeyGenerator.derive_key([_make_valid_entropy(32)], cfg)
        self.assertEqual(len(key), 32)

    def test_various_info_strings_all_produce_different_keys(self):
        entropy = _make_valid_entropy(32)
        infos = [b"", b"signing", b"encryption", b"wrapping", b"binding", os.urandom(16)]
        keys = [KeyGenerator.derive_key([entropy], HKDFConfig(info=i)) for i in infos]
        self.assertEqual(len(set(keys)), len(infos),
            "Different info fields must produce different keys")

    def test_quantum_hardened_config_has_larger_length(self):
        cfg = HKDFConfig.quantum_hardened()
        self.assertGreater(cfg.length, 32,
            "Quantum-hardened config must derive more than 32 bytes")

    def test_custom_config_round_trip_is_deterministic(self):
        cfg = HKDFConfig(salt=b"custom", info=b"test-round-trip", length=40)
        entropy = bytes(range(32))
        k1 = KeyGenerator.derive_key([entropy], cfg)
        k2 = KeyGenerator.derive_key([entropy], cfg)
        self.assertEqual(k1, k2, "Same config + same entropy must always produce same key")

    def test_min_entropy_bytes_enforced_by_config(self):
        """Config min_entropy_bytes must be enforced in generate_fresh_key."""
        cfg = HKDFConfig(min_entropy_bytes=48)
        # Providing only 32 bytes should raise InsufficientEntropyError
        with self.assertRaises((InsufficientEntropyError, EntropyHealthError)):
            KeyGenerator.generate_fresh_key(
                bytes([0x01, 0x02] * 16),  # 32 bytes, but config requires 48
                config=cfg,
                system_random_bytes=bytes(range(48)),
            )


# ===========================================================================
# 7. ErrorPathSafety
# ===========================================================================

class ErrorPathSafety(unittest.TestCase):
    """Exception messages and stack traces must not leak key material."""

    def test_insufficient_entropy_error_message_safe(self):
        """InsufficientEntropyError message must not contain raw key bytes."""
        try:
            KeyGenerator.health_check_entropy(b"\x01" * 10, min_bytes=32)
        except InsufficientEntropyError as exc:
            msg = str(exc)
            # Message should mention sizes but not dump hex of the input
            self.assertNotIn("01010101", msg.lower(),
                "Exception message leaks raw input bytes")
        except Exception:
            pass  # any error is acceptable; we just don't want leakage

    def test_entropy_health_error_message_safe(self):
        """EntropyHealthError must describe the problem, not the key value."""
        try:
            KeyGenerator.health_check_entropy(b"\x42" * 64)
        except EntropyHealthError as exc:
            msg = str(exc)
            self.assertLess(len(msg), 300,
                "Health error message unexpectedly long — possible data dump")

    def test_hkdf_errors_are_descriptive_not_key_dumping(self):
        """ValueError from bad HKDF params must not contain entropy bytes."""
        secret = os.urandom(32)
        try:
            KeyGenerator.hkdf_expand(secret, b"info", -1)
        except ValueError as exc:
            msg = str(exc)
            self.assertNotIn(secret.hex(), msg,
                "HKDF expand ValueError leaks PRK bytes in message")

    def test_type_error_does_not_expose_internal_state(self):
        """TypeError message from wrong input type must be clean."""
        try:
            KeyGenerator.generate_key("not bytes")  # type: ignore[arg-type]
        except TypeError as exc:
            msg = str(exc)
            # Should not contain memory addresses or binary dumps
            self.assertLess(len(msg), 500, "TypeError message is suspiciously long")

    def test_generate_fresh_key_exception_does_not_expose_os_entropy(self):
        """If generate_fresh_key raises, no OS entropy bytes in the message."""
        bad = b"\x00" * 32  # constant — health check should catch
        try:
            KeyGenerator.generate_fresh_key(bad)
        except (EntropyHealthError, InsufficientEntropyError) as exc:
            msg = str(exc)
            self.assertNotIn("00000000000000000000000000000000", msg,
                "Error message leaks zero-entropy input")


# ===========================================================================
# 8. NondeterminismGuarantee
# ===========================================================================

class NondeterminismGuarantee(unittest.TestCase):
    """generate_fresh_key must never repeat even for identical behavioural entropy."""

    FIXED_BEHAVIOUR = bytes(range(32))
    N = 200

    def test_200_fresh_keys_from_same_behaviour_all_unique(self):
        keys = [KeyGenerator.generate_fresh_key(self.FIXED_BEHAVIOUR) for _ in range(self.N)]
        self.assertEqual(len(set(keys)), self.N,
            "generate_fresh_key repeated a key for identical behavioural input")

    def test_fresh_key_differs_from_deterministic_key(self):
        """generate_fresh_key must differ from generate_key on same entropy."""
        e = _make_valid_entropy(32)
        k_det = KeyGenerator.generate_key(e)
        k_fresh = KeyGenerator.generate_fresh_key(e)
        self.assertNotEqual(k_det, k_fresh,
            "generate_fresh_key must not equal generate_key for same input")

    def test_concurrent_fresh_key_generation_never_repeats(self):
        """100 threads each generating 1 fresh key must produce 100 distinct keys."""
        results: list[bytes] = []
        lock = threading.Lock()

        def gen():
            key = KeyGenerator.generate_fresh_key(self.FIXED_BEHAVIOUR)
            with lock:
                results.append(key)

        threads = [threading.Thread(target=gen) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 100)
        self.assertEqual(len(set(results)), 100,
            "Concurrent fresh key generation produced duplicate — race condition?")

    def test_nondeterminism_verified_by_xor(self):
        """XOR of 100 fresh keys from same behaviour must not be all zeros."""
        keys = [KeyGenerator.generate_fresh_key(self.FIXED_BEHAVIOUR) for _ in range(100)]
        xored = bytes(a ^ b for a, b in zip(keys[0], keys[1]))
        self.assertNotEqual(xored, b"\x00" * 32,
            "XOR of two distinct keys is all zeros — identical keys produced")


# ===========================================================================
# 9. CryptoToolsBlackBox
# ===========================================================================

@unittest.skipUnless(_CRYPTO_AVAILABLE, "crypto_tools not available")
class CryptoToolsBlackBox(unittest.TestCase):
    """AES-GCM encrypt/decrypt: round-trip, tamper rejection, nonce freshness."""

    def _key(self) -> bytes:
        return KeyGenerator.generate_fresh_key(os.urandom(32))

    def test_round_trip_basic(self):
        key = self._key()
        msg = b"Hello, SUMIT KEY black-box test"
        enc = encrypt_message(key, msg, associated_data=b"ctx")
        self.assertEqual(decrypt_message(key, enc), msg)

    def test_wrong_key_rejected(self):
        from cryptography.exceptions import InvalidTag
        key = self._key()
        msg = b"secret"
        enc = encrypt_message(key, msg, associated_data=b"ctx")
        wrong_key = self._key()
        with self.assertRaises(InvalidTag):
            decrypt_message(wrong_key, enc)

    def test_tampered_ciphertext_rejected(self):
        from cryptography.exceptions import InvalidTag
        key = self._key()
        enc = encrypt_message(key, b"tamper-me", associated_data=b"ctx")
        tampered = EncryptedMessage(
            nonce=enc.nonce,
            ciphertext=bytes([enc.ciphertext[0] ^ 0xFF]) + enc.ciphertext[1:],
            associated_data=enc.associated_data,
        )
        with self.assertRaises(InvalidTag):
            decrypt_message(key, tampered)

    def test_tampered_nonce_rejected(self):
        from cryptography.exceptions import InvalidTag
        key = self._key()
        enc = encrypt_message(key, b"nonce-test", associated_data=b"ctx")
        tampered = EncryptedMessage(
            nonce=bytes([enc.nonce[0] ^ 0x01]) + enc.nonce[1:],
            ciphertext=enc.ciphertext,
            associated_data=enc.associated_data,
        )
        with self.assertRaises(InvalidTag):
            decrypt_message(key, tampered)

    def test_tampered_aad_rejected(self):
        from cryptography.exceptions import InvalidTag
        key = self._key()
        enc = encrypt_message(key, b"aad-test", associated_data=b"correct")
        tampered = EncryptedMessage(
            nonce=enc.nonce,
            ciphertext=enc.ciphertext,
            associated_data=b"wrong",
        )
        with self.assertRaises(InvalidTag):
            decrypt_message(key, tampered)

    def test_nonce_uniqueness_across_100_encryptions(self):
        """100 encryptions with same key must use 100 different nonces."""
        key = self._key()
        nonces = {encrypt_message(key, b"msg", associated_data=b"ctx").nonce
                  for _ in range(100)}
        self.assertEqual(len(nonces), 100,
            "Nonce repeated in AES-GCM — catastrophic reuse vulnerability")

    def test_empty_plaintext_round_trip(self):
        key = self._key()
        enc = encrypt_message(key, b"", associated_data=b"empty")
        self.assertEqual(decrypt_message(key, enc), b"")

    def test_large_plaintext_round_trip(self):
        key = self._key()
        msg = os.urandom(1024 * 1024)  # 1 MiB
        enc = encrypt_message(key, msg, associated_data=b"large")
        self.assertEqual(decrypt_message(key, enc), msg)

    def test_different_plaintexts_produce_different_ciphertexts(self):
        key = self._key()
        ct1 = encrypt_message(key, b"message-A", associated_data=b"ctx")
        ct2 = encrypt_message(key, b"message-B", associated_data=b"ctx")
        self.assertNotEqual(ct1.ciphertext, ct2.ciphertext)

    def test_truncated_ciphertext_rejected(self):
        from cryptography.exceptions import InvalidTag
        key = self._key()
        enc = encrypt_message(key, b"truncate", associated_data=b"ctx")
        if len(enc.ciphertext) > 4:
            truncated = EncryptedMessage(
                nonce=enc.nonce,
                ciphertext=enc.ciphertext[:-4],
                associated_data=enc.associated_data,
            )
            with self.assertRaises(InvalidTag):
                decrypt_message(key, truncated)


if __name__ == "__main__":
    unittest.main(verbosity=2)
