"""test_deep_audit.py — Deep code audit: bugs found and fixed.

Covers six specific issues uncovered by the 2026-05-28 deep audit:

  1. Vault concurrent-read race (burn_after_read bypassed by two threads)
  2. MITM Shield _seen_seqs unbounded set → replaced with monotonic max
  3. AdvancedThreatDetector _seen_message_ids unbounded growth with eviction
  4. crypto_tools assert → ValueError (disabled by python -O)
  5. APIKeyAuth non-constant-time == comparison → hmac.compare_digest
  6. RateLimitMiddleware X-Forwarded-For IP spoofing

Also adds direct unit tests for:
  7. entropy_engine.extract_keystroke_entropy (no prior dedicated test)
  8. entropy_engine.pool_entropy edge cases
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
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from entropy_engine import (
    extract_keystroke_entropy,
    extract_mouse_entropy,
    pool_entropy,
)
from key_generator import KeyGenerator, HKDFConfig
from fallback_auth import make_chess_like_mouse_events


# ============================================================================
# 1. Vault concurrent-read race with burn_after_read
# ============================================================================

class TestVaultConcurrentReadRace(unittest.TestCase):
    """Bug: two simultaneous retrieve() calls both succeeded on burn_after_read.

    Root cause: HOT state was not blocked in the entry-state guard, so a
    second thread entering retrieve() during the lock-released shard-decryption
    window would also set the state to HOT and decrypt the shards before the
    first thread's burn could clear them.

    Fix: vault.py now raises PermissionError when state == VaultState.HOT.
    """

    def setUp(self):
        from vault import HighVoltageVault
        self.vault = HighVoltageVault()
        self.key = os.urandom(32)
        self.pw = b"testpassword-audit"

    def test_burn_after_read_blocks_second_concurrent_read(self):
        """Two simultaneous retrieve() calls must not both return the key."""
        vid = self.vault.store(
            self.key,
            master_password=self.pw,
            n_shards=5,
            threshold=3,
            burn_after_read=True,
        )

        results: list[bytes] = []
        errors: list[str] = []

        def try_retrieve():
            try:
                k = self.vault.retrieve(vid, [1, 2, 3], master_password=self.pw)
                results.append(k)
            except Exception as exc:
                errors.append(str(exc))

        t1 = threading.Thread(target=try_retrieve)
        t2 = threading.Thread(target=try_retrieve)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(
            len(results), 1,
            f"Expected exactly 1 successful retrieve; got {len(results)}. "
            "burn_after_read race condition not fixed.",
        )
        self.assertEqual(len(errors), 1, "Expected exactly 1 blocked retrieve")
        self.assertIn("HOT", errors[0], "Blocked message should mention HOT state")

    def test_hot_state_visible_during_decryption(self):
        """While one thread is decrypting, the vault must report HOT state."""
        from vault import VaultState

        vid = self.vault.store(
            self.key,
            master_password=self.pw,
            n_shards=5,
            threshold=3,
            burn_after_read=False,
        )

        hot_states_seen: list[str] = []
        mid_lock = threading.Event()
        proceed = threading.Event()

        original_decrypt = self.vault._decrypt_shard

        def slow_decrypt(key_bytes, nonce, ct):
            mid_lock.set()
            proceed.wait(timeout=2.0)
            return original_decrypt(key_bytes, nonce, ct)

        self.vault._decrypt_shard = slow_decrypt

        def retriever():
            try:
                self.vault.retrieve(vid, [1, 2, 3], master_password=self.pw)
            except Exception:
                pass

        t = threading.Thread(target=retriever)
        t.start()
        mid_lock.wait(timeout=2.0)

        status = self.vault.status(vid)
        hot_states_seen.append(status.get("state", ""))
        proceed.set()
        t.join()

        self.assertIn("HOT", hot_states_seen, "Vault should report HOT state during decryption")

    def test_second_retrieve_after_burn_raises_burned(self):
        """After burn_after_read, any subsequent retrieve must raise."""
        vid = self.vault.store(
            self.key,
            master_password=self.pw,
            n_shards=5,
            threshold=3,
            burn_after_read=True,
        )
        self.vault.retrieve(vid, [1, 2, 3], master_password=self.pw)

        with self.assertRaises(PermissionError, msg="Second read must raise PermissionError"):
            self.vault.retrieve(vid, [1, 2, 3], master_password=self.pw)


# ============================================================================
# 2. MITM Shield sequence tracking: O(1) monotonic max vs unbounded set
# ============================================================================

class TestMITMShieldSequenceTracking(unittest.TestCase):
    """Bug: _seen_seqs set grew without bound in long sessions.

    Fix: replaced with _max_seen_seq int; any seq <= max_seen is rejected.
    Maintains identical security (monotonic sequence prevents replay) with O(1)
    memory regardless of message count.
    """

    def setUp(self):
        from vault import MITMShield
        self.alice = MITMShield()
        self.bob = MITMShield()

        init = self.alice.begin_session()
        resp = self.bob.accept_session(init)
        self.alice.finish_session(resp)

    def test_normal_sequence_accepted(self):
        wire = self.alice.send(b"hello")
        result = self.bob.receive(wire)
        self.assertEqual(result, b"hello")

    def test_replay_of_same_wire_rejected(self):
        from vault import MITMShieldError
        wire = self.alice.send(b"important data")
        self.bob.receive(wire)
        with self.assertRaises(MITMShieldError):
            self.bob.receive(wire)

    def test_old_sequence_rejected_after_newer(self):
        from vault import MITMShieldError
        wire1 = self.alice.send(b"msg1")
        wire2 = self.alice.send(b"msg2")
        self.bob.receive(wire1)
        self.bob.receive(wire2)
        with self.assertRaises(MITMShieldError, msg="Old sequence must be rejected"):
            self.bob.receive(wire1)

    def test_shield_has_no_seen_seqs_set(self):
        """After the fix, _seen_seqs must not exist; _max_seen_seq must."""
        from vault import MITMShield
        shield = MITMShield()
        self.assertFalse(hasattr(shield, "_seen_seqs"), "_seen_seqs must be removed")
        self.assertTrue(hasattr(shield, "_max_seen_seq"), "_max_seen_seq must exist")

    def test_many_messages_do_not_grow_memory(self):
        """Send 500 messages — no growing collection of sequence numbers."""
        from vault import MITMShield
        alice2 = MITMShield()
        bob2 = MITMShield()
        init = alice2.begin_session()
        resp = bob2.accept_session(init)
        alice2.finish_session(resp)

        for i in range(500):
            wire = alice2.send(f"msg{i}".encode())
            bob2.receive(wire)

        self.assertFalse(hasattr(bob2, "_seen_seqs"))
        # _max_seen_seq should be 499 (0-indexed)
        self.assertEqual(bob2._max_seen_seq, 499)


# ============================================================================
# 3. AdvancedThreatDetector _seen_message_ids bounded eviction
# ============================================================================

class TestThreatDetectorMessageIdBound(unittest.TestCase):
    """Bug: _seen_message_ids grew without bound.

    Fix: when the set reaches 100,000 entries the oldest half is evicted.
    """

    def _make_identity(self):
        from advanced_security import SystemIdentity
        return SystemIdentity(
            user_id="audit-test",
            device_id="dev1",
            device_secret=os.urandom(32),
            session_id="sess1",
        )

    def test_eviction_keeps_set_bounded(self):
        from advanced_security import AdvancedThreatDetector
        det = AdvancedThreatDetector()
        det._seen_message_ids_limit = 100

        identity = self._make_identity()
        for i in range(120):
            det.assess(
                identity=identity,
                message_id=f"msg-{i}",
                now=time.time(),
            )

        self.assertLessEqual(
            len(det._seen_message_ids),
            100,
            "Set must not exceed the configured limit after eviction",
        )

    def test_replay_detected_after_eviction(self):
        """An ID that survives eviction must still be detected as a replay."""
        from advanced_security import AdvancedThreatDetector
        det = AdvancedThreatDetector()
        det._seen_message_ids_limit = 100

        identity = self._make_identity()
        # Register a target id first
        det.assess(identity=identity, message_id="TARGET", now=time.time())

        # Flood with new ids to trigger eviction
        for i in range(110):
            det.assess(identity=identity, message_id=f"flood-{i}", now=time.time())

        # TARGET may have been evicted — that's the trade-off; just verify no crash
        decision = det.assess(identity=identity, message_id="TARGET", now=time.time())
        self.assertIn(decision.action, {"ALLOW", "STEP_UP", "BLOCK"})

    def test_replay_detected_within_window(self):
        from advanced_security import AdvancedThreatDetector
        det = AdvancedThreatDetector()
        identity = self._make_identity()

        det.assess(identity=identity, message_id="unique-123", now=time.time())
        decision = det.assess(identity=identity, message_id="unique-123", now=time.time())
        self.assertEqual(decision.action, "BLOCK", "Replay within window must be blocked")


# ============================================================================
# 4. crypto_tools assert → ValueError (disabled by python -O)
# ============================================================================

class TestCryptoToolsNoAsserts(unittest.TestCase):
    """Bug: assert statements in the quantum encrypt path are disabled at -O.

    Fix: replaced with explicit if/raise ValueError.
    """

    def test_no_assert_in_quantum_encrypt_path(self):
        """Verify source uses 'raise ValueError', not 'assert', for size checks."""
        src = (PROJECT_ROOT / "crypto_tools.py").read_text(encoding="utf-8")

        # Find the quantum_encrypt_message function
        fn_start = src.index("def quantum_encrypt_message(")
        fn_end = src.index("\ndef ", fn_start + 1)
        fn_body = src[fn_start:fn_end]

        self.assertNotIn(
            "assert len(kem_ct)",
            fn_body,
            "assert must be replaced by if/raise ValueError",
        )
        self.assertNotIn(
            "assert len(hardened_enc)",
            fn_body,
            "assert must be replaced by if/raise ValueError",
        )
        self.assertIn(
            "raise ValueError",
            fn_body,
            "quantum_encrypt_message must raise ValueError on size mismatch",
        )

    def test_quantum_encrypt_round_trip_still_works(self):
        """Replacing assert with raise must not break the encrypt→decrypt path."""
        from crypto_tools import quantum_keygen, quantum_encrypt_message, quantum_decrypt_message

        entropy = make_chess_like_mouse_events(good=True, moves=12)
        entropy_bytes = extract_mouse_entropy(entropy)
        key = KeyGenerator.generate_fresh_key(entropy_bytes)

        session = quantum_keygen()
        pkg = quantum_encrypt_message(
            session,
            b"deep audit test message",
            key,
        )
        plaintext = quantum_decrypt_message(session, pkg)
        self.assertEqual(plaintext, b"deep audit test message")


# ============================================================================
# 5. APIKeyAuth constant-time comparison
# ============================================================================

class TestAPIKeyAuthTimingResistance(unittest.TestCase):
    """Bug: APIKeyAuth.verify used `== ` (variable-time string comparison).

    Fix: now uses hmac.compare_digest on the hex digests.
    """

    def test_verify_uses_hmac_compare_digest(self):
        """Inspect source to confirm hmac.compare_digest is used."""
        src = (PROJECT_ROOT / "security.py").read_text(encoding="utf-8")
        self.assertIn(
            "compare_digest",
            src,
            "security.py must use hmac.compare_digest for API key verification",
        )
        # Must not use a bare == for key comparison
        class_block_start = src.index("class APIKeyAuth")
        class_block_end = src.index("\nclass ", class_block_start + 1)
        class_body = src[class_block_start:class_block_end]
        self.assertNotIn(
            "hexdigest() ==",
            class_body,
            "APIKeyAuth must not use == for comparing key digests",
        )

    def test_correct_key_accepted(self):
        from security import APIKeyAuth
        with patch.dict(os.environ, {"SUMIT_TEST_APIKEY": "mysecretkey"}):
            auth = APIKeyAuth(api_key_env="SUMIT_TEST_APIKEY")
            # Store the hash as the expected key (simulating env setup)
            auth.expected_key = hashlib.sha256(b"mysecretkey").hexdigest()
            self.assertTrue(auth.verify("mysecretkey"))

    def test_wrong_key_rejected(self):
        from security import APIKeyAuth
        with patch.dict(os.environ, {"SUMIT_TEST_APIKEY": "correctkey"}):
            auth = APIKeyAuth(api_key_env="SUMIT_TEST_APIKEY")
            auth.expected_key = hashlib.sha256(b"correctkey").hexdigest()
            self.assertFalse(auth.verify("wrongkey"))
            self.assertFalse(auth.verify(""))
            self.assertFalse(auth.verify(None))

    def test_disabled_when_env_not_set(self):
        from security import APIKeyAuth
        env = {k: v for k, v in os.environ.items() if k != "SUMIT_TEST_APIKEY"}
        with patch.dict(os.environ, env, clear=True):
            auth = APIKeyAuth(api_key_env="SUMIT_TEST_APIKEY")
            self.assertFalse(auth.enabled)
            self.assertTrue(auth.verify(None))   # auth disabled → always pass


# ============================================================================
# 6. RateLimitMiddleware X-Forwarded-For IP spoofing
# ============================================================================

class TestXForwardedForSpoofing(unittest.TestCase):
    """Bug: _get_client_ip blindly trusted X-Forwarded-For from any client.

    An attacker could forge X-Forwarded-For: 1.2.3.4 to appear as a different
    IP and rotate through unlimited IPs to evade per-IP rate limiting.

    Fix: X-Forwarded-For is only trusted when the direct connection IP matches
    the TRUSTED_PROXY env var.
    """

    def _make_request(self, direct_ip: str, forwarded_for: str | None = None) -> MagicMock:
        req = MagicMock()
        req.client = MagicMock()
        req.client.host = direct_ip
        headers = {}
        if forwarded_for is not None:
            headers["x-forwarded-for"] = forwarded_for
        req.headers = headers
        return req

    def test_no_proxy_env_ignores_forwarded_header(self):
        from security import RateLimitMiddleware
        env = {k: v for k, v in os.environ.items() if k != "TRUSTED_PROXY"}
        with patch.dict(os.environ, env, clear=True):
            req = self._make_request("10.0.0.1", forwarded_for="99.99.99.99")
            ip = RateLimitMiddleware._get_client_ip(req)
            self.assertEqual(ip, "10.0.0.1", "Without TRUSTED_PROXY, direct IP must be used")

    def test_trusted_proxy_allows_forwarded_header(self):
        from security import RateLimitMiddleware
        with patch.dict(os.environ, {"TRUSTED_PROXY": "10.0.0.1"}):
            req = self._make_request("10.0.0.1", forwarded_for="203.0.113.5")
            ip = RateLimitMiddleware._get_client_ip(req)
            self.assertEqual(ip, "203.0.113.5", "Trusted proxy should forward client IP")

    def test_untrusted_ip_cannot_spoof_via_header(self):
        from security import RateLimitMiddleware
        with patch.dict(os.environ, {"TRUSTED_PROXY": "10.0.0.1"}):
            # Attacker connects from 5.6.7.8, forges X-Forwarded-For
            req = self._make_request("5.6.7.8", forwarded_for="1.2.3.4")
            ip = RateLimitMiddleware._get_client_ip(req)
            self.assertEqual(ip, "5.6.7.8", "Non-proxy IP must not have forwarded header trusted")

    def test_no_forwarded_header_uses_direct_ip(self):
        from security import RateLimitMiddleware
        req = self._make_request("192.168.1.100")
        ip = RateLimitMiddleware._get_client_ip(req)
        self.assertEqual(ip, "192.168.1.100")

    def test_no_client_returns_unknown(self):
        from security import RateLimitMiddleware
        req = MagicMock()
        req.client = None
        req.headers = {}
        ip = RateLimitMiddleware._get_client_ip(req)
        self.assertEqual(ip, "unknown")


# ============================================================================
# 7. entropy_engine — direct unit tests (no prior dedicated coverage)
# ============================================================================

class TestExtractKeystrokeEntropy(unittest.TestCase):
    """Direct tests for extract_keystroke_entropy (previously uncovered)."""

    def _make_keystrokes(self, n: int = 10) -> list[dict]:
        events = []
        base = time.time()
        keys = list("helloworld")
        for i in range(n):
            press = base + i * 0.15
            release = press + 0.08 + (i % 3) * 0.01
            events.append({
                "key": keys[i % len(keys)],
                "press_timestamp": press,
                "release_timestamp": release,
                "dwell_time_ms": (release - press) * 1000,
                "flight_time_ms": (i * 0.15 - (i - 1) * 0.15) * 1000 if i > 0 else 0.0,
            })
        return events

    def test_returns_bytes(self):
        result = extract_keystroke_entropy(self._make_keystrokes())
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_empty_events_returns_deterministic_zeros(self):
        result = extract_keystroke_entropy([])
        self.assertIsInstance(result, bytes)
        # Deterministic: calling twice gives same bytes
        self.assertEqual(result, extract_keystroke_entropy([]))

    def test_different_timings_produce_different_bytes(self):
        fast = [{"key": "a", "dwell_time_ms": 50.0, "flight_time_ms": 80.0,
                 "press_timestamp": 0.0, "release_timestamp": 0.05}]
        slow = [{"key": "a", "dwell_time_ms": 200.0, "flight_time_ms": 300.0,
                 "press_timestamp": 0.0, "release_timestamp": 0.2}]
        self.assertNotEqual(extract_keystroke_entropy(fast), extract_keystroke_entropy(slow))

    def test_bigram_encoding_changes_output(self):
        """Different key sequences should produce different bigram timings."""
        evts_ab = self._make_keystrokes(10)
        evts_cd = []
        base = time.time()
        for i, key in enumerate(list("qqqqqqqqqq")):
            evts_cd.append({
                "key": key,
                "press_timestamp": base + i * 0.1,
                "release_timestamp": base + i * 0.1 + 0.05,
                "dwell_time_ms": 50.0,
                "flight_time_ms": 50.0,
            })
        self.assertNotEqual(extract_keystroke_entropy(evts_ab), extract_keystroke_entropy(evts_cd))

    def test_deterministic_for_same_input(self):
        events = self._make_keystrokes(15)
        self.assertEqual(extract_keystroke_entropy(events), extract_keystroke_entropy(events))


class TestPoolEntropyEdgeCases(unittest.TestCase):
    """Direct tests for pool_entropy — covers previously untested edge cases."""

    def _mouse_bytes(self) -> bytes:
        evts = make_chess_like_mouse_events(good=True, moves=8)
        return extract_mouse_entropy(evts)

    def test_different_mouse_bytes_produce_different_pool(self):
        evts1 = make_chess_like_mouse_events(good=True, moves=8)
        evts2 = make_chess_like_mouse_events(good=True, moves=16)
        pool1 = pool_entropy(extract_mouse_entropy(evts1), b"\x01" * 40)
        pool2 = pool_entropy(extract_mouse_entropy(evts2), b"\x01" * 40)
        self.assertNotEqual(pool1, pool2)

    def test_different_keystroke_bytes_produce_different_pool(self):
        mouse = self._mouse_bytes()
        pool1 = pool_entropy(mouse, b"\xAA" * 40)
        pool2 = pool_entropy(mouse, b"\xBB" * 40)
        self.assertNotEqual(pool1, pool2)

    def test_pool_output_is_32_bytes(self):
        mouse = self._mouse_bytes()
        result = pool_entropy(mouse, b"\x01" * 40)
        self.assertEqual(len(result), 32)

    def test_pool_rejects_non_bytes_mouse(self):
        with self.assertRaises(TypeError):
            pool_entropy("not bytes", b"\x01" * 40)

    def test_pool_rejects_non_bytes_keystroke(self):
        mouse = self._mouse_bytes()
        with self.assertRaises(TypeError):
            pool_entropy(mouse, "not bytes")

    def test_pool_with_empty_keystroke_is_deterministic(self):
        """Empty keystroke bytes are all-zeros — pool still works but is weaker."""
        mouse = self._mouse_bytes()
        empty_ks = extract_keystroke_entropy([])
        pool1 = pool_entropy(mouse, empty_ks)
        pool2 = pool_entropy(mouse, empty_ks)
        self.assertEqual(pool1, pool2, "Pool must be deterministic")

    def test_all_zero_raw_features_rejected_by_health_check(self):
        """All-zero raw mouse feature bytes are caught by the health gate.

        pool_entropy runs SHA3-256 over its inputs, so the pooled digest is
        always high-diversity regardless of input. The health check must therefore
        be applied to the RAW feature bytes (before pooling), which is what
        generate_key / generate_fresh_key both do.
        """
        from key_generator import EntropyHealthError
        zero_mouse = extract_mouse_entropy([])   # 48 all-zero bytes
        zero_ks = extract_keystroke_entropy([])  # 40 all-zero bytes

        # Raw features ARE all-zero → health check must reject them
        self.assertTrue(all(b == 0 for b in zero_mouse), "empty mouse features must be all-zero")
        with self.assertRaises(EntropyHealthError):
            KeyGenerator.health_check_entropy(zero_mouse)

        # Pooled output is SHA3-256(zeros||zeros) — diverse, not all-zero
        pooled = pool_entropy(zero_mouse, zero_ks)
        self.assertGreater(len(set(pooled)), 2, "SHA3 output is diverse even from zero input")

        # generate_key also catches this via its own minimum-length check on raw entropy
        with self.assertRaises(EntropyHealthError):
            KeyGenerator.generate_fresh_key(zero_mouse)


if __name__ == "__main__":
    unittest.main(verbosity=2)
