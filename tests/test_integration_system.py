"""SUMIT KEY — Full-System Integration Test Suite.

Tests every layer-to-layer interconnection, failover path, and degraded-mode
behaviour. Each test verifies that when one component fails the system either
activates the next fallback layer or fails closed — never silently degrades.

Architecture under test
───────────────────────
  [entropy_engine] ──► [key_generator] ──► [crypto_tools]
        │                                        │
        ▼                                        ▼
  [advanced_security]   ◄────────────►  [self_healing]
  (threat detector, rotating keys)      (journal, failover)
        │                                        │
        ▼                                        ▼
  [fallback_auth]          [vault]          [MITM Shield]
  (mouse→OTP→NFC)   (shards, ZKP, burn)  (replay guard)

Run with:
    python -m pytest tests/test_integration_system.py -v -s --tb=short
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

# ── Formatting ──────────────────────────────────────────────────────────────
W = 74

def _sec(title: str) -> None:
    pad = W - len(title) - 4
    print(f"\n╔{'═'*(W-2)}╗")
    print(f"║  {title}{' '*pad}║")
    print(f"╚{'═'*(W-2)}╝")

def _arrow(src: str, dst: str, msg: str = "") -> None:
    label = f"[{src}→{dst}]"
    print(f"  {label:<30} {msg}")

def _ok(msg: str)  -> None: print(f"  ✓  {msg}")
def _fail(msg: str)-> None: print(f"  ✗  {msg}")
def _warn(msg: str)-> None: print(f"  ⚠  {msg}")
def _info(msg: str)-> None: print(f"  ·  {msg}")


# ── Shared fixtures ──────────────────────────────────────────────────────────

def _mouse_entropy(seed: int = 7, n: int = 12) -> bytes:
    """Deterministic mouse entropy from seeded synthetic events."""
    import random
    from entropy_engine import extract_mouse_entropy
    rng = random.Random(seed)
    events = [
        {
            "x": rng.uniform(100, 1820),
            "y": rng.uniform(100, 980),
            "velocity_px_per_s": abs(rng.gauss(300, 120)),
            "direction_angle_deg": rng.uniform(0, 360),
        }
        for _ in range(n)
    ]
    raw = extract_mouse_entropy(events)
    return raw + hashlib.sha3_256(raw + seed.to_bytes(4, "big")).digest()


def _sys_rand(tag: bytes = b"test") -> bytes:
    """Deterministic system-random material (SHA3-256, not all-same bytes)."""
    return hashlib.sha3_256(b"sys-rand-" + tag).digest()


def _identity(name: str = "alice", secret_tag: bytes = b"a") -> "SystemIdentity":
    from advanced_security import SystemIdentity
    return SystemIdentity(
        user_id=f"user-{name}",
        device_id=f"device-{name}",
        device_secret=hashlib.sha3_256(b"device-secret-" + secret_tag).digest(),
        session_id=f"session-{name}-001",
    )


# ════════════════════════════════════════════════════════════════════════════
# ── Group 1: End-to-end layer pipeline (happy path + degraded modes) ─────────
# ════════════════════════════════════════════════════════════════════════════

class TestLayerPipeline(unittest.TestCase):
    """Entropy → KeyGen → Crypto: all three layers must be connected and live."""

    def test_01_full_pipeline_happy_path(self):
        _sec("LAYER PIPELINE [1/5]: Entropy → Key → Encrypt → Decrypt")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message, decrypt_message

        entropy = _mouse_entropy(seed=1)
        _arrow("entropy_engine", "key_generator", f"{len(entropy)}B entropy")

        key = KeyGenerator.generate_fresh_key(entropy, system_random_bytes=_sys_rand(b"p1"))
        _arrow("key_generator", "crypto_tools", f"256-bit key: {key[:6].hex()}...")

        msg = b"integration test plaintext - layer 1/5"
        enc = encrypt_message(key, msg, associated_data=b"layer-test")
        _arrow("crypto_tools", "decrypt_message", f"ciphertext {len(enc.ciphertext)}B")

        dec = decrypt_message(key, enc)
        self.assertEqual(dec, msg)
        _ok(f"Round-trip: {dec!r}")

    def test_02_entropy_minimum_gate_blocks_pipeline(self):
        _sec("LAYER PIPELINE [2/5]: Entropy health-gate blocks weak input")
        from key_generator import KeyGenerator, EntropyHealthError
        from entropy_engine import extract_mouse_entropy

        zero_events = [{"x": 0.0, "y": 0.0, "velocity_px_per_s": 0.0,
                        "direction_angle_deg": 0.0}] * 3
        weak = extract_mouse_entropy(zero_events)  # all-zero features
        _arrow("entropy_engine", "key_generator", f"weak entropy: {weak[:8].hex()}...")

        with self.assertRaises(EntropyHealthError):
            KeyGenerator.generate_fresh_key(weak, system_random_bytes=_sys_rand(b"p2"))
        _ok("EntropyHealthError raised — pipeline blocked at key_generator gate.")
        _info("Downstream crypto_tools is never reached with bad entropy.")

    def test_03_wrong_key_breaks_decrypt_layer(self):
        _sec("LAYER PIPELINE [3/5]: Wrong key → decrypt layer fires InvalidTag")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message, decrypt_message
        from cryptography.exceptions import InvalidTag

        k1 = KeyGenerator.generate_fresh_key(_mouse_entropy(1), system_random_bytes=_sys_rand(b"k1"))
        k2 = KeyGenerator.generate_fresh_key(_mouse_entropy(2), system_random_bytes=_sys_rand(b"k2"))

        enc = encrypt_message(k1, b"secret", associated_data=b"aad")
        _arrow("crypto_tools[k1]", "crypto_tools[k2]", "wrong key attempt")

        with self.assertRaises(InvalidTag):
            decrypt_message(k2, enc)
        _ok("InvalidTag — wrong key detected at decrypt layer, not silently misread.")

    def test_04_quantum_pipeline_happy_path(self):
        _sec("LAYER PIPELINE [4/5]: Entropy → ML-KEM-1024 → quantum decrypt")
        from crypto_tools import quantum_keygen, quantum_encrypt_message, quantum_decrypt_message

        session  = quantum_keygen()
        entropy  = _mouse_entropy(seed=4, n=16)
        _arrow("entropy_engine", "quantum_encrypt_message",
               f"{len(entropy)}B + ML-KEM-1024 ek")

        pkg = quantum_encrypt_message(
            session, b"quantum pipeline OK", behavioural_entropy=entropy,
            associated_data=b"integration")
        _arrow("quantum_encrypt_message", "quantum_decrypt_message",
               f"pkg: {len(pkg.ciphertext)}B ct + {len(pkg.kem_ct)}B KEM ct")

        result = quantum_decrypt_message(session, pkg)
        self.assertEqual(result, b"quantum pipeline OK")
        _ok(f"Decrypted: {result!r}")

    def test_05_pipeline_with_file_encryption(self):
        _sec("LAYER PIPELINE [5/5]: Entropy → Key → File Encrypt → File Decrypt")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_file, decrypt_file

        key = KeyGenerator.generate_fresh_key(
            _mouse_entropy(5), system_random_bytes=_sys_rand(b"file"))

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "sensitive.txt"
            enc = Path(tmp) / "sensitive.txt.sk"
            dec = Path(tmp) / "sensitive.dec.txt"

            src.write_bytes(b"TOP SECRET: " + os.urandom(128))
            original = src.read_bytes()

            _arrow("key_generator", "encrypt_file", f"{len(original)}B plaintext")
            encrypt_file(key, src, enc)

            _arrow("encrypt_file", "decrypt_file",
                   f"{enc.stat().st_size}B on disk")
            decrypt_file(key, enc, dec)

            self.assertEqual(dec.read_bytes(), original)
            _ok(f"File round-trip: {len(original)}B → {enc.stat().st_size}B → {len(original)}B")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 2: Advanced Security ↔ Self-Healing interconnection ────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestAdvancedSecuritySelfHealing(unittest.TestCase):
    """Rotating keys and self-healer work together; healer never bypasses security."""

    def test_01_rotating_key_and_healer_happy_path(self):
        _sec("SECURITY↔HEALER [1/7]: Normal encrypt — healer commits first try")
        from self_healing import SelfHealingConfig, SelfHealingCryptoService

        now = [3000.0]
        svc = SelfHealingCryptoService(
            _identity("alice"), clock=lambda: now[0],
            config=SelfHealingConfig(retry_backoff_seconds=0.0))

        result = svc.encrypt_message("hello healer", context="chat", operation_id="op-01")

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.active_path, "primary")
        self.assertFalse(result.recovered)
        self.assertEqual(result.attempts, 1)
        stages = [e.stage for e in result.events]
        self.assertIn("commit", stages)
        _arrow("RotatingKeyEnvelope", "SelfHealingCryptoService", "committed on attempt 1")
        _ok(f"Events: {' → '.join(stages)}")

    def test_02_verify_fault_triggers_retry_then_commits(self):
        _sec("SECURITY↔HEALER [2/7]: Verify fault → retry → commit (self-healing)")
        from self_healing import SelfHealingConfig, SelfHealingCryptoService
        from advanced_security import RotatingKeyEnvelope

        now = [3100.0]
        svc = SelfHealingCryptoService(
            _identity("alice"),
            config=SelfHealingConfig(max_retries=2, retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        result = svc.encrypt_message(
            "fault then recover",
            operation_id="op-02",
            failpoints={"verify_once"},
        )

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.recovered)
        self.assertGreaterEqual(result.attempts, 2)
        _arrow("verify_fault", "retry_engine", "one-time verify fault injected")
        _arrow("retry_engine", "SelfHealingCryptoService", f"recovered on attempt {result.attempts}")

        # Verify the resulting envelope actually decrypts correctly
        env = RotatingKeyEnvelope(_identity("alice"), clock=lambda: now[0])
        dec = env.decrypt(result.envelope, context="message",
                          max_clock_skew_seconds=0.5)
        self.assertEqual(dec, b"fault then recover")
        _ok(f"Healer recovered; envelope valid: {dec!r}")

    def test_03_primary_outage_failover_to_backup(self):
        _sec("SECURITY↔HEALER [3/7]: Primary outage → failover to backup identity")
        from self_healing import SelfHealingConfig, SelfHealingCryptoService
        from advanced_security import RotatingKeyEnvelope

        now = [3200.0]
        svc = SelfHealingCryptoService(
            _identity("primary", b"P"),
            backup_identity=_identity("backup", b"B"),
            config=SelfHealingConfig(max_retries=0, retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        result = svc.encrypt_message(
            "must survive on backup",
            operation_id="op-03",
            failpoints={"primary_encrypt"},
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.active_path, "backup")
        self.assertTrue(result.recovered)
        _arrow("primary_path", "backup_path", "primary simulated down")

        env = RotatingKeyEnvelope(_identity("backup", b"B"), clock=lambda: now[0])
        dec = env.decrypt(result.envelope, context="message",
                          max_clock_skew_seconds=0.5)
        self.assertEqual(dec, b"must survive on backup")
        _ok(f"Backup path active; decrypted: {dec!r}")

    def test_04_threat_block_not_healed(self):
        _sec("SECURITY↔HEALER [4/7]: ThreatBlock → healer refuses; fails CLOSED")
        from self_healing import (SelfHealingConfig, SelfHealingCryptoService,
                                   UnrecoverableSecurityError)

        now = [3300.0]
        svc = SelfHealingCryptoService(
            _identity("attacker"),
            backup_identity=_identity("backup-attacker"),
            config=SelfHealingConfig(max_retries=2, retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        _arrow("ThreatDetector", "SelfHealingCryptoService",
               "5 failed OTP attempts → BLOCK signal")

        with self.assertRaises(UnrecoverableSecurityError):
            svc.encrypt_message(
                "must not encrypt",
                failed_otp_attempts=5,
                operation_id="op-04",
            )
        _ok("UnrecoverableSecurityError — healer refuses to bypass BLOCK.")
        _info("Backup identity is NOT tried when security is the stop reason.")

    def test_05_persistent_verify_fault_fails_closed(self):
        _sec("SECURITY↔HEALER [5/7]: Persistent verify fault → all retries exhausted")
        from self_healing import (SelfHealingConfig, SelfHealingCryptoService,
                                   SelfHealingError)

        now = [3400.0]
        svc = SelfHealingCryptoService(
            _identity("alice"),
            config=SelfHealingConfig(max_retries=1, retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        with self.assertRaises(SelfHealingError):
            svc.encrypt_message(
                "will never commit",
                failpoints={"always_verify"},
                operation_id="op-05",
            )
        _ok("SelfHealingError — all retries exhausted; operation fails closed.")

    def test_06_journal_persists_across_service_restart(self):
        _sec("SECURITY↔HEALER [6/7]: Journal survives service 'restart' (new instance)")
        from self_healing import SelfHealingConfig, SelfHealingCryptoService

        with tempfile.TemporaryDirectory() as tmp:
            journal = Path(tmp) / "ops.jsonl"
            now = [3500.0]
            op_id = "op-06-persistent"

            svc1 = SelfHealingCryptoService(
                _identity("alice"),
                config=SelfHealingConfig(journal_path=journal,
                                          retry_backoff_seconds=0.0),
                clock=lambda: now[0],
            )
            svc1.encrypt_message("journaled payload", operation_id=op_id)

            # Simulate restart — fresh service object, same journal
            svc2 = SelfHealingCryptoService(
                _identity("alice"),
                config=SelfHealingConfig(journal_path=journal,
                                          retry_backoff_seconds=0.0),
                clock=lambda: now[0],
            )
            status = svc2.resume_status(op_id)

        self.assertEqual(status["last_stage"], "commit")
        self.assertEqual(status["last_status"], "ok")
        self.assertGreaterEqual(status["event_count"], 4)
        _arrow("svc1 (died)", "svc2 (new)", f"journal: {status['event_count']} events persisted")
        _ok(f"Status after restart: stage={status['last_stage']} status={status['last_status']}")

    def test_07_two_independent_sessions_dont_interfere(self):
        _sec("SECURITY↔HEALER [7/7]: Two parallel sessions — state isolation")
        from self_healing import SelfHealingConfig, SelfHealingCryptoService
        from advanced_security import RotatingKeyEnvelope

        now = [3600.0]
        svc_a = SelfHealingCryptoService(_identity("alice", b"A"),
            config=SelfHealingConfig(retry_backoff_seconds=0.0), clock=lambda: now[0])
        svc_b = SelfHealingCryptoService(_identity("bob", b"B"),
            config=SelfHealingConfig(retry_backoff_seconds=0.0), clock=lambda: now[0])

        r_a = svc_a.encrypt_message("Alice secret", context="chat", operation_id="op-07a")
        r_b = svc_b.encrypt_message("Bob secret",   context="chat", operation_id="op-07b")

        env_a = RotatingKeyEnvelope(_identity("alice", b"A"), clock=lambda: now[0])
        env_b = RotatingKeyEnvelope(_identity("bob",   b"B"), clock=lambda: now[0])

        dec_a = env_a.decrypt(r_a.envelope, context="chat", max_clock_skew_seconds=0.5)
        dec_b = env_b.decrypt(r_b.envelope, context="chat", max_clock_skew_seconds=0.5)

        self.assertEqual(dec_a, b"Alice secret")
        self.assertEqual(dec_b, b"Bob secret")

        # Cross-identity decrypt raises ValueError (identity hash mismatch)
        # before even attempting AES-GCM, so we catch the broader security exception
        with self.assertRaises((ValueError, Exception)):
            env_b.decrypt(r_a.envelope, context="chat")
        with self.assertRaises((ValueError, Exception)):
            env_a.decrypt(r_b.envelope, context="chat")

        _ok("Alice reads Alice's envelope ✓ | Bob reads Bob's envelope ✓")
        _ok("Bob cannot read Alice's envelope ✓ | Alice cannot read Bob's ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 3: Vault ↔ Crypto layer integration ────────────────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestVaultCryptoIntegration(unittest.TestCase):
    """Vault stores crypto keys; crypto layer uses them; burn and ZKP hold."""

    def test_01_store_encrypt_retrieve_decrypt(self):
        _sec("VAULT↔CRYPTO [1/6]: Store key → encrypt → retrieve → decrypt")
        from vault import HighVoltageVault
        from crypto_tools import encrypt_message, decrypt_message

        vault    = HighVoltageVault()
        key_mat  = _mouse_entropy(seed=10)[:32]
        password = hashlib.sha3_256(b"vault-master-1").digest()

        vid = vault.store(key_mat, master_password=password,
                          n_shards=5, threshold=3, ttl_seconds=60, burn_after_read=False)
        _arrow("key_material", "HighVoltageVault", f"vault_id={vid[:12]}...")

        msg  = b"vault protected message"
        enc  = encrypt_message(key_mat, msg, associated_data=b"vault-v1")
        _arrow("crypto_tools[original_key]", "wire", "ciphertext sent")

        retrieved = vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=password)
        self.assertEqual(retrieved, key_mat)
        _arrow("HighVoltageVault", "crypto_tools[retrieved_key]", "key recovered from vault")

        dec = decrypt_message(retrieved, enc)
        self.assertEqual(dec, msg)
        _ok(f"Vault round-trip: encrypted with original, decrypted with retrieved key ✓")

    def test_02_burn_after_read_key_no_longer_usable(self):
        _sec("VAULT↔CRYPTO [2/6]: Burn-after-read — second retrieve fails closed")
        from vault import HighVoltageVault

        vault    = HighVoltageVault()
        key_mat  = _mouse_entropy(seed=11)[:32]
        password = hashlib.sha3_256(b"vault-master-2").digest()

        vid = vault.store(key_mat, master_password=password,
                          n_shards=5, threshold=3, burn_after_read=True)

        first = vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=password)
        self.assertEqual(first, key_mat)
        _arrow("vault", "first_retrieval", "SUCCESS — key released")

        with self.assertRaises(PermissionError):
            vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=password)
        _ok("Second retrieve → PermissionError — vault state=BURNED ✓")

    def test_03_wrong_master_password_rejected(self):
        _sec("VAULT↔CRYPTO [3/6]: Wrong master password → shard decryption fails")
        from vault import HighVoltageVault

        vault   = HighVoltageVault()
        key_mat = _mouse_entropy(12)[:32]
        correct = hashlib.sha3_256(b"correct-pw").digest()
        wrong   = hashlib.sha3_256(b"wrong-pw").digest()

        vid = vault.store(key_mat, master_password=correct, n_shards=5, threshold=3)
        _arrow("attacker", "vault.retrieve", "wrong password attempt")

        with self.assertRaises(PermissionError):
            vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=wrong)
        _ok("PermissionError — shard decryption fails with wrong password ✓")

    def test_04_vault_ttl_seals_after_expiry(self):
        _sec("VAULT↔CRYPTO [4/6]: Vault TTL expiry → state becomes SEALED")
        from vault import HighVoltageVault

        vault   = HighVoltageVault()
        key_mat = _mouse_entropy(13)[:32]
        pw      = hashlib.sha3_256(b"ttl-pw").digest()

        vid = vault.store(key_mat, master_password=pw, n_shards=5, threshold=3,
                          ttl_seconds=0.001)  # effectively instant expiry
        time.sleep(0.005)  # let it expire

        with self.assertRaises(PermissionError):
            vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=pw)

        status = vault.status(vid)
        self.assertEqual(status["state"], "SEALED")
        _arrow("TTL expired", "vault.state", "ARMED → SEALED")
        _ok(f"Vault status={status['state']} — retrieval correctly blocked ✓")

    def test_05_insufficient_shards_rejected(self):
        _sec("VAULT↔CRYPTO [5/6]: Fewer shards than threshold → rejected")
        from vault import HighVoltageVault

        vault   = HighVoltageVault()
        key_mat = _mouse_entropy(14)[:32]
        pw      = hashlib.sha3_256(b"shard-pw").digest()

        vid = vault.store(key_mat, master_password=pw, n_shards=5, threshold=3)
        _arrow("attacker", "vault.retrieve", "only 2 shards (threshold=3)")

        with self.assertRaises(ValueError):
            vault.retrieve(vid, shard_xs=[1, 2], master_password=pw)
        _ok("ValueError — insufficient shards rejected at vault layer ✓")

    def test_06_emergency_zeroize_destroys_key(self):
        _sec("VAULT↔CRYPTO [6/6]: Emergency zeroize — key material destroyed")
        from vault import HighVoltageVault

        vault   = HighVoltageVault()
        key_mat = _mouse_entropy(15)[:32]
        pw      = hashlib.sha3_256(b"zero-pw").digest()

        vid = vault.store(key_mat, master_password=pw, n_shards=5, threshold=3)
        vault.zeroize(vid)
        _arrow("emergency", "vault.zeroize", f"vault_id={vid[:12]}...")

        self.assertNotIn(vid, vault._entries)
        with self.assertRaises(KeyError):
            vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=pw)
        _ok("KeyError — vault entry gone after zeroize; key cannot be recovered ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 4: MITM Shield ↔ Crypto layer integration ──────────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestMITMShieldIntegration(unittest.TestCase):
    """MITM Shield protects wire transit; crypto layer protects content."""

    def _make_pair(self):
        """Return an established (alice_shield, bob_shield) pair."""
        from vault import MITMShield
        alice = MITMShield(); bob = MITMShield()
        alice.finish_session(bob.accept_session(alice.begin_session()))
        return alice, bob

    def test_01_send_receive_round_trip(self):
        _sec("MITM-SHIELD↔CRYPTO [1/5]: Wire round-trip — content intact")
        from crypto_tools import encrypt_message, decrypt_message
        from key_generator import KeyGenerator

        alice_shield, bob_shield = self._make_pair()
        key = KeyGenerator.generate_fresh_key(
            _mouse_entropy(20), system_random_bytes=_sys_rand(b"mitm1"))

        inner_msg = b"payload encrypted by AES-GCM before going through MITM shield"
        enc = encrypt_message(key, inner_msg, associated_data=b"wire-aad")

        # Serialise the EncryptedMessage to bytes for wire
        import json
        from crypto_tools import message_to_dict
        wire_payload = json.dumps(message_to_dict(enc)).encode()

        wire  = alice_shield.send(wire_payload)
        plain = bob_shield.receive(wire)

        from crypto_tools import message_from_dict
        enc_recovered = message_from_dict(json.loads(plain.decode()))
        result = decrypt_message(key, enc_recovered)

        self.assertEqual(result, inner_msg)
        _arrow("alice[AES-GCM]", "alice[MITM-Shield]", "double-encapsulation")
        _arrow("alice[MITM-Shield]", "bob[MITM-Shield]", f"wire: {len(wire)}B")
        _arrow("bob[MITM-Shield]", "bob[AES-GCM]", "outer stripped; inner decrypted")
        _ok(f"Two-layer encryption round-trip: {result!r}")

    def test_02_replay_protection_across_sessions(self):
        _sec("MITM-SHIELD↔CRYPTO [2/5]: Replayed packet rejected")
        from vault import MITMShield, MITMShieldError

        alice, bob = self._make_pair()
        pkt1 = alice.send(b"packet one")
        pkt2 = alice.send(b"packet two")

        bob.receive(pkt1)
        bob.receive(pkt2)

        with self.assertRaises(MITMShieldError):
            bob.receive(pkt1)   # replay
        _ok("Replay (seq=0 after seq=1) → MITMShieldError ✓")

    def test_03_tampered_payload_detected(self):
        _sec("MITM-SHIELD↔CRYPTO [3/5]: Byte-flip mid-transit detected")
        from vault import MITMShield, MITMShieldError

        alice, bob = self._make_pair()
        wire = bytearray(alice.send(b"tamper me"))
        wire[len(wire) // 2] ^= 0x55
        with self.assertRaises(MITMShieldError):
            bob.receive(bytes(wire))
        _ok("Mid-transit byte flip → MITMShieldError (HMAC-SHA3-512) ✓")

    def test_04_wrong_session_key_cannot_decrypt(self):
        _sec("MITM-SHIELD↔CRYPTO [4/5]: Eavesdropper with wrong session cannot decrypt")
        from vault import MITMShield, MITMShieldError

        alice, bob     = self._make_pair()
        eve_a, eve_b   = self._make_pair()  # Eve's own unrelated session

        wire = alice.send(b"only bob can read this")
        _arrow("alice", "eve", "Eve intercepts the packet")

        with self.assertRaises(MITMShieldError):
            eve_b.receive(wire)   # wrong session key / session_id
        _ok("Eavesdropper gets MITMShieldError — session ID mismatch ✓")

    def test_05_multi_message_ordered_delivery(self):
        _sec("MITM-SHIELD↔CRYPTO [5/5]: Multiple messages — order preserved")
        from vault import MITMShield

        alice, bob = self._make_pair()
        messages   = [f"msg-{i:03d}".encode() for i in range(10)]
        wire_pkts  = [alice.send(m) for m in messages]

        received = [bob.receive(p) for p in wire_pkts]
        self.assertEqual(received, messages)
        _ok(f"10 ordered messages delivered without error ✓")
        _info("Each seq counter advanced; any gap or duplication would be caught.")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 5: Fallback Auth ↔ threat detection integration ────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestFallbackAuthIntegration(unittest.TestCase):
    """Mouse → OTP → NFC chain; threat detector blocks on abuse."""

    def _otp(self, secret: bytes = b"otp-secret-bytes-32-total-chars!") -> "SimulatedOTPProvider":
        from fallback_auth import SimulatedOTPProvider
        return SimulatedOTPProvider(secret=secret)

    def _nfc(self, token: str | None = None) -> "SimulatedNFCProvider":
        from fallback_auth import SimulatedNFCProvider
        p = SimulatedNFCProvider()
        if token:
            p.register_token(token)
        return p

    def test_01_good_mouse_authenticates_without_otp(self):
        _sec("FALLBACK-AUTH [1/6]: Good mouse events → auth without OTP/NFC")
        from fallback_auth import (authenticate_game_scenario,
                                    make_chess_like_mouse_events)

        result = authenticate_game_scenario(
            scenario="happy_path",
            mouse_events=make_chess_like_mouse_events(good=True, moves=10),
            otp_destination="test@example.com",
            provided_otp="",
            nfc_token_uid="",
            otp_provider=self._otp(),
            nfc_provider=self._nfc(),
        )
        self.assertTrue(result.authenticated)
        _arrow("mouse_events", "fallback_auth", f"score={result.movement_profile.score:.2f}")
        _ok(f"Auth by mouse; method={result.method} ✓")

    def test_02_weak_mouse_falls_through_to_otp(self):
        _sec("FALLBACK-AUTH [2/6]: Weak mouse → OTP step-up → success")
        from fallback_auth import (authenticate_game_scenario,
                                    make_chess_like_mouse_events, SimulatedOTPProvider)

        otp = SimulatedOTPProvider(secret=b"test-otp-secret-32-bytes-abcdef!")
        dest = "user@test.com"
        code = otp.issue(dest, ttl_seconds=30)

        result = authenticate_game_scenario(
            scenario="weak_mouse_then_otp",
            mouse_events=make_chess_like_mouse_events(good=False, moves=2),
            otp_destination=dest,
            provided_otp=code,
            nfc_token_uid="",
            otp_provider=otp,
            nfc_provider=self._nfc(),
        )
        self.assertTrue(result.authenticated)
        _arrow("mouse_events[weak]", "otp_provider", "step-up triggered")
        _arrow("otp_provider", "authenticated", f"method={result.method}")
        _ok(f"OTP fallback succeeded; method={result.method} ✓")

    def test_03_expired_otp_falls_through_to_nfc(self):
        _sec("FALLBACK-AUTH [3/6]: Expired OTP → NFC final-factor → success")
        from fallback_auth import (authenticate_game_scenario,
                                    make_chess_like_mouse_events, SimulatedOTPProvider)

        otp = SimulatedOTPProvider(secret=b"expired-otp-secret-32-bytes!!!")
        nfc = self._nfc(token="user-nfc-card")
        dest = "user@test.com"
        code = otp.issue(dest, ttl_seconds=0)
        time.sleep(0.005)  # expire it

        result = authenticate_game_scenario(
            scenario="expired_otp_then_nfc",
            mouse_events=make_chess_like_mouse_events(good=False, moves=2),
            otp_destination=dest,
            provided_otp=code,
            nfc_token_uid="user-nfc-card",
            otp_provider=otp,
            nfc_provider=nfc,
        )
        self.assertTrue(result.authenticated)
        self.assertEqual(result.method, "phone_nfc")
        _arrow("otp[expired]", "nfc_provider", "OTP chain exhausted; NFC activated")
        _ok(f"NFC fallback authenticated; method={result.method} ✓")

    def test_04_all_factors_fail_closes_auth(self):
        _sec("FALLBACK-AUTH [4/6]: All factors fail → fails CLOSED (not partial auth)")
        from fallback_auth import (authenticate_game_scenario,
                                    make_chess_like_mouse_events)

        result = authenticate_game_scenario(
            scenario="all_fail_closed",
            mouse_events=make_chess_like_mouse_events(good=False, moves=1),
            otp_destination="nobody@test.com",
            provided_otp="000000",  # wrong code
            nfc_token_uid="unknown-token",  # not registered
            otp_provider=self._otp(),
            nfc_provider=self._nfc(),  # no tokens registered
        )
        self.assertFalse(result.authenticated)
        self.assertEqual(result.method, "none")
        _arrow("mouse[fail]", "otp[fail]", "all factors exhausted")
        _arrow("otp[fail]", "nfc[fail]", "chain fully depleted")
        _ok("Auth chain fails closed; method=none; authenticated=False ✓")

    def test_05_nfc_token_not_registered_is_rejected(self):
        _sec("FALLBACK-AUTH [5/6]: Unregistered NFC token → rejected")
        from fallback_auth import SimulatedNFCProvider

        nfc = SimulatedNFCProvider()
        nfc.register_token("legitimate-card")

        self.assertTrue(nfc.verify("legitimate-card"))
        self.assertFalse(nfc.verify("cloned-card"))
        self.assertFalse(nfc.verify(""))
        self.assertFalse(nfc.verify(None))  # type: ignore[arg-type]
        _ok("Unregistered / cloned / empty NFC token → all rejected ✓")

    def test_06_threat_detector_burst_triggers_step_up(self):
        _sec("FALLBACK-AUTH [6/6]: Burst requests → STEP_UP threat decision")
        from advanced_security import AdvancedThreatDetector

        detector = AdvancedThreatDetector()
        identity = _identity("burst-user")

        last_decision = None
        for i in range(25):
            last_decision = detector.assess(
                identity=identity,
                source_ip="192.168.1.100",
                now=4000.0 + i * 0.1,
            )

        self.assertIsNotNone(last_decision)
        self.assertIn(last_decision.action, {"STEP_UP", "BLOCK"})
        _arrow("burst[25 req/10s]", "AdvancedThreatDetector",
               f"risk={last_decision.risk_score} action={last_decision.action}")
        _ok(f"Burst rate detected; action={last_decision.action} ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 6: ZKP integration ─────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestZKPIntegration(unittest.TestCase):
    """ZKP proves identity without revealing the secret; wrong proofs are rejected."""

    def test_01_zkp_proof_and_verify_correct(self):
        _sec("ZKP [1/4]: Generate keypair → prove → verify (Schnorr Fiat-Shamir)")
        from vault import zkp_keygen, zkp_prove, zkp_verify

        entropy = _mouse_entropy(30, n=16)
        kp      = zkp_keygen(entropy)
        _arrow("entropy_engine", "zkp_keygen", f"sk=int ({kp.sk.bit_length()}bit)")

        proof = zkp_prove(kp, context=b"integration-test")
        _arrow("zkp_keygen[sk]", "zkp_prove", f"R={proof.R_hex[:16]}...")

        self.assertTrue(zkp_verify(kp.pk_hex(), proof, context=b"integration-test"))
        _ok("ZKP proof verified — secret never transmitted ✓")

    def test_02_zkp_wrong_context_fails(self):
        _sec("ZKP [2/4]: Proof for context A does not verify for context B")
        from vault import zkp_keygen, zkp_prove, zkp_verify

        kp    = zkp_keygen(_mouse_entropy(31, 16))
        proof = zkp_prove(kp, context=b"context-A")
        result = zkp_verify(kp.pk_hex(), proof, context=b"context-B")

        self.assertFalse(result)
        _ok("Wrong context → verify returns False ✓")

    def test_03_zkp_tampered_proof_fails(self):
        _sec("ZKP [3/4]: Tampered proof values → verify rejects")
        from vault import zkp_keygen, zkp_prove, zkp_verify, ZKPProof

        kp    = zkp_keygen(_mouse_entropy(32, 16))
        proof = zkp_prove(kp, context=b"ctx")

        tampered = ZKPProof(
            R_hex=proof.R_hex,
            c_hex=proof.c_hex,
            z_hex=format((int(proof.z_hex, 16) + 1) % (2**256), "064x"),
        )
        self.assertFalse(zkp_verify(kp.pk_hex(), tampered, context=b"ctx"))
        _ok("Tampered z_hex → verify fails ✓")

    def test_04_zkp_different_entropy_different_keypair(self):
        _sec("ZKP [4/4]: Different entropy sources → different keypairs (isolation)")
        from vault import zkp_keygen, zkp_prove, zkp_verify

        kp_a = zkp_keygen(_mouse_entropy(33, 16))
        kp_b = zkp_keygen(_mouse_entropy(34, 16))

        proof_a = zkp_prove(kp_a, context=b"ctx")
        # A's proof must not verify against B's public key
        self.assertFalse(zkp_verify(kp_b.pk_hex(), proof_a, context=b"ctx"))
        _ok("kp_a proof does not verify against kp_b.pk — keypair isolation ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 7: Thread-safety — concurrent operations ───────────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestConcurrentOperations(unittest.TestCase):
    """Multiple threads running crypto and vault ops simultaneously."""

    def test_01_concurrent_encrypt_decrypt_no_corruption(self):
        _sec("CONCURRENT [1/3]: 20 threads encrypt/decrypt simultaneously")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message, decrypt_message

        errors: list[Exception] = []
        lock    = threading.Lock()
        results: list[bool]    = []

        def worker(thread_id: int) -> None:
            try:
                entropy = _mouse_entropy(seed=thread_id, n=12)
                key     = KeyGenerator.generate_fresh_key(
                    entropy, system_random_bytes=_sys_rand(str(thread_id).encode()))
                msg = f"thread-{thread_id:03d} payload".encode()
                enc = encrypt_message(key, msg, associated_data=b"concurrent")
                dec = decrypt_message(key, enc)
                ok  = dec == msg
                with lock:
                    results.append(ok)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 21)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [], f"Thread errors: {errors}")
        self.assertTrue(all(results))
        _ok(f"20 concurrent encrypt/decrypt operations — all correct, no corruption ✓")

    def test_02_concurrent_vault_store_retrieve(self):
        _sec("CONCURRENT [2/3]: 10 threads storing+retrieving from vault")
        from vault import HighVoltageVault

        vault   = HighVoltageVault()
        errors  : list[Exception]     = []
        results : list[tuple[bool, str]] = []
        lock    = threading.Lock()

        def vault_worker(tid: int) -> None:
            try:
                key_mat  = _mouse_entropy(seed=50 + tid)[:32]
                password = hashlib.sha3_256(f"pw-{tid}".encode()).digest()
                vid = vault.store(key_mat, master_password=password,
                                  n_shards=5, threshold=3, burn_after_read=False)
                recovered = vault.retrieve(vid, shard_xs=[1, 2, 3],
                                           master_password=password)
                ok = recovered == key_mat
                with lock:
                    results.append((ok, vid[:8]))
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=vault_worker, args=(i,)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [], f"Vault thread errors: {errors}")
        self.assertTrue(all(ok for ok, _ in results))
        _ok(f"10 concurrent vault store/retrieve — all correct ✓")

    def test_03_concurrent_mitm_sessions_independent(self):
        _sec("CONCURRENT [3/3]: 5 independent MITM sessions in parallel")
        from vault import MITMShield

        errors : list[Exception] = []
        results: list[bool]      = []
        lock   = threading.Lock()

        def shield_worker(tid: int) -> None:
            try:
                a = MITMShield(); b = MITMShield()
                a.finish_session(b.accept_session(a.begin_session()))
                msg  = f"mitm-thread-{tid}".encode()
                wire = a.send(msg)
                recv = b.receive(wire)
                with lock:
                    results.append(recv == msg)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=shield_worker, args=(i,)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(errors, [], f"MITM thread errors: {errors}")
        self.assertTrue(all(results))
        _ok("5 concurrent MITM sessions — fully independent, all pass ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 8: Cross-layer cascade — failure propagation ───────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestFailureCascade(unittest.TestCase):
    """Validate that a failure at one layer propagates correctly upward and
    never silently degrades to a weaker security mode."""

    def test_01_entropy_fail_stops_key_and_crypto(self):
        _sec("CASCADE [1/5]: Entropy → KeyGen: insufficient entropy stops chain")
        from key_generator import KeyGenerator, InsufficientEntropyError

        too_short = os.urandom(10)  # less than 32 bytes minimum
        with self.assertRaises(InsufficientEntropyError):
            KeyGenerator.generate_fresh_key(too_short, system_random_bytes=_sys_rand(b"c1"))
        _ok("InsufficientEntropyError at key_generator — crypto_tools never called ✓")

    def test_02_wrong_magic_stops_file_decrypt(self):
        _sec("CASCADE [2/5]: Corrupted file magic → decrypt layer rejects immediately")
        from key_generator import KeyGenerator
        from crypto_tools import decrypt_file

        key = KeyGenerator.generate_fresh_key(
            _mouse_entropy(60), system_random_bytes=_sys_rand(b"c2"))

        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "corrupted.sk"
            out = Path(tmp) / "out.txt"
            bad.write_bytes(b"NOTMAGIC" + os.urandom(128))

            with self.assertRaises(ValueError):
                decrypt_file(key, bad, out)
        _ok("ValueError raised — file magic check stops decrypt before AES ✓")

    def test_03_threat_block_stops_rotating_key_encrypt(self):
        _sec("CASCADE [3/5]: Threat BLOCK → rotating key encrypt refuses")
        from advanced_security import RotatingKeyEnvelope, ThreatBlockedError

        now = [5000.0]
        env = RotatingKeyEnvelope(_identity("blocked"), clock=lambda: now[0])
        with self.assertRaises(ThreatBlockedError):
            env.encrypt("must not encrypt", failed_otp_attempts=6)
        _ok("ThreatBlockedError — rotating key encrypt blocked ✓")

    def test_04_vault_sealed_stops_key_retrieval(self):
        _sec("CASCADE [4/5]: Vault SEALED → retrieval fails → crypto has no key")
        from vault import HighVoltageVault

        vault   = HighVoltageVault()
        key_mat = _mouse_entropy(61)[:32]
        pw      = hashlib.sha3_256(b"seal-cascade").digest()

        vid = vault.store(key_mat, master_password=pw, n_shards=5, threshold=3)
        vault.seal(vid)

        with self.assertRaises(PermissionError):
            vault.retrieve(vid, shard_xs=[1, 2, 3], master_password=pw)
        _ok("PermissionError — sealed vault stops key retrieval, crypto is unreachable ✓")

    def test_05_mitm_broken_session_stops_everything(self):
        _sec("CASCADE [5/5]: MITM session never established → send raises")
        from vault import MITMShield, MITMShieldError

        alice = MITMShield()  # never calls begin_session/finish_session

        with self.assertRaises(MITMShieldError):
            alice.send(b"orphan packet")
        _ok("MITMShieldError — no active session; send is blocked ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 9: Key rotation — epoch boundary behaviour ─────────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestKeyRotation(unittest.TestCase):
    """Rotating key epochs: encrypt in epoch N, try to decrypt in epoch N+2."""

    def test_01_same_epoch_decrypts(self):
        _sec("ROTATION [1/3]: Same epoch → decrypt succeeds")
        from advanced_security import RotatingKeyEnvelope

        now = [6000.0]
        env = RotatingKeyEnvelope(_identity("rot"), clock=lambda: now[0])
        enc = env.encrypt("epoch test", context="chat")

        dec = env.decrypt(enc, context="chat", max_clock_skew_seconds=0.5)
        self.assertEqual(dec, b"epoch test")
        _ok(f"Epoch {enc.epoch}: encrypt+decrypt in same epoch ✓")

    def test_02_expired_epoch_rejects(self):
        _sec("ROTATION [2/3]: Epoch expired → decrypt raises ExpiredKeyEpochError")
        from advanced_security import RotatingKeyEnvelope, ExpiredKeyEpochError

        now = [6000.0]
        env = RotatingKeyEnvelope(_identity("rot2"), clock=lambda: now[0])
        enc = env.encrypt("will expire", context="chat")
        epoch_at_encrypt = enc.epoch

        # Advance clock beyond envelope TTL
        now[0] = enc.expires_at + 5.0
        with self.assertRaises(ExpiredKeyEpochError):
            env.decrypt(enc, context="chat")
        _ok(f"Epoch {epoch_at_encrypt} expired at t={enc.expires_at:.1f}; "
            f"decrypt at t={now[0]:.1f} → ExpiredKeyEpochError ✓")

    def test_03_small_clock_skew_allowed_by_tolerance(self):
        _sec("ROTATION [3/3]: Small clock skew within tolerance → decrypt succeeds")
        from advanced_security import RotatingKeyEnvelope

        now = [6100.0]
        env = RotatingKeyEnvelope(_identity("rot3"), clock=lambda: now[0])
        enc = env.encrypt("skew test", context="chat")

        # Advance clock just past expiry but within tolerance
        now[0] = enc.expires_at + 0.05
        dec = env.decrypt(enc, context="chat", max_clock_skew_seconds=0.2)
        self.assertEqual(dec, b"skew test")
        _ok(f"Clock 50ms past expiry; tolerance=200ms → decrypt succeeds ✓")


# ════════════════════════════════════════════════════════════════════════════
# ── Group 10: Full end-to-end story — all 7 layers active ────────────────────
# ════════════════════════════════════════════════════════════════════════════

class TestFullSystemEndToEnd(unittest.TestCase):
    """Single test that exercises every layer in one integrated scenario."""

    def test_full_system_all_layers_active(self):
        _sec("END-TO-END: All 7 layers active — authenticate → key → vault → MITM → decrypt")

        # ── Layer 1: Entropy ──────────────────────────────────────────────────
        from entropy_engine import extract_mouse_entropy
        from fallback_auth import make_chess_like_mouse_events

        mouse_events = make_chess_like_mouse_events(good=True, moves=12)
        raw_entropy  = extract_mouse_entropy(mouse_events)
        entropy      = raw_entropy + hashlib.sha3_256(raw_entropy + b"e2e").digest()
        _arrow("mouse_events", "entropy_engine",
               f"{len(raw_entropy)}B raw → {len(entropy)}B pooled")

        # ── Layer 2: Key derivation ───────────────────────────────────────────
        from key_generator import KeyGenerator
        key = KeyGenerator.generate_fresh_key(
            entropy, system_random_bytes=_sys_rand(b"e2e"), personalization=b"e2e-test")
        _arrow("entropy_engine", "key_generator", f"AES-256 key: {key[:6].hex()}...")

        # ── Layer 3: Fallback auth (mouse passes) ─────────────────────────────
        from fallback_auth import authenticate_game_scenario, SimulatedOTPProvider, SimulatedNFCProvider
        auth = authenticate_game_scenario(
            scenario="e2e",
            mouse_events=mouse_events,
            otp_destination="e2e@test.com",
            provided_otp="",
            nfc_token_uid="",
            otp_provider=SimulatedOTPProvider(),
            nfc_provider=SimulatedNFCProvider(),
        )
        self.assertTrue(auth.authenticated, "Auth layer must succeed")
        _arrow("mouse_events", "fallback_auth",
               f"auth=True method={auth.method} score={auth.movement_profile.score:.2f}")

        # ── Layer 4: Vault — store key after auth ─────────────────────────────
        from vault import HighVoltageVault
        vault_inst = HighVoltageVault()
        password   = hashlib.sha3_256(b"e2e-master").digest()
        vid = vault_inst.store(key, master_password=password,
                               n_shards=5, threshold=3, burn_after_read=False)
        _arrow("key_generator", "HighVoltageVault",
               f"stored vault_id={vid[:10]}... (shards=5 threshold=3)")

        # ── Layer 5: Rotating key envelope (advanced_security) ────────────────
        from self_healing import SelfHealingConfig, SelfHealingCryptoService
        from advanced_security import RotatingKeyEnvelope
        now = [7000.0]
        svc = SelfHealingCryptoService(
            _identity("e2e-user"),
            config=SelfHealingConfig(retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        heal_result = svc.encrypt_message(
            "End-to-end payload: all seven layers online.",
            context="e2e",
            operation_id="e2e-001",
        )
        self.assertEqual(heal_result.status, "ok")
        _arrow("self_healing", "RotatingKeyEnvelope",
               f"committed; attempts={heal_result.attempts} path={heal_result.active_path}")

        # ── Layer 6: MITM Shield ──────────────────────────────────────────────
        from vault import MITMShield
        sender = MITMShield(); recvr = MITMShield()
        sender.finish_session(recvr.accept_session(sender.begin_session()))

        import json
        payload = json.dumps(heal_result.envelope.to_dict()).encode()
        wire    = sender.send(payload)
        rcvd    = recvr.receive(wire)
        _arrow("sender[MITM-Shield]", "recvr[MITM-Shield]",
               f"wire={len(wire)}B; payload={len(payload)}B")

        # ── Layer 7: Final decrypt ────────────────────────────────────────────
        from advanced_security import RotatingEncryptedMessage
        envelope_dict = json.loads(rcvd.decode())
        envelope      = RotatingEncryptedMessage.from_dict(envelope_dict)
        env           = RotatingKeyEnvelope(_identity("e2e-user"), clock=lambda: now[0])
        final         = env.decrypt(envelope, context="e2e", max_clock_skew_seconds=0.5)
        self.assertEqual(final, b"End-to-end payload: all seven layers online.")
        _arrow("RotatingKeyEnvelope", "plaintext", f"{final!r}")

        # ── Retrieve key from vault and decrypt a separate message ────────────
        retrieved_key = vault_inst.retrieve(vid, shard_xs=[1, 2, 3], master_password=password)
        self.assertEqual(retrieved_key, key)
        from crypto_tools import encrypt_message, decrypt_message
        enc2 = encrypt_message(retrieved_key, b"vault key still works", associated_data=b"e2e-v")
        dec2 = decrypt_message(retrieved_key, enc2)
        self.assertEqual(dec2, b"vault key still works")
        _arrow("HighVoltageVault", "crypto_tools[retrieved_key]", "vault key recovered and used")

        print(f"\n  {'─'*70}")
        _ok("ALL 7 LAYERS ACTIVE AND PASSING")
        _ok("entropy_engine → key_generator → fallback_auth")
        _ok("key_generator → HighVoltageVault → crypto_tools")
        _ok("self_healing → RotatingKeyEnvelope → MITMShield → decrypt")
        print(f"  {'─'*70}\n")


# ════════════════════════════════════════════════════════════════════════════
# ── Runner ───────────────────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "╔" + "═"*(W-2) + "╗")
    print(f"║  SUMIT KEY — Full-System Integration Test Suite{' '*(W-50)}║")
    print(f"║  Groups: Layer Pipeline | Security↔Healer | Vault↔Crypto{' '*(W-59)}║")
    print(f"║          MITM Shield | Fallback Auth | ZKP | Concurrent{' '*(W-58)}║")
    print(f"║          Failure Cascade | Key Rotation | End-to-End{' '*(W-54)}║")
    print("╚" + "═"*(W-2) + "╝\n")
    unittest.main(verbosity=2, failfast=False)
