"""Adversarial scenario tests for SUMIT KEY.

This suite is an objection matrix: each test covers a realistic concern a
reviewer might raise about message encryption, file encryption, rotating keys,
fallback auth, threat detection, dashboard visibility, or NIST-test plumbing.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from cryptography.exceptions import InvalidTag


class MessageEncryptionObjections(unittest.TestCase):
    def _key(self) -> bytes:
        from key_generator import KeyGenerator

        return KeyGenerator.generate_fresh_key(
            bytes(range(32)),
            system_random_bytes=bytes(reversed(range(32))),
            personalization=b"adversarial-message",
        )

    def test_wrong_aad_rejected(self) -> None:
        from crypto_tools import EncryptedMessage, decrypt_message, encrypt_message

        encrypted = encrypt_message(self._key(), b"aad-bound", associated_data=b"correct-context")
        wrong_context = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext,
            associated_data=b"wrong-context",
        )
        with self.assertRaises(InvalidTag):
            decrypt_message(self._key(), wrong_context)

    def test_truncated_ciphertext_rejected(self) -> None:
        from crypto_tools import EncryptedMessage, decrypt_message, encrypt_message

        encrypted = encrypt_message(self._key(), b"truncate-me", associated_data=b"context")
        truncated = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext[:-4],
            associated_data=encrypted.associated_data,
        )
        with self.assertRaises(InvalidTag):
            decrypt_message(self._key(), truncated)

    def test_empty_message_round_trip(self) -> None:
        from crypto_tools import decrypt_message, encrypt_message

        encrypted = encrypt_message(self._key(), b"", associated_data=b"empty")
        self.assertEqual(decrypt_message(self._key(), encrypted), b"")


class FileEncryptionObjections(unittest.TestCase):
    def _key(self) -> bytes:
        from key_generator import KeyGenerator

        return KeyGenerator.generate_quantum_hardened_key(bytes(range(32)))

    def test_wrong_file_magic_rejected(self) -> None:
        from crypto_tools import decrypt_file

        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.sumitkey"
            out = Path(tmp) / "out.txt"
            bad.write_bytes(b"NOTSUMIT" + b"\x00" * 64)
            with self.assertRaises(ValueError):
                decrypt_file(self._key(), bad, out)

    def test_binary_file_round_trip(self) -> None:
        from crypto_tools import decrypt_file, encrypt_file

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "blob.bin"
            enc = Path(tmp) / "blob.bin.sumitkey"
            dec = Path(tmp) / "blob.dec"
            data = bytes(range(256)) * 1024
            src.write_bytes(data)
            encrypt_file(self._key(), src, enc)
            decrypt_file(self._key(), enc, dec)
            self.assertEqual(dec.read_bytes(), data)


class RotatingKeyObjections(unittest.TestCase):
    def _identity(self):
        from advanced_security import SystemIdentity

        return SystemIdentity(
            user_id="reviewer",
            device_id="device-review",
            device_secret=bytes(range(32)),
            session_id="session-review",
        )

    def test_wrong_context_rejected(self) -> None:
        from advanced_security import RotatingKeyEnvelope

        now = [1000.0]
        envelope = RotatingKeyEnvelope(self._identity(), clock=lambda: now[0])
        encrypted = envelope.encrypt("context-bound", context="chat")
        with self.assertRaises(InvalidTag):
            envelope.decrypt(encrypted, context="file")

    def test_clock_skew_can_be_explicitly_allowed(self) -> None:
        from advanced_security import RotatingKeyEnvelope

        now = [1200.0]
        envelope = RotatingKeyEnvelope(self._identity(), clock=lambda: now[0])
        encrypted = envelope.encrypt("skew-ok", context="chat")
        now[0] = encrypted.expires_at + 0.05
        self.assertEqual(
            envelope.decrypt(encrypted, context="chat", max_clock_skew_seconds=0.1),
            b"skew-ok",
        )

    def test_impossible_mouse_velocity_blocks(self) -> None:
        from advanced_security import RotatingKeyEnvelope, ThreatBlockedError

        now = [1300.0]
        envelope = RotatingKeyEnvelope(self._identity(), clock=lambda: now[0])
        mouse = [
            {"x": 0.0, "y": 0.0, "velocity_px_per_s": 0.0, "direction_angle_deg": 0.0},
            {"x": 1_000_000.0, "y": 0.0, "velocity_px_per_s": 100_000.0, "direction_angle_deg": 0.0},
        ]
        with self.assertRaises(ThreatBlockedError):
            envelope.encrypt("blocked", mouse_events=mouse)

    def test_otp_bruteforce_blocks_encryption(self) -> None:
        from advanced_security import RotatingKeyEnvelope, ThreatBlockedError

        envelope = RotatingKeyEnvelope(self._identity(), clock=lambda: 1400.0)
        with self.assertRaises(ThreatBlockedError):
            envelope.encrypt("blocked", failed_otp_attempts=5)

    def test_burst_rate_triggers_step_up(self) -> None:
        from advanced_security import AdvancedThreatDetector

        detector = AdvancedThreatDetector()
        identity = self._identity()
        decision = None
        for index in range(21):
            decision = detector.assess(
                identity=identity,
                source_ip="10.0.0.1",
                now=1500.0 + index * 0.01,
            )
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, "STEP_UP")


class SelfHealingObjections(unittest.TestCase):
    def _identity(self, name: str = "primary"):
        from advanced_security import SystemIdentity

        return SystemIdentity(
            user_id="healing-reviewer",
            device_id=f"device-{name}",
            device_secret=bytes(range(32)) if name == "primary" else bytes(reversed(range(32))),
            session_id="healing-session",
        )

    def test_mid_operation_verify_fault_retries_and_commits(self) -> None:
        from advanced_security import RotatingKeyEnvelope
        from self_healing import SelfHealingConfig, SelfHealingCryptoService

        now = [2000.0]
        service = SelfHealingCryptoService(
            self._identity(),
            config=SelfHealingConfig(max_retries=1, retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        result = service.encrypt_message(
            "recover after verify outage",
            context="chat",
            operation_id="heal-verify-once",
            failpoints={"verify_once"},
        )

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.recovered)
        self.assertEqual(result.active_path, "primary")
        self.assertEqual(result.attempts, 2)
        envelope = RotatingKeyEnvelope(self._identity(), clock=lambda: now[0])
        self.assertEqual(envelope.decrypt(result.envelope, context="chat"), b"recover after verify outage")

    def test_primary_path_outage_fails_over_to_backup_identity(self) -> None:
        from advanced_security import RotatingKeyEnvelope
        from self_healing import SelfHealingConfig, SelfHealingCryptoService

        now = [2100.0]
        service = SelfHealingCryptoService(
            self._identity("primary"),
            backup_identity=self._identity("backup"),
            config=SelfHealingConfig(max_retries=0, retry_backoff_seconds=0.0),
            clock=lambda: now[0],
        )
        result = service.encrypt_message(
            "backup device recovered",
            context="message",
            operation_id="heal-backup",
            failpoints={"primary_encrypt"},
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.active_path, "backup")
        self.assertTrue(result.recovered)
        backup = RotatingKeyEnvelope(self._identity("backup"), clock=lambda: now[0])
        self.assertEqual(backup.decrypt(result.envelope, context="message"), b"backup device recovered")

    def test_self_healing_does_not_bypass_threat_blocks(self) -> None:
        from self_healing import SelfHealingConfig, SelfHealingCryptoService, UnrecoverableSecurityError

        service = SelfHealingCryptoService(
            self._identity(),
            backup_identity=self._identity("backup"),
            config=SelfHealingConfig(max_retries=1, retry_backoff_seconds=0.0),
            clock=lambda: 2200.0,
        )
        with self.assertRaises(UnrecoverableSecurityError):
            service.encrypt_message(
                "must not heal around brute force",
                failed_otp_attempts=5,
                operation_id="heal-threat-block",
            )

    def test_self_healing_journal_can_resume_status(self) -> None:
        from self_healing import SelfHealingConfig, SelfHealingCryptoService

        with tempfile.TemporaryDirectory() as tmp:
            journal = Path(tmp) / "healing.jsonl"
            service = SelfHealingCryptoService(
                self._identity(),
                config=SelfHealingConfig(journal_path=journal, retry_backoff_seconds=0.0),
                clock=lambda: 2300.0,
            )
            result = service.encrypt_message("journaled", operation_id="heal-journal")
            status = service.resume_status("heal-journal")

        self.assertEqual(result.status, "ok")
        self.assertEqual(status["last_stage"], "commit")
        self.assertEqual(status["last_status"], "ok")
        self.assertGreaterEqual(status["event_count"], 4)


class FallbackAuthObjections(unittest.TestCase):
    def test_expired_otp_fails_and_nfc_can_recover(self) -> None:
        from fallback_auth import (
            SimulatedNFCProvider,
            SimulatedOTPProvider,
            authenticate_game_scenario,
            make_chess_like_mouse_events,
        )

        otp = SimulatedOTPProvider(secret=b"expired-otp-secret-32-bytes!!!")
        nfc = SimulatedNFCProvider()
        nfc.register_token("phone-token")
        destination = "user@example.com"
        code = otp.issue(destination, ttl_seconds=0)
        time.sleep(0.001)
        result = authenticate_game_scenario(
            scenario="expired_otp_then_nfc",
            mouse_events=make_chess_like_mouse_events(good=False, moves=2),
            otp_destination=destination,
            provided_otp=code,
            nfc_token_uid="phone-token",
            otp_provider=otp,
            nfc_provider=nfc,
        )
        self.assertTrue(result.authenticated)
        self.assertEqual(result.method, "phone_nfc")

    def test_all_fallbacks_fail_closed(self) -> None:
        from fallback_auth import (
            SimulatedNFCProvider,
            SimulatedOTPProvider,
            authenticate_game_scenario,
            make_chess_like_mouse_events,
        )

        result = authenticate_game_scenario(
            scenario="all_fail_closed",
            mouse_events=make_chess_like_mouse_events(good=False, moves=1),
            otp_destination="user@example.com",
            provided_otp="123456",
            nfc_token_uid="unknown",
            otp_provider=SimulatedOTPProvider(secret=b"fail-secret-32-bytes!!!!!!!!"),
            nfc_provider=SimulatedNFCProvider(),
        )
        self.assertFalse(result.authenticated)
        self.assertEqual(result.method, "none")


class DashboardAndNistObjections(unittest.TestCase):
    def test_dashboard_shows_full_process_and_key_non_disclosure(self) -> None:
        html = Path("dashboard.html").read_text(encoding="utf-8")
        for marker in (
            "Sender Process",
            "Encrypted Packet",
            "Receiver / Storage Check",
            "not sent: raw AES key",
            "Start 1-Min Scheduler",
            "Self-Healing Recovery",
            "retry transient faults, never bypass BLOCK",
            "volunteer prototype",
            "malware can steal plaintext before encryption",
            "derived key fingerprint",
            "Ghost Key Handoff",
            "A second device cannot recreate the same key",
            "ghost key status: cleared from receiver memory after decrypt",
            "AES-GCM",
        ):
            self.assertIn(marker, html)
        self.assertNotIn("system secret preview", html)
        self.assertNotIn("latestMouseKeyHex", html)
        self.assertNotIn("latestKeystrokeKeyHex", html)

    def test_security_limitations_are_documented_for_volunteers(self) -> None:
        security = Path("SECURITY_LIMITATIONS.md").read_text(encoding="utf-8")
        for marker in (
            "not enough as the only secret",
            "not a hardened production vault",
            "malware",
            "must not be printed, logged, stored",
            "nonce uniqueness",
            "different device cannot recreate",
            "clears the key from memory",
            "passkeys, FIDO2/WebAuthn",
            "not official validation",
        ):
            self.assertIn(marker, security)

    def test_netlify_deploy_publishes_only_static_dashboard(self) -> None:
        config = Path("netlify.toml").read_text(encoding="utf-8")
        self.assertIn('publish = "dist"', config)
        self.assertIn("dashboard-complete.html dist/index.html", config)
        self.assertIn("dashboard.html dist/dashboard.html", config)
        self.assertIn("404.html dist/404.html", config)

        dashboard = Path("dashboard.html").read_text(encoding="utf-8")
        self.assertIn("startPrototype", dashboard)
        self.assertIn("demo paused", dashboard)
        self.assertIn("togglePrototype", dashboard)
        self.assertIn("keypressCount", dashboard)
        self.assertIn("admin transparency", dashboard)

    def test_nist_sequence_default_uses_full_battery_size(self) -> None:
        import nist_validator

        self.assertEqual(
            nist_validator.DEFAULT_SEQUENCE_BITS,
            nist_validator.FULL_BATTERY_RECOMMENDED_BITS,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
