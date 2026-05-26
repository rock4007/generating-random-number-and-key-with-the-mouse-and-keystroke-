"""Black-box security tests for SUMIT KEY.

These tests exercise externally visible behaviour rather than implementation
details: fresh key generation should not repeat, small input changes should
strongly alter outputs, malformed entropy should be rejected, and AES-GCM
helpers should authenticate ciphertexts when the optional crypto dependency is
installed.
"""

from __future__ import annotations

import unittest

from key_generator import EntropyHealthError, HKDFConfig, KeyGenerator


def _hamming_distance(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


class FreshKeyBlackBoxTests(unittest.TestCase):
    def test_fresh_generation_does_not_repeat_for_same_behaviour(self) -> None:
        behaviour = bytes(range(32))
        keys = {
            KeyGenerator.generate_fresh_key(behaviour, personalization=b"repeat-check")
            for _ in range(128)
        }

        self.assertEqual(len(keys), 128)

    def test_fixed_external_randomness_is_reproducible_for_tests(self) -> None:
        behaviour = bytes(range(32))
        system_random = bytes(reversed(range(32)))

        first = KeyGenerator.generate_fresh_key(
            behaviour,
            system_random_bytes=system_random,
            personalization=b"deterministic-test",
        )
        second = KeyGenerator.generate_fresh_key(
            behaviour,
            system_random_bytes=system_random,
            personalization=b"deterministic-test",
        )

        self.assertEqual(first, second)

    def test_one_bit_change_has_large_avalanche(self) -> None:
        system_random = bytes(range(32))
        left_behaviour = bytearray(range(32))
        right_behaviour = bytearray(left_behaviour)
        right_behaviour[0] ^= 0x01

        left_key = KeyGenerator.generate_fresh_key(
            left_behaviour,
            system_random_bytes=system_random,
            personalization=b"avalanche",
        )
        right_key = KeyGenerator.generate_fresh_key(
            right_behaviour,
            system_random_bytes=system_random,
            personalization=b"avalanche",
        )

        self.assertGreaterEqual(_hamming_distance(left_key, right_key), 96)

    def test_quantum_profile_returns_512_bits(self) -> None:
        key = KeyGenerator.generate_fresh_quantum_hardened_key(
            bytes(range(32)),
            system_random_bytes=bytes(reversed(range(32))),
            personalization=b"quantum-size",
        )

        self.assertEqual(len(key), 64)

    def test_entropy_health_rejects_constant_input(self) -> None:
        with self.assertRaises(EntropyHealthError):
            KeyGenerator.generate_fresh_key(
                b"\x00" * 32,
                system_random_bytes=bytes(range(32)),
            )

    def test_custom_config_length_is_honoured(self) -> None:
        config = HKDFConfig(
            salt=b"SUMIT_KEY_TEST",
            info=b"blackbox-length",
            length=48,
            min_entropy_bytes=32,
        )
        key = KeyGenerator.generate_fresh_key(
            bytes(range(32)),
            config=config,
            system_random_bytes=bytes(reversed(range(32))),
        )

        self.assertEqual(len(key), 48)


class EncryptionBlackBoxTests(unittest.TestCase):
    def test_aes_gcm_round_trip_and_tamper_rejection(self) -> None:
        try:
            from cryptography.exceptions import InvalidTag
            from crypto_tools import EncryptedMessage, decrypt_message, encrypt_message
        except ModuleNotFoundError:
            self.skipTest("cryptography is not installed")

        key = KeyGenerator.generate_fresh_key(
            bytes(range(32)),
            system_random_bytes=bytes(reversed(range(32))),
            personalization=b"encryption",
        )
        encrypted = encrypt_message(key, b"secret payload", associated_data=b"context")

        self.assertEqual(decrypt_message(key, encrypted), b"secret payload")

        tampered = EncryptedMessage(
            nonce=encrypted.nonce,
            ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
            associated_data=encrypted.associated_data,
        )
        with self.assertRaises(InvalidTag):
            decrypt_message(key, tampered)


class RotatingKeyThreatTests(unittest.TestCase):
    def _identity(self, user: str = "alice", device: str = "device-a"):
        from advanced_security import SystemIdentity

        return SystemIdentity(
            user_id=user,
            device_id=device,
            device_secret=bytes(range(32)),
            session_id="session-001",
        )

    def test_rotating_key_changes_after_point_three_seconds(self) -> None:
        from advanced_security import RotatingKeyEnvelope

        current_time = [100.0]
        envelope = RotatingKeyEnvelope(
            self._identity(),
            clock=lambda: current_time[0],
        )

        key_epoch_a = envelope.derive_epoch_key(context=b"message")
        current_time[0] += 0.31
        key_epoch_b = envelope.derive_epoch_key(context=b"message")

        self.assertNotEqual(key_epoch_a, key_epoch_b)

    def test_message_decrypts_before_expiry_and_fails_after(self) -> None:
        from advanced_security import ExpiredKeyEpochError, RotatingKeyEnvelope

        current_time = [100.0]
        envelope = RotatingKeyEnvelope(
            self._identity(),
            clock=lambda: current_time[0],
        )

        encrypted = envelope.encrypt("short lived secret", context="chat")
        self.assertEqual(envelope.decrypt(encrypted, context="chat"), b"short lived secret")

        current_time[0] = encrypted.expires_at + 0.001
        with self.assertRaises(ExpiredKeyEpochError):
            envelope.decrypt(encrypted, context="chat")

    def test_individual_system_identity_separates_keys(self) -> None:
        from cryptography.exceptions import InvalidTag
        from advanced_security import RotatingKeyEnvelope, SystemIdentity

        current_time = [250.0]
        alice = RotatingKeyEnvelope(self._identity(), clock=lambda: current_time[0])
        other_identity = SystemIdentity(
            user_id="alice",
            device_id="device-b",
            device_secret=bytes(reversed(range(32))),
            session_id="session-001",
        )
        bob_device = RotatingKeyEnvelope(other_identity, clock=lambda: current_time[0])

        encrypted = alice.encrypt(b"device-bound message", context="device-test")
        with self.assertRaises(ValueError):
            bob_device.decrypt(encrypted, context="device-test")

        # Same AAD and ciphertext still fail under a wrong epoch key if identity
        # checks are bypassed by malformed data.
        tampered = encrypted.to_dict()
        tampered["identity_hash"] = bob_device.identity_hash()
        from advanced_security import RotatingEncryptedMessage

        with self.assertRaises(InvalidTag):
            bob_device.decrypt(RotatingEncryptedMessage.from_dict(tampered), context="device-test")

    def test_threat_detector_blocks_replay_message_id(self) -> None:
        from advanced_security import RotatingKeyEnvelope, ThreatBlockedError

        current_time = [300.0]
        envelope = RotatingKeyEnvelope(
            self._identity(),
            clock=lambda: current_time[0],
        )

        envelope.encrypt("first", message_id="msg-1")
        with self.assertRaises(ThreatBlockedError):
            envelope.encrypt("replay", message_id="msg-1")

    def test_threat_detector_step_up_for_weak_mouse(self) -> None:
        from advanced_security import AdvancedThreatDetector

        detector = AdvancedThreatDetector()
        weak_mouse = [{"x": 1.0, "y": 1.0, "velocity_px_per_s": 0.0, "direction_angle_deg": 0.0}]
        decision = detector.assess(
            identity=self._identity(),
            mouse_events=weak_mouse,
            now=500.0,
        )

        self.assertEqual(decision.action, "STEP_UP")
        self.assertGreaterEqual(decision.risk_score, 35)


if __name__ == "__main__":
    unittest.main(verbosity=2)
