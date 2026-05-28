# Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved.
# PROPRIETARY AND CONFIDENTIAL — see LICENSE (Part A) for terms.
# Unauthorised copying, modification, distribution, or use is strictly prohibited.

"""advanced_security.py — Rotating-key encryption and threat detection.

High-security message flow:
1. Build an individual system identity from device/user/session material.
2. Derive an AES-256-GCM key for the current 0.3-second epoch.
3. Bind ciphertext to device, user, session, epoch, and risk decision using AAD.
4. Rotate automatically on the next epoch; old envelopes expire after TTL.
5. Run threat detection before encryption and block high-risk sessions.

This module is local/sandbox safe. It does not transmit telemetry, OTP, or
hardware secrets. Production deployments should protect device secrets in a
TPM/Secure Enclave/Keychain and stream threat events to a SIEM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import os
import platform
import socket
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROTATION_SECONDS = 0.3
AAD_VERSION = "SUMIT-ROTATE-AAD-v1"


class ThreatBlockedError(Exception):
    """Raised when a message is blocked by threat policy."""


class ExpiredKeyEpochError(Exception):
    """Raised when a rotating-key envelope is outside its allowed lifetime."""


@dataclass(frozen=True)
class SystemIdentity:
    """Per-system identity material for key derivation."""

    user_id: str
    device_id: str
    device_secret: bytes
    session_id: str

    @classmethod
    def from_current_system(
        cls,
        *,
        user_id: str,
        session_id: str | None = None,
        device_secret: bytes | None = None,
    ) -> "SystemIdentity":
        """Create identity from local platform data plus a secret.

        The generated secret is process-local unless supplied. Persist it in a
        protected store if stable keys must survive process restarts.
        """

        if not user_id:
            raise ValueError("user_id must not be empty")
        host = socket.gethostname()
        platform_blob = "|".join(
            [
                platform.system(),
                platform.release(),
                platform.machine(),
                host,
            ]
        )
        device_id = hashlib.sha256(platform_blob.encode("utf-8")).hexdigest()
        active_secret = device_secret if device_secret is not None else os.urandom(32)
        if len(active_secret) < 32:
            raise ValueError("device_secret must be at least 32 bytes")
        active_session = session_id if session_id is not None else os.urandom(16).hex()
        return cls(
            user_id=user_id,
            device_id=device_id,
            device_secret=bytes(active_secret),
            session_id=active_session,
        )


@dataclass(frozen=True)
class ThreatSignal:
    """One observed security signal."""

    name: str
    severity: int
    detail: str


@dataclass(frozen=True)
class ThreatDecision:
    """Risk decision produced before encryption."""

    risk_score: int
    action: str
    signals: tuple[ThreatSignal, ...]

    @property
    def allowed(self) -> bool:
        return self.action in {"ALLOW", "STEP_UP"}


@dataclass(frozen=True)
class RotatingEncryptedMessage:
    """Envelope encrypted under one 0.3-second key epoch."""

    version: int
    algorithm: str
    epoch: int
    issued_at: float
    expires_at: float
    nonce: bytes
    ciphertext: bytes
    aad: bytes
    identity_hash: str
    threat_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "epoch": self.epoch,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce_hex": self.nonce.hex(),
            "ciphertext_hex": self.ciphertext.hex(),
            "aad_hex": self.aad.hex(),
            "identity_hash": self.identity_hash,
            "threat_action": self.threat_action,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RotatingEncryptedMessage":
        return cls(
            version=int(data["version"]),
            algorithm=str(data["algorithm"]),
            epoch=int(data["epoch"]),
            issued_at=float(data["issued_at"]),
            expires_at=float(data["expires_at"]),
            nonce=bytes.fromhex(str(data["nonce_hex"])),
            ciphertext=bytes.fromhex(str(data["ciphertext_hex"])),
            aad=bytes.fromhex(str(data["aad_hex"])),
            identity_hash=str(data["identity_hash"]),
            threat_action=str(data["threat_action"]),
        )


class AdvancedThreatDetector:
    """Risk engine for movement, request, replay, and environment anomalies."""

    def __init__(self, *, block_threshold: int = 90, step_up_threshold: int = 45) -> None:
        self.block_threshold = block_threshold
        self.step_up_threshold = step_up_threshold
        self._seen_message_ids: set[str] = set()
        self._seen_message_ids_limit = 100_000   # evict oldest half when full
        self._recent_attempts: dict[str, list[float]] = {}

    def assess(
        self,
        *,
        identity: SystemIdentity,
        mouse_events: list[dict[str, Any]] | None = None,
        message_id: str | None = None,
        source_ip: str = "local",
        failed_otp_attempts: int = 0,
        nfc_required_but_missing: bool = False,
        now: float | None = None,
    ) -> ThreatDecision:
        """Assess a session and return ALLOW, STEP_UP, or BLOCK."""

        current = time.time() if now is None else float(now)
        signals: list[ThreatSignal] = []

        if message_id:
            if message_id in self._seen_message_ids:
                signals.append(ThreatSignal("replay_message_id", 95, "message id was already used"))
            else:
                if len(self._seen_message_ids) >= self._seen_message_ids_limit:
                    # Discard the oldest half to bound memory use.
                    keep = set(list(self._seen_message_ids)[self._seen_message_ids_limit // 2:])
                    self._seen_message_ids = keep
                self._seen_message_ids.add(message_id)

        key = f"{identity.user_id}|{source_ip}"
        attempts = [ts for ts in self._recent_attempts.get(key, []) if current - ts < 10.0]
        attempts.append(current)
        self._recent_attempts[key] = attempts
        if len(attempts) > 20:
            signals.append(ThreatSignal("burst_rate", 45, f"{len(attempts)} attempts in 10 seconds"))

        if failed_otp_attempts >= 5:
            signals.append(ThreatSignal("otp_bruteforce", 90, f"{failed_otp_attempts} failed OTP attempts"))
        elif failed_otp_attempts >= 2:
            signals.append(ThreatSignal("otp_retries", 35, f"{failed_otp_attempts} failed OTP attempts"))

        if nfc_required_but_missing:
            signals.append(ThreatSignal("missing_required_nfc", 75, "NFC was required but absent"))

        if mouse_events is not None:
            movement_signals = self._assess_mouse(mouse_events)
            signals.extend(movement_signals)

        risk_score = min(100, sum(signal.severity for signal in signals))
        if risk_score >= self.block_threshold:
            action = "BLOCK"
        elif risk_score >= self.step_up_threshold:
            action = "STEP_UP"
        else:
            action = "ALLOW"

        return ThreatDecision(
            risk_score=risk_score,
            action=action,
            signals=tuple(signals),
        )

    @staticmethod
    def _assess_mouse(mouse_events: list[dict[str, Any]]) -> list[ThreatSignal]:
        signals: list[ThreatSignal] = []
        velocities = [float(event.get("velocity_px_per_s", 0.0)) for event in mouse_events]
        if len(mouse_events) < 8:
            signals.append(ThreatSignal("low_mouse_activity", 45, "too few mouse events"))
            if max(velocities, default=0.0) > 80_000:
                signals.append(ThreatSignal("impossible_mouse_velocity", 70, "mouse velocity is implausibly high"))
            return signals

        unique_positions = len(
            {
                (round(float(event.get("x", 0.0)), 1), round(float(event.get("y", 0.0)), 1))
                for event in mouse_events
            }
        )
        if unique_positions <= 2:
            signals.append(ThreatSignal("static_mouse_path", 65, "mouse positions barely changed"))

        if max(velocities, default=0.0) > 80_000:
            signals.append(ThreatSignal("impossible_mouse_velocity", 70, "mouse velocity is implausibly high"))

        direction_changes = 0
        previous_direction: float | None = None
        for event in mouse_events:
            direction = float(event.get("direction_angle_deg", 0.0))
            if previous_direction is not None:
                diff = abs(direction - previous_direction) % 360.0
                diff = diff if diff <= 180.0 else 360.0 - diff
                if diff >= 20.0:
                    direction_changes += 1
            previous_direction = direction
        if direction_changes == 0:
            signals.append(ThreatSignal("linear_mouse_path", 35, "no meaningful direction changes"))

        return signals


class RotatingKeyEnvelope:
    """Encrypt/decrypt messages with 0.3-second per-system rotating keys."""

    def __init__(
        self,
        identity: SystemIdentity,
        *,
        rotation_seconds: float = ROTATION_SECONDS,
        clock: Callable[[], float] | None = None,
        threat_detector: AdvancedThreatDetector | None = None,
    ) -> None:
        if rotation_seconds <= 0:
            raise ValueError("rotation_seconds must be positive")
        self.identity = identity
        self.rotation_seconds = float(rotation_seconds)
        self.clock = clock if clock is not None else time.time
        self.threat_detector = threat_detector if threat_detector is not None else AdvancedThreatDetector()

    def current_epoch(self, now: float | None = None) -> int:
        active_now = self.clock() if now is None else float(now)
        return int(math.floor(active_now / self.rotation_seconds))

    def derive_epoch_key(
        self,
        *,
        epoch: int | None = None,
        context: bytes = b"",
    ) -> bytes:
        """Derive the AES-256 key for one epoch and context."""

        active_epoch = self.current_epoch() if epoch is None else int(epoch)
        ikm = b"|".join(
            [
                b"SUMIT_ROTATING_KEY_V1",
                self.identity.user_id.encode("utf-8"),
                self.identity.device_id.encode("utf-8"),
                self.identity.session_id.encode("utf-8"),
                str(active_epoch).encode("ascii"),
                context,
            ]
        )
        return hmac.new(self.identity.device_secret, ikm, hashlib.sha3_256).digest()

    def encrypt(
        self,
        plaintext: str | bytes,
        *,
        context: str = "message",
        mouse_events: list[dict[str, Any]] | None = None,
        message_id: str | None = None,
        source_ip: str = "local",
        failed_otp_attempts: int = 0,
        nfc_required_but_missing: bool = False,
    ) -> RotatingEncryptedMessage:
        """Encrypt only if threat policy allows the operation."""

        now = self.clock()
        threat = self.threat_detector.assess(
            identity=self.identity,
            mouse_events=mouse_events,
            message_id=message_id,
            source_ip=source_ip,
            failed_otp_attempts=failed_otp_attempts,
            nfc_required_but_missing=nfc_required_but_missing,
            now=now,
        )
        if threat.action == "BLOCK":
            details = ", ".join(f"{signal.name}:{signal.detail}" for signal in threat.signals)
            raise ThreatBlockedError(f"encryption blocked risk={threat.risk_score}: {details}")

        epoch = self.current_epoch(now)
        context_bytes = context.encode("utf-8")
        key = self.derive_epoch_key(epoch=epoch, context=context_bytes)
        nonce = os.urandom(12)
        expires_at = (epoch + 1) * self.rotation_seconds
        aad = self._build_aad(
            epoch=epoch,
            context=context,
            issued_at=now,
            expires_at=expires_at,
            threat=threat,
        )
        payload = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        ciphertext = AESGCM(key).encrypt(nonce, payload, aad)
        return RotatingEncryptedMessage(
            version=1,
            algorithm="AES-256-GCM/0.3s-rotating-key",
            epoch=epoch,
            issued_at=now,
            expires_at=expires_at,
            nonce=nonce,
            ciphertext=ciphertext,
            aad=aad,
            identity_hash=self.identity_hash(),
            threat_action=threat.action,
        )

    def decrypt(
        self,
        envelope: RotatingEncryptedMessage,
        *,
        context: str = "message",
        max_clock_skew_seconds: float = 0.0,
    ) -> bytes:
        """Decrypt only during the key epoch lifetime plus explicit skew."""

        now = self.clock()
        if now > envelope.expires_at + max_clock_skew_seconds:
            raise ExpiredKeyEpochError(
                f"key epoch expired at {envelope.expires_at:.6f}; now={now:.6f}"
            )
        if envelope.identity_hash != self.identity_hash():
            raise ValueError("envelope was not created for this system identity")

        key = self.derive_epoch_key(
            epoch=envelope.epoch,
            context=context.encode("utf-8"),
        )
        return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, envelope.aad)

    def identity_hash(self) -> str:
        digest = hashlib.sha256(
            b"|".join(
                [
                    self.identity.user_id.encode("utf-8"),
                    self.identity.device_id.encode("utf-8"),
                    self.identity.session_id.encode("utf-8"),
                ]
            )
        ).hexdigest()
        return digest

    def _build_aad(
        self,
        *,
        epoch: int,
        context: str,
        issued_at: float,
        expires_at: float,
        threat: ThreatDecision,
    ) -> bytes:
        data = {
            "aad_version": AAD_VERSION,
            "user_id": self.identity.user_id,
            "device_id": self.identity.device_id,
            "session_id": self.identity.session_id,
            "identity_hash": self.identity_hash(),
            "epoch": epoch,
            "rotation_seconds": self.rotation_seconds,
            "context": context,
            "issued_at": round(issued_at, 9),
            "expires_at": round(expires_at, 9),
            "threat_action": threat.action,
            "threat_score": threat.risk_score,
            "signals": [signal.name for signal in threat.signals],
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
