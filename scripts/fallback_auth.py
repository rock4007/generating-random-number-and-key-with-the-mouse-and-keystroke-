"""fallback_auth.py — Scenario authentication fallback chain for SUMIT KEY.

This module models the real-world flow:
1. Try mouse-turn / vibration behaviour first.
2. If movement quality is weak or does not match, require OTP by phone/email.
3. If OTP is unavailable or wrong, require phone NFC.

The providers here are sandbox-safe simulations. They do not send SMS/email and
do not access NFC hardware. Production integrations should replace the provider
methods with Twilio/SMTP/WebAuthn/NFC bridge calls while preserving the same
decision states.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import math
import secrets
import time
from typing import Any


@dataclass(frozen=True)
class MovementProfile:
    """Quality scores extracted from a mouse/game movement session."""

    event_count: int
    direction_changes: int
    micro_vibration_steps: int
    unique_positions: int
    mean_velocity_px_s: float
    score: float
    verdict: str
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class FallbackDecision:
    """One step in the auth chain decision log."""

    step: str
    status: str
    detail: str


@dataclass
class AuthScenarioResult:
    """Final result for a scenario-auth attempt."""

    scenario: str
    authenticated: bool
    method: str
    movement_profile: MovementProfile
    decisions: list[FallbackDecision] = field(default_factory=list)
    nist_us_notes: list[str] = field(default_factory=list)


class SimulatedOTPProvider:
    """Sandbox OTP provider for phone/email fallback tests."""

    def __init__(self, secret: bytes | None = None) -> None:
        self.secret = secret if secret is not None else secrets.token_bytes(32)
        self._active_codes: dict[str, tuple[str, float]] = {}

    def issue(self, destination: str, *, ttl_seconds: int = 300) -> str:
        """Issue a deterministic-looking six-digit OTP for test delivery."""

        if not destination:
            raise ValueError("destination must not be empty")
        now_step = int(time.time() // 30)
        digest = hmac.new(
            self.secret,
            f"{destination}|{now_step}|{secrets.token_hex(8)}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        code = str(int.from_bytes(digest[:4], "big") % 1_000_000).zfill(6)
        self._active_codes[destination] = (code, time.time() + ttl_seconds)
        return code

    def verify(self, destination: str, code: str) -> bool:
        """Verify an issued OTP using constant-time comparison."""

        active = self._active_codes.get(destination)
        if active is None:
            return False
        expected, expires_at = active
        if time.time() > expires_at:
            return False
        return hmac.compare_digest(expected, str(code).strip())


class SimulatedNFCProvider:
    """Sandbox NFC provider for final-factor tests."""

    def __init__(self, allowed_token_hashes: set[str] | None = None) -> None:
        self.allowed_token_hashes = allowed_token_hashes or set()

    @staticmethod
    def token_hash(token_uid: str) -> str:
        """Hash an NFC token UID before storing/comparing it."""

        if not token_uid:
            raise ValueError("token_uid must not be empty")
        return hashlib.sha256(token_uid.encode("utf-8")).hexdigest()

    def register_token(self, token_uid: str) -> None:
        self.allowed_token_hashes.add(self.token_hash(token_uid))

    def verify(self, token_uid: str | None) -> bool:
        if not token_uid:
            return False
        return self.token_hash(token_uid) in self.allowed_token_hashes


def make_chess_like_mouse_events(
    *,
    good: bool = True,
    moves: int = 8,
    vibration: bool = True,
) -> list[dict[str, Any]]:
    """Generate game/chess-like mouse events for fallback-chain tests."""

    if moves <= 0:
        raise ValueError("moves must be positive")

    events: list[dict[str, Any]] = []
    base_time = time.time()
    last_x: float | None = None
    last_y: float | None = None
    last_t: float | None = None

    board_left = 160.0
    board_top = 120.0
    cell = 64.0
    samples_per_move = 8 if good else 3

    def append(x: float, y: float, t: float) -> None:
        nonlocal last_x, last_y, last_t

        velocity = 0.0
        direction = 0.0
        if last_x is not None and last_y is not None and last_t is not None:
            dx = x - last_x
            dy = y - last_y
            dt = t - last_t
            if dt > 0:
                velocity = math.sqrt(dx * dx + dy * dy) / dt
            direction = math.degrees(math.atan2(dy, dx))

        events.append(
            {
                "x": x,
                "y": y,
                "timestamp": t,
                "velocity_px_per_s": velocity,
                "direction_angle_deg": direction,
            }
        )
        last_x = x
        last_y = y
        last_t = t

    for move_index in range(moves):
        from_col = move_index % 8
        from_row = (move_index * 2) % 8
        to_col = (from_col + 1 + (move_index % 3)) % 8
        to_row = (from_row + 2) % 8

        start_x = board_left + from_col * cell + cell / 2
        start_y = board_top + from_row * cell + cell / 2
        end_x = board_left + to_col * cell + cell / 2
        end_y = board_top + to_row * cell + cell / 2

        for sample in range(samples_per_move):
            ratio = sample / max(1, samples_per_move - 1)
            curve = math.sin(ratio * math.pi)
            jitter = 0.9 if good and vibration else 0.0
            x = start_x + (end_x - start_x) * ratio + curve * 12.0
            y = start_y + (end_y - start_y) * ratio - curve * 8.0
            if good:
                x += math.sin(sample * 3.3 + move_index) * jitter
                y += math.cos(sample * 2.9 + move_index) * jitter
            timestamp = base_time + len(events) * (0.026 if good else 0.18)
            append(x, y, timestamp)

            if good and vibration:
                append(
                    x + math.sin(sample * 5.1) * 0.55,
                    y + math.cos(sample * 4.8) * 0.55,
                    timestamp + 0.009,
                )

    if not good:
        # Flatten the path into coarse, low-information jumps.
        return events[::2]
    return events


def evaluate_mouse_movement(
    mouse_events: list[dict[str, Any]],
    *,
    min_events: int = 40,
    min_direction_changes: int = 10,
    min_micro_vibrations: int = 8,
    min_unique_positions: int = 20,
) -> MovementProfile:
    """Score whether mouse turns/vibration are good enough for primary auth."""

    if not mouse_events:
        return MovementProfile(0, 0, 0, 0, 0.0, 0.0, "FAIL", ("no mouse events",))

    direction_changes = 0
    micro_steps = 0
    velocities: list[float] = []
    previous_direction: float | None = None

    for index, event in enumerate(mouse_events):
        velocities.append(float(event.get("velocity_px_per_s", 0.0)))
        direction = float(event.get("direction_angle_deg", 0.0))
        if previous_direction is not None:
            diff = abs(direction - previous_direction) % 360.0
            diff = diff if diff <= 180.0 else 360.0 - diff
            if diff >= 20.0:
                direction_changes += 1
        previous_direction = direction

        if index > 0:
            prev = mouse_events[index - 1]
            dx = float(event.get("x", 0.0)) - float(prev.get("x", 0.0))
            dy = float(event.get("y", 0.0)) - float(prev.get("y", 0.0))
            step = math.sqrt(dx * dx + dy * dy)
            if 0.0 < step < 5.0:
                micro_steps += 1

    unique_positions = len(
        {
            (round(float(event.get("x", 0.0)), 1), round(float(event.get("y", 0.0)), 1))
            for event in mouse_events
        }
    )
    mean_velocity = sum(velocities) / max(1, len(velocities))

    checks = [
        (len(mouse_events) >= min_events, "too few mouse events"),
        (direction_changes >= min_direction_changes, "not enough turns/direction changes"),
        (micro_steps >= min_micro_vibrations, "not enough micro-vibration"),
        (unique_positions >= min_unique_positions, "not enough unique positions"),
    ]
    passed = sum(1 for ok, _reason in checks if ok)
    score = passed / len(checks)
    reasons = tuple(reason for ok, reason in checks if not ok)
    verdict = "PASS" if passed == len(checks) else ("WARN" if score >= 0.75 else "FAIL")

    return MovementProfile(
        event_count=len(mouse_events),
        direction_changes=direction_changes,
        micro_vibration_steps=micro_steps,
        unique_positions=unique_positions,
        mean_velocity_px_s=round(mean_velocity, 2),
        score=round(score, 3),
        verdict=verdict,
        reasons=reasons,
    )


def authenticate_game_scenario(
    *,
    scenario: str,
    mouse_events: list[dict[str, Any]],
    otp_destination: str | None = None,
    provided_otp: str | None = None,
    nfc_token_uid: str | None = None,
    otp_provider: SimulatedOTPProvider | None = None,
    nfc_provider: SimulatedNFCProvider | None = None,
) -> AuthScenarioResult:
    """Run primary movement auth, then OTP, then NFC fallback."""

    active_otp = otp_provider if otp_provider is not None else SimulatedOTPProvider()
    active_nfc = nfc_provider if nfc_provider is not None else SimulatedNFCProvider()
    profile = evaluate_mouse_movement(mouse_events)
    decisions: list[FallbackDecision] = []

    if profile.verdict == "PASS":
        decisions.append(
            FallbackDecision(
                "mouse_movement",
                "PASS",
                "mouse turns and vibration matched expected game profile",
            )
        )
        return AuthScenarioResult(
            scenario=scenario,
            authenticated=True,
            method="mouse_movement",
            movement_profile=profile,
            decisions=decisions,
            nist_us_notes=_framework_notes(),
        )

    decisions.append(
        FallbackDecision(
            "mouse_movement",
            profile.verdict,
            "; ".join(profile.reasons) if profile.reasons else "movement quality warning",
        )
    )

    if otp_destination:
        if provided_otp is not None and active_otp.verify(otp_destination, provided_otp):
            decisions.append(FallbackDecision("otp_phone_email", "PASS", "OTP verified"))
            return AuthScenarioResult(
                scenario=scenario,
                authenticated=True,
                method="otp_phone_email",
                movement_profile=profile,
                decisions=decisions,
                nist_us_notes=_framework_notes(),
            )
        decisions.append(
            FallbackDecision(
                "otp_phone_email",
                "FAIL",
                "OTP missing, expired, or incorrect",
            )
        )
    else:
        decisions.append(
            FallbackDecision("otp_phone_email", "SKIP", "no phone/email destination")
        )

    if active_nfc.verify(nfc_token_uid):
        decisions.append(FallbackDecision("phone_nfc", "PASS", "registered NFC token verified"))
        return AuthScenarioResult(
            scenario=scenario,
            authenticated=True,
            method="phone_nfc",
            movement_profile=profile,
            decisions=decisions,
            nist_us_notes=_framework_notes(),
        )

    decisions.append(FallbackDecision("phone_nfc", "FAIL", "NFC token missing or unregistered"))
    return AuthScenarioResult(
        scenario=scenario,
        authenticated=False,
        method="none",
        movement_profile=profile,
        decisions=decisions,
        nist_us_notes=_framework_notes(),
    )


def _framework_notes() -> list[str]:
    return [
        "NIST SP 800-63B style MFA posture: behavioural signal plus OTP/NFC fallback factors.",
        "Phone/SMS OTP is treated as a restricted, rate-limited fallback rather than a primary factor.",
        "Email OTP is treated as an out-of-band recovery fallback and should be risk-scored.",
        "NFC should be implemented with phishing-resistant FIDO2/WebAuthn or smart-card semantics in production.",
        "OTP must be rate-limited, short-lived, and invalidated after use in production.",
        "NFC token identifiers are hashed before storage/comparison in this sandbox model.",
        "Behavioural mouse movement is a risk signal, not a formal NIST authenticator by itself.",
    ]
