from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import statistics
import threading
import time
from dataclasses import dataclass
from typing import Literal

import uvicorn
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

log = logging.getLogger("sumit_key_fixed")

APP_VERSION = "3.0.0"

CHALLENGE_TTL_SECONDS = int(
    os.getenv("SUMIT_CHALLENGE_TTL_SECONDS", "30")
)

AUTH_TOKEN_TTL_SECONDS = int(
    os.getenv("SUMIT_AUTH_TOKEN_TTL_SECONDS", "30")
)

PACKAGE_TTL_SECONDS = int(
    os.getenv("SUMIT_PACKAGE_TTL_SECONDS", "120")
)

OTP_TTL_SECONDS = int(
    os.getenv("SUMIT_OTP_TTL_SECONDS", "300")
)

OTP_RESEND_SECONDS = int(
    os.getenv("SUMIT_OTP_RESEND_SECONDS", "30")
)

MAX_OTP_ATTEMPTS = int(
    os.getenv("SUMIT_MAX_OTP_ATTEMPTS", "5")
)

TRACE_REPLAY_TTL_SECONDS = int(
    os.getenv("SUMIT_TRACE_REPLAY_TTL_SECONDS", "600")
)

LOCAL_EPHEMERAL_KEY_TARGET_SECONDS = float(
    os.getenv(
        "SUMIT_LOCAL_EPHEMERAL_KEY_TARGET_SECONDS",
        "0.03",
    )
)

DEFAULT_MATCH_THRESHOLD = float(
    os.getenv("SUMIT_MATCH_THRESHOLD", "0.85")
)

DEV_SHOW_OTP = os.getenv(
    "SUMIT_DEV_SHOW_OTP",
    "0",
) == "1"


def load_master_key() -> bytes:
    raw = os.getenv(
        "SUMIT_MASTER_KEY_HEX",
        "",
    ).strip()

    if raw:
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise RuntimeError(
                "SUMIT_MASTER_KEY_HEX must be valid hex"
            ) from exc

        if len(key) != 32:
            raise RuntimeError(
                "SUMIT_MASTER_KEY_HEX must encode exactly 32 bytes"
            )

        return key

    key = os.urandom(32)

    log.warning(
        "SUMIT_MASTER_KEY_HEX is not configured. "
        "Temporary development master key generated."
    )

    return key


MASTER_KEY = load_master_key()
MASTER_AEAD = AESGCM(MASTER_KEY)

STATE_LOCK = threading.RLock()


class MouseEvent(BaseModel):
    x: float
    y: float
    t: float


class KeyTimingEvent(BaseModel):
    dwell_ms: float = Field(
        ge=0.0,
        le=5000.0,
    )

    flight_ms: float = Field(
        ge=0.0,
        le=10000.0,
    )

    t: float


class DeviceProfile(BaseModel):
    device_id: str = Field(
        min_length=1,
        max_length=128,
    )

    dpi: float = Field(
        default=800.0,
        gt=0.0,
        le=30000.0,
    )

    polling_rate_hz: float = Field(
        default=125.0,
        gt=0.0,
        le=10000.0,
    )

    screen_width: int = Field(
        default=1920,
        gt=0,
        le=20000,
    )

    screen_height: int = Field(
        default=1080,
        gt=0,
        le=20000,
    )

    operating_system: str = Field(
        default="unknown",
        max_length=128,
    )

    input_type: Literal[
        "mouse",
        "trackpad",
        "other",
    ] = "mouse"


class BehaviourCapture(BaseModel):
    mouse_events: list[MouseEvent] = Field(
        default_factory=list,
        max_length=5000,
    )

    keystroke_events: list[KeyTimingEvent] = Field(
        default_factory=list,
        max_length=2000,
    )

    device: DeviceProfile


class EnrolRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    email: str | None = Field(
        default=None,
        max_length=320,
    )

    phone: str | None = Field(
        default=None,
        max_length=64,
    )

    capture: BehaviourCapture

    match_threshold: float = Field(
        default=DEFAULT_MATCH_THRESHOLD,
        gt=0.05,
        le=5.0,
    )


class ChallengeRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    purpose: Literal[
        "encrypt",
        "decrypt",
        "register_nfc",
        "generic",
    ] = "generic"


class VerifyBehaviourRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    challenge_id: str = Field(
        min_length=8,
        max_length=256,
    )

    capture: BehaviourCapture


class EncryptRequest(BaseModel):
    sender_id: str = Field(
        min_length=1,
        max_length=128,
    )

    recipient_id: str = Field(
        min_length=1,
        max_length=128,
    )

    auth_token: str = Field(
        min_length=16,
        max_length=512,
    )

    plaintext: str

    ttl_seconds: int = Field(
        default=PACKAGE_TTL_SECONDS,
        ge=1,
        le=3600,
    )


class DecryptRequest(BaseModel):
    recipient_id: str = Field(
        min_length=1,
        max_length=128,
    )

    auth_token: str = Field(
        min_length=16,
        max_length=512,
    )

    message_id: str = Field(
        min_length=8,
        max_length=256,
    )


class OTPRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    channel: Literal[
        "email",
        "phone",
    ]


class OTPVerifyRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    channel: Literal[
        "email",
        "phone",
    ]

    code: str = Field(
        min_length=4,
        max_length=12,
    )


class NFCRegisterRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    auth_token: str = Field(
        min_length=16,
        max_length=512,
    )

    token_id: str = Field(
        min_length=1,
        max_length=128,
    )


class NFCChallengeRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    token_id: str = Field(
        min_length=1,
        max_length=128,
    )


class NFCVerifyRequest(BaseModel):
    user_id: str = Field(
        min_length=1,
        max_length=128,
    )

    token_id: str = Field(
        min_length=1,
        max_length=128,
    )

    challenge_id: str = Field(
        min_length=8,
        max_length=256,
    )

    signature_hex: str = Field(
        min_length=64,
        max_length=128,
    )


class ResearchConditionRequest(BaseModel):
    source: Literal[
        "mouse",
        "keyboard",
        "combined",
    ]

    capture: BehaviourCapture


class MetricsRequest(BaseModel):
    true_accept: int = Field(ge=0)
    true_reject: int = Field(ge=0)
    false_accept: int = Field(ge=0)
    false_reject: int = Field(ge=0)


@dataclass
class UserRecord:
    user_id: str
    template: list[float]
    threshold: float
    stable_secret_nonce: bytes
    encrypted_stable_secret: bytes
    device_id: str
    email: str | None
    phone: str | None
    created_at: float


@dataclass
class ChallengeRecord:
    challenge_id: str
    nonce: str
    user_id: str
    purpose: str
    expires_at: float
    used: bool = False


@dataclass
class AuthTokenRecord:
    token: str
    user_id: str
    method: str
    purpose: str
    expires_at: float
    used: bool = False


@dataclass
class MessageRecord:
    message_id: str
    sender_id: str
    recipient_id: str
    nonce: bytes
    ciphertext: bytes
    wrap_nonce: bytes
    wrapped_dek: bytes
    aad_json: str
    created_at: float
    expires_at: float
    used: bool = False
    local_dek_lifetime_ms: float = 0.0


@dataclass
class OTPRecord:
    digest: bytes
    expires_at: float
    issued_at: float
    attempts: int = 0


@dataclass
class NFCRecord:
    token_id: str
    secret_nonce: bytes
    encrypted_secret: bytes


@dataclass
class NFCChallengeRecord:
    challenge_id: str
    user_id: str
    token_id: str
    challenge: bytes
    expires_at: float
    used: bool = False


USERS: dict[str, UserRecord] = {}
CHALLENGES: dict[str, ChallengeRecord] = {}
AUTH_TOKENS: dict[str, AuthTokenRecord] = {}
MESSAGES: dict[str, MessageRecord] = {}

OTP_CODES: dict[
    tuple[str, str],
    OTPRecord,
] = {}

NFC_TOKENS: dict[
    tuple[str, str],
    NFCRecord,
] = {}

NFC_CHALLENGES: dict[
    str,
    NFCChallengeRecord,
] = {}

RECENT_TRACE_HASHES: dict[
    tuple[str, str],
    float,
] = {}

FAILED_AUTH: dict[
    str,
    list[float],
] = {}


FEATURE_SCALES = [
    100.0,
    100.0,
    10.0,
    10.0,
    5.0,
    5.0,
    10.0,
    1.0,
    500.0,
    200.0,
    1000.0,
    400.0,
    500.0,
    1000.0,
]


def mean(values: list[float]) -> float:
    if not values:
        return 0.0

    return statistics.fmean(values)


def std(values: list[float]) -> float:
    if len(values) <= 1:
        return 0.0

    return statistics.pstdev(values)


def sorted_by_time(items: list) -> list:
    return sorted(
        items,
        key=lambda item: float(item.t),
    )


def validate_monotonic_times(
    values: list[float],
    name: str,
) -> None:

    if any(
        not math.isfinite(value)
        for value in values
    ):
        raise HTTPException(
            status_code=422,
            detail=f"{name} contains non-finite timestamps",
        )

    if any(
        current < previous
        for previous, current in zip(
            values,
            values[1:],
        )
    ):
        raise HTTPException(
            status_code=422,
            detail=f"{name} timestamps must be monotonic",
        )


def extract_behaviour_features(
    capture: BehaviourCapture,
) -> list[float]:

    mouse = sorted_by_time(
        capture.mouse_events
    )

    keys = sorted_by_time(
        capture.keystroke_events
    )

    validate_monotonic_times(
        [event.t for event in mouse],
        "mouse",
    )

    validate_monotonic_times(
        [event.t for event in keys],
        "keyboard",
    )

    dpi = float(
        capture.device.dpi
    )

    mm_per_pixel = 25.4 / dpi

    distances_mm = []
    speeds = []
    accelerations = []
    direction_changes = []

    previous_angle = None
    previous_speed = None

    for previous, current in zip(
        mouse,
        mouse[1:],
    ):

        dx = (
            current.x - previous.x
        ) * mm_per_pixel

        dy = (
            current.y - previous.y
        ) * mm_per_pixel

        distance = math.hypot(
            dx,
            dy,
        )

        dt_ms = (
            current.t - previous.t
        )

        if dt_ms <= 0:
            continue

        speed = (
            distance / dt_ms
        )

        distances_mm.append(
            distance
        )

        speeds.append(
            speed
        )

        if previous_speed is not None:
            accelerations.append(
                (
                    speed - previous_speed
                ) / dt_ms
            )

        previous_speed = speed

        if distance > 0:
            angle = math.atan2(
                dy,
                dx,
            )

            if previous_angle is not None:
                delta = abs(
                    angle - previous_angle
                )

                delta = min(
                    delta,
                    2 * math.pi - delta,
                )

                direction_changes.append(
                    delta
                )

            previous_angle = angle

    tremor_steps = [
        distance
        for distance in distances_mm
        if 0.0 < distance < 0.20
    ]

    total_distance = sum(
        distances_mm
    )

    mouse_duration = (
        mouse[-1].t - mouse[0].t
        if len(mouse) > 1
        else 0.0
    )

    dwell = [
        float(event.dwell_ms)
        for event in keys
    ]

    flight = [
        float(event.flight_ms)
        for event in keys
    ]

    key_duration = (
        keys[-1].t - keys[0].t
        if len(keys) > 1
        else 0.0
    )

    return [
        total_distance,
        mouse_duration,
        mean(speeds),
        std(speeds),
        mean(accelerations),
        std(accelerations),
        mean(direction_changes),
        len(tremor_steps)
        / max(
            1,
            len(distances_mm),
        ),
        mean(dwell),
        std(dwell),
        mean(flight),
        std(flight),
        float(len(keys)),
        key_duration,
    ]


def normalized_distance(
    first: list[float],
    second: list[float],
) -> float:

    if (
        len(first) != len(second)
        or len(first) != len(FEATURE_SCALES)
    ):
        raise ValueError(
            "Feature vectors are incompatible"
        )

    values = [
        (
            (
                first_value
                - second_value
            )
            / scale
        )
        ** 2
        for (
            first_value,
            second_value,
            scale,
        ) in zip(
            first,
            second,
            FEATURE_SCALES,
        )
    ]

    return math.sqrt(
        sum(values)
        / len(values)
    )


def validate_capture_quality(
    capture: BehaviourCapture,
) -> None:

    if len(
        capture.mouse_events
    ) < 12:
        raise HTTPException(
            status_code=422,
            detail=(
                "At least 12 mouse events "
                "are required"
            ),
        )

    if len(
        capture.keystroke_events
    ) < 4:
        raise HTTPException(
            status_code=422,
            detail=(
                "At least 4 keystroke timing "
                "events are required"
            ),
        )

    mouse = sorted_by_time(
        capture.mouse_events
    )

    if (
        mouse[-1].t
        - mouse[0].t
    ) < 250.0:
        raise HTTPException(
            status_code=422,
            detail="Mouse capture is too short",
        )

    unique_positions = {
        (
            round(event.x, 2),
            round(event.y, 2),
        )
        for event in mouse
    }

    if len(
        unique_positions
    ) < 8:
        raise HTTPException(
            status_code=422,
            detail=(
                "Mouse capture does not "
                "contain enough movement"
            ),
        )


def canonical_trace_hash(
    capture: BehaviourCapture,
) -> str:

    mouse_events = sorted_by_time(
        capture.mouse_events
    )

    key_events = sorted_by_time(
        capture.keystroke_events
    )

    if mouse_events:
        mouse_start = mouse_events[0].t
    else:
        mouse_start = 0.0

    if key_events:
        key_start = key_events[0].t
    else:
        key_start = 0.0

    mouse = [
        [
            round(event.x, 2),
            round(event.y, 2),
            round(
                event.t - mouse_start,
                2,
            ),
        ]
        for event in mouse_events
    ]

    keys = [
        [
            round(
                event.dwell_ms,
                2,
            ),
            round(
                event.flight_ms,
                2,
            ),
            round(
                event.t - key_start,
                2,
            ),
        ]
        for event in key_events
    ]

    payload = json.dumps(
        {
            "mouse": mouse,
            "keys": keys,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


def cleanup_state() -> None:
    now = time.time()

    with STATE_LOCK:
        for challenge_id in list(
            CHALLENGES
        ):
            record = CHALLENGES[
                challenge_id
            ]

            if (
                record.used
                or record.expires_at < now
            ):
                CHALLENGES.pop(
                    challenge_id,
                    None,
                )

        for token in list(
            AUTH_TOKENS
        ):
            record = AUTH_TOKENS[
                token
            ]

            if (
                record.used
                or record.expires_at < now
            ):
                AUTH_TOKENS.pop(
                    token,
                    None,
                )

        for key in list(
            OTP_CODES
        ):
            if (
                OTP_CODES[key].expires_at
                < now
            ):
                OTP_CODES.pop(
                    key,
                    None,
                )

        for key in list(
            RECENT_TRACE_HASHES
        ):
            if (
                RECENT_TRACE_HASHES[key]
                < now
            ):
                RECENT_TRACE_HASHES.pop(
                    key,
                    None,
                )

        for challenge_id in list(
            NFC_CHALLENGES
        ):
            record = NFC_CHALLENGES[
                challenge_id
            ]

            if (
                record.used
                or record.expires_at < now
            ):
                NFC_CHALLENGES.pop(
                    challenge_id,
                    None,
                )

        for user_id in list(
            FAILED_AUTH
        ):
            FAILED_AUTH[user_id] = [
                event_time
                for event_time
                in FAILED_AUTH[user_id]
                if (
                    now - event_time
                    <= 60.0
                )
            ]

            if not FAILED_AUTH[
                user_id
            ]:
                FAILED_AUTH.pop(
                    user_id,
                    None,
                )


def encrypt_with_master(
    data: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:

    nonce = os.urandom(12)

    encrypted = MASTER_AEAD.encrypt(
        nonce,
        data,
        aad,
    )

    return (
        nonce,
        encrypted,
    )


def decrypt_with_master(
    nonce: bytes,
    data: bytes,
    aad: bytes,
) -> bytes:

    return MASTER_AEAD.decrypt(
        nonce,
        data,
        aad,
    )


def derive_user_kek(
    stable_secret: bytes,
    user_id: str,
) -> bytes:

    salt = hashlib.sha256(
        (
            "SUMIT-USER-KEK|"
            + user_id
        ).encode("utf-8")
    ).digest()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"SUMIT-KEY-USER-KEK-V1",
    ).derive(
        stable_secret
    )


def load_user_kek(
    user_id: str,
) -> bytearray:

    with STATE_LOCK:
        user = USERS.get(
            user_id
        )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown user",
        )

    aad = (
        "stable-secret|"
        + user_id
    ).encode("utf-8")

    stable_secret = bytearray(
        decrypt_with_master(
            user.stable_secret_nonce,
            user.encrypted_stable_secret,
            aad,
        )
    )

    try:
        kek = derive_user_kek(
            bytes(stable_secret),
            user_id,
        )

        return bytearray(
            kek
        )

    finally:
        for index in range(
            len(stable_secret)
        ):
            stable_secret[index] = 0


def issue_auth_token(
    user_id: str,
    method: str,
    purpose: str,
) -> str:

    token = secrets.token_urlsafe(
        32
    )

    with STATE_LOCK:
        AUTH_TOKENS[token] = AuthTokenRecord(
            token=token,
            user_id=user_id,
            method=method,
            purpose=purpose,
            expires_at=(
                time.time()
                + AUTH_TOKEN_TTL_SECONDS
            ),
        )

    return token


def consume_auth_token(
    token: str,
    user_id: str,
    expected_purpose: str,
) -> AuthTokenRecord:

    cleanup_state()

    with STATE_LOCK:
        record = AUTH_TOKENS.get(
            token
        )

        if record is None:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Unknown or expired "
                    "authentication token"
                ),
            )

        if record.user_id != user_id:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Authentication token "
                    "belongs to another user"
                ),
            )

        if record.used:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Authentication token "
                    "already used"
                ),
            )

        if (
            record.expires_at
            < time.time()
        ):
            AUTH_TOKENS.pop(
                token,
                None,
            )

            raise HTTPException(
                status_code=401,
                detail=(
                    "Authentication token expired"
                ),
            )

        if record.purpose not in (
            expected_purpose,
            "generic",
            "fallback",
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Authentication token is "
                    "for a different purpose"
                ),
            )

        record.used = True

        return record


def record_failed_auth(
    user_id: str,
) -> None:

    now = time.time()

    with STATE_LOCK:
        failures = FAILED_AUTH.setdefault(
            user_id,
            [],
        )

        failures[:] = [
            event_time
            for event_time
            in failures
            if (
                now - event_time
                <= 60.0
            )
        ]

        failures.append(
            now
        )


def check_auth_rate(
    user_id: str,
) -> None:

    cleanup_state()

    with STATE_LOCK:
        failures = FAILED_AUTH.get(
            user_id,
            [],
        )

        if len(
            failures
        ) >= 5:
            raise HTTPException(
                status_code=429,
                detail=(
                    "Too many failed behavioural "
                    "attempts. Use OTP or NFC."
                ),
            )


def otp_digest(
    user_id: str,
    channel: str,
    code: str,
) -> bytes:

    return hmac.new(
        MASTER_KEY,
        (
            f"OTP|{user_id}|"
            f"{channel}|{code}"
        ).encode("utf-8"),
        hashlib.sha256,
    ).digest()


def nfc_secret(
    user_id: str,
    token_id: str,
) -> bytes:

    with STATE_LOCK:
        record = NFC_TOKENS.get(
            (
                user_id,
                token_id,
            )
        )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown NFC token",
        )

    return decrypt_with_master(
        record.secret_nonce,
        record.encrypted_secret,
        (
            f"nfc|{user_id}|"
            f"{token_id}"
        ).encode("utf-8"),
    )


def admin_key_required(
    x_admin_key: str | None = Header(
        default=None
    ),
) -> None:

    expected = os.getenv(
        "SUMIT_ADMIN_API_KEY",
        "",
    )

    if not expected:
        raise HTTPException(
            status_code=503,
            detail=(
                "Admin API key is not configured"
            ),
        )

    if not hmac.compare_digest(
        x_admin_key or "",
        expected,
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )


app = FastAPI(
    title="SUMIT KEY Fixed Core API",
    version=APP_VERSION,
    description=(
        "Replay-resistant behavioural "
        "authentication with ephemeral "
        "symmetric encryption."
    ),
)


origins = [
    value.strip()
    for value in os.getenv(
        "SUMIT_CORS_ORIGINS",
        (
            "http://localhost:3000,"
            "http://localhost:8000"
        ),
    ).split(",")
    if value.strip()
]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
    ],
    allow_headers=[
        "Content-Type",
        "X-Admin-Key",
    ],
)


@app.middleware("http")
async def security_headers(
    request: Request,
    call_next,
):
    response = await call_next(
        request
    )

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    response.headers[
        "Cache-Control"
    ] = "no-store"

    return response


@app.get("/health")
def health():
    cleanup_state()

    return {
        "status": "ok",
        "version": APP_VERSION,
        "users": len(USERS),
        "pending_messages": sum(
            1
            for message
            in MESSAGES.values()
            if not message.used
        ),
    }


@app.get("/info")
def info():
    return {
        "architecture": (
            "trusted-server symmetric "
            "key wrapping"
        ),
        "public_key_crypto": False,
        "behaviour_role": (
            "tolerant authentication "
            "unlocking a stable user KEK"
        ),
        "data_encryption": (
            "AES-256-GCM"
        ),
        "key_derivation": (
            "HKDF-SHA256"
        ),
        "replay_controls": [
            "single-use challenge",
            "single-use auth token",
            "trace replay cache",
            "one-time message",
        ],
        "local_ephemeral_key_target_seconds": (
            LOCAL_EPHEMERAL_KEY_TARGET_SECONDS
        ),
        "package_ttl_seconds": (
            PACKAGE_TTL_SECONDS
        ),
    }


@app.post("/auth/enrol")
def enrol(
    body: EnrolRequest,
):
    validate_capture_quality(
        body.capture
    )

    features = extract_behaviour_features(
        body.capture
    )

    stable_secret = bytearray(
        os.urandom(32)
    )

    try:
        aad = (
            "stable-secret|"
            + body.user_id
        ).encode("utf-8")

        nonce, encrypted = (
            encrypt_with_master(
                bytes(stable_secret),
                aad,
            )
        )

        with STATE_LOCK:
            USERS[
                body.user_id
            ] = UserRecord(
                user_id=body.user_id,
                template=features,
                threshold=(
                    body.match_threshold
                ),
                stable_secret_nonce=nonce,
                encrypted_stable_secret=encrypted,
                device_id=(
                    body.capture
                    .device
                    .device_id
                ),
                email=body.email,
                phone=body.phone,
                created_at=time.time(),
            )

        return {
            "status": "enrolled",
            "user_id": body.user_id,
            "device_id": (
                body.capture
                .device
                .device_id
            ),
            "feature_count": len(
                features
            ),
            "match_threshold": (
                body.match_threshold
            ),
        }

    finally:
        for index in range(
            len(stable_secret)
        ):
            stable_secret[index] = 0


@app.post("/auth/challenge")
def create_challenge(
    body: ChallengeRequest,
):
    cleanup_state()

    with STATE_LOCK:
        if body.user_id not in USERS:
            raise HTTPException(
                status_code=404,
                detail="Unknown user",
            )

        challenge_id = (
            secrets.token_urlsafe(24)
        )

        nonce = secrets.token_hex(
            32
        )

        record = ChallengeRecord(
            challenge_id=challenge_id,
            nonce=nonce,
            user_id=body.user_id,
            purpose=body.purpose,
            expires_at=(
                time.time()
                + CHALLENGE_TTL_SECONDS
            ),
        )

        CHALLENGES[
            challenge_id
        ] = record

    return {
        "challenge_id": (
            challenge_id
        ),
        "nonce": nonce,
        "purpose": body.purpose,
        "expires_at": (
            record.expires_at
        ),
        "mouse_instruction": (
            "Move naturally across several "
            "directions."
        ),
        "keyboard_instruction": (
            "Type the prompt. Only timing "
            "values are sent."
        ),
        "typing_prompt": secrets.choice(
            [
                "SUMIT KEY",
                "SECURE SESSION",
                "GHOST KEY",
                "CYBER PROJECT",
            ]
        ),
    }


@app.post("/auth/verify")
def verify_behaviour(
    body: VerifyBehaviourRequest,
):
    check_auth_rate(
        body.user_id
    )

    validate_capture_quality(
        body.capture
    )

    cleanup_state()

    with STATE_LOCK:
        user = USERS.get(
            body.user_id
        )

        challenge = CHALLENGES.get(
            body.challenge_id
        )

        if user is None:
            raise HTTPException(
                status_code=404,
                detail="Unknown user",
            )

        if challenge is None:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Unknown or expired challenge"
                ),
            )

        if (
            challenge.user_id
            != body.user_id
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Challenge belongs "
                    "to another user"
                ),
            )

        if challenge.used:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Challenge already used"
                ),
            )

        if (
            challenge.expires_at
            < time.time()
        ):
            CHALLENGES.pop(
                body.challenge_id,
                None,
            )

            raise HTTPException(
                status_code=401,
                detail="Challenge expired",
            )

        challenge.used = True

    trace_hash = canonical_trace_hash(
        body.capture
    )

    trace_key = (
        body.user_id,
        trace_hash,
    )

    with STATE_LOCK:
        if (
            trace_key
            in RECENT_TRACE_HASHES
        ):
            record_failed_auth(
                body.user_id
            )

            raise HTTPException(
                status_code=409,
                detail=(
                    "Exact behavioural "
                    "trace replay detected"
                ),
            )

        RECENT_TRACE_HASHES[
            trace_key
        ] = (
            time.time()
            + TRACE_REPLAY_TTL_SECONDS
        )

    current = extract_behaviour_features(
        body.capture
    )

    distance = normalized_distance(
        user.template,
        current,
    )

    accepted = (
        distance
        <= user.threshold
    )

    if not accepted:
        record_failed_auth(
            body.user_id
        )

        return {
            "authenticated": False,
            "distance": distance,
            "threshold": (
                user.threshold
            ),
            "fallback_required": True,
        }

    with STATE_LOCK:
        FAILED_AUTH.pop(
            body.user_id,
            None,
        )

    token = issue_auth_token(
        body.user_id,
        "behaviour",
        challenge.purpose,
    )

    return {
        "authenticated": True,
        "distance": distance,
        "threshold": (
            user.threshold
        ),
        "auth_token": token,
        "auth_token_expires_in_seconds": (
            AUTH_TOKEN_TTL_SECONDS
        ),
        "challenge_consumed": True,
    }


@app.post("/message/encrypt")
def encrypt_message(
    body: EncryptRequest,
):
    consume_auth_token(
        body.auth_token,
        body.sender_id,
        "encrypt",
    )

    with STATE_LOCK:
        if (
            body.sender_id
            not in USERS
        ):
            raise HTTPException(
                status_code=404,
                detail="Unknown sender",
            )

        if (
            body.recipient_id
            not in USERS
        ):
            raise HTTPException(
                status_code=404,
                detail="Unknown recipient",
            )

    now = time.time()

    message_id = (
        secrets.token_urlsafe(24)
    )

    expires_at = (
        now
        + body.ttl_seconds
    )

    aad_object = {
        "version": 1,
        "message_id": message_id,
        "sender_id": (
            body.sender_id
        ),
        "recipient_id": (
            body.recipient_id
        ),
        "created_at": now,
        "expires_at": expires_at,
    }

    aad_json = json.dumps(
        aad_object,
        sort_keys=True,
        separators=(",", ":"),
    )

    aad = aad_json.encode(
        "utf-8"
    )

    dek = bytearray(
        os.urandom(32)
    )

    recipient_kek = load_user_kek(
        body.recipient_id
    )

    dek_created_ns = (
        time.perf_counter_ns()
    )

    try:
        nonce = os.urandom(
            12
        )

        ciphertext = AESGCM(
            bytes(dek)
        ).encrypt(
            nonce,
            body.plaintext.encode(
                "utf-8"
            ),
            aad,
        )

        wrap_nonce = os.urandom(
            12
        )

        wrapped_dek = AESGCM(
            bytes(recipient_kek)
        ).encrypt(
            wrap_nonce,
            bytes(dek),
            aad + b"|DEK-WRAP",
        )

    finally:
        for index in range(
            len(dek)
        ):
            dek[index] = 0

        for index in range(
            len(recipient_kek)
        ):
            recipient_kek[
                index
            ] = 0

        dek_zeroed_ns = (
            time.perf_counter_ns()
        )

    lifetime_ms = (
        (
            dek_zeroed_ns
            - dek_created_ns
        )
        / 1_000_000.0
    )

    with STATE_LOCK:
        MESSAGES[
            message_id
        ] = MessageRecord(
            message_id=message_id,
            sender_id=(
                body.sender_id
            ),
            recipient_id=(
                body.recipient_id
            ),
            nonce=nonce,
            ciphertext=ciphertext,
            wrap_nonce=wrap_nonce,
            wrapped_dek=wrapped_dek,
            aad_json=aad_json,
            created_at=now,
            expires_at=expires_at,
            local_dek_lifetime_ms=(
                lifetime_ms
            ),
        )

    return {
        "status": "encrypted",
        "message_id": (
            message_id
        ),
        "sender_id": (
            body.sender_id
        ),
        "recipient_id": (
            body.recipient_id
        ),
        "expires_at": (
            expires_at
        ),
        "ciphertext_hex": (
            ciphertext.hex()
        ),
        "nonce_hex": (
            nonce.hex()
        ),
        "wrapped_dek_hex": (
            wrapped_dek.hex()
        ),
        "wrap_nonce_hex": (
            wrap_nonce.hex()
        ),
        "aad": aad_object,
        "raw_key_returned": False,
        "local_dek_lifetime_ms": (
            lifetime_ms
        ),
        "local_dek_target_ms": (
            LOCAL_EPHEMERAL_KEY_TARGET_SECONDS
            * 1000.0
        ),
    }


@app.post("/message/decrypt")
def decrypt_message(
    body: DecryptRequest,
):
    token = consume_auth_token(
        body.auth_token,
        body.recipient_id,
        "decrypt",
    )

    with STATE_LOCK:
        record = MESSAGES.get(
            body.message_id
        )

        if record is None:
            raise HTTPException(
                status_code=404,
                detail="Unknown message",
            )

        if (
            record.recipient_id
            != body.recipient_id
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Message is addressed "
                    "to another recipient"
                ),
            )

        if record.used:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Message already consumed"
                ),
            )

        if (
            record.expires_at
            < time.time()
        ):
            MESSAGES.pop(
                body.message_id,
                None,
            )

            raise HTTPException(
                status_code=410,
                detail="Message expired",
            )

    aad = record.aad_json.encode(
        "utf-8"
    )

    recipient_kek = load_user_kek(
        body.recipient_id
    )

    dek = bytearray()

    dek_loaded_ns = 0

    try:
        recovered = AESGCM(
            bytes(recipient_kek)
        ).decrypt(
            record.wrap_nonce,
            record.wrapped_dek,
            aad + b"|DEK-WRAP",
        )

        dek = bytearray(
            recovered
        )

        dek_loaded_ns = (
            time.perf_counter_ns()
        )

        plaintext = AESGCM(
            bytes(dek)
        ).decrypt(
            record.nonce,
            record.ciphertext,
            aad,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "Decryption or integrity "
                "verification failed"
            ),
        ) from exc

    finally:
        for index in range(
            len(dek)
        ):
            dek[index] = 0

        for index in range(
            len(recipient_kek)
        ):
            recipient_kek[
                index
            ] = 0

        dek_zeroed_ns = (
            time.perf_counter_ns()
        )

    if dek_loaded_ns:
        lifetime_ms = (
            (
                dek_zeroed_ns
                - dek_loaded_ns
            )
            / 1_000_000.0
        )
    else:
        lifetime_ms = 0.0

    with STATE_LOCK:
        record.used = True

        MESSAGES.pop(
            body.message_id,
            None,
        )

    return {
        "status": "decrypted",
        "message_id": (
            body.message_id
        ),
        "recipient_id": (
            body.recipient_id
        ),
        "authentication_method": (
            token.method
        ),
        "plaintext": plaintext.decode(
            "utf-8"
        ),
        "message_consumed": True,
        "local_dek_lifetime_ms": (
            lifetime_ms
        ),
        "raw_key_returned": False,
    }


@app.post("/fallback/otp/issue")
def issue_otp(
    body: OTPRequest,
):
    cleanup_state()

    with STATE_LOCK:
        user = USERS.get(
            body.user_id
        )

        if user is None:
            raise HTTPException(
                status_code=404,
                detail="Unknown user",
            )

        if (
            body.channel
            == "email"
        ):
            destination = (
                user.email
            )
        else:
            destination = (
                user.phone
            )

        if not destination:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"No registered "
                    f"{body.channel}"
                ),
            )

        key = (
            body.user_id,
            body.channel,
        )

        previous = OTP_CODES.get(
            key
        )

        now = time.time()

        if (
            previous
            and (
                now
                - previous.issued_at
            )
            < OTP_RESEND_SECONDS
        ):
            raise HTTPException(
                status_code=429,
                detail=(
                    "OTP resend requested "
                    "too soon"
                ),
            )

        code = (
            f"{secrets.randbelow(1_000_000):06d}"
        )

        OTP_CODES[
            key
        ] = OTPRecord(
            digest=otp_digest(
                body.user_id,
                body.channel,
                code,
            ),
            expires_at=(
                now
                + OTP_TTL_SECONDS
            ),
            issued_at=now,
        )

    response = {
        "status": "issued",
        "channel": (
            body.channel
        ),
        "expires_in_seconds": (
            OTP_TTL_SECONDS
        ),
        "destination_hint": (
            destination[:2]
            + "***"
        ),
        "delivery": (
            "provider integration required"
        ),
    }

    if DEV_SHOW_OTP:
        response[
            "development_code"
        ] = code

    return response


@app.post("/fallback/otp/verify")
def verify_otp(
    body: OTPVerifyRequest,
):
    cleanup_state()

    key = (
        body.user_id,
        body.channel,
    )

    with STATE_LOCK:
        record = OTP_CODES.get(
            key
        )

        if record is None:
            raise HTTPException(
                status_code=401,
                detail="No active OTP",
            )

        if (
            record.expires_at
            < time.time()
        ):
            OTP_CODES.pop(
                key,
                None,
            )

            raise HTTPException(
                status_code=401,
                detail="OTP expired",
            )

        record.attempts += 1

        if (
            record.attempts
            > MAX_OTP_ATTEMPTS
        ):
            OTP_CODES.pop(
                key,
                None,
            )

            raise HTTPException(
                status_code=429,
                detail=(
                    "OTP attempt limit exceeded"
                ),
            )

        supplied = otp_digest(
            body.user_id,
            body.channel,
            body.code.strip(),
        )

        if not hmac.compare_digest(
            record.digest,
            supplied,
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid OTP",
            )

        OTP_CODES.pop(
            key,
            None,
        )

    token = issue_auth_token(
        body.user_id,
        f"{body.channel}_otp",
        "fallback",
    )

    return {
        "authenticated": True,
        "method": (
            f"{body.channel}_otp"
        ),
        "auth_token": token,
        "one_time_code_consumed": True,
    }


@app.post("/fallback/nfc/register")
def register_nfc(
    body: NFCRegisterRequest,
):
    consume_auth_token(
        body.auth_token,
        body.user_id,
        "register_nfc",
    )

    secret = bytearray(
        os.urandom(32)
    )

    try:
        aad = (
            f"nfc|{body.user_id}|"
            f"{body.token_id}"
        ).encode("utf-8")

        nonce, encrypted = (
            encrypt_with_master(
                bytes(secret),
                aad,
            )
        )

        with STATE_LOCK:
            NFC_TOKENS[
                (
                    body.user_id,
                    body.token_id,
                )
            ] = NFCRecord(
                token_id=(
                    body.token_id
                ),
                secret_nonce=nonce,
                encrypted_secret=encrypted,
            )

        return {
            "status": "registered",
            "token_id": (
                body.token_id
            ),
            "token_secret_hex": (
                bytes(secret).hex()
            ),
            "warning": (
                "This secret is for the "
                "test challenge-response "
                "token. Do not use NFC UID."
            ),
        }

    finally:
        for index in range(
            len(secret)
        ):
            secret[index] = 0


@app.post("/fallback/nfc/challenge")
def create_nfc_challenge(
    body: NFCChallengeRequest,
):
    cleanup_state()

    with STATE_LOCK:
        token_key = (
            body.user_id,
            body.token_id,
        )

        if (
            token_key
            not in NFC_TOKENS
        ):
            raise HTTPException(
                status_code=404,
                detail="Unknown NFC token",
            )

        challenge_id = (
            secrets.token_urlsafe(24)
        )

        challenge = os.urandom(
            32
        )

        NFC_CHALLENGES[
            challenge_id
        ] = NFCChallengeRecord(
            challenge_id=(
                challenge_id
            ),
            user_id=body.user_id,
            token_id=body.token_id,
            challenge=challenge,
            expires_at=(
                time.time()
                + CHALLENGE_TTL_SECONDS
            ),
        )

    return {
        "challenge_id": (
            challenge_id
        ),
        "challenge_hex": (
            challenge.hex()
        ),
        "expires_in_seconds": (
            CHALLENGE_TTL_SECONDS
        ),
        "protocol": (
            "HMAC challenge-response; "
            "UID alone is never accepted"
        ),
    }


@app.post("/fallback/nfc/verify")
def verify_nfc(
    body: NFCVerifyRequest,
):
    cleanup_state()

    with STATE_LOCK:
        challenge = NFC_CHALLENGES.get(
            body.challenge_id
        )

        if challenge is None:
            raise HTTPException(
                status_code=401,
                detail=(
                    "Unknown or expired "
                    "NFC challenge"
                ),
            )

        if (
            challenge.user_id
            != body.user_id
            or challenge.token_id
            != body.token_id
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "NFC challenge does not "
                    "match user/token"
                ),
            )

        if challenge.used:
            raise HTTPException(
                status_code=409,
                detail=(
                    "NFC challenge already used"
                ),
            )

        if (
            challenge.expires_at
            < time.time()
        ):
            NFC_CHALLENGES.pop(
                body.challenge_id,
                None,
            )

            raise HTTPException(
                status_code=401,
                detail=(
                    "NFC challenge expired"
                ),
            )

        challenge.used = True

    try:
        signature = bytes.fromhex(
            body.signature_hex
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=(
                "signature_hex must be "
                "valid hex"
            ),
        ) from exc

    secret = bytearray(
        nfc_secret(
            body.user_id,
            body.token_id,
        )
    )

    try:
        expected = hmac.new(
            bytes(secret),
            challenge.challenge,
            hashlib.sha256,
        ).digest()

    finally:
        for index in range(
            len(secret)
        ):
            secret[index] = 0

    if not hmac.compare_digest(
        expected,
        signature,
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid NFC challenge response"
            ),
        )

    token = issue_auth_token(
        body.user_id,
        "nfc_challenge_response",
        "fallback",
    )

    return {
        "authenticated": True,
        "method": (
            "nfc_challenge_response"
        ),
        "auth_token": token,
        "challenge_consumed": True,
    }


@app.post(
    "/research/conditioned-behaviour"
)
def conditioned_behaviour(
    body: ResearchConditionRequest,
):
    validate_capture_quality(
        body.capture
    )

    full_features = (
        extract_behaviour_features(
            body.capture
        )
    )

    if body.source == "mouse":
        selected = (
            full_features[:8]
        )

    elif body.source == "keyboard":
        selected = (
            full_features[8:]
        )

    else:
        selected = (
            full_features
        )

    canonical = json.dumps(
        [
            round(
                value,
                8,
            )
            for value
            in selected
        ],
        separators=(",", ":"),
    ).encode("utf-8")

    conditioned = hashlib.sha3_256(
        canonical
    ).digest()

    return {
        "source": body.source,
        "conditioned_output_hex": (
            conditioned.hex()
        ),
        "os_csprng_mixed": False,
        "warning": (
            "Research-conditioned sample "
            "only. It is not proof of "
            "min-entropy and is not the "
            "AES encryption key."
        ),
    }


@app.post(
    "/research/os-csprng-baseline"
)
def os_csprng_baseline(
    samples: int = 1,
):
    if (
        samples < 1
        or samples > 1000
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "samples must be "
                "between 1 and 1000"
            ),
        )

    outputs = [
        os.urandom(
            32
        ).hex()
        for _ in range(
            samples
        )
    ]

    return {
        "source": "os_csprng",
        "samples": outputs,
        "separate_from_behavioural_dataset": True,
    }


@app.post("/research/metrics")
def research_metrics(
    body: MetricsRequest,
):
    total = (
        body.true_accept
        + body.true_reject
        + body.false_accept
        + body.false_reject
    )

    if total == 0:
        raise HTTPException(
            status_code=422,
            detail=(
                "At least one trial is required"
            ),
        )

    genuine = (
        body.true_accept
        + body.false_reject
    )

    impostor = (
        body.true_reject
        + body.false_accept
    )

    accuracy = (
        (
            body.true_accept
            + body.true_reject
        )
        / total
    )

    if impostor:
        far = (
            body.false_accept
            / impostor
        )
    else:
        far = 0.0

    if genuine:
        frr = (
            body.false_reject
            / genuine
        )

        tar = (
            body.true_accept
            / genuine
        )

    else:
        frr = 0.0
        tar = 0.0

    return {
        "trials": total,
        "accuracy": accuracy,
        "accuracy_percent": (
            accuracy * 100.0
        ),
        "far": far,
        "frr": frr,
        "tar": tar,
        "hard_coded_99_98": False,
    }


@app.get(
    "/admin/state",
    dependencies=[
        Depends(
            admin_key_required
        )
    ],
)
def admin_state():
    cleanup_state()

    with STATE_LOCK:
        return {
            "users": list(
                USERS
            ),
            "active_challenges": len(
                CHALLENGES
            ),
            "active_auth_tokens": len(
                AUTH_TOKENS
            ),
            "pending_messages": [
                {
                    "message_id": (
                        message.message_id
                    ),
                    "sender_id": (
                        message.sender_id
                    ),
                    "recipient_id": (
                        message.recipient_id
                    ),
                    "expires_at": (
                        message.expires_at
                    ),
                    "used": (
                        message.used
                    ),
                }
                for message
                in MESSAGES.values()
            ],
            "active_otps": len(
                OTP_CODES
            ),
            "registered_nfc_tokens": len(
                NFC_TOKENS
            ),
        }


if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host=os.getenv(
            "SUMIT_HOST",
            "127.0.0.1",
        ),
        port=int(
            os.getenv(
                "SUMIT_PORT",
                "8000",
            )
        ),
        reload=False,
    )