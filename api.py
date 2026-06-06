"""api.py — SUMIT KEY REST API

Exposes the behavioural entropy key generator as a lightweight HTTP service.
Works on any hardware with a standard HID mouse (including $5 USB mice).

Platform support:
  - Windows   : pynput/Win32 (any HID mouse, runs as-is)
  - macOS     : pynput/Quartz (any HID mouse, runs as-is)
  - Linux + X : pynput/XRecord (Xvfb for headless: DISPLAY=:99)
  - Linux raw : evdev backend via /dev/input (no display required,
                user must be in 'input' group or run as root)

Endpoints:
  GET  /health     — service liveness check
  GET  /info       — platform / backend capability info
  POST /generate   — capture entropy and return key + random number

Usage:
  # standard (starts on localhost:8000)
  python api.py

  # debug with verbose logging
  python api.py --debug

  # expose on all interfaces, custom port
  python api.py --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import secrets
import sys
import threading
import time
from typing import Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from security import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    ThreatLogger,
    threat_logger,
    resource_limits,
    validate_duration,
    validate_security_level,
    register_exception_handlers,
    lookup_mac_address,
)

# ---------------------------------------------------------------------------
# Logging — set up early so every import below can emit debug lines
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sumit_key_api")

# ---------------------------------------------------------------------------
# Internal imports (project modules)
# ---------------------------------------------------------------------------
from main import (  # noqa: E402
    generate_per_mouse_movement_outputs,
    generate_random_number_and_key,
    run_all_experiments,
)
from pydantic import BaseModel
from crypto_tools import (
    encrypt_message as _encrypt_msg,
    decrypt_message as _decrypt_msg,
    message_to_dict,
    message_from_dict,
    encryption_info,
    EncryptedMessage,
    quantum_keygen as _quantum_keygen,
    quantum_encrypt_message as _quantum_encrypt,
    quantum_decrypt_message as _quantum_decrypt,
    quantum_package_to_dict,
    quantum_package_from_dict,
    quantum_encryption_info,
    QuantumSession,
)
from debug_pipeline import (
    EntropyAgent,
    PipelineDebugger,
    make_synthetic_mouse_events,
    make_synthetic_keystroke_events,
)
from crypto_benchmark import get_benchmark_summary
from threat_model import get_threat_model
from vault import (
    zkp_keygen as _zkp_keygen,
    zkp_prove as _zkp_prove,
    zkp_verify as _zkp_verify,
    ZKPProof,
    shamir_split,
    shamir_combine,
    HighVoltageVault,
    MITMShield,
    MITMShieldError,
    AdvancedThreatDetector,
    ThreatLevel,
    vault_info,
    lambda_handler as _vault_lambda,
)
from advanced_security import (  # noqa: E402
    ExpiredKeyEpochError,
    RotatingEncryptedMessage,
    RotatingKeyEnvelope,
    SystemIdentity,
    ThreatBlockedError,
)
from self_healing import (  # noqa: E402
    SelfHealingConfig,
    SelfHealingCryptoService,
    SelfHealingError,
    UnrecoverableSecurityError,
)

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def _detect_backend() -> str:
    """Return which input capture backend is available on this machine."""
    system = platform.system()
    if system == "Windows":
        return "pynput-win32"
    if system == "Darwin":
        return "pynput-quartz"
    # Linux / other POSIX
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        return "pynput-x11"
    # Headless Linux — try evdev
    try:
        import evdev  # type: ignore[import]
        devices = evdev.list_devices()
        return f"evdev ({len(devices)} device(s))"
    except ImportError:
        return "evdev-not-installed"
    except Exception as exc:
        return f"evdev-error:{exc}"


def _assert_capture_possible() -> None:
    """Raise RuntimeError with a helpful message if no capture backend works."""
    backend = _detect_backend()
    if backend in ("evdev-not-installed",) or backend.startswith("evdev-error"):
        raise RuntimeError(
            "No input backend available. On headless Linux either:\n"
            "  1) Set DISPLAY (e.g. 'export DISPLAY=:99' + start Xvfb), or\n"
            "  2) Install evdev: pip install evdev  and add user to 'input' group."
        )


def _api_system_identity(
    *,
    user_id: str,
    session_id: str,
    device_secret_hex: str = "",
) -> SystemIdentity:
    """Build API identity for rotating-key endpoints."""

    secret_hex = device_secret_hex or os.environ.get("SUMIT_DEVICE_SECRET_HEX", "")
    if secret_hex:
        try:
            device_secret = bytes.fromhex(secret_hex)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="device_secret_hex must be valid hex") from exc
        if len(device_secret) < 32:
            raise HTTPException(status_code=422, detail="device_secret_hex must encode at least 32 bytes")
    else:
        device_secret = os.urandom(32)

    return SystemIdentity.from_current_system(
        user_id=user_id,
        session_id=session_id,
        device_secret=device_secret,
    )


def _api_backup_identity(
    *,
    user_id: str,
    session_id: str,
    backup_device_secret_hex: str = "",
) -> SystemIdentity | None:
    """Build optional backup identity for self-healing failover."""

    if not backup_device_secret_hex:
        return None
    try:
        backup_secret = bytes.fromhex(backup_device_secret_hex)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="backup_device_secret_hex must be valid hex") from exc
    if len(backup_secret) < 32:
        raise HTTPException(status_code=422, detail="backup_device_secret_hex must encode at least 32 bytes")
    return SystemIdentity.from_current_system(
        user_id=user_id,
        session_id=session_id,
        device_secret=backup_secret,
    )


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SUMIT KEY API",
    description=(
        "Behavioural entropy key generator. "
        "Move your mouse during the capture window to generate a cryptographic key."
    ),
    version="2.0.0",
)

# ---------------------------------------------------------------------------
# Security Middleware
# ---------------------------------------------------------------------------

# Rate limiting: 10 req/min, 100 req/hour per IP
app.add_middleware(RateLimitMiddleware, requests_per_minute=10, requests_per_hour=100)

# Security headers (HSTS, X-Frame-Options, CSP, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# CORS: Allow only localhost and optionally CORS_ORIGINS env var
cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Register exception handlers (prevent stack trace leaks)
register_exception_handlers(app)


_ghost_lock = threading.Lock()
_ghost_keys: dict[str, dict[str, Any]] = {}
_GHOST_MAX_TTL_SECONDS = 300


def _fingerprint(data: bytes | bytearray, *, length: int = 16) -> str:
    """Short non-secret fingerprint for logs, UI, and package metadata."""

    return "fp:" + hashlib.sha256(bytes(data)).hexdigest()[:length]


def _zeroize(buf: bytearray) -> None:
    for index in range(len(buf)):
        buf[index] = 0


def _cleanup_expired_ghost_keys(now: float | None = None) -> None:
    current = time.time() if now is None else now
    expired: list[str] = []
    with _ghost_lock:
        for ghost_id, record in _ghost_keys.items():
            if float(record["expires_at"]) <= current:
                _zeroize(record["key"])
                expired.append(ghost_id)
        for ghost_id in expired:
            del _ghost_keys[ghost_id]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", summary="Liveness check")
def health() -> dict[str, Any]:
    """Returns 200 OK with a timestamp — use for load-balancer health checks."""
    return {"status": "ok", "timestamp": time.time()}


@app.get("/info", summary="Platform and capability info")
def info() -> dict[str, Any]:
    """Returns information about the host platform and the active input backend."""
    backend = _detect_backend()
    return {
        "platform": platform.system(),
        "platform_detail": platform.platform(),
        "python_version": sys.version.split()[0],
        "display_env": os.environ.get("DISPLAY"),
        "wayland_env": os.environ.get("WAYLAND_DISPLAY"),
        "input_backend": backend,
        "backend_ready": not backend.startswith("evdev-not") and not backend.startswith("evdev-error"),
        "api_version": "2.0.0",
    }


@app.post("/generate", summary="Generate a cryptographic key from mouse entropy")
def generate(
    request: Request,
    duration: float = Query(default=10.0, description="Capture duration in seconds (1-60)."),
    security_level: str = Query(default="quantum", description="'quantum' (512-bit) or 'standard' (256-bit)."),
    debug: bool = Query(default=False, description="Include debug metrics."),
) -> dict[str, Any]:
    """
    Run the entropy capture pipeline and return a random number + cryptographic key.

    **How to use:**
    1. Move your mouse naturally for the `duration` seconds.
    2. Receive a unique key derived from your movement patterns.
    
    Security: Key is never stored or transmitted — only returned in this response.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Validate inputs
    try:
        duration = validate_duration(duration)
        security_level = validate_security_level(security_level)
    except HTTPException as exc:
        threat_logger.log_threat("INVALID_INPUT", client_ip, f"{exc.detail}")
        raise
    
    # Check resource availability
    if not resource_limits.acquire():
        threat_logger.log_threat("RESOURCE_EXHAUSTED", client_ip, "Max concurrent captures reached")
        raise HTTPException(
            status_code=503,
            detail="Server busy: max concurrent captures reached. Try again in a few seconds.",
        )

    log.info("POST /generate from %s: duration=%.1fs security=%s", client_ip, duration, security_level)

    try:
        _assert_capture_possible()
    except RuntimeError as exc:
        log.error("Capture backend unavailable: %s", exc)
        threat_logger.log_threat("CAPTURE_UNAVAILABLE", client_ip, str(exc))
        raise HTTPException(status_code=503, detail="Capture backend unavailable") from exc

    t_start = time.time()
    try:
        result = generate_random_number_and_key(
            capture_duration_seconds=duration,
            security_level=security_level,
        )
    except Exception as exc:
        log.exception("Key generation failed")
        threat_logger.log_threat("GENERATION_FAILURE", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Key generation failed") from exc
    finally:
        resource_limits.release()

    elapsed = time.time() - t_start
    log.info(
        "Generation complete: %d-bit key, %d mouse events, %.1fs elapsed",
        result["key_bits"], result["mouse_event_count"], elapsed,
    )

    response: dict[str, Any] = {
        "status": "ok",
        "random_number": result["random_number"],
        "key_hex": result["key_hex"],
        "key_bits": result["key_bits"],
        "security_level": result["security_level"],
        "mouse_event_count": result["mouse_event_count"],
        "keystroke_event_count": result["keystroke_event_count"],
    }

    if debug:
        response["debug"] = {
            "capture_duration_seconds": result["capture_duration_seconds"],
            "generation_elapsed_seconds": round(elapsed, 3),
            "platform": platform.system(),
            "input_backend": _detect_backend(),
            "api_version": "2.0.0",
        }

    log.info("Generation success for %s: %d-bit key, %d mouse events", client_ip, result["key_bits"], result["mouse_event_count"])
    return response


@app.post("/generate-per-move", summary="Generate one key per mouse movement")
def generate_per_move(
    request: Request,
    duration: float = Query(default=10.0, description="Capture duration in seconds (1-60)."),
    security_level: str = Query(default="quantum", description="'quantum' (512-bit) or 'standard' (256-bit)."),
    max_items: int = Query(default=200, ge=1, le=2000, description="Max per-move records returned in response."),
) -> dict[str, Any]:
    """Capture behaviour and generate key/random output for every mouse move."""

    client_ip = request.client.host if request.client else "unknown"

    try:
        duration = validate_duration(duration)
        security_level = validate_security_level(security_level)
    except HTTPException as exc:
        threat_logger.log_threat("INVALID_INPUT", client_ip, f"{exc.detail}")
        raise

    if not resource_limits.acquire():
        threat_logger.log_threat("RESOURCE_EXHAUSTED", client_ip, "Max concurrent captures reached")
        raise HTTPException(status_code=503, detail="Server busy. Try again shortly.")

    try:
        _assert_capture_possible()
        result = generate_per_mouse_movement_outputs(
            capture_duration_seconds=duration,
            security_level=security_level,
        )
    except Exception as exc:
        threat_logger.log_threat("PER_MOVE_GENERATION_FAILURE", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Per-move generation failed") from exc
    finally:
        resource_limits.release()

    outputs = result.get("outputs", [])
    trimmed_outputs = outputs[:max_items]
    return {
        "status": "ok",
        "security_level": result["security_level"],
        "capture_duration_seconds": result["capture_duration_seconds"],
        "mouse_event_count": result["mouse_event_count"],
        "keystroke_event_count": result["keystroke_event_count"],
        "per_move_count": result["per_move_count"],
        "returned_count": len(trimmed_outputs),
        "outputs": trimmed_outputs,
    }


@app.post("/nist/run", summary="Run full NIST experiments")
def nist_run(
    request: Request,
    num_keys: int = Query(default=4000, ge=500, le=20000, description="Keys per experiment."),
    duration: float = Query(default=4.0, description="Behaviour capture duration in seconds (1-60)."),
) -> dict[str, Any]:
    """Run Experiments A/B/C and return condensed NIST summary."""

    client_ip = request.client.host if request.client else "unknown"
    try:
        duration = validate_duration(duration)
    except HTTPException as exc:
        threat_logger.log_threat("INVALID_INPUT", client_ip, f"{exc.detail}")
        raise

    if not resource_limits.acquire():
        threat_logger.log_threat("RESOURCE_EXHAUSTED", client_ip, "Max concurrent captures reached")
        raise HTTPException(status_code=503, detail="Server busy. Try again shortly.")

    try:
        _assert_capture_possible()
        results = run_all_experiments(num_keys=num_keys, capture_duration_seconds=duration)
    except Exception as exc:
        threat_logger.log_threat("NIST_RUN_FAILURE", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="NIST run failed") from exc
    finally:
        resource_limits.release()

    compact: dict[str, Any] = {}
    for name, item in results.items():
        compact[name] = {
            "overall_passed_tests": item["overall_passed_tests"],
            "overall_eligible_tests": item["overall_eligible_tests"],
            "overall_pass_rate_percent": item["overall_pass_rate_percent"],
            "sequence_count": item["sequence_count"],
            "total_bits": item["total_bits"],
            "scoring_mode": item["scoring_mode"],
        }

    return {
        "status": "ok",
        "num_keys": num_keys,
        "capture_duration_seconds": duration,
        "results": compact,
    }


@app.get("/encryption-info", summary="Encryption algorithm details")
def get_encryption_info() -> dict[str, Any]:
    """Return details about the encryption scheme used (AES-256-GCM)."""
    return encryption_info()


class _EncryptMessageBody(BaseModel):
    """POST body for /encrypt/message — keeps key_hex out of URLs and server logs."""
    message: str
    key_hex: str
    label: str = ""


class _DecryptMessageBody(BaseModel):
    """POST body for /decrypt/message — keeps key_hex out of URLs and server logs."""
    nonce_hex: str
    ciphertext_hex: str
    key_hex: str
    associated_data_hex: str = ""


class _GenerateAndEncryptBody(BaseModel):
    """POST body for /generate-and-encrypt — keeps message out of URLs and logs."""
    message: str
    duration: float = 10.0
    security_level: str = "quantum"
    label: str = ""


class _RotatingEncryptBody(BaseModel):
    """POST body for /encrypt/rotating-message — keeps message and secrets out of URLs."""
    message: str
    user_id: str
    session_id: str
    context: str = "message"
    device_secret_hex: str = ""
    message_id: str = ""
    failed_otp_attempts: int = 0
    nfc_required_but_missing: bool = False


class _RotatingDecryptBody(BaseModel):
    """POST body for /decrypt/rotating-message — keeps ciphertext and secrets out of URLs."""
    envelope_json: str
    user_id: str
    session_id: str
    context: str = "message"
    device_secret_hex: str = ""
    max_clock_skew_seconds: float = 0.0


class _SelfHealingEncryptBody(BaseModel):
    """POST body for /encrypt/self-healing-message — keeps message and secrets out of URLs."""
    message: str
    user_id: str
    session_id: str
    context: str = "message"
    device_secret_hex: str = ""
    backup_device_secret_hex: str = ""
    operation_id: str = ""
    message_id: str = ""
    failed_otp_attempts: int = 0
    nfc_required_but_missing: bool = False
    max_retries: int = 2


class _GhostEncryptBody(BaseModel):
    """POST body for /ghost/encrypt."""

    message: str
    label: str = "ghost-message"
    ttl_seconds: int = 120


class _GhostPackageBody(BaseModel):
    """Portable ghost package for one-time API decrypt."""

    version: int
    ghost_id: str
    algorithm: str
    nonce_hex: str
    ciphertext_hex: str
    associated_data_hex: str = ""
    key_fingerprint: str = ""


@app.post("/encrypt/message", summary="Encrypt a text message with an existing key")
def encrypt_message_endpoint(
    request: Request,
    body: _EncryptMessageBody,
) -> dict[str, Any]:
    """Encrypt a message using AES-256-GCM with a previously generated key.

    Supply `key_hex` from a prior `/generate` call.
    The returned `nonce_hex` + `ciphertext_hex` + `associated_data_hex` are all
    needed to decrypt; store them together.

    Security note: key_hex is accepted in the POST body only — never in query
    params — so it cannot appear in server access logs, browser history, or
    HTTP Referer headers.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        key_bytes = bytes.fromhex(body.key_hex)
    except ValueError:
        threat_logger.log_threat("INVALID_INPUT", client_ip, "bad key_hex")
        raise HTTPException(status_code=422, detail="key_hex must be valid hexadecimal")

    if len(key_bytes) < 32:
        raise HTTPException(
            status_code=422,
            detail=f"key_hex must be at least 64 hex characters (32 bytes); got {len(key_bytes)} bytes",
        )

    aad = body.label.encode("utf-8") if body.label else b""
    try:
        encrypted = _encrypt_msg(key_bytes, body.message, associated_data=aad)
    except Exception as exc:
        log.exception("Encryption failed")
        raise HTTPException(status_code=500, detail="Encryption failed") from exc

    result = message_to_dict(encrypted)
    result["algorithm"] = "AES-256-GCM"
    result["plaintext_length_bytes"] = len(body.message.encode("utf-8"))
    result["ciphertext_length_bytes"] = len(encrypted.ciphertext)
    return result


@app.post("/decrypt/message", summary="Decrypt a message with an existing key")
def decrypt_message_endpoint(
    request: Request,
    body: _DecryptMessageBody,
) -> dict[str, Any]:
    """Decrypt a message produced by /encrypt/message.

    Security note: key_hex is accepted in the POST body only.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        key_bytes = bytes.fromhex(body.key_hex)
        encrypted = message_from_dict({
            "nonce_hex": body.nonce_hex,
            "ciphertext_hex": body.ciphertext_hex,
            "associated_data_hex": body.associated_data_hex,
        })
    except ValueError as exc:
        threat_logger.log_threat("INVALID_INPUT", client_ip, f"bad hex input: {exc}")
        raise HTTPException(status_code=422, detail=f"Invalid hex input: {exc}") from exc

    try:
        plaintext_bytes = _decrypt_msg(key_bytes, encrypted)
    except Exception as exc:
        threat_logger.log_threat("DECRYPT_FAILED", client_ip, type(exc).__name__)
        raise HTTPException(
            status_code=400,
            detail="Decryption failed — wrong key, tampered ciphertext, or wrong AAD",
        ) from exc

    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_str = None

    return {
        "status": "ok",
        "plaintext": plaintext_str,
        "plaintext_bytes_hex": plaintext_bytes.hex() if plaintext_str is None else None,
        "decrypted_length_bytes": len(plaintext_bytes),
    }


@app.get("/ghost/info", summary="Ghost handoff API details")
def ghost_info() -> dict[str, Any]:
    """Explain the portable one-time ghost handoff flow."""

    _cleanup_expired_ghost_keys()
    return {
        "status": "ok",
        "purpose": "Portable volunteer demo handoff for devices without SUMIT KEY installed.",
        "flow": [
            "POST /ghost/encrypt with plaintext to create a package.",
            "Move the returned package to any other device.",
            "POST /ghost/decrypt with that package to open it once.",
            "The server zeroizes and deletes the ghost key after decrypt or expiry.",
        ],
        "security_boundary": (
            "The receiver's random mouse movement cannot recreate the sender key. "
            "The API holds a short-lived one-time key for this demo."
        ),
        "active_ghost_keys": len(_ghost_keys),
        "max_ttl_seconds": _GHOST_MAX_TTL_SECONDS,
    }


@app.post("/ghost/encrypt", summary="Create a portable one-time ghost package")
def ghost_encrypt_endpoint(
    request: Request,
    body: _GhostEncryptBody,
) -> dict[str, Any]:
    """Create a ghost package that can be opened once from any device.

    The raw key is never returned. It is held in process memory, short-lived,
    and zeroized/deleted after `/ghost/decrypt` succeeds or the TTL expires.
    """

    client_ip = request.client.host if request.client else "unknown"
    _cleanup_expired_ghost_keys()

    ttl = max(1, min(int(body.ttl_seconds), _GHOST_MAX_TTL_SECONDS))
    key = os.urandom(32)
    aad = json.dumps(
        {
            "label": body.label,
            "mode": "ghost-api",
            "created_at": time.time(),
        },
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        encrypted = _encrypt_msg(key, body.message, associated_data=aad)
    except Exception as exc:
        threat_logger.log_threat("GHOST_ENCRYPT_FAILED", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Ghost encryption failed") from exc

    ghost_id = secrets.token_urlsafe(24)
    expires_at = time.time() + ttl
    key_buffer = bytearray(key)
    key_fp = _fingerprint(key_buffer)
    with _ghost_lock:
        _ghost_keys[ghost_id] = {
            "key": key_buffer,
            "expires_at": expires_at,
            "created_at": time.time(),
            "key_fingerprint": key_fp,
        }

    return {
        "status": "ok",
        "package": {
            "version": 1,
            "ghost_id": ghost_id,
            "algorithm": "AES-256-GCM",
            "nonce_hex": encrypted.nonce.hex(),
            "ciphertext_hex": encrypted.ciphertext.hex(),
            "associated_data_hex": encrypted.associated_data.hex(),
            "key_fingerprint": key_fp,
            "expires_at": expires_at,
            "warning": "Demo only. The API can open this once while the ghost key is alive.",
        },
        "instructions": "Send package to /ghost/decrypt from any device. The key is cleared after first decrypt.",
    }


@app.post("/ghost/decrypt", summary="Open a ghost package once, then clear the key")
def ghost_decrypt_endpoint(
    request: Request,
    body: _GhostPackageBody,
) -> dict[str, Any]:
    """Decrypt a ghost package once and immediately zeroize/delete its key."""

    client_ip = request.client.host if request.client else "unknown"
    _cleanup_expired_ghost_keys()

    if body.version != 1 or body.algorithm != "AES-256-GCM":
        raise HTTPException(status_code=422, detail="Unsupported ghost package")

    with _ghost_lock:
        record = _ghost_keys.pop(body.ghost_id, None)

    if record is None:
        threat_logger.log_threat("GHOST_KEY_MISSING", client_ip, body.ghost_id)
        raise HTTPException(status_code=410, detail="Ghost key expired, missing, or already used")

    key_buffer = record["key"]
    if float(record["expires_at"]) <= time.time():
        _zeroize(key_buffer)
        raise HTTPException(status_code=410, detail="Ghost key expired")

    try:
        encrypted = message_from_dict(
            {
                "nonce_hex": body.nonce_hex,
                "ciphertext_hex": body.ciphertext_hex,
                "associated_data_hex": body.associated_data_hex,
            }
        )
        plaintext_bytes = _decrypt_msg(bytes(key_buffer), encrypted)
    except ValueError as exc:
        threat_logger.log_threat("INVALID_GHOST_PACKAGE", client_ip, str(exc))
        raise HTTPException(status_code=422, detail=f"Invalid ghost package: {exc}") from exc
    except Exception as exc:
        threat_logger.log_threat("GHOST_DECRYPT_FAILED", client_ip, type(exc).__name__)
        raise HTTPException(status_code=400, detail="Ghost decrypt failed") from exc
    finally:
        _zeroize(key_buffer)

    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_str = None

    return {
        "status": "ok",
        "plaintext": plaintext_str,
        "plaintext_bytes_hex": plaintext_bytes.hex() if plaintext_str is None else None,
        "key_fingerprint": record["key_fingerprint"],
        "ghost_key_status": "zeroized_and_deleted",
        "decrypted_length_bytes": len(plaintext_bytes),
    }


@app.get("/ghost/status/{ghost_id}", summary="Check whether a ghost key is still alive")
def ghost_status_endpoint(ghost_id: str) -> dict[str, Any]:
    """Return ghost-key state without revealing key material."""

    _cleanup_expired_ghost_keys()
    with _ghost_lock:
        record = _ghost_keys.get(ghost_id)
        if record is None:
            return {
                "status": "gone",
                "ghost_id": ghost_id,
                "available": False,
                "detail": "expired, revoked, missing, or already used",
            }
        return {
            "status": "alive",
            "ghost_id": ghost_id,
            "available": True,
            "key_fingerprint": record["key_fingerprint"],
            "expires_at": record["expires_at"],
            "seconds_remaining": max(0, round(float(record["expires_at"]) - time.time(), 3)),
        }


@app.post("/ghost/revoke/{ghost_id}", summary="Revoke and zeroize a ghost key")
def ghost_revoke_endpoint(ghost_id: str) -> dict[str, Any]:
    """Manually burn a ghost key before it is opened."""

    _cleanup_expired_ghost_keys()
    with _ghost_lock:
        record = _ghost_keys.pop(ghost_id, None)
    if record is None:
        return {
            "status": "gone",
            "ghost_id": ghost_id,
            "revoked": False,
            "detail": "expired, revoked, missing, or already used",
        }
    _zeroize(record["key"])
    return {
        "status": "revoked",
        "ghost_id": ghost_id,
        "revoked": True,
        "key_fingerprint": record["key_fingerprint"],
        "ghost_key_status": "zeroized_and_deleted",
    }


@app.post("/generate-and-encrypt", summary="Generate key from mouse entropy, then encrypt a message")
def generate_and_encrypt(
    request: Request,
    body: _GenerateAndEncryptBody,
) -> dict[str, Any]:
    """Capture mouse entropy, derive a key, and encrypt the given message in one step.

    The key is returned in the response so the caller can decrypt later.
    Move your mouse during the capture window.

    Security note: message and label are accepted in the POST body only so they
    never appear in URLs, server access logs, or browser history.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        duration = validate_duration(body.duration)
        security_level = validate_security_level(body.security_level)
    except HTTPException as exc:
        threat_logger.log_threat("INVALID_INPUT", client_ip, exc.detail)
        raise

    if not resource_limits.acquire():
        raise HTTPException(status_code=503, detail="Server busy. Try again shortly.")

    try:
        _assert_capture_possible()
        gen_result = generate_random_number_and_key(
            capture_duration_seconds=duration,
            security_level=security_level,
        )
    except Exception as exc:
        threat_logger.log_threat("GENERATION_FAILURE", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Key generation failed") from exc
    finally:
        resource_limits.release()

    key_bytes = bytes.fromhex(gen_result["key_hex"])
    aad = body.label.encode("utf-8") if body.label else b""
    encrypted = _encrypt_msg(key_bytes, body.message, associated_data=aad)
    enc_dict = message_to_dict(encrypted)

    return {
        "status": "ok",
        "security_level": security_level,
        "key_hex": gen_result["key_hex"],
        "key_bits": gen_result["key_bits"],
        "random_number": gen_result["random_number"],
        "mouse_event_count": gen_result["mouse_event_count"],
        "keystroke_event_count": gen_result["keystroke_event_count"],
        "encrypted_message": enc_dict,
        "algorithm": "AES-256-GCM",
        "note": "Store key_hex and encrypted_message together to decrypt later via /decrypt/message",
    }


@app.post("/encrypt/rotating-message", summary="Encrypt with 0.3-second rotating per-system keys")
def rotating_encrypt_message_endpoint(
    request: Request,
    body: _RotatingEncryptBody,
) -> dict[str, Any]:
    """Encrypt under a key that rotates every 0.3 seconds.

    The key is derived from this individual system identity, session id, device
    secret, context, and the current 0.3-second epoch. High-risk threat signals
    block encryption.

    Security note: message, device_secret_hex, and all credentials are accepted
    in the POST body only — never in query params — to keep them out of server
    access logs and browser history.
    """

    client_ip = request.client.host if request.client else "unknown"
    identity = _api_system_identity(
        user_id=body.user_id,
        session_id=body.session_id,
        device_secret_hex=body.device_secret_hex,
    )
    rotating = RotatingKeyEnvelope(identity)

    try:
        encrypted = rotating.encrypt(
            body.message,
            context=body.context,
            message_id=body.message_id or None,
            source_ip=client_ip,
            failed_otp_attempts=body.failed_otp_attempts,
            nfc_required_but_missing=body.nfc_required_but_missing,
        )
    except ThreatBlockedError as exc:
        threat_logger.log_threat("ROTATING_ENCRYPT_BLOCKED", client_ip, str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    output = encrypted.to_dict()
    output["status"] = "ok"
    output["rotation_seconds"] = rotating.rotation_seconds
    output["note"] = (
        "Decrypt before expires_at. For stable decrypt calls, provide the same "
        "user_id, session_id, context, and device_secret_hex or SUMIT_DEVICE_SECRET_HEX."
    )
    return output


@app.post("/decrypt/rotating-message", summary="Decrypt a 0.3-second rotating-key message")
def rotating_decrypt_message_endpoint(
    request: Request,
    body: _RotatingDecryptBody,
) -> dict[str, Any]:
    """Decrypt a rotating-key envelope if it has not expired.

    Security note: envelope_json and device_secret_hex are accepted in the POST
    body only to keep ciphertext and credentials out of server access logs.
    """

    client_ip = request.client.host if request.client else "unknown"
    try:
        envelope_data = json.loads(body.envelope_json)
        encrypted = RotatingEncryptedMessage.from_dict(envelope_data)
    except Exception as exc:
        threat_logger.log_threat("ROTATING_DECRYPT_BAD_ENVELOPE", client_ip, type(exc).__name__)
        raise HTTPException(status_code=422, detail="envelope_json is invalid") from exc

    identity = _api_system_identity(
        user_id=body.user_id,
        session_id=body.session_id,
        device_secret_hex=body.device_secret_hex,
    )
    rotating = RotatingKeyEnvelope(identity)

    try:
        plaintext = rotating.decrypt(
            encrypted,
            context=body.context,
            max_clock_skew_seconds=body.max_clock_skew_seconds,
        )
    except ExpiredKeyEpochError as exc:
        threat_logger.log_threat("ROTATING_DECRYPT_EXPIRED", client_ip, str(exc))
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except Exception as exc:
        threat_logger.log_threat("ROTATING_DECRYPT_FAILED", client_ip, type(exc).__name__)
        raise HTTPException(status_code=400, detail="rotating decrypt failed") from exc

    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    return {
        "status": "ok",
        "plaintext": text,
        "plaintext_bytes_hex": plaintext.hex() if text is None else None,
        "decrypted_length_bytes": len(plaintext),
    }


@app.post("/encrypt/self-healing-message", summary="Encrypt with self-healing rotating-key recovery")
def self_healing_encrypt_message_endpoint(
    request: Request,
    body: _SelfHealingEncryptBody,
) -> dict[str, Any]:
    """Encrypt with journaled recovery, retry, verification, and backup failover.

    Recovery is fail-closed: real threat blocks, tamper failures, and identity
    mismatches are returned as security stops instead of being bypassed.

    Security note: message, device_secret_hex, and all credentials are accepted
    in the POST body only — never in query params — to keep them out of server
    access logs and browser history.
    """

    client_ip = request.client.host if request.client else "unknown"
    identity = _api_system_identity(
        user_id=body.user_id,
        session_id=body.session_id,
        device_secret_hex=body.device_secret_hex,
    )
    backup_identity = _api_backup_identity(
        user_id=body.user_id,
        session_id=body.session_id,
        backup_device_secret_hex=body.backup_device_secret_hex,
    )
    healer = SelfHealingCryptoService(
        identity,
        backup_identity=backup_identity,
        config=SelfHealingConfig(max_retries=body.max_retries),
    )

    try:
        result = healer.encrypt_message(
            body.message,
            context=body.context,
            operation_id=body.operation_id or None,
            message_id=body.message_id or None,
            source_ip=client_ip,
            failed_otp_attempts=body.failed_otp_attempts,
            nfc_required_but_missing=body.nfc_required_but_missing,
        )
    except UnrecoverableSecurityError as exc:
        threat_logger.log_threat("SELF_HEALING_SECURITY_STOP", client_ip, str(exc))
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except SelfHealingError as exc:
        threat_logger.log_threat("SELF_HEALING_FAILED", client_ip, str(exc))
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    output = result.to_dict()
    output["note"] = (
        "Self-healing retried only transient faults. It did not bypass threat "
        "blocks, AES-GCM verification, or identity checks."
    )
    return output


@app.get("/debug/pipeline", summary="Debug the full pipeline with synthetic events")
def debug_pipeline_synthetic(
    n_moves: int = Query(default=20, ge=1, le=200, description="Number of synthetic mouse moves."),
    security_level: str = Query(default="quantum"),
) -> dict[str, Any]:
    """Run the full pipeline debug trace on synthetic (non-hardware) events.

    Returns stage-by-stage results and per-move key/RNG analysis.
    Useful for verifying the pipeline works without a mouse session.
    """
    try:
        security_level = validate_security_level(security_level)
    except HTTPException:
        raise

    mouse_events = make_synthetic_mouse_events(n_moves)
    keystroke_events = make_synthetic_keystroke_events(min(n_moves // 3, 10))

    debugger = PipelineDebugger(security_level=security_level)
    pipeline_result = debugger.run(mouse_events, keystroke_events)

    agent = EntropyAgent(security_level=security_level)
    report = agent.analyze(mouse_events, keystroke_events)

    per_move_summary = [
        {
            "move_index": r.move_index,
            "key_hex_preview": r.key_hex_preview,
            "key_bits": r.key_bits,
            "random_number": r.random_number,
            "key_changed": r.key_changed,
            "entropy_bits_estimate": r.entropy_bits_estimate,
        }
        for r in report.records
    ]

    return {
        "status": "ok",
        "pipeline": {
            "all_stages_passed": pipeline_result["all_passed"],
            "stages_run": pipeline_result["stages"],
            "key_hex": pipeline_result["key_hex"],
            "key_bits": pipeline_result["key_bits"],
            "random_number": pipeline_result["random_number"],
        },
        "per_move_agent": {
            "total_moves": report.total_moves,
            "keys_generated": report.total_moves,
            "random_numbers_generated": report.total_moves,
            "unique_keys": report.unique_keys,
            "unique_random_numbers": report.unique_rngs,
            "key_change_rate_percent": report.change_rate_percent,
            "key_bits": report.records[0].key_bits if report.records else 0,
        },
        "per_move_detail": per_move_summary,
    }


@app.post("/debug/per-move-live", summary="Live per-move debug: key + RNG per mouse movement")
def debug_per_move_live(
    request: Request,
    duration: float = Query(default=5.0, description="Capture duration in seconds (1-30)."),
    security_level: str = Query(default="quantum"),
    max_items: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Capture live mouse events and report one key + random number per move.

    Move your mouse during the capture window.
    Shows exactly: for each individual mouse movement, what key and RNG are produced.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        duration = validate_duration(duration)
        security_level = validate_security_level(security_level)
    except HTTPException as exc:
        threat_logger.log_threat("INVALID_INPUT", client_ip, exc.detail)
        raise

    if not resource_limits.acquire():
        raise HTTPException(status_code=503, detail="Server busy. Try again shortly.")

    try:
        _assert_capture_possible()
        from capture import capture_behaviour
        mouse_events, keystroke_events = capture_behaviour(duration)
    except Exception as exc:
        threat_logger.log_threat("CAPTURE_FAILURE", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Capture failed") from exc
    finally:
        resource_limits.release()

    agent = EntropyAgent(security_level=security_level)
    report = agent.analyze(mouse_events, keystroke_events)

    per_move_detail = [
        {
            "move_index": r.move_index,
            "x": round(r.x, 1),
            "y": round(r.y, 1),
            "velocity_px_s": round(r.velocity_px_per_s, 1),
            "direction_deg": round(r.direction_deg, 1),
            "key_hex_preview": r.key_hex_preview,
            "key_bits": r.key_bits,
            "random_number": r.random_number,
            "key_changed_from_prev": r.key_changed,
            "entropy_bits_estimate": r.entropy_bits_estimate,
        }
        for r in report.records[:max_items]
    ]

    return {
        "status": "ok",
        "capture_duration_seconds": duration,
        "security_level": security_level,
        "agent_summary": {
            "total_moves_captured": report.total_moves,
            "keys_generated": report.total_moves,
            "random_numbers_generated": report.total_moves,
            "unique_keys": report.unique_keys,
            "unique_random_numbers": report.unique_rngs,
            "key_change_rate_percent": report.change_rate_percent,
            "key_bits": report.records[0].key_bits if report.records else 0,
        },
        "per_move_detail": per_move_detail,
        "returned_count": len(per_move_detail),
    }


@app.get("/benchmark", summary="Cryptographic benchmark: entropy quality, cipher speed, Argon2id, ML-KEM, MAYO")
def benchmark(
    quick: bool = Query(default=True, description="Quick mode uses 64KB payload; full mode uses 1MB."),
) -> dict[str, Any]:
    """Run the full cryptographic benchmark suite and return structured results.

    Covers:
    - Entropy quality analysis (Shannon, chi-squared, autocorrelation) on SUMIT KEY output
    - AES-256-GCM vs ChaCha20-Poly1305 throughput (MB/s)
    - HKDF-SHA3 vs Argon2id key derivation speed and cost comparison
    - ML-KEM-512/768/1024 (FIPS 203 Kyber) keygen / encaps / decaps timing
    - MAYO-5 documented security analysis (requires liboqs for runtime benchmark)
    """
    try:
        result = get_benchmark_summary(quick=quick)
        result["status"] = "ok"
        result["mode"] = "quick" if quick else "full"
        return result
    except Exception as exc:
        log.exception("Benchmark failed")
        raise HTTPException(status_code=500, detail=f"Benchmark failed: {type(exc).__name__}") from exc


@app.get("/threat-model", summary="Full cryptographic threat model for all algorithms")
def threat_model_endpoint() -> dict[str, Any]:
    """Return the complete threat model for the SUMIT KEY cryptographic pipeline.

    Includes per-algorithm analysis of:
    - Classical attacks (brute-force, birthday, meet-in-the-middle)
    - Quantum attacks (Grover, Shor, BKZ lattice)
    - Side-channel attacks (timing, power, cache)
    - Protocol attacks (nonce reuse, downgrade, replay)
    - Implementation risks and known CVEs

    Algorithms covered: AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA3,
    Argon2id, ML-KEM-1024 (FIPS 203), MAYO-5.

    Also includes the entropy source threat surface and recommended secure stack.
    """
    try:
        model = get_threat_model()
        model["status"] = "ok"
        return model
    except Exception as exc:
        log.exception("Threat model generation failed")
        raise HTTPException(status_code=500, detail=f"Threat model failed: {type(exc).__name__}") from exc


# ---------------------------------------------------------------------------
# Quantum-safe hybrid pipeline endpoints
# ---------------------------------------------------------------------------

class QuantumEncryptRequest(BaseModel):
    ek_hex: str
    message: str
    label: str = ""


class QuantumDecryptRequest(BaseModel):
    dk_hex: str
    kem_ct_hex: str
    argon2_salt_hex: str
    argon2_time_cost: int
    argon2_memory_kb: int
    hardened_nonce_hex: str
    hardened_enc_hex: str
    nonce_hex: str
    ciphertext_hex: str
    associated_data_hex: str = ""


@app.post("/quantum/keygen", summary="Generate ML-KEM-1024 quantum key pair")
def quantum_keygen_endpoint() -> dict[str, Any]:
    """Generate an ML-KEM-1024 (FIPS 203) key pair.

    Returns `ek_hex` (1568 bytes) and `dk_hex` (3168 bytes).
    Keep `dk_hex` secret — it is needed for decryption.
    """
    try:
        session = _quantum_keygen()
        return {
            "status": "ok",
            "ek_hex": session.ek,
            "dk_hex": session.dk,
            "ek_size_bytes": len(session.ek_bytes()),
            "dk_size_bytes": len(session.dk_bytes()),
            **quantum_encryption_info(),
        }
    except Exception as exc:
        log.exception("Quantum keygen failed")
        raise HTTPException(status_code=500, detail="Quantum key generation failed") from exc


@app.post("/quantum/encrypt", summary="Encrypt with ML-KEM-1024 + Argon2id + AES-256-GCM")
def quantum_encrypt_endpoint(
    request: Request,
    body: QuantumEncryptRequest,
) -> dict[str, Any]:
    """Encrypt a message with the full quantum-safe hybrid pipeline.

    Supply `ek_hex` from `/quantum/keygen`.  The response contains everything
    required by `/quantum/decrypt` (plus `dk_hex` kept by the recipient).
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        ek_bytes = bytes.fromhex(body.ek_hex)
    except ValueError:
        threat_logger.log_threat("INVALID_INPUT", client_ip, "bad ek_hex")
        raise HTTPException(status_code=422, detail="ek_hex must be valid hexadecimal")

    if len(ek_bytes) != 1568:
        raise HTTPException(
            status_code=422,
            detail=f"ek_hex must be 3136 hex chars (1568 bytes); got {len(ek_bytes)} bytes",
        )

    session = QuantumSession(ek=body.ek_hex, dk="00" * 3168)
    aad = body.label.encode("utf-8") if body.label else b""

    try:
        pkg = _quantum_encrypt(session, body.message.encode("utf-8"), os.urandom(64), associated_data=aad)
    except Exception as exc:
        log.exception("Quantum encryption failed")
        raise HTTPException(status_code=500, detail="Quantum encryption failed") from exc

    pkg_dict = quantum_package_to_dict(pkg)
    pkg_dict["status"] = "ok"
    pkg_dict["algorithm"] = "ML-KEM-1024 + Argon2id + AES-256-GCM"
    pkg_dict["plaintext_length_bytes"] = len(body.message.encode("utf-8"))
    return pkg_dict


@app.post("/quantum/decrypt", summary="Decrypt a quantum-safe package")
def quantum_decrypt_endpoint(
    request: Request,
    body: QuantumDecryptRequest,
) -> dict[str, Any]:
    """Decrypt a package from `/quantum/encrypt`.

    Supply `dk_hex` from `/quantum/keygen` and all fields returned by
    `/quantum/encrypt`.  Returns 400 on wrong key or tampered ciphertext.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        dk_bytes = bytes.fromhex(body.dk_hex)
    except ValueError:
        threat_logger.log_threat("INVALID_INPUT", client_ip, "bad dk_hex")
        raise HTTPException(status_code=422, detail="dk_hex must be valid hexadecimal")

    if len(dk_bytes) != 3168:
        raise HTTPException(
            status_code=422,
            detail=f"dk_hex must be 6336 hex chars (3168 bytes); got {len(dk_bytes)} bytes",
        )

    try:
        pkg = quantum_package_from_dict({
            "kem_ct_hex": body.kem_ct_hex,
            "argon2_salt_hex": body.argon2_salt_hex,
            "argon2_time_cost": body.argon2_time_cost,
            "argon2_memory_kb": body.argon2_memory_kb,
            "hardened_nonce_hex": body.hardened_nonce_hex,
            "hardened_enc_hex": body.hardened_enc_hex,
            "nonce_hex": body.nonce_hex,
            "ciphertext_hex": body.ciphertext_hex,
            "associated_data_hex": body.associated_data_hex,
        })
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid package fields: {exc}") from exc

    session = QuantumSession(ek="00" * 1568, dk=body.dk_hex)
    try:
        plaintext_bytes = _quantum_decrypt(session, pkg)
    except Exception as exc:
        threat_logger.log_threat("QUANTUM_DECRYPT_FAILED", client_ip, type(exc).__name__)
        raise HTTPException(
            status_code=400,
            detail="Decryption failed — wrong key, tampered ciphertext, or corrupted package",
        ) from exc

    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_str = None

    return {
        "status": "ok",
        "plaintext": plaintext_str,
        "plaintext_bytes_hex": plaintext_bytes.hex() if plaintext_str is None else None,
        "decrypted_length_bytes": len(plaintext_bytes),
    }


@app.get("/threat-stats", summary="Threat detection statistics (admin)")
def threat_stats() -> dict[str, Any]:
    """Return security threat statistics and IP blocklist.

    **Note:** This endpoint should be protected by firewall rules in production.
    Only access from internal/localhost.
    """
    return threat_logger.get_stats()


@app.get("/resource-status", summary="Current resource usage")
def resource_status() -> dict[str, Any]:
    """Return current resource allocation (concurrent captures, etc.)."""
    return resource_limits.get_status()


# ---------------------------------------------------------------------------
# High-Voltage Vault / ZKP / MITM Shield / Threat Detector endpoints
# ---------------------------------------------------------------------------

# Singletons (lazy, cold-start-safe)
_vault_singleton: HighVoltageVault | None = None
_detector_singleton: AdvancedThreatDetector | None = None
_vault_lock = threading.Lock()


def _get_vault() -> HighVoltageVault:
    global _vault_singleton
    with _vault_lock:
        if _vault_singleton is None:
            _vault_singleton = HighVoltageVault()
    return _vault_singleton


def _get_detector() -> AdvancedThreatDetector:
    global _detector_singleton
    with _vault_lock:
        if _detector_singleton is None:
            _detector_singleton = AdvancedThreatDetector()
    return _detector_singleton


# ── Pydantic models for vault/ZKP endpoints ───────────────────────────────

class ZKPProveRequest(BaseModel):
    entropy_hex: str
    context: str = ""


class ZKPVerifyRequest(BaseModel):
    pk_hex: str
    proof: dict[str, str]
    context: str = ""


class VaultStoreRequest(BaseModel):
    key_hex: str
    master_password: str
    n_shards: int = 5
    threshold: int = 3
    ttl_seconds: float = 3600.0
    burn_after_read: bool = True


class VaultRetrieveRequest(BaseModel):
    vault_id: str
    shard_xs: list[int]
    master_password: str


class ThreatAssessRequest(BaseModel):
    source_ip: str = "unknown"
    message_id: Optional[str] = None
    mouse_event_timestamps_ms: Optional[list[float]] = None
    key_hex: str = ""
    honeypot_filled: bool = False
    user_agent: str = ""
    failed_attempts: int = 0


# ── ZKP endpoints ────────────────────────────────────────────────────────────

@app.get("/vault/info", summary="Vault, ZKP, MITM Shield and threat detector capabilities")
def vault_info_endpoint() -> dict[str, Any]:
    """Return full capability summary for the High-Voltage Vault system."""
    return {"status": "ok", **vault_info()}


@app.post("/vault/zkp/keygen", summary="Generate Schnorr ZKP key pair from entropy")
def zkp_keygen_endpoint(
    entropy_hex: str = Query(default="", description="64-byte hex entropy (auto-generated if empty)."),
) -> dict[str, Any]:
    """Derive a 2048-bit Schnorr key pair from behavioural entropy.

    The secret key (sk) is derived deterministically from your entropy.
    Only the public key (pk) is returned — sk never leaves the server.
    """
    entropy = bytes.fromhex(entropy_hex) if entropy_hex else os.urandom(64)
    kp = _zkp_keygen(entropy)
    return {
        "status": "ok",
        "pk_hex": kp.pk_hex(),
        "group": "RFC-3526-Group14-2048bit",
        "generator": 2,
        "scheme": "Schnorr (Fiat-Shamir SHA3-256)",
        "security_classical_bits": 128,
        "security_quantum_bits": 64,
    }


@app.post("/vault/zkp/prove", summary="Generate a non-interactive Schnorr ZKP")
def zkp_prove_endpoint(body: ZKPProveRequest) -> dict[str, Any]:
    """Prove knowledge of the secret key without revealing it.

    Supply the same `entropy_hex` used at key generation.
    The proof is non-interactive (Fiat-Shamir) and single-use — each call
    produces a fresh proof with a new random nonce.
    """
    try:
        entropy = bytes.fromhex(body.entropy_hex)
    except ValueError:
        raise HTTPException(status_code=422, detail="entropy_hex must be valid hexadecimal")
    kp = _zkp_keygen(entropy)
    proof = _zkp_prove(kp, body.context.encode())
    return {
        "status": "ok",
        "pk_hex": kp.pk_hex(),
        "proof": proof.to_dict(),
        "context": body.context,
    }


@app.post("/vault/zkp/verify", summary="Verify a Schnorr ZKP (no secret needed)")
def zkp_verify_endpoint(body: ZKPVerifyRequest) -> dict[str, Any]:
    """Verify a ZKP produced by /vault/zkp/prove.

    Only the public key (pk_hex) and the proof are needed.
    The secret key is never revealed or required by the verifier.
    """
    try:
        proof = ZKPProof.from_dict(body.proof)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Invalid proof format: {exc}")
    verified = _zkp_verify(body.pk_hex, proof, body.context.encode())
    return {"status": "ok", "verified": verified, "context": body.context}


# ── High-Voltage Vault endpoints ─────────────────────────────────────────────

@app.post("/vault/store", summary="Store a key in the High-Voltage Vault (Shamir sharded)")
def vault_store_endpoint(request: Request, body: VaultStoreRequest) -> dict[str, Any]:
    """Shard and store a key using Shamir Secret Sharing + AES-256-GCM per shard.

    The plaintext key is immediately split into `n_shards` shards.
    Retrieving it requires at least `threshold` shards + the master_password.
    Set `burn_after_read=true` for one-time-use keys.
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        key_bytes = bytes.fromhex(body.key_hex)
    except ValueError:
        threat_logger.log_threat("INVALID_INPUT", client_ip, "bad key_hex in vault_store")
        raise HTTPException(status_code=422, detail="key_hex must be valid hexadecimal")
    if len(key_bytes) < 1:
        raise HTTPException(status_code=422, detail="key_hex must be non-empty")
    try:
        vault_id = _get_vault().store(
            key_bytes,
            master_password=body.master_password.encode(),
            n_shards=body.n_shards,
            threshold=body.threshold,
            ttl_seconds=body.ttl_seconds,
            burn_after_read=body.burn_after_read,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "status": "ok",
        "vault_id": vault_id,
        "n_shards": body.n_shards,
        "threshold": body.threshold,
        "burn_after_read": body.burn_after_read,
        "ttl_seconds": body.ttl_seconds,
        "note": f"Need any {body.threshold} of {body.n_shards} shard indices [1..{body.n_shards}] to retrieve",
    }


@app.post("/vault/retrieve", summary="Retrieve a key from the vault using threshold shards")
def vault_retrieve_endpoint(request: Request, body: VaultRetrieveRequest) -> dict[str, Any]:
    """Reconstruct the key from threshold shards.

    If `burn_after_read` was set at store time, the vault transitions to BURNED
    immediately after decryption and the key cannot be retrieved again.
    """
    client_ip = request.client.host if request.client else "unknown"
    try:
        key_bytes = _get_vault().retrieve(
            body.vault_id,
            body.shard_xs,
            body.master_password.encode(),
        )
    except PermissionError as exc:
        threat_logger.log_threat("VAULT_ACCESS_DENIED", client_ip, str(exc))
        raise HTTPException(status_code=403, detail=str(exc))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "ok", "key_hex": key_bytes.hex(), "key_bits": len(key_bytes) * 8}


@app.get("/vault/status/{vault_id}", summary="Get vault state without revealing key material")
def vault_status_endpoint(vault_id: str) -> dict[str, Any]:
    """Return vault state (ARMED/BURNED/SEALED/ZEROIZED) and metadata."""
    return {"status": "ok", **_get_vault().status(vault_id)}


@app.post("/vault/seal/{vault_id}", summary="Manually seal a vault (no further reads)")
def vault_seal_endpoint(vault_id: str) -> dict[str, Any]:
    """Permanently seal a vault — no further retrieval is possible."""
    _get_vault().seal(vault_id)
    return {"status": "ok", "vault_id": vault_id, "sealed": True}


@app.post("/vault/zeroize/{vault_id}", summary="Emergency: wipe all shard memory")
def vault_zeroize_endpoint(vault_id: str) -> dict[str, Any]:
    """Overwrite all shard bytes in memory and destroy the vault entry.

    **This is irreversible.** Use only in emergency (key compromise suspected).
    """
    _get_vault().zeroize(vault_id)
    return {"status": "ok", "vault_id": vault_id, "zeroized": True}


# ── Advanced Threat Detector endpoint ────────────────────────────────────────

@app.post("/vault/threat/assess", summary="Multi-layer behavioral threat assessment")
def threat_assess_endpoint(request: Request, body: ThreatAssessRequest) -> dict[str, Any]:
    """Assess a request for threats: honeypot, brute-force, probe, replay, entropy anomaly.

    Risk levels:
    - ALLOW (0-25): proceed normally
    - MONITOR (26-50): log and proceed
    - QUARANTINE (51-80): trigger step-up verification
    - BLOCK (81+): reject request

    The MITM Shield intercepts wire traffic; this endpoint scores behavioural signals.
    """
    client_ip = request.client.host if request.client else body.source_ip
    key_bytes = bytes.fromhex(body.key_hex) if body.key_hex else None
    assessment = _get_detector().assess(
        source_ip=client_ip,
        message_id=body.message_id,
        mouse_event_timestamps_ms=body.mouse_event_timestamps_ms,
        key_bytes=key_bytes,
        honeypot_filled=body.honeypot_filled,
        user_agent=body.user_agent or request.headers.get("user-agent", ""),
        failed_attempts=body.failed_attempts,
    )
    if assessment.level == ThreatLevel.BLOCK:
        threat_logger.log_threat("THREAT_BLOCKED", client_ip,
                                 f"score={assessment.risk_score} signals={[s.name for s in assessment.signals]}")
    return {"status": "ok", **assessment.to_dict()}


# ── Serverless proxy endpoint ─────────────────────────────────────────────────

class _VaultServerlessBody(BaseModel):
    """POST body for /vault/serverless."""
    action: str
    payload: dict[str, Any] = {}


@app.post("/vault/serverless", summary="Provider-agnostic serverless action dispatcher")
def vault_serverless_endpoint(body: _VaultServerlessBody) -> dict[str, Any]:
    """Dispatch a vault action through the AWS Lambda / GCP / Azure compatible handler.

    Same interface as the Lambda `lambda_handler(event, context)` function —
    useful for testing serverless behaviour without deploying to a cloud provider.
    """
    event = {"action": body.action, "payload": body.payload}
    result = _vault_lambda(event)
    result_body = json.loads(result["body"])
    result_body["http_status"] = result["statusCode"]
    return result_body


# ---------------------------------------------------------------------------
# Quantum Ghost Session — two-device, presence-proof, burn-after-read
# ---------------------------------------------------------------------------
#
# FLOW:
#  [Receiver device — SETUP]
#    POST /ghost/quantum/session
#      → ML-KEM-1024 keypair generated (ek, dk)
#      → dk stored in HighVoltageVault (burn_after_read, TTL=5min)
#      → Returns: vault_id, session_secret_hex (share both with receiver
#        out-of-band), ek_hex (public — give to sender)
#
#  [Sender device — ENCRYPT]
#    POST /ghost/quantum/send
#      Body: { ek_hex, message, mouse_events }
#      → Sender moves mouse → entropy extracted
#      → quantum_encrypt(ek, message, mouse_entropy) → QuantumSafePackage
#      → Returns: package (share with receiver)
#
#  [Receiver device — DECRYPT + BURN]
#    POST /ghost/quantum/receive
#      Body: { vault_id, session_secret_hex, package, mouse_events }
#      → Receiver moves mouse → proves physical presence
#      → Vault releases dk using session_secret (burn_after_read BURNS it)
#      → quantum_decrypt(dk, package) → plaintext
#      → Ghost key is gone — cannot be reused
#
# Any MITM attempt triggers IP+MAC logging and BLOCK.

_qs_vault: "HighVoltageVault | None" = None
_qs_vault_lock = threading.Lock()


def _get_qs_vault() -> "HighVoltageVault":
    global _qs_vault
    with _qs_vault_lock:
        if _qs_vault is None:
            _qs_vault = HighVoltageVault()
    return _qs_vault


class _QsSessionBody(BaseModel):
    ttl_seconds: int = 300


class _QsSendBody(BaseModel):
    ek_hex: str
    message: str
    mouse_events: list[dict] = []
    label: str = "ghost-message"


class _QsReceiveBody(BaseModel):
    vault_id: str
    session_secret_hex: str
    package: dict
    mouse_events: list[dict] = []


class _QsRevokeBody(BaseModel):
    vault_id: str


@app.post("/ghost/quantum/session", summary="Setup a quantum ghost session (receiver device)")
def qs_session_endpoint(request: Request, body: _QsSessionBody) -> dict[str, Any]:
    """Generate ML-KEM-1024 keypair; store dk in burn-after-read vault.

    Call this on the RECEIVER device. Returns:
    - ek_hex      — give to the sender (public)
    - vault_id    — keep for /ghost/quantum/receive
    - session_secret_hex — keep for /ghost/quantum/receive (authenticates vault access)
    """
    client_ip = request.client.host if request.client else "unknown"
    ttl = max(30, min(int(body.ttl_seconds), 600))

    session = _quantum_keygen()
    session_secret = os.urandom(32)

    vault = _get_qs_vault()
    dk_bytes = session.dk_bytes()

    vault_id = vault.store(
        dk_bytes,
        master_password=session_secret,
        n_shards=5,
        threshold=3,
        ttl_seconds=float(ttl),
        burn_after_read=True,
    )

    expires_at = time.time() + ttl
    log.info("Ghost quantum session created vault=%s from=%s ttl=%ds", vault_id[:8], client_ip, ttl)

    return {
        "status": "ok",
        "vault_id": vault_id,
        "session_secret_hex": session_secret.hex(),
        "ek_hex": session.ek,
        "expires_at": expires_at,
        "ttl_seconds": ttl,
        "instructions": {
            "sender": "POST /ghost/quantum/send with ek_hex + message + mouse_events",
            "receiver": "POST /ghost/quantum/receive with vault_id + session_secret_hex + package + mouse_events",
        },
        "warning": "Share vault_id+session_secret only with the intended receiver. dk is burn-after-read.",
    }


@app.post("/ghost/quantum/send", summary="Encrypt a message for a quantum ghost session (sender device)")
def qs_send_endpoint(request: Request, body: _QsSendBody) -> dict[str, Any]:
    """Encrypt a message using the receiver's ek + your mouse entropy.

    Any device can send — only the receiver with the matching dk (in the vault)
    can decrypt. The sender's mouse movement hardens the Argon2id layer inside
    the quantum-safe package.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        ek_bytes = bytes.fromhex(body.ek_hex)
    except ValueError:
        raise HTTPException(status_code=422, detail="ek_hex must be valid hex")
    if len(ek_bytes) != 1568:
        raise HTTPException(status_code=422, detail="ek_hex must be 1568 bytes (ML-KEM-1024)")

    from entropy_engine import extract_mouse_entropy
    from key_generator import KeyGenerator, HKDFConfig, EntropyHealthError

    if body.mouse_events:
        raw_entropy = extract_mouse_entropy(body.mouse_events)
    else:
        raw_entropy = os.urandom(32)

    try:
        behavioural = KeyGenerator.generate_fresh_key(raw_entropy)
    except EntropyHealthError:
        behavioural = os.urandom(32)

    try:
        pkg = _quantum_encrypt(
            body.ek_hex,
            body.message,
            behavioural,
            associated_data=body.label.encode("utf-8"),
        )
    except Exception as exc:
        threat_logger.log_threat("QS_ENCRYPT_FAILED", client_ip, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Quantum encryption failed") from exc

    pkg_dict = quantum_package_to_dict(pkg)
    pkg_dict["label"] = body.label
    pkg_dict["kem_fingerprint"] = hashlib.sha256(bytes.fromhex(pkg_dict["kem_ct_hex"])).hexdigest()[:16]

    log.info("Ghost quantum send from=%s label=%s", client_ip, body.label)
    return {
        "status": "ok",
        "package": pkg_dict,
        "algorithm": "ML-KEM-1024 + Argon2id + AES-256-GCM (HKDF-SHA3-512)",
        "instructions": "Send this package to the receiver — only the dk in their vault can decrypt it.",
    }


@app.post("/ghost/quantum/receive", summary="Decrypt a quantum ghost package (receiver device)")
def qs_receive_endpoint(request: Request, body: _QsReceiveBody) -> dict[str, Any]:
    """Prove physical presence via mouse entropy, release dk from vault, decrypt, burn.

    After this call the dk is permanently destroyed — the ghost key is gone.
    Any subsequent attempt to decrypt the same package will fail.
    """
    client_ip = request.client.host if request.client else "unknown"

    from entropy_engine import extract_mouse_entropy
    from key_generator import KeyGenerator, EntropyHealthError

    # Presence proof — receiver must move mouse
    if len(body.mouse_events) < 5:
        threat_logger.log_threat(
            "QS_NO_PRESENCE_PROOF", client_ip,
            f"only {len(body.mouse_events)} mouse events (need ≥5)",
        )
        raise HTTPException(
            status_code=422,
            detail="Too few mouse events — move your mouse to prove physical presence",
        )

    try:
        session_secret = bytes.fromhex(body.session_secret_hex)
    except ValueError:
        raise HTTPException(status_code=422, detail="session_secret_hex must be valid hex")

    vault = _get_qs_vault()

    try:
        dk_bytes = vault.retrieve(
            body.vault_id,
            shard_xs=[1, 2, 3],
            master_password=session_secret,
        )
    except KeyError:
        threat_logger.log_threat("QS_VAULT_MISS", client_ip, body.vault_id[:16])
        mac = lookup_mac_address(client_ip)
        log.warning("Ghost key not found. Attacker IP=%s MAC=%s", client_ip, mac)
        raise HTTPException(status_code=410, detail="Ghost key expired, burned, or invalid vault_id")
    except PermissionError as exc:
        threat_logger.log_threat("QS_VAULT_DENIED", client_ip, str(exc)[:80])
        mac = lookup_mac_address(client_ip)
        log.warning("Ghost vault access denied. IP=%s MAC=%s reason=%s", client_ip, mac, exc)
        raise HTTPException(status_code=403, detail=str(exc))

    try:
        pkg = quantum_package_from_dict(body.package)
        plaintext_bytes = _quantum_decrypt(dk_bytes.hex(), pkg)
    except Exception as exc:
        threat_logger.log_threat("QS_DECRYPT_FAILED", client_ip, type(exc).__name__)
        mac = lookup_mac_address(client_ip)
        log.warning("Ghost decrypt failed — possible MITM. IP=%s MAC=%s", client_ip, mac)
        raise HTTPException(
            status_code=400,
            detail="Decryption failed — package tampered or wrong session",
        ) from exc

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext = None

    log.info("Ghost quantum received and burned vault=%s from=%s", body.vault_id[:8], client_ip)
    return {
        "status": "ok",
        "plaintext": plaintext,
        "plaintext_bytes_hex": plaintext_bytes.hex() if plaintext is None else None,
        "ghost_key_status": "burned — key destroyed, cannot be reused",
        "receiver_presence_events": len(body.mouse_events),
    }


@app.post("/ghost/quantum/revoke", summary="Destroy a quantum ghost key before it is used")
def qs_revoke_endpoint(request: Request, body: _QsRevokeBody) -> dict[str, Any]:
    """Emergency revoke — permanently destroys the dk in the vault."""
    client_ip = request.client.host if request.client else "unknown"
    vault = _get_qs_vault()
    try:
        vault.zeroize(body.vault_id)
        log.info("Ghost key revoked vault=%s from=%s", body.vault_id[:8], client_ip)
        return {"status": "revoked", "vault_id": body.vault_id, "ghost_key_status": "zeroized"}
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Vault not found or already gone: {exc}") from exc


# ---------------------------------------------------------------------------
# Fallback auth assessment endpoint (used by browser extension)
# ---------------------------------------------------------------------------

class _FallbackAssessBody(BaseModel):
    mouse_events: list[dict] = []
    scenario: str = "extension-demo"
    otp_destination: Optional[str] = None
    provided_otp: Optional[str] = None
    nfc_token_uid: Optional[str] = None


@app.post("/fallback/assess", summary="Assess mouse quality and fallback chain status")
def fallback_assess_endpoint(body: _FallbackAssessBody) -> dict[str, Any]:
    """Used by the browser extension to show the fallback auth chain state."""
    from fallback_auth import evaluate_mouse_movement, make_chess_like_mouse_events

    events = body.mouse_events if body.mouse_events else []
    profile = evaluate_mouse_movement(events)

    return {
        "mouse_verdict": profile.verdict,
        "score": round(profile.score, 3),
        "event_count": profile.event_count,
        "authenticated": profile.verdict == "PASS",
        "method": "mouse_movement" if profile.verdict == "PASS" else "none",
        "otp_available": bool(body.otp_destination),
        "nfc_available": bool(body.nfc_token_uid),
        "reasons": list(profile.reasons),
        "direction_changes": profile.direction_changes,
        "micro_vibrations": profile.micro_vibration_steps,
    }


# ---------------------------------------------------------------------------
# Admin threats endpoint — IP + MAC of all detected attackers
# ---------------------------------------------------------------------------

@app.get("/admin/threats", summary="Admin: view all detected threats with IP and MAC")
def admin_threats_endpoint(request: Request) -> dict[str, Any]:
    """Return the full threat log including attacker IP and MAC address.

    In production this endpoint must be protected by API key auth and served
    only on an internal interface. In this demo it is open for volunteer review.
    """
    stats = threat_logger.get_stats()
    return {
        "total_threats": stats["total_threat_events"],
        "blocked_ips": stats["blocked_ips"],
        "threats": stats["recent_threats"],
        "note": (
            "MAC addresses are resolved from the local ARP cache. "
            "They are only available for hosts on the same LAN segment."
        ),
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args():
    parser = argparse.ArgumentParser(
        description="SUMIT KEY API — behavioural entropy key generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python api.py                        # localhost:8000, INFO logging
  python api.py --debug                # verbose DEBUG logging
  python api.py --host 0.0.0.0        # expose to LAN (any laptop on network)
  python api.py --port 9000           # custom port
  DISPLAY=:99 python api.py           # headless Linux with Xvfb

Environment variables:
  CORS_ORIGINS                         # comma-separated list of allowed CORS origins
  SUMIT_API_KEY                        # if set, enables API key auth (optional)

Tip: on headless Linux start Xvfb first:
  Xvfb :99 -screen 0 1024x768x24 &
  export DISPLAY=:99
  python api.py
""",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--debug", action="store_true", help="Enable DEBUG logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    log.info("Starting SUMIT KEY API on %s:%d", args.host, args.port)
    log.info("Input backend: %s", _detect_backend())
    log.info("Docs available at http://%s:%d/docs", args.host, args.port)

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="debug" if args.debug else "info",
    )
