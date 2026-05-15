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
import logging
import os
import platform
import sys
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
