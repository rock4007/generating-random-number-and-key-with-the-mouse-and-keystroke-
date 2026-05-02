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

import logging
import os
import platform
import sys
import time
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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
from main import _derive_random_number_from_key, generate_random_number_and_key  # noqa: E402

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

# Allow calls from any origin (useful when embedding in a web front-end)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


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
    duration: float = Query(
        default=10.0,
        ge=1.0,
        le=60.0,
        description="Capture window in seconds. Move your mouse during this time.",
    ),
    security_level: str = Query(
        default="quantum",
        description="Key strength: 'quantum' = 512-bit (recommended) or 'standard' = 256-bit.",
    ),
    debug: bool = Query(
        default=False,
        description="Include extra debug metrics in the response.",
    ),
) -> dict[str, Any]:
    """
    Run the entropy capture pipeline and return a random number + cryptographic key.

    **How to use:**
    1. Call this endpoint.
    2. Move your mouse naturally for the `duration` seconds.
    3. The response will contain a unique key derived from your movement patterns.

    The key is generated using SHA3-256 entropy pooling → HKDF derivation
    and is never stored or transmitted — it is only returned in this response.
    """
    if security_level not in ("quantum", "standard"):
        raise HTTPException(status_code=422, detail="security_level must be 'quantum' or 'standard'")

    log.info(
        "POST /generate  duration=%.1fs  security=%s  debug=%s",
        duration, security_level, debug,
    )

    try:
        _assert_capture_possible()
    except RuntimeError as exc:
        log.error("Capture backend unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    t_start = time.time()
    try:
        result = generate_random_number_and_key(
            capture_duration_seconds=duration,
            security_level=security_level,
        )
    except Exception as exc:
        log.exception("Key generation failed")
        raise HTTPException(status_code=500, detail=f"Generation error: {exc}") from exc

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

    return response


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args():
    import argparse
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
