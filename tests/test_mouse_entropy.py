"""test_mouse_entropy.py — Verify mouse movement generates entropy.

Uses pynput's mouse.Listener to capture real X11 mouse events, driven by
pynput's mouse.Controller for synthetic injection.  The keyboard listener
is intentionally omitted because X11's XRecord backend can hang on join()
in headless environments.

Tests:
  1. Mouse events are captured (non-zero count).
  2. Entropy bytes are non-empty and non-zero.
  3. Shannon entropy of the extracted bytes exceeds a minimum threshold.
  4. Two captures produce different entropy bytes (non-determinism).
"""

from __future__ import annotations

import math
import threading
import time
from collections import Counter
from math import atan2, degrees, sqrt
from threading import Lock

from pynput import mouse as pynput_mouse

from entropy_engine import extract_mouse_entropy

CAPTURE_DURATION = 4.0   # seconds per capture window
MIN_EVENTS = 10          # minimum mouse events expected
MIN_SHANNON = 1.5        # bits/byte threshold


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _capture_mouse_only(duration: float) -> list[dict]:
    """Capture mouse move events for `duration` seconds using pynput Listener.

    Only starts a mouse.Listener (no keyboard.Listener) to avoid the X11
    XRecord hang on join() in headless environments.
    """
    events: list[dict] = []
    last_point: dict | None = None
    lock = Lock()
    done = threading.Event()

    def on_move(x: float, y: float) -> None:
        nonlocal last_point
        t = time.time()
        with lock:
            velocity = 0.0
            angle = 0.0
            if last_point is not None:
                dt = t - last_point["timestamp"]
                if dt > 0:
                    dist = sqrt((x - last_point["x"]) ** 2 + (y - last_point["y"]) ** 2)
                    velocity = dist / dt
                dx = x - last_point["x"]
                dy = y - last_point["y"]
                angle = degrees(atan2(dy, dx))
            events.append({
                "x": x,
                "y": y,
                "timestamp": t,
                "velocity_px_per_s": velocity,
                "direction_angle_deg": angle,
            })
            last_point = {"x": x, "y": y, "timestamp": t}

    listener = pynput_mouse.Listener(on_move=on_move)
    listener.start()
    done.wait(timeout=duration)
    time.sleep(duration)   # honour the full window
    listener.stop()
    # join with a timeout so we never hang forever
    listener.join(timeout=2.0)
    return events


def _inject_movements(duration: float) -> None:
    """Drive the virtual cursor in a figure-8 using pynput Controller."""
    controller = pynput_mouse.Controller()
    end = time.time() + duration
    step = 0
    while time.time() < end:
        t = step * 0.15
        x = int(400 + 200 * math.sin(t))
        y = int(300 + 100 * math.sin(2 * t))
        controller.position = (x, y)
        time.sleep(0.04)
        step += 1


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_mouse_events_are_captured() -> list:
    print("\n[TEST 1] Mouse events are captured during movement...")

    injector = threading.Thread(target=_inject_movements, args=(CAPTURE_DURATION,), daemon=True)
    injector.start()

    events = _capture_mouse_only(CAPTURE_DURATION)
    injector.join(timeout=1)

    count = len(events)
    print(f"  Captured {count} mouse events")
    assert count >= MIN_EVENTS, (
        f"Expected >= {MIN_EVENTS} mouse events, got {count}. "
        "Mouse capture may not be working."
    )
    print(f"  PASS — {count} events captured")
    return events


def test_entropy_bytes_are_non_trivial(events: list) -> bytes:
    print("\n[TEST 2] Extracted entropy bytes are non-empty and non-trivial...")

    entropy_bytes = extract_mouse_entropy(events)

    assert isinstance(entropy_bytes, (bytes, bytearray)), "extract_mouse_entropy must return bytes"
    assert len(entropy_bytes) > 0, "Entropy bytes must not be empty"
    assert any(b != 0 for b in entropy_bytes), "Entropy bytes must not be all-zero"

    shannon = _shannon_entropy(bytes(entropy_bytes))
    print(f"  Entropy length : {len(entropy_bytes)} bytes")
    print(f"  Shannon entropy: {shannon:.3f} bits/byte  (threshold: {MIN_SHANNON})")
    assert shannon >= MIN_SHANNON, (
        f"Shannon entropy {shannon:.3f} < {MIN_SHANNON}. "
        "Mouse data appears too uniform to be useful."
    )
    print(f"  PASS — entropy bytes look non-trivial")
    return bytes(entropy_bytes)


def test_two_captures_differ() -> None:
    print("\n[TEST 3] Two separate captures produce different entropy bytes...")

    results: list[bytes] = []
    for run in range(2):
        injector = threading.Thread(target=_inject_movements, args=(CAPTURE_DURATION,), daemon=True)
        injector.start()
        evts = _capture_mouse_only(CAPTURE_DURATION)
        injector.join(timeout=1)
        entropy = extract_mouse_entropy(evts)
        results.append(bytes(entropy))
        print(f"  Run {run + 1}: {results[-1].hex()[:32]}...")

    assert results[0] != results[1], (
        "Both captures produced identical entropy bytes — "
        "the system appears deterministic."
    )
    print("  PASS — captures produced different entropy bytes (non-determinism confirmed)")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  Mouse Entropy Generation Test")
    print("=" * 60)

    passed = 0
    failed = 0

    try:
        events = test_mouse_events_are_captured()
        passed += 1
    except AssertionError as e:
        print(f"  FAIL — {e}")
        failed += 1
        events = []

    if events:
        try:
            test_entropy_bytes_are_non_trivial(events)
            passed += 1
        except AssertionError as e:
            print(f"  FAIL — {e}")
            failed += 1

    try:
        test_two_captures_differ()
        passed += 1
    except AssertionError as e:
        print(f"  FAIL — {e}")
        failed += 1

    print()
    print("=" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed:
        raise SystemExit(1)
