"""Analyze move-by-move randomness from mouse events.

What this does:
1) Captures mouse move events for a short window.
2) For each prefix of events (1..N), extracts mouse entropy and derives a key.
3) Reports how many times the derived key changed from previous move.
4) Reports unique key ratio and first duplicate (if any).

This is a diagnostic script, not production key generation.
"""

from __future__ import annotations

from collections import Counter
from math import atan2, degrees, sin, sqrt
from threading import Event, Lock, Thread
import time

from pynput import mouse as pynput_mouse

from entropy_engine import extract_mouse_entropy
from key_generator import KeyGenerator

CAPTURE_SECONDS = 5.0


def _capture_mouse_only(duration_seconds: float) -> list[dict]:
    events: list[dict] = []
    last_point: dict | None = None
    lock = Lock()
    waiter = Event()

    def on_move(x: float, y: float) -> None:
        nonlocal last_point
        t = time.time()
        with lock:
            velocity = 0.0
            direction = 0.0
            if last_point is not None:
                dt = t - last_point["timestamp"]
                if dt > 0:
                    distance = sqrt((x - last_point["x"]) ** 2 + (y - last_point["y"]) ** 2)
                    velocity = distance / dt
                direction = degrees(atan2(y - last_point["y"], x - last_point["x"]))

            events.append(
                {
                    "x": x,
                    "y": y,
                    "timestamp": t,
                    "velocity_px_per_s": velocity,
                    "direction_angle_deg": direction,
                }
            )
            last_point = {"x": x, "y": y, "timestamp": t}

    listener = pynput_mouse.Listener(on_move=on_move)
    listener.start()
    waiter.wait(timeout=duration_seconds)
    listener.stop()
    listener.join(timeout=2.0)
    return events


def _inject_mouse(duration_seconds: float) -> None:
    controller = pynput_mouse.Controller()
    end = time.time() + duration_seconds
    step = 0
    while time.time() < end:
        t = step * 0.14
        x = int(450 + 220 * sin(t))
        y = int(300 + 120 * sin(2 * t))
        controller.position = (x, y)
        time.sleep(0.03)
        step += 1


def analyze(events: list[dict]) -> None:
    if not events:
        print("No mouse events captured.")
        return

    keys: list[bytes] = []
    for i in range(1, len(events) + 1):
        entropy = extract_mouse_entropy(events[:i])
        key = KeyGenerator.generate_key(entropy)
        keys.append(key)

    changed = 0
    unchanged = 0
    for i in range(1, len(keys)):
        if keys[i] != keys[i - 1]:
            changed += 1
        else:
            unchanged += 1

    unique = len(set(keys))
    total = len(keys)
    unique_ratio = (unique / total) * 100.0
    change_ratio = (changed / max(1, total - 1)) * 100.0

    first_duplicate_index = None
    seen: dict[bytes, int] = {}
    for idx, k in enumerate(keys):
        if k in seen:
            first_duplicate_index = (seen[k], idx)
            break
        seen[k] = idx

    print("=" * 64)
    print("Per-move randomness analysis")
    print("=" * 64)
    print(f"Mouse moves captured           : {len(events)}")
    print(f"Per-move keys generated        : {total}")
    print(f"Unique keys                    : {unique} ({unique_ratio:.2f}%)")
    print(f"Key changed vs previous move   : {changed}/{max(1, total - 1)} ({change_ratio:.2f}%)")
    print(f"Key unchanged vs previous move : {unchanged}")

    if first_duplicate_index is None:
        print("First duplicate key index      : none")
    else:
        a, b = first_duplicate_index
        print(f"First duplicate key index      : {a} and {b}")

    key_counts = Counter(keys)
    repeats = sum(1 for c in key_counts.values() if c > 1)
    print(f"Distinct key values repeated   : {repeats}")
    print("Sample first key (hex)         :", keys[0].hex()[:32] + "...")
    print("Sample last key  (hex)         :", keys[-1].hex()[:32] + "...")


if __name__ == "__main__":
    injector = Thread(target=_inject_mouse, args=(CAPTURE_SECONDS,), daemon=True)
    injector.start()
    mouse_events = _capture_mouse_only(CAPTURE_SECONDS)
    injector.join(timeout=1.0)
    analyze(mouse_events)
