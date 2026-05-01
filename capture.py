"""Behavioural data capture for the SUMIT KEY project.

This module records user behaviour for a fixed window (default: 10 seconds)
using two independent entropy sources:
1) Mouse movement dynamics.
2) Keystroke timing dynamics.

Python version target: 3.11+
"""

from __future__ import annotations

from math import atan2, degrees, sqrt
from threading import Lock
import time
from typing import Any

from pynput import keyboard, mouse  # type: ignore[reportMissingModuleSource]


def _key_to_string(key: keyboard.Key | keyboard.KeyCode) -> str:
    """Convert a pynput key object into a stable text label.

    Why this matters cryptographically:
    - Stable labels let us consistently match press and release pairs,
      which is required for correct dwell-time extraction.
    """

    if hasattr(key, "char") and key.char is not None:
        return f"char:{key.char}"
    return f"special:{str(key)}"


def _compute_velocity(prev_x: float, prev_y: float, prev_t: float, x: float, y: float, t: float) -> float:
    """Compute mouse velocity in pixels per second between two points.

    Why this matters cryptographically:
    - Velocity captures subtle motor behaviour patterns (fast, slow, jittery),
      which are difficult to reproduce exactly and therefore add entropy.
    """

    dt = t - prev_t
    if dt <= 0:
        return 0.0
    distance = sqrt((x - prev_x) ** 2 + (y - prev_y) ** 2)
    return distance / dt


def _compute_direction_angle(prev_x: float, prev_y: float, x: float, y: float) -> float:
    """Compute movement direction angle in degrees from previous point.

    Why this matters cryptographically:
    - Direction reflects trajectory changes and micro-corrections, which are
      user-specific and help diversify the entropy pool.
    """

    dx = x - prev_x
    dy = y - prev_y
    return degrees(atan2(dy, dx))


def capture_behaviour(duration_seconds: float = 10.0) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Capture mouse and keystroke behaviour for a fixed duration.

    Returns:
    - mouse_events: list of movement events with x, y, timestamp, velocity,
      and direction angle.
    - keystroke_events: list of key events with press/release timestamps,
      dwell time, and flight time.

    Why this matters cryptographically:
    - Dwell time is how long a key is held down (release - press). It captures
      neuromotor timing that varies naturally between users and moments.
    - Flight time is the gap between successive key releases. It captures typing
      rhythm transitions that are hard to script deterministically.
    - Combining independent timing and movement signals increases entropy depth
      versus using only one behavioural source.
    """

    print(
        "Capturing behaviour... please move mouse and type naturally for "
        f"{duration_seconds:g} seconds"
    )

    mouse_events: list[dict[str, Any]] = []
    keystroke_events: list[dict[str, Any]] = []

    pressed_at: dict[str, float] = {}
    last_release_time: float | None = None

    last_mouse_point: dict[str, float] | None = None

    lock = Lock()

    def on_move(x: float, y: float) -> None:
        """Handle each mouse movement callback and derive motion features."""

        nonlocal last_mouse_point
        event_time = time.time()

        with lock:
            velocity = 0.0
            angle = 0.0
            if last_mouse_point is not None:
                velocity = _compute_velocity(
                    prev_x=last_mouse_point["x"],
                    prev_y=last_mouse_point["y"],
                    prev_t=last_mouse_point["timestamp"],
                    x=x,
                    y=y,
                    t=event_time,
                )
                angle = _compute_direction_angle(
                    prev_x=last_mouse_point["x"],
                    prev_y=last_mouse_point["y"],
                    x=x,
                    y=y,
                )

            mouse_events.append(
                {
                    "x": x,
                    "y": y,
                    "timestamp": event_time,
                    "velocity_px_per_s": velocity,
                    "direction_angle_deg": angle,
                }
            )

            last_mouse_point = {"x": x, "y": y, "timestamp": event_time}

    def on_press(key: keyboard.Key | keyboard.KeyCode) -> None:
        """Record key press timestamp for later dwell-time computation."""

        key_label = _key_to_string(key)
        event_time = time.time()

        with lock:
            pressed_at[key_label] = event_time

    def on_release(key: keyboard.Key | keyboard.KeyCode) -> None:
        """Record release and derive dwell/flight timing features."""

        nonlocal last_release_time
        key_label = _key_to_string(key)
        release_time = time.time()

        with lock:
            press_time = pressed_at.pop(key_label, None)
            if press_time is None:
                return

            dwell_ms = (release_time - press_time) * 1000.0

            # Flight time: milliseconds between this key release and the
            # previous key release; reflects transition rhythm between actions.
            flight_ms = 0.0 if last_release_time is None else (release_time - last_release_time) * 1000.0

            keystroke_events.append(
                {
                    "key": key_label,
                    "press_timestamp": press_time,
                    "release_timestamp": release_time,
                    "dwell_time_ms": dwell_ms,
                    "flight_time_ms": flight_ms,
                }
            )

            last_release_time = release_time

    mouse_listener = mouse.Listener(on_move=on_move)
    keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release)

    mouse_listener.start()
    keyboard_listener.start()

    try:
        time.sleep(duration_seconds)
    finally:
        mouse_listener.stop()
        keyboard_listener.stop()
        mouse_listener.join()
        keyboard_listener.join()

    return mouse_events, keystroke_events


if __name__ == "__main__":
    mouse_data, keystroke_data = capture_behaviour(duration_seconds=10.0)
    print(f"Captured mouse events: {len(mouse_data)}")
    print(f"Captured keystroke events: {len(keystroke_data)}")
