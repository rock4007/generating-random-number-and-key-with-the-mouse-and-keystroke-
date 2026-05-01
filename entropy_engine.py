"""Entropy feature extraction and pooling for SUMIT KEY.

This module converts raw behavioural events into compact entropy bytes and then
pools mouse + keystroke entropy using SHA3-256.

Python version target: 3.11+
"""

from __future__ import annotations

import hashlib
from math import sqrt
import statistics
import struct
from typing import Any


def _safe_mean(values: list[float]) -> float:
    """Return mean or 0.0 for empty input.

    Why this matters cryptographically:
    - Feature extraction must be deterministic even for sparse captures so the
      key pipeline remains stable and does not crash.
    """

    if not values:
        return 0.0
    return float(statistics.fmean(values))


def _safe_stdev(values: list[float]) -> float:
    """Return population standard deviation or 0.0 for short input.

    Why this matters cryptographically:
    - Standard deviation captures variability, not just central tendency.
    - Behavioural variability is a strong entropy signal because humans do not
      repeat timing and motion with exact precision.
    """

    if len(values) < 2:
        return 0.0
    return float(statistics.pstdev(values))


def _angle_delta_degrees(prev_angle: float, current_angle: float) -> float:
    """Compute smallest absolute angular difference in degrees."""

    diff = abs(current_angle - prev_angle) % 360.0
    return diff if diff <= 180.0 else 360.0 - diff


def extract_mouse_entropy(mouse_events: list[dict[str, Any]]) -> bytes:
    """Extract mouse entropy features and encode them as deterministic bytes.

    Extracted features:
    - Mean velocity: average movement speed across events.
    - Velocity standard deviation: how much speed fluctuates over time.
    - Direction change frequency: rate of meaningful heading changes.
    - Micro-tremor amplitude: amplitude of tiny movements (<3 px).

    Why these features contain entropy:
    - Velocity and direction summarize motor dynamics that naturally vary from
      person to person and from moment to moment.
    - Micro-tremor reflects involuntary neuromuscular jitter, which is subtle,
      hard to fake precisely, and therefore entropy-rich.
    """

    velocities: list[float] = []
    directions: list[float] = []
    tremor_steps: list[float] = []

    for event in mouse_events:
        velocity = float(event.get("velocity_px_per_s", 0.0))
        direction = float(event.get("direction_angle_deg", 0.0))
        velocities.append(velocity)
        directions.append(direction)

    for idx in range(1, len(mouse_events)):
        prev_event = mouse_events[idx - 1]
        curr_event = mouse_events[idx]

        prev_x = float(prev_event.get("x", 0.0))
        prev_y = float(prev_event.get("y", 0.0))
        curr_x = float(curr_event.get("x", 0.0))
        curr_y = float(curr_event.get("y", 0.0))

        step_distance = sqrt((curr_x - prev_x) ** 2 + (curr_y - prev_y) ** 2)

        # Micro-tremor means very small cursor displacements; we keep only
        # steps under 3 pixels to isolate fine-grained involuntary motion.
        if 0.0 < step_distance < 3.0:
            tremor_steps.append(step_distance)

    direction_changes = 0
    for idx in range(1, len(directions)):
        if _angle_delta_degrees(directions[idx - 1], directions[idx]) >= 20.0:
            direction_changes += 1

    direction_change_frequency = (
        direction_changes / max(1, len(directions) - 1)
        if directions
        else 0.0
    )

    # RMS gives a stable amplitude summary of tremor-sized movements.
    micro_tremor_amplitude = (
        sqrt(sum(step * step for step in tremor_steps) / len(tremor_steps))
        if tremor_steps
        else 0.0
    )

    mean_velocity = _safe_mean(velocities)
    velocity_std = _safe_stdev(velocities)

    # Deterministic binary layout keeps output stable for the same input.
    return struct.pack(
        ">4d3I",
        mean_velocity,
        velocity_std,
        direction_change_frequency,
        micro_tremor_amplitude,
        len(mouse_events),
        len(directions),
        len(tremor_steps),
    )


def extract_keystroke_entropy(keystroke_events: list[dict[str, Any]]) -> bytes:
    """Extract keystroke entropy features and encode them as deterministic bytes.

    Extracted features:
    - Mean dwell time and standard deviation.
    - Mean flight time and standard deviation.
    - Bigram timing between specific key pairs.

    Feature meaning:
    - Dwell time is key-hold duration (release - press) in milliseconds.
    - Flight time is delay between consecutive key releases in milliseconds.
    - Bigram timing captures transition timing for pairs such as "t->h".

    Why these features contain entropy:
    - Dwell and flight timings encode rhythm and motor control.
    - Their standard deviations add entropy by modeling natural variation,
      not only average behaviour.
    """

    dwell_times = [float(event.get("dwell_time_ms", 0.0)) for event in keystroke_events]
    flight_times = [float(event.get("flight_time_ms", 0.0)) for event in keystroke_events]

    mean_dwell = _safe_mean(dwell_times)
    dwell_std = _safe_stdev(dwell_times)
    mean_flight = _safe_mean(flight_times)
    flight_std = _safe_stdev(flight_times)

    bigram_timings: dict[str, list[float]] = {}
    for idx in range(1, len(keystroke_events)):
        prev_event = keystroke_events[idx - 1]
        curr_event = keystroke_events[idx]

        prev_key = str(prev_event.get("key", "<unknown>"))
        curr_key = str(curr_event.get("key", "<unknown>"))
        prev_release = float(prev_event.get("release_timestamp", 0.0))
        curr_release = float(curr_event.get("release_timestamp", 0.0))

        dt_ms = (curr_release - prev_release) * 1000.0
        if dt_ms < 0:
            continue

        pair = f"{prev_key}->{curr_key}"
        bigram_timings.setdefault(pair, []).append(dt_ms)

    # We include per-bigram mean timings to preserve transition-specific entropy.
    bigram_means: list[tuple[str, float]] = sorted(
        (pair, _safe_mean(values)) for pair, values in bigram_timings.items()
    )

    output = bytearray()
    output.extend(struct.pack(">4dI", mean_dwell, dwell_std, mean_flight, flight_std, len(keystroke_events)))
    output.extend(struct.pack(">I", len(bigram_means)))

    for pair, pair_mean_ms in bigram_means:
        pair_bytes = pair.encode("utf-8")
        output.extend(struct.pack(">H", len(pair_bytes)))
        output.extend(pair_bytes)
        output.extend(struct.pack(">d", pair_mean_ms))

    return bytes(output)


def pool_entropy(mouse_bytes: bytes, keystroke_bytes: bytes) -> bytes:
    """Pool mouse and keystroke entropy into one SHA3-256 digest.

    Why pooling entropy matters:
    - Entropy pooling means combining multiple imperfect/random sources into one
      stronger and fixed-length output.
    - SHA3-256 diffusion ensures changes in either source strongly influence the
      final digest used by the key derivation stage.
    """

    if not isinstance(mouse_bytes, (bytes, bytearray)):
        raise TypeError("mouse_bytes must be bytes-like")
    if not isinstance(keystroke_bytes, (bytes, bytearray)):
        raise TypeError("keystroke_bytes must be bytes-like")

    mouse_payload = bytes(mouse_bytes)
    key_payload = bytes(keystroke_bytes)

    hasher = hashlib.sha3_256()

    # Length-prefixing avoids ambiguity in concatenation boundaries.
    hasher.update(len(mouse_payload).to_bytes(4, "big"))
    hasher.update(mouse_payload)
    hasher.update(len(key_payload).to_bytes(4, "big"))
    hasher.update(key_payload)

    return hasher.digest()
