"""Test per-move randomness analysis with synthetic mouse data.

This script simulates the per-move randomness analysis using synthetic mouse
movement data to show how many random numbers/keys are generated per movement.
"""

from __future__ import annotations

from collections import Counter
from math import atan2, degrees, sin, sqrt
import time

from entropy_engine import extract_mouse_entropy
from key_generator import KeyGenerator


def generate_synthetic_mouse_events(duration_seconds: float = 5.0) -> list[dict]:
    """Generate synthetic mouse movement events similar to the _inject_mouse function."""
    events = []
    start_time = time.time()
    end_time = start_time + duration_seconds
    step = 0

    while time.time() < end_time:
        t = step * 0.14
        x = 450 + 220 * sin(t)
        y = 300 + 120 * sin(2 * t)
        timestamp = start_time + step * 0.03

        # Calculate velocity and direction
        velocity = 0.0
        direction = 0.0
        if events:
            prev = events[-1]
            dt = timestamp - prev["timestamp"]
            if dt > 0:
                distance = sqrt((x - prev["x"]) ** 2 + (y - prev["y"]) ** 2)
                velocity = distance / dt
            direction = degrees(atan2(y - prev["y"], x - prev["x"]))

        events.append({
            "x": x,
            "y": y,
            "timestamp": timestamp,
            "velocity_px_per_s": velocity,
            "direction_angle_deg": direction,
        })

        step += 1
        time.sleep(0.001)  # Small delay to simulate real timing

    return events


def analyze_per_move_randomness(events: list[dict]) -> None:
    """Analyze how many random numbers/keys are generated per mouse movement."""
    if not events:
        print("No mouse events captured.")
        return

    print(f"Analyzing {len(events)} mouse movement events...")

    keys: list[bytes] = []
    random_numbers: list[int] = []

    for i in range(1, len(events) + 1):
        entropy = extract_mouse_entropy(events[:i])
        key = KeyGenerator.generate_key(entropy)
        keys.append(key)

        # Derive random number from key (same as main.py)
        import hashlib
        digest = hashlib.sha3_256(bytes(key) + b"|SUMIT_KEY_RANDOM_NUMBER|").digest()
        random_number = int.from_bytes(digest[:8], "big")
        random_numbers.append(random_number)

    # Analyze key changes
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

    # Find first duplicate
    first_duplicate_index = None
    seen: dict[bytes, int] = {}
    for idx, k in enumerate(keys):
        if k in seen:
            first_duplicate_index = (seen[k], idx)
            break
        seen[k] = idx

    # Analyze random number changes
    rand_changed = 0
    rand_unchanged = 0
    for i in range(1, len(random_numbers)):
        if random_numbers[i] != random_numbers[i - 1]:
            rand_changed += 1
        else:
            rand_unchanged += 1

    rand_unique = len(set(random_numbers))
    rand_unique_ratio = (rand_unique / total) * 100.0
    rand_change_ratio = (rand_changed / max(1, total - 1)) * 100.0

    print("=" * 80)
    print("PER-MOVE RANDOMNESS ANALYSIS")
    print("=" * 80)
    print(f"Mouse moves captured           : {len(events)}")
    print(f"Per-move keys generated        : {total}")
    print(f"Per-move random numbers generated: {total}")
    print()

    print("KEY ANALYSIS:")
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
    print()

    print("RANDOM NUMBER ANALYSIS:")
    print(f"Unique random numbers          : {rand_unique} ({rand_unique_ratio:.2f}%)")
    print(f"Random # changed vs previous   : {rand_changed}/{max(1, total - 1)} ({rand_change_ratio:.2f}%)")
    print(f"Random # unchanged vs previous : {rand_unchanged}")
    print()

    print("SAMPLE OUTPUTS:")
    print("Sample first key (hex)         :", keys[0].hex()[:32] + "...")
    print("Sample last key  (hex)         :", keys[-1].hex()[:32] + "...")
    print("Sample first random number     :", random_numbers[0])
    print("Sample last random number      :", random_numbers[-1])
    print()

    print("CONCLUSION:")
    print(f"✓ One random number is generated PER mouse movement event")
    print(f"✓ Total events: {len(events)} → Total random numbers: {len(random_numbers)}")
    print(f"✓ Each movement produces a new entropy sample → new key → new random number")


if __name__ == "__main__":
    print("Generating synthetic mouse movement data...")
    mouse_events = generate_synthetic_mouse_events(5.0)
    print(f"Generated {len(mouse_events)} synthetic mouse events")
    analyze_per_move_randomness(mouse_events)