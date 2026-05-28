from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from debug_pipeline import make_synthetic_keystroke_events, make_synthetic_mouse_events
from main import run_all_experiments


def synthetic_capture(duration_seconds: float):
    """Return synthetic events for headless NIST validation runs."""

    mouse_events = make_synthetic_mouse_events(max(96, int(duration_seconds * 32)))
    keystroke_events = make_synthetic_keystroke_events(max(32, int(duration_seconds * 12)))

    base = time.time()
    for index, event in enumerate(mouse_events):
        event["timestamp"] = base + index * 0.031
    for index, event in enumerate(keystroke_events):
        press = base + index * 0.071
        dwell = 0.04 + (index % 9) * 0.003
        event["press_timestamp"] = press
        event["release_timestamp"] = press + dwell
        event["dwell_time_ms"] = dwell * 1000.0
        event["flight_time_ms"] = 0.0 if index == 0 else 31.0 + (index % 7)

    return mouse_events, keystroke_events


if __name__ == "__main__":
    results = run_all_experiments(
        num_keys=4000,
        capture_duration_seconds=4.0,
        capture_fn=synthetic_capture,
    )

    print("FINAL_SUMMARY")
    for name, result in results.items():
        print(
            f"{name}: {result['overall_passed_tests']}/{result['overall_eligible_tests']} "
            f"({result['overall_pass_rate_percent']:.2f}%), "
            f"calibrated={result['calibrated_passed_tests']}/{result['calibrated_eligible_tests']} "
            f"({result['calibrated_pass_rate_percent']:.2f}%), "
            f"mode={result['scoring_mode']}, seq={result['sequence_count']}, bits={result['total_bits']}"
        )
