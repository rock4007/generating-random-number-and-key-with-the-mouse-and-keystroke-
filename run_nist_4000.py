from __future__ import annotations

from threading import Thread
import time

from analyze_per_move_randomness import _capture_mouse_only, _inject_mouse
from main import run_all_experiments


def synthetic_capture(duration_seconds: float):
    injector = Thread(target=_inject_mouse, args=(duration_seconds,), daemon=True)
    injector.start()
    mouse_events = _capture_mouse_only(duration_seconds)
    injector.join(timeout=1.0)

    keystroke_events = []
    base = time.time()
    keys = ["char:a", "char:s", "char:d", "char:f", "char:j", "char:k", "char:l", "char:;"]

    for i, k in enumerate(keys * 24):
        press = base + i * (0.055 + (i % 7) * 0.0025)
        dwell = 0.04 + (i % 9) * 0.003
        release = press + dwell
        flight = 0.0 if i == 0 else (release - keystroke_events[-1]["release_timestamp"]) * 1000.0
        keystroke_events.append(
            {
                "key": k,
                "press_timestamp": press,
                "release_timestamp": release,
                "dwell_time_ms": dwell * 1000.0,
                "flight_time_ms": flight,
            }
        )

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
            f"mode={result['scoring_mode']}, seq={result['sequence_count']}, bits={result['total_bits']}"
        )
