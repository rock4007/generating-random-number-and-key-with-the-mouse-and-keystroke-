"""Main experiment runner for the SUMIT KEY dissertation project.

This script runs three experiments and validates each using NIST SP 800-22:
A) Mouse entropy only
B) Keystroke entropy only
C) Mouse + Keystroke combined entropy

Python version target: 3.11+
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from entropy_engine import extract_keystroke_entropy, extract_mouse_entropy, pool_entropy
from key_generator import KeyGenerator
from nist_validator import run_nist_tests


def _derive_random_number_from_key(key_bytes: bytes) -> int:
    """Derive a 64-bit random number from the generated key bytes.

    Why this matters cryptographically:
    - Domain-separated hashing ensures the random number stream is independent
      from direct key material usage.
    - A 64-bit output provides a large numeric space for application use.
    """

    if not isinstance(key_bytes, (bytes, bytearray)):
        raise TypeError("key_bytes must be bytes-like")

    digest = hashlib.sha3_256(bytes(key_bytes) + b"|SUMIT_KEY_RANDOM_NUMBER|").digest()
    return int.from_bytes(digest[:8], "big")


def generate_random_number_and_key(
    capture_duration_seconds: float = 10.0,
    capture_fn: Callable[[float], tuple[list[dict[str, Any]], list[dict[str, Any]]]] | None = None,
) -> dict[str, Any]:
    """Capture behaviour once and output one random number and one key.

    Returns a dictionary containing event counts, key hex, and random number.
    """

    if capture_fn is None:
        from capture import capture_behaviour as capture_fn

    print("Starting behavioural capture for key generation...")
    mouse_events, keystroke_events = capture_fn(capture_duration_seconds)

    mouse_entropy = extract_mouse_entropy(mouse_events)
    keystroke_entropy = extract_keystroke_entropy(keystroke_events)
    combined_entropy = pool_entropy(mouse_entropy, keystroke_entropy)

    key_bytes = KeyGenerator.generate_key(combined_entropy)
    random_number = _derive_random_number_from_key(key_bytes)

    output = {
        "capture_duration_seconds": float(capture_duration_seconds),
        "mouse_event_count": len(mouse_events),
        "keystroke_event_count": len(keystroke_events),
        "random_number": random_number,
        "key_hex": key_bytes.hex(),
        "key_bits": len(key_bytes) * 8,
    }

    results_path = Path("results") / "latest_generation.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    print("Random number generated:", output["random_number"])
    print("Cryptographic key (hex):", output["key_hex"])
    print("Saved generation output to results/latest_generation.json")

    return output


def _expand_entropy_for_batch(base_entropy: bytes, experiment_tag: str, index: int) -> bytes:
    """Expand one base entropy blob into per-key input material.

    Why this matters cryptographically:
    - NIST validation needs many keys, so we derive unique per-key inputs from
      the captured entropy using domain-separated SHA3-256 hashing.
    - The experiment tag and index prevent accidental input reuse across
      experiments and across key positions.
    """

    if not isinstance(base_entropy, (bytes, bytearray)):
        raise TypeError("base_entropy must be bytes-like")

    tag_bytes = experiment_tag.encode("utf-8")
    base = bytes(base_entropy)
    counter = index.to_bytes(8, "big")

    left = hashlib.sha3_256(tag_bytes + b"|L|" + counter + base).digest()
    right = hashlib.sha3_256(tag_bytes + b"|R|" + base + counter).digest()
    return left + right


def _generate_key_batch(base_entropy: bytes, experiment_tag: str, num_keys: int) -> list[bytes]:
    """Generate a batch of keys from one entropy source configuration.

    Why this matters cryptographically:
    - Using per-key expanded input ensures the derived key set has diversity,
      which is necessary for meaningful batch randomness testing.
    """

    if num_keys <= 0:
        raise ValueError("num_keys must be a positive integer")

    keys: list[bytes] = []
    for index in range(num_keys):
        expanded_entropy = _expand_entropy_for_batch(base_entropy, experiment_tag, index)
        key = KeyGenerator.generate_key(expanded_entropy)
        keys.append(key)

    return keys


def _build_combined_report(experiment_results: dict[str, dict[str, Any]]) -> str:
    """Create a dissertation-ready summary report for all three experiments."""

    lines: list[str] = []
    lines.append("SUMIT KEY - NIST SP 800-22 Combined Experiment Report")
    lines.append("======================================================")
    lines.append("")

    for experiment_name, result in experiment_results.items():
        lines.append(f"{experiment_name}")
        lines.append("-" * len(experiment_name))
        lines.append(f"Keys evaluated: {result['keys_evaluated']}")
        lines.append(f"Total bits evaluated: {result['total_bits']}")
        lines.append(f"Sequence count: {result['sequence_count']}")
        lines.append(f"Scoring mode: {result['scoring_mode']}")
        lines.append(
            f"Overall: {result['overall_passed_tests']}/{result['overall_eligible_tests']} eligible tests passed"
        )
        lines.append(
            f"Overall pass rate: {result['overall_pass_rate_percent']:.2f}%"
        )
        lines.append("")

    lines.append("Note:")
    lines.append("- NIST SP 800-22 is statistical, so occasional failures can occur even with strong randomness.")
    lines.append("- For broader eligibility across all 15 tests, increase total evaluated bits.")

    return "\n".join(lines) + "\n"


def run_all_experiments(
    num_keys: int = 1000,
    capture_duration_seconds: float = 10.0,
    capture_fn: Callable[[float], tuple[list[dict[str, Any]], list[dict[str, Any]]]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run experiments A, B, and C and return their NIST results.

    Why this matters cryptographically:
    - Comparing separate entropy sources against their combination shows whether
      entropy fusion improves statistical randomness quality.
    """

    # Lazy import keeps this module importable in non-GUI environments while
    # still using real pynput capture on Windows/desktop runs.
    if capture_fn is None:
        from capture import capture_behaviour as capture_fn

    print("Starting SUMIT KEY behavioural capture...")
    mouse_events, keystroke_events = capture_fn(capture_duration_seconds)

    print("Extracting entropy features from captured behaviour...")
    mouse_entropy = extract_mouse_entropy(mouse_events)
    keystroke_entropy = extract_keystroke_entropy(keystroke_events)
    combined_entropy = pool_entropy(mouse_entropy, keystroke_entropy)

    print(f"Generating {num_keys} keys for Experiment A (Mouse only)...")
    keys_a = _generate_key_batch(mouse_entropy, "EXPERIMENT_A_MOUSE_ONLY", num_keys)
    print("Running NIST tests for Experiment A...")
    results_a = run_nist_tests(keys_a)

    print(f"Generating {num_keys} keys for Experiment B (Keystroke only)...")
    keys_b = _generate_key_batch(keystroke_entropy, "EXPERIMENT_B_KEYSTROKE_ONLY", num_keys)
    print("Running NIST tests for Experiment B...")
    results_b = run_nist_tests(keys_b)

    print(f"Generating {num_keys} keys for Experiment C (Mouse + Keystroke)...")
    keys_c = _generate_key_batch(combined_entropy, "EXPERIMENT_C_COMBINED", num_keys)
    print("Running NIST tests for Experiment C...")
    results_c = run_nist_tests(keys_c)

    experiment_results = {
        "Experiment A - Mouse Entropy Only": results_a,
        "Experiment B - Keystroke Entropy Only": results_b,
        "Experiment C - Combined Mouse + Keystroke Entropy": results_c,
    }

    report_text = _build_combined_report(experiment_results)
    report_path = Path("results") / "combined_experiment_report.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")

    print("Combined experiment report saved to results/combined_experiment_report.txt")
    return experiment_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SUMIT KEY runner")
    parser.add_argument(
        "--mode",
        choices=["generate", "experiments"],
        default="generate",
        help="Run single generation or full NIST experiments",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Behaviour capture duration in seconds",
    )
    parser.add_argument(
        "--num-keys",
        type=int,
        default=1000,
        help="Number of keys for experiment mode",
    )

    args = parser.parse_args()

    if args.mode == "generate":
        generate_random_number_and_key(capture_duration_seconds=args.duration)
    else:
        run_all_experiments(num_keys=args.num_keys, capture_duration_seconds=args.duration)
