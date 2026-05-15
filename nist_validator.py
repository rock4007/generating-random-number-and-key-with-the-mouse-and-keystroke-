"""NIST SP 800-22 validator for SUMIT KEY.

This module evaluates generated keys using the nistrng implementation of
NIST SP 800-22 statistical randomness tests.

Python version target: 3.11+
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

import numpy as np
from nistrng import SP800_22R1A_BATTERY, run_all_battery


# Canonical test labels shown in the report table (15 SP 800-22 tests).
CANONICAL_TEST_NAMES = [
    "Frequency (Monobit)",
    "Block Frequency",
    "Runs",
    "Longest Run of Ones",
    "Binary Matrix Rank",
    "Discrete Fourier Transform",
    "Non-overlapping Template Matching",
    "Overlapping Template Matching",
    "Universal Statistical",
    "Linear Complexity",
    "Serial",
    "Approximate Entropy",
    "Cumulative Sums",
    "Random Excursions",
    "Random Excursions Variant",
]

# Each comment explains what that test checks in plain language.
NIST_TEST_PURPOSES = {
    "Frequency (Monobit)": "Checks whether ones and zeros are balanced globally.",
    "Block Frequency": "Checks bit balance inside fixed-size local blocks.",
    "Runs": "Checks whether run lengths of equal bits look random.",
    "Longest Run of Ones": "Checks whether longest one-runs per block are plausible.",
    "Binary Matrix Rank": "Checks for linear dependence patterns in bit matrices.",
    "Discrete Fourier Transform": "Checks for periodic patterns in the sequence spectrum.",
    "Non-overlapping Template Matching": "Checks frequencies of specific non-overlapping bit templates.",
    "Overlapping Template Matching": "Checks frequencies of overlapping template occurrences.",
    "Universal Statistical": "Checks whether the sequence is compressible (predictable).",
    "Linear Complexity": "Checks complexity of the shortest LFSR generating the sequence.",
    "Serial": "Checks frequencies of all overlapping m-bit patterns.",
    "Approximate Entropy": "Checks pattern regularity across neighboring block lengths.",
    "Cumulative Sums": "Checks excursion size of random walk partial sums.",
    "Random Excursions": "Checks visit counts to states in random-walk cycles.",
    "Random Excursions Variant": "Checks total visits to states across full walk.",
}

# Practical lower bound often used for broad SP 800-22 coverage.
FULL_BATTERY_RECOMMENDED_BITS = 1_000_000
DEFAULT_SEQUENCE_BITS = 50_000
MIN_SEQUENCES_FOR_PROPORTION_MODE = 20


def _normalize_keys(keys_list: list[bytes | bytearray]) -> list[bytes]:
    """Validate key list and return normalized immutable bytes.

    Why this matters cryptographically:
    - NIST tests must run on the exact key bytes that were produced.
    - Strict validation avoids accidental type coercion or mixed encodings.
    """

    if not isinstance(keys_list, list):
        raise TypeError("keys_list must be a list of bytes-like keys")

    normalized: list[bytes] = []
    for index, key in enumerate(keys_list):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError(f"key at index {index} must be bytes-like")
        normalized.append(bytes(key))

    if not normalized:
        raise ValueError("keys_list must not be empty")

    return normalized


def _bytes_to_bits(data: bytes) -> np.ndarray:
    """Convert raw key bytes into a NumPy bit array expected by nistrng."""

    byte_array = np.frombuffer(data, dtype=np.uint8)
    # int64 prevents overflow in cumulative-sums style tests inside nistrng.
    return np.unpackbits(byte_array).astype(np.int64)


def _build_sequences(keys: list[bytes], sequence_bits: int = DEFAULT_SEQUENCE_BITS) -> list[np.ndarray]:
    """Build longer bit sequences from keys for statistically meaningful tests.

    Why this matters cryptographically:
    - Many NIST tests require far more than 256 bits to be eligible.
    - Concatenating independently generated keys gives a better view of batch
      randomness quality without altering any key values.
    """

    all_bytes = b"".join(keys)
    all_bits = _bytes_to_bits(all_bytes)

    if all_bits.size == 0:
        return []

    if all_bits.size <= sequence_bits:
        return [all_bits]

    sequence_count = max(1, all_bits.size // sequence_bits)
    chunk_size = all_bits.size // sequence_count

    sequences: list[np.ndarray] = []
    for index in range(sequence_count):
        start = index * chunk_size
        end = (index + 1) * chunk_size if index < sequence_count - 1 else all_bits.size
        chunk = all_bits[start:end]
        if chunk.size > 0:
            sequences.append(chunk)

    return sequences


def _format_report_table(results: dict[str, Any]) -> str:
    """Build the printable and file-ready report text table."""

    lines: list[str] = []
    lines.append("NIST SP 800-22 RESULTS - SUMIT KEY")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"{'Test Name':<30} {'Pass Rate':<10} Status")

    for test in results["tests"]:
        if test["status"] == "PASS":
            status_text = "✓ PASS"
        elif test["status"] == "FAIL":
            status_text = "✗ FAIL"
        else:
            status_text = "• N/A"
        lines.append(f"{test['name']:<30} {test['pass_rate_percent']:>6.1f}%   {status_text}")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(
        f"Overall: {results['overall_passed_tests']}/{results['overall_eligible_tests']} eligible tests passed"
    )
    lines.append(f"Keys evaluated: {results['keys_evaluated']}")
    lines.append(f"Total bits evaluated: {results['total_bits']}")
    lines.append(f"Sequence count: {results['sequence_count']}")
    lines.append(f"Recommended bits for full battery coverage: {FULL_BATTERY_RECOMMENDED_BITS}")
    lines.append(f"Estimated keys needed for full coverage: {results['estimated_keys_for_full_coverage']}")
    lines.append("Threshold: >=95.0% pass rate per test (proportion mode)")
    lines.append(
        "Adaptive scoring: direct NIST verdict is used when sequence count is too low for stable proportions"
    )
    return "\n".join(lines)


def run_nist_tests(keys_list: list[bytes | bytearray]) -> dict[str, Any]:
    """Run NIST SP 800-22 tests across a list of generated keys.

    Args:
        keys_list: Expected to be a list of 1000 keys (bytes).

    Returns:
        Dictionary containing per-test pass rates, status, and summary metrics.

    Cryptographic notes:
    - p-value meaning: a p-value estimates how likely the observed statistic is
      under the null hypothesis of randomness. In these tests, higher than the
      significance level means "no evidence to reject randomness" for that test.
    - 95% threshold rationale: when running many independent sequences, NIST
      commonly uses a proportion criterion near 0.99 +/- tolerance; in practical
      engineering workflows, >=95% is used as a conservative acceptance floor
      for per-test pass proportion across batches.
    - Why these tests matter: they detect statistical bias, structure, and
      predictability that would weaken cryptographic key material.
    """

    normalized_keys = _normalize_keys(keys_list)
    key_lengths = [len(key) for key in normalized_keys]
    average_key_bytes = float(np.mean(key_lengths)) if key_lengths else 0.0
    total_bits = sum(length * 8 for length in key_lengths)
    estimated_keys_for_full_coverage = (
        math.ceil(FULL_BATTERY_RECOMMENDED_BITS / (average_key_bytes * 8))
        if average_key_bytes > 0
        else 0
    )

    sequences = _build_sequences(normalized_keys, sequence_bits=DEFAULT_SEQUENCE_BITS)
    if not sequences:
        raise ValueError("No bits available for NIST evaluation")

    # We aggregate test outcomes across longer sequences rather than per-key
    # 256-bit fragments, which improves eligibility and statistical validity.
    stats: dict[str, dict[str, Any]] = {
        name: {
            "name": name,
            "description": NIST_TEST_PURPOSES[name],
            "attempted": 0,
            "eligible": 0,
            "passed": 0,
            "p_values": [],
            "pass_rate_percent": 0.0,
            "status": "FAIL",
        }
        for name in CANONICAL_TEST_NAMES
    }

    for bits in sequences:
        battery_results = run_all_battery(bits, SP800_22R1A_BATTERY, check_eligibility=True)

        for index, test_name in enumerate(CANONICAL_TEST_NAMES):
            test_stats = stats[test_name]
            test_stats["attempted"] += 1

            # nistrng returns None when that test is not eligible for this bit length.
            item = battery_results[index] if index < len(battery_results) else None
            if item is None:
                continue

            result_obj, _elapsed = item
            test_stats["eligible"] += 1
            test_stats["p_values"].append(float(result_obj.score))
            if bool(result_obj.passed):
                test_stats["passed"] += 1

    tests_output: list[dict[str, Any]] = []
    overall_passed_tests = 0
    overall_eligible_tests = 0
    use_proportion_mode = len(sequences) >= MIN_SEQUENCES_FOR_PROPORTION_MODE

    for test_name in CANONICAL_TEST_NAMES:
        test_stats = stats[test_name]
        eligible = int(test_stats["eligible"])
        passed = int(test_stats["passed"])

        pass_rate = (passed / eligible * 100.0) if eligible > 0 else 0.0
        mean_p_value = (
            float(np.mean(test_stats["p_values"])) if test_stats["p_values"] else 0.0
        )

        if eligible == 0:
            status = "N/A"
        else:
            if use_proportion_mode:
                status = "PASS" if pass_rate >= 95.0 else "FAIL"
            else:
                # With very few sequences, pass-rate percentages become too coarse.
                # In that case we use direct nistrng pass/fail consensus.
                status = "PASS" if passed == eligible else "FAIL"

            if status == "PASS":
                overall_passed_tests += 1
            overall_eligible_tests += 1

        tests_output.append(
            {
                "name": test_name,
                "description": test_stats["description"],
                "attempted": int(test_stats["attempted"]),
                "eligible": eligible,
                "passed": passed,
                "pass_rate_percent": pass_rate,
                "mean_p_value": mean_p_value,
                "status": status,
            }
        )

    results: dict[str, Any] = {
        "keys_evaluated": len(normalized_keys),
        "expected_keys": 1000,
        "total_bits": total_bits,
        "sequence_count": len(sequences),
        "estimated_keys_for_full_coverage": estimated_keys_for_full_coverage,
        "overall_passed_tests": overall_passed_tests,
        "overall_eligible_tests": overall_eligible_tests,
        "overall_total_tests": 15,
        "overall_pass_rate_percent": (
            overall_passed_tests / overall_eligible_tests * 100.0
            if overall_eligible_tests > 0
            else 0.0
        ),
        "scoring_mode": "proportion" if use_proportion_mode else "direct_verdict",
        "tests": tests_output,
    }

    report_text = _format_report_table(results)
    print(report_text)

    report_path = Path("results") / "nist_report.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text + "\n", encoding="utf-8")

    return results
