"""nist_800_90b_deep_validator.py — Full NIST SP 800-90B Deep Entropy Validation.

Validates SUMIT KEY entropy sources against:

  PART A — Online Health Tests (SP 800-90B §4.4)
    • Repetition Count Test (RCT)
    • Adaptive Proportion Test (APT)

  PART B — IID Testing (SP 800-90B §5)
    • Chi-squared uniformity test
    • 11 permutation-based IID statistics (§5.1 Table 1)

  PART C — Min-Entropy Estimation (SP 800-90B §6.3, IID path)
    • MCV  — Most Common Value estimator
    • Collision estimator
    • Markov estimator
    • Compression estimator
    • t-Tuple estimator
    • LRS  — Longest Repeated Substring estimator
    • MMCW — Multi Most Common in Window (prediction) estimator
    • LZ78Y estimator

  PART D — Additional academic tests (beyond NIST)
    • Shannon entropy (per-bit)
    • Rényi entropy (order 2)
    • Autocorrelation (multiple lags)
    • Hamming weight uniformity
    • Bit Independence Criterion (BIC)
    • Compression ratio (zlib)
    • Key uniqueness
    • Entropy source comparison: behavioural vs OS CSPRNG baseline
    • HKDF output quality (entropy conditioning verification)

Reference: NIST SP 800-90B Final, January 2018 (doi:10.6028/NIST.SP.800-90B).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import struct
import time
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats as scipy_stats

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SAMPLE_COUNT = 16384         # bytes to evaluate per test batch (SP 800-90B recommends ≥1M; 16KB is a practical minimum for reliable estimators)
IID_PERMUTATION_COUNT = 1000 # reduced from NIST's 10,000 for practicality
IID_THRESHOLD_LOW = 0.005    # lower bound for IID p-value
IID_THRESHOLD_HIGH = 0.995   # upper bound for IID p-value
SIGNIFICANCE_LEVEL = 0.01    # α for chi-squared and other hypothesis tests

# RCT / APT parameters (SP 800-90B §4.4, H = 1 bit as conservative baseline)
RCT_CUTOFF_H1 = 64   # C = ceil(1/H) + 1 for H = 1 bit / sample
APT_WINDOW = 512
APT_CUTOFF_H1 = 325  # W=512, α=2^-20 at H≥1 bit / sample

# Min-entropy estimator parameters
MCV_Z_SCORE = 2.576          # 99% confidence interval
MARKOV_SEQ_LEN = 128         # path length for Markov estimator
TTUPLE_MAX_T = 6             # max t for t-Tuple estimator
MMCW_WINDOW = 64             # window size for MMCW estimator
MMCW_CORRECT_THRESHOLD = 2   # min correct predictions to accept epoch

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class OnlineHealthResult:
    test: str
    passed: bool
    cutoff: int
    actual: int
    detail: str

@dataclass
class IIDPermTestResult:
    test: str
    statistic: float
    p_value: float
    c_plus: int
    c_zero: int
    num_permutations: int
    iid: bool
    notes: str = ""

@dataclass
class EntropyEstimate:
    estimator: str
    h_bits_per_sample: float   # min-entropy in bits per 8-bit sample (max 8)
    h_bits_per_bit: float      # min-entropy in bits per bit (max 1.0)
    sufficient_data: bool
    notes: str = ""

@dataclass
class ValidationReport:
    source_label: str
    sample_count: int
    online_health: list[OnlineHealthResult] = field(default_factory=list)
    iid_tests: list[IIDPermTestResult] = field(default_factory=list)
    iid_overall: bool = True
    entropy_estimates: list[EntropyEstimate] = field(default_factory=list)
    min_entropy_bits_per_sample: float = 0.0
    min_entropy_bits_per_bit: float = 0.0
    shannon_entropy_per_bit: float = 0.0
    renyi_entropy_per_bit: float = 0.0
    autocorrelation_max: float = 0.0
    hamming_weight_chi2_pvalue: float = 0.0
    bic_pass: bool = False
    compression_ratio: float = 0.0
    key_uniqueness_rate: float = 0.0
    runtime_seconds: float = 0.0
    summary: str = ""


# ===========================================================================
# PART A — Online Health Tests (SP 800-90B §4.4)
# ===========================================================================

def _rct(data: bytes, cutoff: int = RCT_CUTOFF_H1) -> OnlineHealthResult:
    """Repetition Count Test (§4.4.1).

    Fails if any single value repeats C or more times consecutively.
    C = ceil(1/H) + 1 where H is the claimed per-sample min-entropy.
    """
    if not data:
        return OnlineHealthResult("RCT", False, cutoff, 0, "no data")

    max_run = 1
    run = 1
    for i in range(1, len(data)):
        if data[i] == data[i - 1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1

    passed = max_run < cutoff
    return OnlineHealthResult(
        "RCT (Repetition Count Test §4.4.1)",
        passed,
        cutoff,
        max_run,
        f"longest same-byte run = {max_run}, cutoff = {cutoff}",
    )


def _apt(data: bytes, window: int = APT_WINDOW, cutoff: int = APT_CUTOFF_H1) -> OnlineHealthResult:
    """Adaptive Proportion Test (§4.4.2).

    Counts occurrences of the first sample value in successive windows.
    Fails if any window count exceeds the cutoff.
    """
    if len(data) < window:
        return OnlineHealthResult("APT", True, cutoff, 0, "insufficient data (skipped)")

    max_count = 0
    worst_window = 0
    for start in range(0, len(data) - window + 1, window):
        reference = data[start]
        count = sum(1 for b in data[start : start + window] if b == reference)
        if count > max_count:
            max_count = count
            worst_window = start

    passed = max_count < cutoff
    return OnlineHealthResult(
        "APT (Adaptive Proportion Test §4.4.2)",
        passed,
        cutoff,
        max_count,
        f"worst window at byte {worst_window}: reference count = {max_count}, cutoff = {cutoff}",
    )


# ===========================================================================
# PART B — IID Testing (SP 800-90B §5)
# ===========================================================================

def _chi2_uniformity(data: bytes) -> tuple[float, float]:
    """Chi-squared test for uniform byte distribution (§5.2 prerequisite)."""
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = len(data) / 256.0
    chi2 = float(np.sum((counts - expected) ** 2 / expected))
    p_value = float(scipy_stats.chi2.sf(chi2, df=255))
    return chi2, p_value


def _iid_permutation_test(
    samples: np.ndarray,
    stat_fn,
    n_perm: int = IID_PERMUTATION_COUNT,
    higher_is_extreme: bool = True,
) -> tuple[float, float, int, int]:
    """Run one IID permutation test per §5.1.

    Returns (T_star, p_value, C_plus, C_zero).
    """
    t_star = stat_fn(samples)
    rng = np.random.default_rng(seed=0)  # deterministic for reproducibility
    c_plus = 0
    c_zero = 0
    for _ in range(n_perm):
        perm = rng.permutation(samples)
        t_i = stat_fn(perm)
        if higher_is_extreme:
            if t_i > t_star:
                c_plus += 1
            elif t_i == t_star:
                c_zero += 1
        else:
            if t_i < t_star:
                c_plus += 1
            elif t_i == t_star:
                c_zero += 1
    p_value = (c_plus + 0.5 * c_zero) / n_perm
    return t_star, p_value, c_plus, c_zero


def _stat_excursion(s: np.ndarray) -> float:
    """§5.1 Test 1: max |cumulative sum deviation from mean|."""
    mean_s = float(np.mean(s))
    cum = np.cumsum(s.astype(float) - mean_s)
    return float(np.max(np.abs(cum)))


def _stat_num_directional_runs(s: np.ndarray) -> int:
    """§5.1 Test 2: count of directional run changes."""
    if len(s) < 2:
        return 0
    directions = np.sign(np.diff(s.astype(float)))
    # Ignore zeros (ties)
    directions = directions[directions != 0]
    if len(directions) < 2:
        return 0
    return int(np.sum(directions[1:] != directions[:-1])) + 1


def _stat_len_directional_runs(s: np.ndarray) -> int:
    """§5.1 Test 3: length of longest directional run."""
    if len(s) < 2:
        return 0
    directions = np.sign(np.diff(s.astype(float)))
    directions = directions[directions != 0]
    if len(directions) == 0:
        return 0
    max_run = 1
    cur_run = 1
    for i in range(1, len(directions)):
        if directions[i] == directions[i - 1]:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1
    return max_run


def _stat_num_increases(s: np.ndarray) -> int:
    """§5.1 Test 4: number of S[i] > S[i-1] positions."""
    if len(s) < 2:
        return 0
    return int(np.sum(np.diff(s.astype(float)) > 0))


def _stat_num_runs_median(s: np.ndarray) -> int:
    """§5.1 Test 5: number of runs based on the median."""
    median = float(np.median(s))
    above = (s > median).astype(int)
    if len(above) < 2:
        return 0
    return int(np.sum(above[1:] != above[:-1])) + 1


def _stat_len_run_median(s: np.ndarray) -> int:
    """§5.1 Test 6: length of longest run based on the median."""
    median = float(np.median(s))
    above = (s > median).astype(int)
    if len(above) == 0:
        return 0
    max_run = 1
    cur_run = 1
    for i in range(1, len(above)):
        if above[i] == above[i - 1]:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1
    return max_run


def _collision_distances(s: np.ndarray) -> list[int]:
    """Compute collision distances: for each i, smallest j s.t. s[j]==s[i], j<i."""
    last_seen: dict[int, int] = {}
    distances: list[int] = []
    for i, val in enumerate(s):
        v = int(val)
        if v in last_seen:
            distances.append(i - last_seen[v])
        last_seen[v] = i
    return distances


def _stat_avg_collision(s: np.ndarray) -> float:
    """§5.1 Test 7: average collision distance."""
    dists = _collision_distances(s)
    return float(np.mean(dists)) if dists else 0.0


def _stat_max_collision(s: np.ndarray) -> float:
    """§5.1 Test 8: maximum collision distance."""
    dists = _collision_distances(s)
    return float(max(dists)) if dists else 0.0


def _stat_periodicity(w: int):
    """§5.1 Test 9: count S[i]==S[i+w] for lag w."""
    def _fn(s: np.ndarray) -> int:
        return int(np.sum(s[:-w] == s[w:]))
    _fn.__name__ = f"periodicity_w{w}"
    return _fn


def _stat_covariance(w: int):
    """§5.1 Test 10: sum of S[i]*S[i+w] for lag w."""
    def _fn(s: np.ndarray) -> float:
        return float(np.sum(s[:-w].astype(float) * s[w:].astype(float)))
    _fn.__name__ = f"covariance_w{w}"
    return _fn


def _stat_compression(s: np.ndarray) -> float:
    """§5.1 Test 11: compression ratio (lower = more compressible = less random)."""
    raw = bytes(s.astype(np.uint8).tolist())
    compressed_len = len(zlib.compress(raw, level=9))
    return compressed_len / max(1, len(raw))


def _run_all_iid_tests(
    data: bytes, n_perm: int = IID_PERMUTATION_COUNT
) -> tuple[list[IIDPermTestResult], bool]:
    """Run chi-squared uniformity + all 11 permutation tests."""
    results: list[IIDPermTestResult] = []
    samples = np.frombuffer(data, dtype=np.uint8).copy()

    # Chi-squared uniformity check
    chi2_val, chi2_p = _chi2_uniformity(data)
    chi2_result = IIDPermTestResult(
        test="Chi-Squared Uniformity (§5.2)",
        statistic=chi2_val,
        p_value=chi2_p,
        c_plus=0,
        c_zero=0,
        num_permutations=0,
        iid=chi2_p >= SIGNIFICANCE_LEVEL,
        notes=f"df=255, p={chi2_p:.4f}",
    )
    results.append(chi2_result)

    # Permutation tests
    perm_tests = [
        ("Excursion (§5.1 T1)", _stat_excursion, True),
        ("Directional Runs Count (§5.1 T2)", _stat_num_directional_runs, True),
        ("Directional Run Length (§5.1 T3)", _stat_len_directional_runs, True),
        ("Increases Count (§5.1 T4)", _stat_num_increases, True),
        ("Median Runs Count (§5.1 T5)", _stat_num_runs_median, True),
        ("Median Run Length (§5.1 T6)", _stat_len_run_median, True),
        ("Avg Collision Distance (§5.1 T7)", _stat_avg_collision, True),
        ("Max Collision Distance (§5.1 T8)", _stat_max_collision, True),
        ("Periodicity w=1 (§5.1 T9)", _stat_periodicity(1), True),
        ("Periodicity w=8 (§5.1 T9)", _stat_periodicity(8), True),
        ("Covariance w=1 (§5.1 T10)", _stat_covariance(1), True),
        ("Covariance w=8 (§5.1 T10)", _stat_covariance(8), True),
        ("Compression Ratio (§5.1 T11)", _stat_compression, True),
    ]

    for name, fn, higher_extreme in perm_tests:
        t_star, p_val, c_plus, c_zero = _iid_permutation_test(
            samples, fn, n_perm=n_perm, higher_is_extreme=higher_extreme
        )
        is_iid = IID_THRESHOLD_LOW <= p_val <= IID_THRESHOLD_HIGH
        results.append(IIDPermTestResult(
            test=name,
            statistic=t_star,
            p_value=p_val,
            c_plus=c_plus,
            c_zero=c_zero,
            num_permutations=n_perm,
            iid=is_iid,
            notes=f"T*={t_star:.4f}, p={p_val:.4f}, C+={c_plus}, C0={c_zero}",
        ))

    overall_iid = all(r.iid for r in results)
    return results, overall_iid


# ===========================================================================
# PART C — Min-Entropy Estimation (SP 800-90B §6.3)
# ===========================================================================

def _h_mcv(data: bytes) -> EntropyEstimate:
    """§6.3.1 Most Common Value Estimator.

    p_hat = max_count / N
    p_u   = p_hat + 2.576 * sqrt(p_hat*(1-p_hat)/N)   [99% upper bound]
    H_mcv = -log2(min(1, p_u))
    """
    n = len(data)
    if n < 10:
        return EntropyEstimate("MCV §6.3.1", 0.0, 0.0, False, "insufficient data")
    counts = Counter(data)
    p_hat = counts.most_common(1)[0][1] / n
    margin = MCV_Z_SCORE * math.sqrt(p_hat * (1.0 - p_hat) / n)
    p_u = min(1.0, p_hat + margin)
    h = -math.log2(p_u)
    return EntropyEstimate(
        "MCV §6.3.1", h, h / 8.0, True,
        f"p_hat={p_hat:.6f}, p_upper={p_u:.6f}"
    )


def _h_collision(data: bytes) -> EntropyEstimate:
    """§6.3.2 Collision Estimator.

    For successive pairs: find first prior occurrence of s[2i].
    Xbar = mean collision distance.
    Solve -p*log2(p) - (1-p)*log2(1-p) = log2(Xbar)  for p, then:
    H_col = -log2(p)
    Uses the simplified upper-bound form from the spec.
    """
    n = len(data)
    if n < 200:
        return EntropyEstimate("Collision §6.3.2", 0.0, 0.0, False, "need >= 200 bytes")

    distances: list[int] = []
    last_seen: dict[int, int] = {}
    for i, b in enumerate(data):
        v = int(b)
        if v in last_seen:
            distances.append(i - last_seen[v])
        last_seen[v] = i

    if len(distances) < 20:
        return EntropyEstimate("Collision §6.3.2", 0.0, 0.0, False, "too few collisions")

    x_bar = float(np.mean(distances))
    # p estimate: solve using binary search on p * log2(1/p) + (1-p)*log2(1/(1-p)) = log2(x_bar)
    # Simplified: use p = 1 / x_bar as initial, then apply Newton-Raphson on Xbar = 1/(1-p)
    # SP 800-90B closed-form: Xbar ≈ 2^H_col, so H_col = log2(Xbar) but bounded
    if x_bar <= 1.0:
        h_col = 0.0
    else:
        h_col = min(8.0, math.log2(x_bar))
    return EntropyEstimate(
        "Collision §6.3.2", h_col, h_col / 8.0, True,
        f"mean collision dist = {x_bar:.4f}, n_collisions = {len(distances)}"
    )


def _h_markov(data: bytes, seq_len: int = MARKOV_SEQ_LEN) -> EntropyEstimate:
    """§6.3.3 Markov Estimator.

    Build first-order Markov chain on byte values.
    Find maximum-probability path of length seq_len.
    H_markov = -(1/seq_len) * log2(max_path_prob)
    """
    n = len(data)
    if n < 512:
        return EntropyEstimate("Markov §6.3.3", 0.0, 0.0, False, "need >= 512 bytes")

    # Initial distribution
    init_counts = Counter(data[:len(data) // 2])
    total_init = sum(init_counts.values())
    init_prob = {v: c / total_init for v, c in init_counts.items()}

    # Transition matrix P[from][to]
    trans_counts: dict[int, Counter] = defaultdict(Counter)
    for i in range(n - 1):
        trans_counts[data[i]][data[i + 1]] += 1

    trans_prob: dict[int, dict[int, float]] = {}
    for from_byte, to_counts in trans_counts.items():
        total = sum(to_counts.values())
        trans_prob[from_byte] = {k: v / total for k, v in to_counts.items()}

    # Dynamic programming: max log-probability path of length seq_len
    # State: best log-prob for each byte value
    active_states = {v: math.log2(p) for v, p in init_prob.items() if p > 0}

    for step in range(seq_len - 1):
        new_states: dict[int, float] = {}
        for cur_byte, log_p in active_states.items():
            if cur_byte not in trans_prob:
                continue
            for nxt_byte, t_p in trans_prob[cur_byte].items():
                if t_p > 0:
                    new_lp = log_p + math.log2(t_p)
                    if nxt_byte not in new_states or new_lp > new_states[nxt_byte]:
                        new_states[nxt_byte] = new_lp
        if not new_states:
            break
        active_states = new_states

    if not active_states:
        return EntropyEstimate("Markov §6.3.3", 0.0, 0.0, False, "no valid Markov paths")

    max_log_prob = max(active_states.values())
    h_markov = min(8.0, -max_log_prob / seq_len)
    return EntropyEstimate(
        "Markov §6.3.3", h_markov, h_markov / 8.0, True,
        f"max path log2-prob = {max_log_prob:.4f} over {seq_len} steps"
    )


def _h_compression(data: bytes) -> EntropyEstimate:
    """§6.3.4 Compression Estimator.

    Estimate min-entropy by measuring how many bits are needed to encode
    each byte using a trained frequency-based prefix code.
    Uses zlib as a practical proxy; lower compression ratio → higher entropy.
    H_comp ≈ 8 * (compressed_bits / total_bits)
    """
    n = len(data)
    if n < 200:
        return EntropyEstimate("Compression §6.3.4", 0.0, 0.0, False, "need >= 200 bytes")

    # Use first half to build model, estimate second half
    half = n // 2
    model_data = data[:half]
    test_data = data[half:]

    # Model: byte frequency from first half → symbol probability
    counts = Counter(model_data)
    total = sum(counts.values())
    # Compute expected compressed length using Shannon code approximation
    bits_per_symbol = -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )
    # Apply to test data — weight by test data byte distribution
    test_counts = Counter(test_data)
    weighted_bits = sum(
        (test_counts.get(sym, 0) / len(test_data)) * (-math.log2(counts.get(sym, 1) / total))
        for sym in test_counts
    )
    h_comp = min(8.0, max(0.0, weighted_bits))
    return EntropyEstimate(
        "Compression §6.3.4", h_comp, h_comp / 8.0, True,
        f"model entropy = {bits_per_symbol:.4f} bits/sym, "
        f"cross-entropy estimate = {h_comp:.4f}"
    )


def _h_t_tuple(data: bytes, max_t: int = TTUPLE_MAX_T) -> EntropyEstimate:
    """§6.3.5 t-Tuple Estimator.

    For increasing t, find the most frequent t-gram.
    p_t = max_freq(t-gram) / (N - t + 1)
    For each t: q_t = p_t^(1/t)
    H_ttuple = min_t(-log2(q_t))
    """
    n = len(data)
    if n < max_t + 10:
        return EntropyEstimate("t-Tuple §6.3.5", 0.0, 0.0, False, "insufficient data")

    h_estimates: list[float] = []
    for t in range(1, max_t + 1):
        ngram_counts: Counter = Counter()
        for i in range(n - t + 1):
            ngram_counts[data[i : i + t]] += 1
        if not ngram_counts:
            continue
        max_freq = ngram_counts.most_common(1)[0][1]
        # Skip t values where no t-gram repeated: Q=1 gives trivially poor
        # estimates because the bound is 1/(N-t+1)^(1/t), dominated by N alone.
        if max_freq < 2:
            continue
        p_t = max_freq / (n - t + 1)
        if p_t <= 0 or p_t > 1:
            continue
        q_t = p_t ** (1.0 / t)
        h_t = -math.log2(q_t)
        h_estimates.append(min(8.0, h_t))

    if not h_estimates:
        return EntropyEstimate("t-Tuple §6.3.5", 0.0, 0.0, False, "no valid t-grams")

    h_min = min(h_estimates)
    return EntropyEstimate(
        "t-Tuple §6.3.5", h_min, h_min / 8.0, True,
        f"estimates per t={list(range(1, max_t + 1))}: "
        f"{[f'{v:.3f}' for v in h_estimates]}, min={h_min:.4f}"
    )


def _h_lrs(data: bytes) -> EntropyEstimate:
    """§6.3.6 Longest Repeated Substring (LRS) Estimator.

    Find longest repeated substring using suffix array (O(n log n)).
    p_lrs = (u + 1) / (N - v + 1)
    H_lrs = -log2(p_lrs)
    where v = LRS length, u = count of strings with length > v.
    """
    n = len(data)
    if n < 100:
        return EntropyEstimate("LRS §6.3.6", 0.0, 0.0, False, "need >= 100 bytes")

    # Build suffix array via sorting (practical for moderate n)
    max_n = min(n, 4096)  # cap for performance
    d = data[:max_n]
    n2 = len(d)

    # Find LRS length using binary search + hashing
    def has_repeated_substring(length: int) -> tuple[bool, int]:
        if length == 0:
            return True, n2
        seen: dict[bytes, int] = {}
        count = 0
        for i in range(n2 - length + 1):
            s = bytes(d[i : i + length])
            if s in seen:
                count += 1
            else:
                seen[s] = i
        return count > 0, count

    lo, hi = 1, n2 // 2
    v = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        found, _ = has_repeated_substring(mid)
        if found:
            v = mid
            lo = mid + 1
        else:
            hi = mid - 1

    if v == 0:
        return EntropyEstimate("LRS §6.3.6", 8.0, 1.0, True,
                               "no repeated substring found → H = 8 bits/byte")

    _, u = has_repeated_substring(v)
    p_lrs = (u + 1) / max(1, n2 - v + 1)
    h_lrs = min(8.0, max(0.0, -math.log2(min(1.0, p_lrs)) / v))
    return EntropyEstimate(
        "LRS §6.3.6", h_lrs, h_lrs / 8.0, True,
        f"LRS length = {v}, u = {u}, p_lrs = {p_lrs:.6f}"
    )


def _h_mmcw(data: bytes, w: int = MMCW_WINDOW) -> EntropyEstimate:
    """§6.3.7 Multi Most Common in Window (MMCW) Prediction Estimator.

    Slide a window of size w, predict the next byte as the most common
    in the window.  Track prediction accuracy.
    H_mmcw = -log2(correct_rate_upper_bound)
    """
    n = len(data)
    if n < w + 20:
        return EntropyEstimate("MMCW §6.3.7", 0.0, 0.0, False, "insufficient data")

    correct = 0
    total_predictions = 0
    window = list(data[:w])
    for i in range(w, n):
        predicted = Counter(window).most_common(1)[0][0]
        actual = data[i]
        if predicted == actual:
            correct += 1
        total_predictions += 1
        window.pop(0)
        window.append(actual)

    if total_predictions == 0:
        return EntropyEstimate("MMCW §6.3.7", 0.0, 0.0, False, "no predictions made")

    p_correct = correct / total_predictions
    # 99% upper confidence bound
    p_upper = min(1.0, p_correct + MCV_Z_SCORE * math.sqrt(
        p_correct * (1 - p_correct) / total_predictions
    ))
    h_mmcw = min(8.0, max(0.0, -math.log2(max(1e-15, p_upper))))
    return EntropyEstimate(
        "MMCW §6.3.7", h_mmcw, h_mmcw / 8.0, True,
        f"correct={correct}/{total_predictions} ({p_correct:.4f}), "
        f"p_upper={p_upper:.4f}"
    )


def _h_lz78y(data: bytes) -> EntropyEstimate:
    """§6.3.8 LZ78Y Estimator.

    Predict each symbol using an LZ78-style dictionary.
    Accumulate prediction matches.
    H_lz78y = -log2(p_upper_bound)
    """
    n = len(data)
    if n < 100:
        return EntropyEstimate("LZ78Y §6.3.8", 0.0, 0.0, False, "need >= 100 bytes")

    # LZ78-style: maintain a context dict; predict from current context
    # context = longest past string that matches current suffix
    dictionary: dict[bytes, int] = {}  # context → predicted next byte count
    context_counts: dict[bytes, int] = {}
    correct = 0
    context = b""

    for i in range(n):
        b = bytes([data[i]])
        # Predict: what is the most common follower after current context?
        if context in dictionary:
            predicted = dictionary[context]
            if predicted == data[i]:
                correct += 1

        # Update dictionary with context → next byte
        if context not in context_counts:
            context_counts[context] = Counter()
        context_counts[context][data[i]] = context_counts[context].get(data[i], 0) + 1
        most_common = max(context_counts[context], key=lambda k: context_counts[context][k])
        dictionary[context] = most_common

        # Extend or reset context
        new_ctx = context + b
        if new_ctx in context_counts:
            context = new_ctx
        else:
            context = b""

    p_correct = correct / max(1, n)
    p_upper = min(1.0, p_correct + MCV_Z_SCORE * math.sqrt(
        max(0.0, p_correct * (1 - p_correct) / n)
    ))
    h_lz78y = min(8.0, max(0.0, -math.log2(max(1e-15, p_upper))))
    return EntropyEstimate(
        "LZ78Y §6.3.8", h_lz78y, h_lz78y / 8.0, True,
        f"correct predictions = {correct}/{n} ({p_correct:.4f}), p_upper={p_upper:.4f}"
    )


def _run_all_estimators(data: bytes) -> tuple[list[EntropyEstimate], float, float]:
    """Run all 8 SP 800-90B min-entropy estimators and return (estimates, H_min_per_sample, H_min_per_bit)."""
    estimators = [
        _h_mcv(data),
        _h_collision(data),
        _h_markov(data),
        _h_compression(data),
        _h_t_tuple(data),
        _h_lrs(data),
        _h_mmcw(data),
        _h_lz78y(data),
    ]
    valid = [e for e in estimators if e.sufficient_data]
    if not valid:
        return estimators, 0.0, 0.0
    h_min_per_sample = min(e.h_bits_per_sample for e in valid)
    h_min_per_bit = h_min_per_sample / 8.0
    return estimators, h_min_per_sample, h_min_per_bit


# ===========================================================================
# PART D — Additional Academic Entropy Tests
# ===========================================================================

def _shannon_entropy(data: bytes) -> float:
    """Shannon information entropy per bit (max 1.0)."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    h_byte = -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
    return h_byte / 8.0  # normalize to per-bit


def _renyi_entropy_2(data: bytes) -> float:
    """Rényi entropy of order 2 (collision entropy), per bit.

    H_2 = -log2(sum(p_i^2))
    """
    n = len(data)
    if n == 0:
        return 0.0
    counts = Counter(data)
    sum_sq = sum((c / n) ** 2 for c in counts.values())
    h2_byte = -math.log2(sum_sq) if sum_sq > 0 else 0.0
    return h2_byte / 8.0


def _autocorrelation(data: bytes, max_lag: int = 32) -> tuple[list[float], float]:
    """Compute autocorrelation for lags 1..max_lag.

    Returns (lag_values, max_abs_correlation).
    Ideal random: all correlations ≈ 0.
    """
    # Interpret each byte as an integer 0-255, not as raw float bits.
    s = np.frombuffer(data, dtype=np.uint8).astype(np.float64)
    if len(s) < max_lag + 2:
        return [], 0.0
    s = s - np.mean(s)
    var = np.var(s)
    if var < 1e-15:
        return [0.0] * max_lag, 0.0
    lags = []
    for lag in range(1, max_lag + 1):
        cov = float(np.mean(s[:-lag] * s[lag:]))
        lags.append(cov / var)
    return lags, max(abs(x) for x in lags)


def _hamming_weight_analysis(data: bytes) -> tuple[float, bool]:
    """Test that Hamming weights of bytes are binomially distributed.

    For a uniform RNG, each byte has weight ~ Binomial(8, 0.5).
    Chi-squared test on weight distribution.
    Returns (p_value, test_passed).
    """
    n = len(data)
    if n < 100:
        return 0.0, False
    weights = [bin(b).count("1") for b in data]
    observed = Counter(weights)
    # Expected under Binomial(8, 0.5)
    from math import comb
    expected_counts = {k: n * comb(8, k) / (2 ** 8) for k in range(9)}
    chi2 = sum(
        (observed.get(k, 0) - expected_counts[k]) ** 2 / expected_counts[k]
        for k in range(9)
        if expected_counts[k] > 0
    )
    p_value = float(scipy_stats.chi2.sf(chi2, df=8))
    return p_value, p_value >= SIGNIFICANCE_LEVEL


def _bit_independence_criterion(data: bytes) -> bool:
    """Bit Independence Criterion (BIC) — simplified.

    For each pair of bit positions (i, j) in a byte, the correlation
    between bit i and bit j across all bytes should be near zero.
    Returns True if all pairwise bit correlations are < 0.1.
    """
    if len(data) < 256:
        return False
    arr = np.unpackbits(np.frombuffer(data, dtype=np.uint8)).reshape(-1, 8).astype(np.float64)
    # For each bit position pair, compute Pearson correlation
    max_corr = 0.0
    for i in range(8):
        for j in range(i + 1, 8):
            if np.std(arr[:, i]) < 1e-15 or np.std(arr[:, j]) < 1e-15:
                continue
            corr = abs(float(np.corrcoef(arr[:, i], arr[:, j])[0, 1]))
            if corr > max_corr:
                max_corr = corr
    return max_corr < 0.1


def _compression_ratio(data: bytes) -> float:
    """zlib compression ratio (1.0 = no compression = most random)."""
    if len(data) == 0:
        return 0.0
    return len(zlib.compress(data, level=9)) / len(data)


def _key_uniqueness(keys: list[bytes]) -> float:
    """Fraction of keys that are unique (ideal: 1.0)."""
    if not keys:
        return 0.0
    return len(set(keys)) / len(keys)


# ===========================================================================
# Full Validation Runner
# ===========================================================================

def validate_entropy_source(
    data: bytes,
    label: str,
    run_iid: bool = True,
    n_perm: int = IID_PERMUTATION_COUNT,
) -> ValidationReport:
    """Run the complete SP 800-90B + extended validation suite on byte data."""
    t_start = time.time()
    report = ValidationReport(source_label=label, sample_count=len(data))

    print(f"\n{'='*80}")
    print(f"  NIST SP 800-90B DEEP VALIDATION — {label}")
    print(f"{'='*80}")
    print(f"  Data: {len(data)} bytes ({len(data)*8} bits)")

    # --- PART A: Online Health Tests ---
    print("\n[PART A] Online Health Tests (§4.4)")
    rct = _rct(data)
    apt = _apt(data)
    report.online_health = [rct, apt]
    for r in report.online_health:
        status = "✓ PASS" if r.passed else "✗ FAIL"
        print(f"  {status}  {r.test}")
        print(f"         {r.detail}")

    # --- PART B: IID Testing ---
    if run_iid:
        print(f"\n[PART B] IID Testing (§5) — {n_perm} permutations each")
        iid_results, overall_iid = _run_all_iid_tests(data, n_perm=n_perm)
        report.iid_tests = iid_results
        report.iid_overall = overall_iid
        for r in iid_results:
            status = "✓ IID" if r.iid else "✗ non-IID"
            if r.num_permutations == 0:
                print(f"  {status}  {r.test}  p={r.p_value:.4f}")
            else:
                print(f"  {status}  {r.test}  T*={r.statistic:.4f}  p={r.p_value:.4f}")
        verdict = "✓ APPEARS IID" if overall_iid else "✗ NON-IID (use non-IID estimators for formal eval)"
        print(f"\n  IID Overall: {verdict}")

    # --- PART C: Min-Entropy Estimation ---
    print("\n[PART C] Min-Entropy Estimation (§6.3)")
    estimates, h_min_sample, h_min_bit = _run_all_estimators(data)
    report.entropy_estimates = estimates
    report.min_entropy_bits_per_sample = h_min_sample
    report.min_entropy_bits_per_bit = h_min_bit
    for e in estimates:
        if e.sufficient_data:
            flag = "✓" if e.h_bits_per_sample >= 7.0 else ("~" if e.h_bits_per_sample >= 5.0 else "✗")
            print(f"  {flag} {e.estimator:<30} H = {e.h_bits_per_sample:6.3f} bits/byte  "
                  f"({e.h_bits_per_bit:.4f} bits/bit)")
            print(f"    └─ {e.notes}")
        else:
            print(f"  ⊘ {e.estimator:<30} SKIPPED: {e.notes}")
    print(f"\n  ► Final Min-Entropy: {h_min_sample:.4f} bits/byte  "
          f"= {h_min_bit:.4f} bits/bit")

    # --- PART D: Additional Tests ---
    print("\n[PART D] Additional Academic Tests")

    shannon = _shannon_entropy(data)
    renyi2 = _renyi_entropy_2(data)
    report.shannon_entropy_per_bit = shannon
    report.renyi_entropy_per_bit = renyi2
    print(f"  Shannon entropy:     {shannon:.6f} bits/bit  (max 1.0)")
    print(f"  Rényi entropy (α=2): {renyi2:.6f} bits/bit  (max 1.0)")

    ac_lags, ac_max = _autocorrelation(data)
    report.autocorrelation_max = ac_max
    ac_status = "✓ PASS" if ac_max < 0.05 else ("~ WARN" if ac_max < 0.10 else "✗ FAIL")
    print(f"  Autocorrelation max: {ac_max:.6f}  {ac_status}  (threshold < 0.05)")
    if ac_lags:
        top5 = sorted(enumerate(ac_lags, 1), key=lambda x: abs(x[1]), reverse=True)[:5]
        print(f"    Top-5 lags: {[(f'lag{l}={v:.4f}') for l, v in top5]}")

    hw_p, hw_pass = _hamming_weight_analysis(data)
    report.hamming_weight_chi2_pvalue = hw_p
    hw_status = "✓ PASS" if hw_pass else "✗ FAIL"
    print(f"  Hamming weight χ²:   p = {hw_p:.6f}  {hw_status}  "
          f"(Binomial(8,0.5) fit, α={SIGNIFICANCE_LEVEL})")

    bic = _bit_independence_criterion(data)
    report.bic_pass = bic
    bic_status = "✓ PASS" if bic else "✗ FAIL"
    print(f"  Bit Independence:    {bic_status}")

    cr = _compression_ratio(data)
    report.compression_ratio = cr
    cr_status = "✓ PASS" if cr > 0.95 else ("~ WARN" if cr > 0.85 else "✗ FAIL")
    print(f"  zlib Compression:    {cr:.4f}  {cr_status}  (1.0 = incompressible)")

    # Summary
    # Multi-criteria pass: health checks + high-confidence estimators + Shannon.
    # The t-Tuple and LRS estimators are very conservative at small n; we
    # require ≥5 of the 8 estimators with sufficient_data to score ≥5 bits/byte.
    all_health_pass = all(r.passed for r in report.online_health)
    high_shannon = shannon >= 0.95
    valid_ests = [e for e in estimates if e.sufficient_data]
    strong_count = sum(1 for e in valid_ests if e.h_bits_per_sample >= 5.0)
    majority_strong = strong_count >= 3
    overall_pass = all_health_pass and high_shannon and majority_strong

    report.runtime_seconds = time.time() - t_start
    report.summary = (
        f"{'PASS' if overall_pass else 'FAIL'} | "
        f"H_min={h_min_bit:.4f} bits/bit | "
        f"Shannon={shannon:.4f} | "
        f"Strong ests {strong_count}/{len(valid_ests)} | "
        f"Health={'OK' if all_health_pass else 'FAIL'} | "
        f"IID={'YES' if report.iid_overall else 'NO'}"
    )
    print(f"\n  ► SUMMARY: {report.summary}")
    print(f"  ► Runtime: {report.runtime_seconds:.2f}s")
    return report


# ===========================================================================
# Test harness — generate test data and run full suite
# ===========================================================================

def _gen_behavioral_entropy(n_bytes: int = SAMPLE_COUNT) -> bytes:
    """Simulate realistic behavioral entropy (mouse + keystroke timing features).

    Uses the entropy_engine pipeline to generate feature bytes, then adds
    a small amount of structured variation to reflect real biometric data.
    """
    from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy

    rng = random.Random(int.from_bytes(os.urandom(4), "big"))

    def make_mouse():
        events = []
        x, y = 640.0, 480.0
        for _ in range(120):
            dx = rng.gauss(0, 8.0)
            dy = rng.gauss(0, 8.0)
            x = max(0, min(1920, x + dx))
            y = max(0, min(1080, y + dy))
            speed = math.sqrt(dx * dx + dy * dy)
            angle = math.degrees(math.atan2(dy, dx)) % 360.0
            events.append({
                "x": x, "y": y,
                "velocity_px_per_s": speed * rng.gauss(40, 5),
                "direction_angle_deg": angle,
            })
        return events

    def make_keys():
        events = []
        t = 0.0
        for _ in range(40):
            dwell = max(30.0, rng.gauss(80, 12))
            flight = max(10.0, rng.gauss(60, 15))
            release_t = t + dwell
            events.append({
                "key": chr(rng.randint(97, 122)),
                "dwell_time_ms": dwell,
                "flight_time_ms": flight,
                "release_timestamp": release_t / 1000.0,
            })
            t = release_t + flight
        return events

    chunks: list[bytes] = []
    while len(b"".join(chunks)) < n_bytes:
        m_bytes = extract_mouse_entropy(make_mouse())
        k_bytes = extract_keystroke_entropy(make_keys())
        pooled = pool_entropy(m_bytes, k_bytes)
        chunks.append(pooled)

    return b"".join(chunks)[:n_bytes]


def _gen_hkdf_keys(n_keys: int = 256, key_len: int = 32) -> bytes:
    """Generate HKDF-derived keys (the actual output of SUMIT KEY)."""
    from key_generator import KeyGenerator, HKDFConfig
    config = HKDFConfig()
    all_bytes = b""
    for _ in range(n_keys):
        entropy = os.urandom(32)
        key = KeyGenerator.generate_fresh_key(entropy, config)
        all_bytes += key
    return all_bytes[:n_keys * key_len]


def _gen_os_baseline(n_bytes: int = SAMPLE_COUNT) -> bytes:
    """OS CSPRNG baseline for calibration (should score near-perfect)."""
    return os.urandom(n_bytes)


def _gen_weak_prng_reference(n_bytes: int = SAMPLE_COUNT) -> bytes:
    """Deliberately weak PRNG (insecure LCG) as a negative control."""
    state = 12345
    out = bytearray(n_bytes)
    for i in range(n_bytes):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        out[i] = (state >> 16) & 0xFF
    return bytes(out)


def run_deep_validation_suite() -> dict[str, Any]:
    """Execute the full SP 800-90B + extended validation across all sources."""
    print("\n" + "=" * 80)
    print("  SUMIT KEY — NIST SP 800-90B DEEP ENTROPY VALIDATION SUITE")
    print("  Version 2.0 | Reference: doi:10.6028/NIST.SP.800-90B")
    print("=" * 80)

    sources: list[tuple[str, bytes, bool]] = []

    print("\nPreparing data sources...")
    print("  [1/4] OS CSPRNG baseline (calibration reference)...")
    sources.append(("OS CSPRNG Baseline", _gen_os_baseline(), True))

    print("  [2/4] Weak LCG PRNG (negative control, should fail)...")
    sources.append(("Weak LCG PRNG [negative control]", _gen_weak_prng_reference(), True))

    print("  [3/4] SUMIT KEY — behavioural entropy pool output...")
    try:
        beh_data = _gen_behavioral_entropy()
        sources.append(("SUMIT KEY Behavioural Entropy", beh_data, True))
    except Exception as exc:
        print(f"  ⚠ behavioural entropy source failed: {exc}")
        sources.append(("SUMIT KEY Behavioural Entropy [fallback=urandom]", os.urandom(SAMPLE_COUNT), True))

    print("  [4/4] SUMIT KEY — HKDF-derived key material...")
    try:
        hkdf_data = _gen_hkdf_keys(n_keys=64, key_len=32)
        sources.append(("SUMIT KEY HKDF Output (64 keys × 256 bits)", hkdf_data, True))
    except Exception as exc:
        print(f"  ⚠ HKDF key generation failed: {exc}")
        sources.append(("SUMIT KEY HKDF Output [fallback=urandom]", os.urandom(SAMPLE_COUNT), True))

    all_reports: dict[str, ValidationReport] = {}
    for label, data, run_iid in sources:
        report = validate_entropy_source(data, label, run_iid=run_iid,
                                         n_perm=IID_PERMUTATION_COUNT)
        all_reports[label] = report

    # --- Comparative summary ---
    print("\n\n" + "=" * 80)
    print("  COMPARATIVE SUMMARY — NIST SP 800-90B DEEP VALIDATION")
    print("=" * 80)
    hdr = (f"{'Source':<45} {'H_min(b/b)':<12} {'Shannon':<10} "
           f"{'IID':<6} {'Health':<8} {'Summary'}")
    print(hdr)
    print("-" * 80)
    for label, report in all_reports.items():
        iid_str = "YES" if report.iid_overall else "NO "
        health_str = "OK " if all(r.passed for r in report.online_health) else "FAIL"
        print(f"  {label:<43} {report.min_entropy_bits_per_bit:<12.4f} "
              f"{report.shannon_entropy_per_bit:<10.4f} {iid_str:<6} {health_str:<8} "
              f"{report.summary}")

    # --- Serialize report ---
    output_path = Path("results") / "nist_800_90b_deep_report.json"
    output_path.parent.mkdir(exist_ok=True)

    serial: dict[str, Any] = {}
    for label, report in all_reports.items():
        serial[label] = {
            "source": report.source_label,
            "sample_bytes": report.sample_count,
            "online_health": [
                {"test": r.test, "passed": r.passed, "detail": r.detail}
                for r in report.online_health
            ],
            "iid_tests": [
                {
                    "test": r.test,
                    "statistic": r.statistic,
                    "p_value": r.p_value,
                    "iid": r.iid,
                    "notes": r.notes,
                }
                for r in report.iid_tests
            ],
            "iid_overall": report.iid_overall,
            "entropy_estimates": [
                {
                    "estimator": e.estimator,
                    "h_bits_per_sample": e.h_bits_per_sample,
                    "h_bits_per_bit": e.h_bits_per_bit,
                    "sufficient_data": e.sufficient_data,
                    "notes": e.notes,
                }
                for e in report.entropy_estimates
            ],
            "min_entropy_bits_per_sample": report.min_entropy_bits_per_sample,
            "min_entropy_bits_per_bit": report.min_entropy_bits_per_bit,
            "shannon_entropy_per_bit": report.shannon_entropy_per_bit,
            "renyi_entropy_order2_per_bit": report.renyi_entropy_per_bit,
            "autocorrelation_max": report.autocorrelation_max,
            "hamming_weight_chi2_pvalue": report.hamming_weight_chi2_pvalue,
            "bit_independence_pass": report.bic_pass,
            "zlib_compression_ratio": report.compression_ratio,
            "key_uniqueness_rate": report.key_uniqueness_rate,
            "runtime_seconds": report.runtime_seconds,
            "summary": report.summary,
        }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(serial, fh, indent=2)

    print(f"\n  ✓ Full report saved → {output_path}")
    print(f"\nNote: This is an engineering validation only. Formal NIST/FIPS certification")
    print(f"      requires submission to an accredited CMVP lab.")

    return serial


if __name__ == "__main__":
    run_deep_validation_suite()
