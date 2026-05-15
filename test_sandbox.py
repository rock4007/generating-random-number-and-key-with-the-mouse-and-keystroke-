"""test_sandbox.py — Unit tests for SUMIT KEY entropy and key generation pipeline.

This file contains synthetic tests that validate the mouse entropy extraction,
pooling, and key derivation without requiring GUI or hardware dependencies.

Run with: python test_sandbox.py
"""

from __future__ import annotations

import math
import time
from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
from key_generator import KeyGenerator


def test_mouse_entropy_extraction():
    """Test mouse entropy extraction with synthetic movement data."""
    print("\n[TEST] Mouse entropy extraction...")

    # Generate synthetic mouse events with varying velocity and direction
    events = []
    start_time = time.time()
    for i in range(20):
        x = 100 + i * 5 + math.sin(i * 0.5) * 10
        y = 200 + i * 3 + math.cos(i * 0.3) * 8
        t = start_time + i * 0.1

        velocity = 0.0
        direction = 0.0
        if events:
            prev = events[-1]
            dx = x - prev['x']
            dy = y - prev['y']
            dt = t - prev['timestamp']
            if dt > 0:
                velocity = math.sqrt(dx*dx + dy*dy) / dt
                direction = math.degrees(math.atan2(dy, dx))

        events.append({
            'x': x,
            'y': y,
            'timestamp': t,
            'velocity_px_per_s': velocity,
            'direction_angle_deg': direction,
        })

    entropy_bytes = extract_mouse_entropy(events)
    assert len(entropy_bytes) == 44, f"Expected 44 bytes, got {len(entropy_bytes)}"
    assert entropy_bytes != b'\x00' * 44, "Entropy bytes should not be all zeros"

    print(f"  ✓ Extracted {len(entropy_bytes)} bytes of mouse entropy")
    return entropy_bytes


def test_keystroke_entropy_extraction():
    """Test keystroke entropy extraction with synthetic timing data."""
    print("\n[TEST] Keystroke entropy extraction...")

    # Generate synthetic keystroke events with varying dwell/flight times
    events = []
    start_time = time.time()
    keys = ['a', 'b', 'c', 'd', 'e']
    for i, key in enumerate(keys):
        press_time = start_time + i * 0.2 + (i % 2) * 0.05
        release_time = press_time + 0.1 + (i % 3) * 0.02

        flight_time = 0.0
        if events:
            flight_time = (press_time - events[-1]['release_timestamp']) * 1000

        events.append({
            'key': key,
            'press_timestamp': press_time,
            'release_timestamp': release_time,
            'dwell_time_ms': (release_time - press_time) * 1000,
            'flight_time_ms': flight_time,
        })

    entropy_bytes = extract_keystroke_entropy(events)
    assert len(entropy_bytes) > 0, "Keystroke entropy should not be empty"
    assert entropy_bytes != b'', "Entropy bytes should not be empty"

    print(f"  ✓ Extracted {len(entropy_bytes)} bytes of keystroke entropy")
    return entropy_bytes


def test_entropy_pooling():
    """Test entropy pooling from mouse and keystroke sources."""
    print("\n[TEST] Entropy pooling...")

    mouse_bytes = test_mouse_entropy_extraction()
    keystroke_bytes = test_keystroke_entropy_extraction()

    pooled = pool_entropy(mouse_bytes, keystroke_bytes)
    assert len(pooled) == 32, f"Expected 32-byte SHA3-256 digest, got {len(pooled)}"

    # Test that different inputs produce different outputs
    pooled2 = pool_entropy(mouse_bytes, b'different')
    assert pooled != pooled2, "Different inputs should produce different pooled entropy"

    print(f"  ✓ Pooled entropy: {pooled.hex()[:32]}...")
    return pooled


def test_key_derivation():
    """Test cryptographic key derivation from pooled entropy."""
    print("\n[TEST] Key derivation...")

    pooled = test_entropy_pooling()

    # Test standard key
    key_std = KeyGenerator.generate_key(pooled)
    assert len(key_std) == 32, f"Standard key should be 256 bits, got {len(key_std)*8} bits"

    # Test quantum-hardened key
    key_quantum = KeyGenerator.generate_quantum_hardened_key(pooled)
    assert len(key_quantum) == 64, f"Quantum key should be 512 bits, got {len(key_quantum)*8} bits"

    # Test that different entropy produces different keys
    key2 = KeyGenerator.generate_key(pooled + b'extra')
    assert key_std != key2, "Different entropy should produce different keys"

    print(f"  ✓ Standard key: {key_std.hex()[:32]}... ({len(key_std)*8} bits)")
    print(f"  ✓ Quantum key: {key_quantum.hex()[:32]}... ({len(key_quantum)*8} bits)")
    return key_std, key_quantum


def test_deterministic_behavior():
    """Test that the same input produces the same output (deterministic)."""
    print("\n[TEST] Deterministic behavior...")

    # Same synthetic data twice
    events = []
    start_time = time.time()
    for i in range(10):
        x = 100 + i * 2
        y = 200 + i * 1
        t = start_time + i * 0.1
        events.append({
            'x': x,
            'y': y,
            'timestamp': t,
            'velocity_px_per_s': 10.0 + i,
            'direction_angle_deg': 45.0 + i * 5,
        })

    entropy1 = extract_mouse_entropy(events)
    entropy2 = extract_mouse_entropy(events)
    assert entropy1 == entropy2, "Same input should produce same entropy"

    pooled1 = pool_entropy(entropy1, b'')
    pooled2 = pool_entropy(entropy2, b'')
    assert pooled1 == pooled2, "Same entropy should produce same pooled output"

    key1 = KeyGenerator.generate_key(pooled1)
    key2 = KeyGenerator.generate_key(pooled2)
    assert key1 == key2, "Same pooled entropy should produce same key"

    print("  ✓ Pipeline produces deterministic results")


def run_all_tests():
    """Run all sandbox tests."""
    print("=" * 60)
    print("  SUMIT KEY Test Sandbox")
    print("=" * 60)

    passed = 0
    failed = 0

    tests = [
        test_mouse_entropy_extraction,
        test_keystroke_entropy_extraction,
        test_entropy_pooling,
        test_key_derivation,
        test_deterministic_behavior,
    ]

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"  ✗ {test_func.__name__} failed: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    run_all_tests()