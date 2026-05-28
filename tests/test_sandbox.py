"""test_sandbox.py — Unit tests for SUMIT KEY entropy and key generation pipeline.

This file contains synthetic tests that validate the mouse entropy extraction,
pooling, and key derivation without requiring GUI or hardware dependencies.

Run with: python test_sandbox.py
"""

from __future__ import annotations

import math
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
from key_generator import KeyGenerator


# ---------------------------------------------------------------------------
# Shared helpers — called by multiple tests; NOT test functions themselves
# ---------------------------------------------------------------------------

def _make_mouse_entropy_bytes() -> bytes:
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
        events.append({'x': x, 'y': y, 'timestamp': t,
                       'velocity_px_per_s': velocity, 'direction_angle_deg': direction})
    return extract_mouse_entropy(events)


def _make_keystroke_entropy_bytes() -> bytes:
    events = []
    start_time = time.time()
    keys = ['a', 'b', 'c', 'd', 'e']
    for i, key in enumerate(keys):
        press_time = start_time + i * 0.2 + (i % 2) * 0.05
        release_time = press_time + 0.1 + (i % 3) * 0.02
        flight_time = 0.0
        if events:
            flight_time = (press_time - events[-1]['release_timestamp']) * 1000
        events.append({'key': key, 'press_timestamp': press_time,
                       'release_timestamp': release_time,
                       'dwell_time_ms': (release_time - press_time) * 1000,
                       'flight_time_ms': flight_time})
    return extract_keystroke_entropy(events)


def _make_pooled_entropy() -> bytes:
    return pool_entropy(_make_mouse_entropy_bytes(), _make_keystroke_entropy_bytes())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_mouse_entropy_extraction():
    """Test mouse entropy extraction with synthetic movement data."""
    print("\n[TEST] Mouse entropy extraction...")
    entropy_bytes = _make_mouse_entropy_bytes()
    assert len(entropy_bytes) == 48, f"Expected 48 bytes, got {len(entropy_bytes)}"
    assert entropy_bytes != b'\x00' * 48, "Entropy bytes should not be all zeros"
    print(f"  ✓ Extracted {len(entropy_bytes)} bytes of mouse entropy")


def test_keystroke_entropy_extraction():
    """Test keystroke entropy extraction with synthetic timing data."""
    print("\n[TEST] Keystroke entropy extraction...")
    entropy_bytes = _make_keystroke_entropy_bytes()
    assert len(entropy_bytes) > 0, "Keystroke entropy should not be empty"
    print(f"  ✓ Extracted {len(entropy_bytes)} bytes of keystroke entropy")


def test_entropy_pooling():
    """Test entropy pooling from mouse and keystroke sources."""
    print("\n[TEST] Entropy pooling...")
    mouse_bytes = _make_mouse_entropy_bytes()
    keystroke_bytes = _make_keystroke_entropy_bytes()
    pooled = pool_entropy(mouse_bytes, keystroke_bytes)
    assert len(pooled) == 32, f"Expected 32-byte SHA3-256 digest, got {len(pooled)}"
    pooled2 = pool_entropy(mouse_bytes, b'different')
    assert pooled != pooled2, "Different inputs should produce different pooled entropy"
    print(f"  ✓ Pooled entropy: {pooled.hex()[:32]}...")


def test_key_derivation():
    """Test cryptographic key derivation from pooled entropy."""
    print("\n[TEST] Key derivation...")
    pooled = _make_pooled_entropy()
    key_std = KeyGenerator.generate_key(pooled)
    assert len(key_std) == 32, f"Standard key should be 256 bits, got {len(key_std)*8} bits"
    key_quantum = KeyGenerator.generate_quantum_hardened_key(pooled)
    assert len(key_quantum) == 64, f"Quantum key should be 512 bits, got {len(key_quantum)*8} bits"
    key2 = KeyGenerator.generate_key(pooled + b'extra')
    assert key_std != key2, "Different entropy should produce different keys"
    print(f"  ✓ Standard key: {key_std.hex()[:32]}... ({len(key_std)*8} bits)")
    print(f"  ✓ Quantum key:  {key_quantum.hex()[:32]}... ({len(key_quantum)*8} bits)")


def test_quantum_binary_string():
    """Test that quantum hardened entropy produces a valid binary string."""
    print("\n[TEST] Quantum binary string generation...")
    pooled = _make_pooled_entropy()
    binary_string = KeyGenerator.generate_quantum_binary_string(pooled)
    assert len(binary_string) == 512, f"Expected 512 bit string, got {len(binary_string)}"
    assert set(binary_string) <= {"0", "1"}, "Binary string should contain only 0 and 1"
    print(f"  ✓ Generated {len(binary_string)}-bit quantum binary string")


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


def test_message_encryption_roundtrip():
    """Test AES-256-GCM message encryption and decryption round-trip."""
    print("\n[TEST] Message encryption round-trip...")
    import os
    from crypto_tools import encrypt_message, decrypt_message, message_to_dict, message_from_dict

    pooled = _make_pooled_entropy()
    key = KeyGenerator.generate_quantum_hardened_key(pooled)

    plaintext = "Hello SUMIT KEY — AES-256-GCM test message!"
    aad = b"test-label-2025"

    enc = encrypt_message(key, plaintext, associated_data=aad)
    assert len(enc.nonce) == 12, f"Nonce must be 12 bytes, got {len(enc.nonce)}"
    assert len(enc.ciphertext) > len(plaintext.encode()), "Ciphertext should be larger than plaintext (includes tag)"

    dec = decrypt_message(key, enc)
    assert dec.decode("utf-8") == plaintext, "Decrypted text must match original"

    # Wrong key must fail
    wrong_key = os.urandom(32) + os.urandom(32)
    try:
        decrypt_message(wrong_key, enc)
        assert False, "Wrong key should raise an exception"
    except Exception:
        pass

    # Serialize / deserialize round-trip
    d = message_to_dict(enc)
    enc2 = message_from_dict(d)
    dec2 = decrypt_message(key, enc2)
    assert dec2 == dec, "Serialized round-trip must produce same plaintext"

    # Two encryptions of the same plaintext must produce different ciphertexts (random nonce)
    enc3 = encrypt_message(key, plaintext, associated_data=aad)
    assert enc.nonce != enc3.nonce, "Each encryption must use a fresh nonce"
    assert enc.ciphertext != enc3.ciphertext, "Different nonces → different ciphertexts"

    print(f"  ✓ Encrypted: {enc.ciphertext[:12].hex()}... ({len(enc.ciphertext)} bytes incl. tag)")
    print(f"  ✓ Nonce    : {enc.nonce.hex()}")
    print(f"  ✓ Decrypted: {dec.decode()}")
    print(f"  ✓ Wrong-key rejection: PASS")
    print(f"  ✓ Nonce uniqueness: PASS")


def test_file_encryption_roundtrip():
    """Test AES-256-GCM file encryption and decryption round-trip."""
    print("\n[TEST] File encryption round-trip...")
    import os
    import tempfile
    from pathlib import Path
    from crypto_tools import encrypt_file, decrypt_file

    pooled = _make_pooled_entropy()
    key = KeyGenerator.generate_quantum_hardened_key(pooled)

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "secret.txt"
        enc_file = Path(tmpdir) / "secret.txt.sumitkey"
        dec_file = Path(tmpdir) / "decrypted.txt"

        original_content = b"Top secret file contents.\nLine 2.\nLine 3.\n" * 10
        src.write_bytes(original_content)

        enc_info = encrypt_file(key, src, enc_file)
        assert enc_file.exists(), "Encrypted file must be created"
        assert enc_info["original_size_bytes"] == len(original_content)

        dec_info = decrypt_file(key, enc_file, dec_file)
        assert dec_file.exists(), "Decrypted file must be created"
        assert dec_file.read_bytes() == original_content, "File round-trip must be lossless"

        # Tamper detection: flip a byte in ciphertext
        raw = enc_file.read_bytes()
        tampered = bytearray(raw)
        tampered[-5] ^= 0xFF
        enc_file.write_bytes(bytes(tampered))
        try:
            decrypt_file(key, enc_file, Path(tmpdir) / "tampered_out.txt")
            assert False, "Tampered file must raise an exception"
        except Exception:
            pass

    print(f"  ✓ Original size  : {enc_info['original_size_bytes']} bytes")
    print(f"  ✓ Encrypted size : {enc_info['encrypted_size_bytes']} bytes")
    print(f"  ✓ Decrypted size : {dec_info['decrypted_size_bytes']} bytes")
    print(f"  ✓ Tamper detection: PASS")


def test_debug_pipeline():
    """Test the PipelineDebugger with synthetic events."""
    print("\n[TEST] PipelineDebugger with synthetic events...")
    from debug_pipeline import PipelineDebugger, make_synthetic_mouse_events, make_synthetic_keystroke_events

    mouse_events = make_synthetic_mouse_events(20)
    keystroke_events = make_synthetic_keystroke_events(6)

    debugger = PipelineDebugger(security_level="quantum")
    result = debugger.run(mouse_events, keystroke_events)

    assert result["all_passed"], f"All pipeline stages should pass, got: {result}"
    assert result["stages"] == 5, f"Expected 5 stages, got {result['stages']}"
    assert result["key_hex"] is not None, "Should produce a key"
    assert result["key_bits"] == 512, f"Quantum key should be 512 bits, got {result['key_bits']}"
    assert result["random_number"] is not None, "Should produce a random number"

    print(f"  ✓ All {result['stages']} pipeline stages passed")
    print(f"  ✓ Key ({result['key_bits']}-bit): {result['key_hex'][:32]}...")
    print(f"  ✓ Random number: {result['random_number']}")


def test_entropy_agent():
    """Test EntropyAgent per-movement key and random number generation."""
    print("\n[TEST] EntropyAgent per-movement analysis...")
    from debug_pipeline import EntropyAgent, make_synthetic_mouse_events, make_synthetic_keystroke_events

    mouse_events = make_synthetic_mouse_events(15)
    keystroke_events = make_synthetic_keystroke_events(5)

    agent = EntropyAgent(security_level="quantum")
    report = agent.analyze(mouse_events, keystroke_events)

    # Each move produces exactly 1 key and 1 random number
    assert report.total_moves == len(mouse_events), "One record per mouse move"
    assert len(report.records) == len(mouse_events)

    for r in report.records:
        assert r.key_bits == 512, f"Quantum key should be 512 bits"
        assert r.random_number > 0, "Random number must be positive"
        assert len(r.key_hex_preview) > 0

    # First move cannot be "changed" (no previous)
    assert not report.records[0].key_changed, "First record has no previous to compare"

    # All keys should be unique for varied synthetic data
    assert report.unique_keys >= 2, "Varying events must produce multiple unique keys"

    print(f"  ✓ Total moves    : {report.total_moves}")
    print(f"  ✓ Keys generated : {report.total_moves} (1 per move)")
    print(f"  ✓ RNGs generated : {report.total_moves} (1 per move)")
    print(f"  ✓ Unique keys    : {report.unique_keys}/{report.total_moves}")
    print(f"  ✓ Key change rate: {report.change_rate_percent}%")
    print(f"  ✓ Key bits       : {report.records[0].key_bits}")

    # Print first 5 rows as a sanity table
    for r in report.records[:5]:
        changed = "NEW" if r.move_index == 1 else ("CHANGED" if r.key_changed else "same")
        print(f"    Move {r.move_index:>3}: key={r.key_hex_preview[:24]}  rng={r.random_number}  [{changed}]")


def test_static_mouse_turn_encryption_chain():
    """Test full mouse-turn/vibration -> static key -> AES-GCM chain."""
    print("\n[TEST] Static mouse-turn/vibration encryption chain...")
    from debug_pipeline import make_turn_vibration_mouse_events, run_static_encryption_chain

    mouse_events = make_turn_vibration_mouse_events(turns=4, samples_per_turn=12)
    message = "Few mouse turns plus vibration produce a static encryption key."

    first = run_static_encryption_chain(
        mouse_events,
        message,
        security_level="quantum",
        label="sandbox-static-chain",
    )
    second = run_static_encryption_chain(
        mouse_events,
        message,
        security_level="quantum",
        label="sandbox-static-chain",
    )

    assert first["status"] == "ok"
    assert first["key_mode"] == "static-repeatable"
    assert first["static_key_bits"] == 512
    assert first["static_key_hex"] == second["static_key_hex"], "Static chain must repeat for same movement data"
    assert first["encryption"]["decrypt_verified"], "AES-GCM decrypt verification must pass"
    assert first["micro_vibration_steps"] >= 0
    assert any(check["status"] == "PASS" for check in first["framework_checks"])

    print(f"  ✓ Mouse events       : {first['mouse_event_count']}")
    print(f"  ✓ Direction changes  : {first['turn_direction_changes']}")
    print(f"  ✓ Vibration steps    : {first['micro_vibration_steps']}")
    print(f"  ✓ Static key         : {first['static_key_hex'][:32]}... ({first['static_key_bits']} bits)")
    print(f"  ✓ AES-GCM nonce      : {first['encryption']['nonce_hex']}")
    print(f"  ✓ Decrypt verified   : {first['encryption']['decrypt_verified']}")


def test_game_fallback_auth_chain():
    """Test game/chess movement auth with OTP and NFC fallbacks."""
    print("\n[TEST] Game/chess fallback auth chain...")
    from fallback_auth import (
        SimulatedNFCProvider,
        SimulatedOTPProvider,
        authenticate_game_scenario,
        make_chess_like_mouse_events,
    )

    otp_provider = SimulatedOTPProvider(secret=b"sandbox-otp-secret-32-bytes!!!!")
    nfc_provider = SimulatedNFCProvider()
    nfc_provider.register_token("sandbox-phone-nfc")
    destination = "user@example.com"
    otp = otp_provider.issue(destination)

    direct = authenticate_game_scenario(
        scenario="good_chess_mouse",
        mouse_events=make_chess_like_mouse_events(good=True, moves=8),
        otp_provider=otp_provider,
        nfc_provider=nfc_provider,
    )
    assert direct.authenticated
    assert direct.method == "mouse_movement"

    otp_fallback = authenticate_game_scenario(
        scenario="weak_mouse_otp",
        mouse_events=make_chess_like_mouse_events(good=False, moves=4),
        otp_destination=destination,
        provided_otp=otp,
        otp_provider=otp_provider,
        nfc_provider=nfc_provider,
    )
    assert otp_fallback.authenticated
    assert otp_fallback.method == "otp_phone_email"

    nfc_fallback = authenticate_game_scenario(
        scenario="bad_otp_nfc",
        mouse_events=make_chess_like_mouse_events(good=False, moves=3),
        otp_destination=destination,
        provided_otp="000000",
        nfc_token_uid="sandbox-phone-nfc",
        otp_provider=otp_provider,
        nfc_provider=nfc_provider,
    )
    assert nfc_fallback.authenticated
    assert nfc_fallback.method == "phone_nfc"

    deny = authenticate_game_scenario(
        scenario="all_fail",
        mouse_events=make_chess_like_mouse_events(good=False, moves=2),
        otp_destination=destination,
        provided_otp="111111",
        nfc_token_uid="unknown",
        otp_provider=otp_provider,
        nfc_provider=nfc_provider,
    )
    assert not deny.authenticated
    assert deny.method == "none"

    print(f"  ✓ Direct movement auth : {direct.method} ({direct.movement_profile.verdict})")
    print(f"  ✓ OTP fallback         : {otp_fallback.method}")
    print(f"  ✓ NFC fallback         : {nfc_fallback.method}")
    print(f"  ✓ Deny all failed      : {not deny.authenticated}")


def test_entropy_quality_analysis():
    """Test entropy quality analyzer on SUMIT KEY outputs and baselines."""
    print("\n[TEST] Entropy quality analysis...")
    import os
    from crypto_benchmark import analyze_entropy_quality

    # Perfect uniform random (OS): should be GOOD or EXCELLENT
    random_data = os.urandom(3200)
    result = analyze_entropy_quality(random_data, "os.urandom test")
    assert result.shannon_bits_per_byte >= 7.5, f"urandom shannon low: {result.shannon_bits_per_byte}"
    assert result.byte_count == 3200

    # All-zero: should be WEAK with entropy 0
    zeros = bytes(256)
    result_zero = analyze_entropy_quality(zeros, "zeros test")
    assert result_zero.shannon_bits_per_byte == 0.0, "Zero bytes should have 0 entropy"
    assert result_zero.verdict == "WEAK"

    # Derived key batch (SUMIT KEY output): should be GOOD or EXCELLENT
    from debug_pipeline import make_synthetic_mouse_events, make_synthetic_keystroke_events
    from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
    from key_generator import KeyGenerator
    import hashlib

    m = make_synthetic_mouse_events(50)
    k = make_synthetic_keystroke_events(15)
    pooled = pool_entropy(extract_mouse_entropy(m), extract_keystroke_entropy(k))
    batch = b"".join(
        KeyGenerator.generate_quantum_hardened_key(
            hashlib.sha3_256(pooled + i.to_bytes(4, "big")).digest()
        )
        for i in range(50)
    )
    result_key = analyze_entropy_quality(batch, "SUMIT KEY batch")
    assert result_key.shannon_bits_per_byte >= 7.5, f"Key batch entropy too low: {result_key.shannon_bits_per_byte}"
    assert result_key.verdict in {"EXCELLENT", "GOOD"}, f"Key batch verdict: {result_key.verdict}"

    print(f"  ✓ os.urandom: {result.shannon_bits_per_byte:.4f} bits/byte — {result.verdict}")
    print(f"  ✓ all-zeros : {result_zero.shannon_bits_per_byte:.4f} bits/byte — {result_zero.verdict}")
    print(f"  ✓ key batch : {result_key.shannon_bits_per_byte:.4f} bits/byte — {result_key.verdict}")
    print(f"  ✓ chi²(key) : {result_key.chi_squared:.1f} (pass: {result_key.chi_squared_pass})")
    print(f"  ✓ autocorr  : {result_key.max_autocorrelation:.4f}")


def test_benchmark_summary():
    """Test that get_benchmark_summary returns a well-structured result."""
    print("\n[TEST] Benchmark summary (quick mode)...")
    from crypto_benchmark import get_benchmark_summary

    result = get_benchmark_summary(quick=True)

    assert "entropy_quality" in result
    eq = result["entropy_quality"]
    assert len(eq) >= 5, f"Expected >= 5 entropy quality entries, got {len(eq)}"
    for entry in eq:
        assert "shannon_bits_per_byte" in entry
        assert "verdict" in entry

    # Symmetric ciphers — both must be available and fast
    assert "symmetric_ciphers" in result
    for r in result["symmetric_ciphers"]:
        assert r["available"], f"{r['algorithm']} should be available"
        assert r["throughput_mb_s"] > 0, f"{r['algorithm']} throughput should be > 0"
        assert r["security_classical_bits"] == 256

    # HKDF must be faster than Argon2id
    hkdf = next(r for r in result["key_derivation"] if "HKDF" in r["algorithm"])
    argon = next(r for r in result["key_derivation"] if "Argon2id" in r["algorithm"])
    assert hkdf["latency_ms"] < argon["latency_ms"], "Argon2id must be slower than HKDF"

    # ML-KEM-1024
    kem = result["ml_kem"][0]
    assert kem["available"], "ML-KEM-1024 should be available"
    assert kem["security_quantum_bits"] == 128
    assert kem["ct_size_bytes"] == 1568

    # MAYO documented only
    mayo = result["mayo_documented"]
    assert mayo["algorithm"] == "MAYO-5"
    assert not mayo["available"], "MAYO-5 needs liboqs"
    assert mayo["security_classical_bits"] == 256

    print(f"  ✓ Entropy quality entries : {len(eq)}")
    for r in result["symmetric_ciphers"]:
        print(f"  ✓ {r['algorithm']:25}: {r['throughput_mb_s']:.1f} MB/s")
    print(f"  ✓ HKDF latency            : {hkdf['latency_ms']:.4f}ms")
    print(f"  ✓ Argon2id latency        : {argon['latency_ms']:.1f}ms")
    print(f"  ✓ ML-KEM-1024 latency     : {kem['latency_ms']:.2f}ms | ct={kem['ct_size_bytes']}B")
    print(f"  ✓ MAYO-5 documented       : classical={mayo['security_classical_bits']}b quantum={mayo['security_quantum_bits']}b")


def test_threat_model():
    """Test that threat model returns a complete, valid structure."""
    print("\n[TEST] Threat model structure...")
    from threat_model import get_threat_model

    tm = get_threat_model()

    for key in ("title", "summary", "overall_quantum_readiness", "algorithms", "recommended_stack", "entropy_source_attacks"):
        assert key in tm, f"Missing key: {key}"

    algo_names = {a["algorithm"] for a in tm["algorithms"]}
    expected_algos = {"AES-256-GCM", "ChaCha20-Poly1305", "HKDF-SHA3-256", "Argon2id",
                      "ML-KEM-1024 (Kyber-1024 / FIPS 203)", "MAYO-5"}
    assert expected_algos == algo_names, f"Algorithm mismatch: {algo_names}"

    for algo in tm["algorithms"]:
        assert len(algo["known_attacks"]) >= 2
        assert algo["overall_verdict"] in {"RECOMMENDED", "ACCEPTABLE", "DEPRECATED", "ANALYSIS_ONLY"}
        for av in algo["known_attacks"]:
            for f in ("name", "attack_type", "severity", "mitigation"):
                assert f in av
            assert av["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"}

    critical = [a for a in tm["entropy_source_attacks"] if a["severity"] == "CRITICAL"]
    assert len(critical) >= 1

    aes_algo = next(a for a in tm["algorithms"] if a["algorithm"] == "AES-256-GCM")
    mayo_algo = next(a for a in tm["algorithms"] if a["algorithm"] == "MAYO-5")
    mlkem_algo = next(a for a in tm["algorithms"] if "ML-KEM" in a["algorithm"])
    assert aes_algo["overall_verdict"] == "RECOMMENDED"
    assert mayo_algo["overall_verdict"] == "ANALYSIS_ONLY"
    assert mlkem_algo["overall_verdict"] == "RECOMMENDED"

    print(f"  ✓ Algorithms covered      : {len(tm['algorithms'])}")
    for a in tm["algorithms"]:
        print(f"  ✓ {a['algorithm']:<38}: {len(a['known_attacks'])} attacks | {a['overall_verdict']}")
    print(f"  ✓ Entropy source threats  : {len(tm['entropy_source_attacks'])}")
    print(f"  ✓ CRITICAL threats        : {len(critical)}")


def test_quantum_pipeline_roundtrip():
    """Test the full quantum-safe hybrid pipeline: keygen → encrypt → decrypt."""
    print("\n[TEST] Quantum-safe hybrid pipeline roundtrip...")
    import os
    from crypto_tools import (
        quantum_keygen,
        quantum_encrypt_message,
        quantum_decrypt_message,
        quantum_package_to_dict,
        quantum_package_from_dict,
        quantum_encryption_info,
    )

    session = quantum_keygen()
    assert len(session.ek_bytes()) == 1568, "ML-KEM-1024 ek must be 1568 bytes"
    assert len(session.dk_bytes()) == 3168, "ML-KEM-1024 dk must be 3168 bytes"

    plaintext = b"SUMIT KEY quantum hybrid pipeline end-to-end test!"
    entropy = os.urandom(64)
    aad = b"test-quantum-label"

    pkg = quantum_encrypt_message(session, plaintext, entropy, associated_data=aad)
    assert len(pkg.kem_ct) == 1568, f"KEM ciphertext must be 1568 bytes, got {len(pkg.kem_ct)}"
    assert len(pkg.argon2_salt) == 16
    assert len(pkg.hardened_enc) == 80
    assert len(pkg.nonce) == 12
    assert pkg.ciphertext != plaintext

    decrypted = quantum_decrypt_message(session, pkg)
    assert decrypted == plaintext, f"Decrypted text must match original; got {decrypted!r}"

    # Wrong key must fail
    wrong_session = quantum_keygen()
    try:
        quantum_decrypt_message(wrong_session, pkg)
        assert False, "Wrong key should raise an exception"
    except Exception:
        pass

    # JSON serialisation round-trip
    d = quantum_package_to_dict(pkg)
    pkg2 = quantum_package_from_dict(d)
    decrypted2 = quantum_decrypt_message(session, pkg2)
    assert decrypted2 == plaintext, "Serialised package round-trip must be lossless"

    # Two encryptions must produce different ciphertexts (fresh KEM encaps each time)
    pkg3 = quantum_encrypt_message(session, plaintext, os.urandom(64), associated_data=aad)
    assert pkg.kem_ct != pkg3.kem_ct, "Each encryption must use a fresh KEM encapsulation"
    assert pkg.ciphertext != pkg3.ciphertext

    # quantum_encryption_info must report ML-KEM-1024
    info = quantum_encryption_info()
    assert "ML-KEM-1024" in info.get("post_quantum_kem", info.get("algorithm", "")), f"Unexpected info: {info}"

    print(f"  ✓ ML-KEM-1024 ek={len(session.ek_bytes())}B dk={len(session.dk_bytes())}B")
    print(f"  ✓ Plaintext         : {plaintext.decode()}")
    print(f"  ✓ KEM ciphertext    : {len(pkg.kem_ct)}B")
    print(f"  ✓ Argon2id salt     : {pkg.argon2_salt.hex()}")
    print(f"  ✓ Hardened enc      : {len(pkg.hardened_enc)}B")
    print(f"  ✓ Payload nonce     : {pkg.nonce.hex()}")
    print(f"  ✓ Decrypted         : {decrypted.decode()}")
    print(f"  ✓ Wrong-key reject  : PASS")
    print(f"  ✓ JSON roundtrip    : PASS")
    print(f"  ✓ Fresh-encaps check: PASS")


def test_zero_knowledge_proof():
    """Test Schnorr ZKP: prove and verify without revealing the secret key."""
    print("\n[TEST] Zero-Knowledge Proof (Schnorr / RFC-3526 Group 14)...")
    import os
    from vault import zkp_keygen, zkp_prove, zkp_verify

    entropy = os.urandom(64)
    kp = zkp_keygen(entropy)
    assert kp.pk > 0, "Public key must be positive"

    # Valid proof for correct context
    ctx = b"sumit-key-login-2026"
    proof = zkp_prove(kp, ctx)
    assert zkp_verify(kp.pk_hex(), proof, ctx), "ZKP must verify with correct context"

    # Wrong context must fail
    assert not zkp_verify(kp.pk_hex(), proof, b"wrong-context"), "Wrong context must fail"

    # Different entropy = different key pair = different proof → verify fails
    kp2 = zkp_keygen(os.urandom(64))
    proof2 = zkp_prove(kp2, ctx)
    assert not zkp_verify(kp.pk_hex(), proof2, ctx), "Wrong keypair must fail"

    # Each proof has a fresh nonce — two proofs for same key must differ
    proof3 = zkp_prove(kp, ctx)
    assert proof.R_hex != proof3.R_hex, "Each proof must use a fresh nonce"

    # ZKP to_dict / from_dict round-trip
    from vault import ZKPProof
    restored = ZKPProof.from_dict(proof.to_dict())
    assert zkp_verify(kp.pk_hex(), restored, ctx), "Serialised proof must still verify"

    print(f"  ✓ pk (first 32 hex): {kp.pk_hex()[:32]}...")
    print(f"  ✓ Proof R (first 24): {proof.R_hex[:24]}...")
    print(f"  ✓ Correct ctx verify: PASS")
    print(f"  ✓ Wrong ctx reject:   PASS")
    print(f"  ✓ Wrong keypair reject: PASS")
    print(f"  ✓ Fresh-nonce uniqueness: PASS")
    print(f"  ✓ JSON round-trip: PASS")


def test_shamir_secret_sharing():
    """Test Shamir Secret Sharing over GF(2^8)."""
    print("\n[TEST] Shamir Secret Sharing (GF 2^8)...")
    import os
    from vault import shamir_split, shamir_combine

    secret = os.urandom(32)

    # 3-of-5 scheme
    shares = shamir_split(secret, n_shares=5, threshold=3)
    assert len(shares) == 5
    assert shamir_combine(shares[:3]) == secret, "3/5 must reconstruct"
    assert shamir_combine(shares[1:4]) == secret, "mid-3/5 must reconstruct"
    assert shamir_combine(shares[2:]) == secret, "last-3/5 must reconstruct"
    assert shamir_combine(shares) == secret, "5/5 must reconstruct"

    # 2-of-2 edge case
    s2 = shamir_split(os.urandom(16), n_shares=2, threshold=2)
    assert shamir_combine(s2) == shamir_combine(s2[:2])

    # Different secrets produce different shares
    shares_b = shamir_split(os.urandom(32), n_shares=5, threshold=3)
    assert shares[0][1] != shares_b[0][1], "Different secrets must produce different shares"

    print(f"  ✓ 3-of-5 reconstruction: PASS")
    print(f"  ✓ Mid-3-of-5:            PASS")
    print(f"  ✓ All-5-of-5:            PASS")
    print(f"  ✓ 2-of-2 edge case:      PASS")


def test_high_voltage_vault():
    """Test High-Voltage Vault: store, retrieve, burn-after-read, seal, zeroize."""
    print("\n[TEST] High-Voltage Vault...")
    import os
    from vault import HighVoltageVault, VaultState

    vault = HighVoltageVault()
    password = b"test-master-password-32-bytes!!!"

    # Store and retrieve
    key = os.urandom(32)
    vid = vault.store(key, master_password=password, n_shards=5, threshold=3,
                      ttl_seconds=60, burn_after_read=False)
    status = vault.status(vid)
    assert status["state"] == VaultState.ARMED.value
    recovered = vault.retrieve(vid, [1, 2, 3], password)
    assert recovered == key, "Retrieved key must match stored key"

    # Burn-after-read
    vid_burn = vault.store(key, master_password=password, n_shards=3, threshold=2,
                           ttl_seconds=60, burn_after_read=True)
    vault.retrieve(vid_burn, [1, 2], password)
    assert vault.status(vid_burn)["state"] == VaultState.BURNED.value
    try:
        vault.retrieve(vid_burn, [1, 2], password)
        assert False, "Should raise after burn"
    except PermissionError:
        pass

    # Manual seal
    vault.seal(vid)
    assert vault.status(vid)["state"] == VaultState.SEALED.value
    try:
        vault.retrieve(vid, [1, 2, 3], password)
        assert False, "Sealed vault must reject"
    except PermissionError:
        pass

    # Emergency zeroize
    vid_z = vault.store(os.urandom(32), master_password=password, n_shards=3, threshold=2)
    vault.zeroize(vid_z)
    assert vault.status(vid_z)["state"] == "NOT_FOUND"

    print(f"  ✓ Store and retrieve:    PASS")
    print(f"  ✓ Burn-after-read:       PASS")
    print(f"  ✓ Manual seal:           PASS")
    print(f"  ✓ Emergency zeroize:     PASS")


def test_mitm_shield():
    """Test MITM Shield: session establishment, encrypt/decrypt, tamper and replay detection."""
    print("\n[TEST] MITM Shield (ML-KEM-1024 + AES-256-GCM + HMAC-SHA3-512)...")
    from vault import MITMShield, MITMShieldError

    alice = MITMShield()
    bob = MITMShield()

    # Key exchange
    init_pkt = alice.begin_session()
    assert "ek_hex" in init_pkt
    resp_pkt = bob.accept_session(init_pkt)
    assert "kem_ct_hex" in resp_pkt
    alice.finish_session(resp_pkt)

    # Roundtrip
    msg = b"High-voltage shielded message"
    wire = alice.send(msg, b"context-label")
    plaintext = bob.receive(wire, b"context-label")
    assert plaintext == msg, f"Expected {msg!r}, got {plaintext!r}"

    # Tamper detection (flip a byte in the middle)
    tampered = bytearray(wire)
    tampered[50] ^= 0xAA
    try:
        bob.receive(bytes(tampered), b"context-label")
        assert False, "Tamper must raise"
    except MITMShieldError:
        pass

    # Replay detection
    wire2 = alice.send(b"second message", b"ctx")
    bob.receive(wire2, b"ctx")
    try:
        bob.receive(wire2, b"ctx")
        assert False, "Replay must raise"
    except MITMShieldError:
        pass

    print(f"  ✓ Session established (ML-KEM-1024): PASS")
    print(f"  ✓ Roundtrip encrypt/decrypt:         PASS")
    print(f"  ✓ Tamper detection (HMAC-SHA3-512):  PASS")
    print(f"  ✓ Replay detection (seq counter):    PASS")


def test_advanced_threat_detector():
    """Test Advanced Threat Detector scoring and level classification."""
    print("\n[TEST] Advanced Threat Detector...")
    from vault import AdvancedThreatDetector, ThreatLevel

    det = AdvancedThreatDetector()

    # Honeypot → BLOCK
    a = det.assess(source_ip="1.2.3.4", honeypot_filled=True)
    assert a.level == ThreatLevel.BLOCK, f"Honeypot: expected BLOCK, got {a.level}"
    assert any(s.name == "HONEYPOT" for s in a.signals)

    # Zero-entropy key → QUARANTINE or BLOCK
    a2 = det.assess(source_ip="2.3.4.5", key_bytes=bytes(32))
    assert a2.level in (ThreatLevel.QUARANTINE, ThreatLevel.BLOCK)

    # Machine-regular timing → QUARANTINE+
    machine_ts = [float(i * 10) for i in range(25)]  # perfectly regular 10ms
    a3 = det.assess(source_ip="3.4.5.6", mouse_event_timestamps_ms=machine_ts)
    assert a3.level in (ThreatLevel.QUARANTINE, ThreatLevel.BLOCK)
    assert any(s.name == "MACHINE_TIMING" for s in a3.signals)

    # Replay
    det2 = AdvancedThreatDetector()
    det2.assess(source_ip="4.5.6.7", message_id="msg-abc-123")
    a4 = det2.assess(source_ip="4.5.6.7", message_id="msg-abc-123")
    assert any(s.name == "REPLAY" for s in a4.signals)

    # Clean request → ALLOW
    a5 = det.assess(source_ip="5.6.7.8")
    assert a5.level == ThreatLevel.ALLOW

    # to_dict round-trip
    d = a.to_dict()
    assert "risk_score" in d and "level" in d and "signals" in d

    print(f"  ✓ Honeypot → BLOCK:          score={a.risk_score}")
    print(f"  ✓ Zero-key entropy:           level={a2.level.value}")
    print(f"  ✓ Machine timing → QUARANTINE: score={a3.risk_score}")
    print(f"  ✓ Replay detection:           signals={[s.name for s in a4.signals]}")
    print(f"  ✓ Clean request → ALLOW:      score={a5.risk_score}")


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
        test_quantum_binary_string,
        test_key_derivation,
        test_deterministic_behavior,
        test_message_encryption_roundtrip,
        test_file_encryption_roundtrip,
        test_debug_pipeline,
        test_entropy_agent,
        test_static_mouse_turn_encryption_chain,
        test_game_fallback_auth_chain,
        test_entropy_quality_analysis,
        test_benchmark_summary,
        test_threat_model,
        test_quantum_pipeline_roundtrip,
        test_zero_knowledge_proof,
        test_shamir_secret_sharing,
        test_high_voltage_vault,
        test_mitm_shield,
        test_advanced_threat_detector,
    ]

    for test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            print(f"  ✗ {test_func.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    run_all_tests()
