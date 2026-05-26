"""debug_pipeline.py — Stage-by-stage diagnostic tracer for SUMIT KEY.

Answers two key questions:
  1. Exactly what happens at each pipeline stage (capture → entropy → key)?
  2. Per single mouse movement: how many keys and random numbers are generated,
     how much does each move change the output?

Usage:
  python debug_pipeline.py                        # synthetic events, full trace
  python debug_pipeline.py --live 5              # 5-second live capture + trace
  python debug_pipeline.py --per-move-live 5     # per-move live analysis

Classes:
  EntropyAgent       — monitors per-movement key/RNG generation
  PipelineDebugger   — wraps the full pipeline with step-by-step tracing
"""

from __future__ import annotations

import hashlib
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any

from crypto_tools import decrypt_message, encrypt_message, message_to_dict
from entropy_engine import extract_keystroke_entropy, extract_mouse_entropy, pool_entropy
from key_generator import EntropyHealthError, HKDFConfig, KeyGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _estimate_entropy_bits(data: bytes) -> float:
    """Shannon entropy estimate in bits for the byte distribution of `data`."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy * total  # total bits of entropy


def _hex_preview(data: bytes, n: int = 16) -> str:
    """Show first n bytes as hex + ellipsis if truncated."""
    preview = data[:n].hex()
    return preview + ("..." if len(data) > n else "")


def _derive_random_number(key_bytes: bytes) -> int:
    """Domain-separated 64-bit random number from key bytes."""
    digest = hashlib.sha3_256(bytes(key_bytes) + b"|SUMIT_KEY_RANDOM_NUMBER|").digest()
    return int.from_bytes(digest[:8], "big")


# ---------------------------------------------------------------------------
# Stage trace result
# ---------------------------------------------------------------------------

@dataclass
class StageTrace:
    stage: str
    ok: bool
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def print(self) -> None:
        status = "PASS" if self.ok else "FAIL"
        print(f"\n  [{status}] Stage: {self.stage}")
        for k, v in self.details.items():
            print(f"        {k}: {v}")
        if self.error:
            print(f"        ERROR: {self.error}")


# ---------------------------------------------------------------------------
# Per-move record
# ---------------------------------------------------------------------------

@dataclass
class PerMoveRecord:
    move_index: int
    timestamp: float
    x: float
    y: float
    velocity_px_per_s: float
    direction_deg: float
    entropy_bytes_hex: str          # pooled entropy hex preview
    entropy_bits_estimate: float
    key_hex_preview: str            # first 16 bytes
    key_bits: int
    random_number: int
    key_changed: bool               # compared to previous move
    random_changed: bool


@dataclass(frozen=True)
class FrameworkCheck:
    """One security-framework check in the full chain report."""

    framework: str
    requirement: str
    status: str
    evidence: str


# ---------------------------------------------------------------------------
# EntropyAgent — answers "per one mouse movement, how many keys and RNGs?"
# ---------------------------------------------------------------------------

class EntropyAgent:
    """Analyzes key and random number generation per mouse movement.

    For every movement prefix [0..idx], derives one key and one random number.
    Tracks changes, uniqueness, and accumulation rate.
    """

    def __init__(self, security_level: str = "quantum", key_mode: str = "static") -> None:
        self.security_level = security_level
        self.key_mode = key_mode
        self.records: list[PerMoveRecord] = []

    def _derive_key_for_move(self, combined: bytes, idx: int) -> bytes:
        """Derive either a repeatable static key or a fresh production key."""

        if self.key_mode not in {"static", "fresh"}:
            raise ValueError("key_mode must be 'static' or 'fresh'")

        if self.key_mode == "fresh":
            personalization = f"entropy-agent:{idx}".encode("utf-8")
            if self.security_level == "quantum":
                return KeyGenerator.generate_fresh_quantum_hardened_key(
                    combined,
                    personalization=personalization,
                )
            return KeyGenerator.generate_fresh_key(
                combined,
                personalization=personalization,
            )

        if self.security_level == "quantum":
            return KeyGenerator.generate_quantum_hardened_key(combined)
        return KeyGenerator.generate_key(combined)

    def analyze(
        self,
        mouse_events: list[dict[str, Any]],
        keystroke_events: list[dict[str, Any]] | None = None,
    ) -> "EntropyAgentReport":
        """Run per-move analysis on a captured event list."""
        if keystroke_events is None:
            keystroke_events = []

        self.records = []
        prev_key: bytes | None = None
        prev_rng: int | None = None

        for idx, move in enumerate(mouse_events, start=1):
            mouse_prefix = mouse_events[:idx]
            move_time = float(move.get("timestamp", 0.0))

            key_prefix = [
                ev for ev in keystroke_events
                if float(ev.get("release_timestamp", 0.0)) <= move_time
            ]

            m_entropy = extract_mouse_entropy(mouse_prefix)
            k_entropy = extract_keystroke_entropy(key_prefix)
            combined = pool_entropy(m_entropy, k_entropy)

            key_bytes = self._derive_key_for_move(combined, idx)

            rng = _derive_random_number(key_bytes)
            entropy_bits = _estimate_entropy_bits(combined)

            record = PerMoveRecord(
                move_index=idx,
                timestamp=move_time,
                x=float(move.get("x", 0.0)),
                y=float(move.get("y", 0.0)),
                velocity_px_per_s=float(move.get("velocity_px_per_s", 0.0)),
                direction_deg=float(move.get("direction_angle_deg", 0.0)),
                entropy_bytes_hex=_hex_preview(combined),
                entropy_bits_estimate=round(entropy_bits, 2),
                key_hex_preview=_hex_preview(key_bytes),
                key_bits=len(key_bytes) * 8,
                random_number=rng,
                key_changed=(prev_key is not None and key_bytes != prev_key),
                random_changed=(prev_rng is not None and rng != prev_rng),
            )
            self.records.append(record)
            prev_key = key_bytes
            prev_rng = rng

        return EntropyAgentReport(
            records=self.records,
            security_level=self.security_level,
            key_mode=self.key_mode,
        )


@dataclass
class EntropyAgentReport:
    records: list[PerMoveRecord]
    security_level: str
    key_mode: str = "static"

    # ------------------------------------------------------------------ stats

    @property
    def total_moves(self) -> int:
        return len(self.records)

    @property
    def keys_changed(self) -> int:
        return sum(1 for r in self.records if r.key_changed)

    @property
    def keys_unchanged(self) -> int:
        return sum(1 for r in self.records if not r.key_changed and r.move_index > 1)

    @property
    def unique_keys(self) -> int:
        return len({r.key_hex_preview for r in self.records})

    @property
    def unique_rngs(self) -> int:
        return len({r.random_number for r in self.records})

    @property
    def change_rate_percent(self) -> float:
        eligible = max(1, self.total_moves - 1)
        return round(self.keys_changed / eligible * 100, 2)

    # ------------------------------------------------------------------ print

    def print_summary(self) -> None:
        print("\n" + "=" * 72)
        print("  SUMIT KEY — EntropyAgent Per-Movement Report")
        print("=" * 72)
        print(f"  Security level          : {self.security_level}")
        print(f"  Key mode                : {self.key_mode}")
        print(f"  Total mouse moves       : {self.total_moves}")
        print(f"  Keys generated total    : {self.total_moves}  (1 per move)")
        print(f"  Random numbers total    : {self.total_moves}  (1 per move)")
        print(f"  Unique keys             : {self.unique_keys} / {self.total_moves}")
        print(f"  Unique random numbers   : {self.unique_rngs} / {self.total_moves}")
        print(f"  Key changed per move    : {self.keys_changed}/{max(1,self.total_moves-1)} ({self.change_rate_percent}%)")
        print(f"  Key bits                : {self.records[0].key_bits if self.records else 'N/A'}")

    def print_per_move_table(self, max_rows: int = 30) -> None:
        """Print a table showing every move's key and RNG output."""
        print("\n  Per-Move Detail Table")
        print(f"  {'Move':>5}  {'Key preview (hex)':32}  {'Random number':20}  {'Changed?':8}  {'Entropy bits':12}")
        print("  " + "-" * 86)
        rows = self.records[:max_rows]
        for r in rows:
            changed_tag = "YES" if r.key_changed else ("---" if r.move_index == 1 else "no")
            print(
                f"  {r.move_index:>5}  {r.key_hex_preview:32}  {r.random_number:>20}  {changed_tag:8}  {r.entropy_bits_estimate:>12.2f}"
            )
        if len(self.records) > max_rows:
            print(f"  ... ({len(self.records) - max_rows} more rows omitted)")

    def print_full(self, max_rows: int = 30) -> None:
        self.print_summary()
        self.print_per_move_table(max_rows=max_rows)


# ---------------------------------------------------------------------------
# PipelineDebugger — full stage-by-stage trace
# ---------------------------------------------------------------------------

class PipelineDebugger:
    """Traces the full SUMIT KEY pipeline stage by stage."""

    def __init__(self, security_level: str = "quantum", key_mode: str = "static") -> None:
        self.security_level = security_level
        self.key_mode = key_mode
        self.traces: list[StageTrace] = []

    def _record(self, trace: StageTrace) -> StageTrace:
        self.traces.append(trace)
        trace.print()
        return trace

    # ------------------------------------------------------------------ stages

    def trace_capture(
        self,
        mouse_events: list[dict[str, Any]],
        keystroke_events: list[dict[str, Any]],
    ) -> StageTrace:
        """Stage 1: analyse raw captured events."""
        velocities = [float(e.get("velocity_px_per_s", 0)) for e in mouse_events]
        directions = [float(e.get("direction_angle_deg", 0)) for e in mouse_events]

        mean_v = sum(velocities) / max(1, len(velocities))
        max_v = max(velocities) if velocities else 0.0
        unique_positions = len({(e.get("x", 0), e.get("y", 0)) for e in mouse_events})

        dwell_times = [float(e.get("dwell_time_ms", 0)) for e in keystroke_events]
        mean_dwell = sum(dwell_times) / max(1, len(dwell_times))

        return self._record(StageTrace(
            stage="1. Raw Capture",
            ok=len(mouse_events) > 0,
            details={
                "mouse_events": len(mouse_events),
                "unique_mouse_positions": unique_positions,
                "mean_velocity_px_s": round(mean_v, 2),
                "max_velocity_px_s": round(max_v, 2),
                "keystroke_events": len(keystroke_events),
                "mean_dwell_time_ms": round(mean_dwell, 2),
                "direction_range_deg": f"{min(directions, default=0):.1f}..{max(directions, default=0):.1f}",
            },
            error="" if mouse_events else "No mouse events captured",
        ))

    def trace_mouse_entropy(self, mouse_events: list[dict[str, Any]]) -> tuple[StageTrace, bytes]:
        """Stage 2a: extract mouse entropy bytes."""
        try:
            m_bytes = extract_mouse_entropy(mouse_events)
            bits = _estimate_entropy_bits(m_bytes)
            return self._record(StageTrace(
                stage="2a. Mouse Entropy Extraction",
                ok=True,
                details={
                    "output_bytes": len(m_bytes),
                    "output_hex_preview": _hex_preview(m_bytes),
                    "shannon_entropy_bits": round(bits, 2),
                    "unique_byte_values": len(set(m_bytes)),
                },
            )), m_bytes
        except Exception as exc:
            return self._record(StageTrace(
                stage="2a. Mouse Entropy Extraction", ok=False, error=str(exc)
            )), b""

    def trace_keystroke_entropy(self, keystroke_events: list[dict[str, Any]]) -> tuple[StageTrace, bytes]:
        """Stage 2b: extract keystroke entropy bytes."""
        try:
            k_bytes = extract_keystroke_entropy(keystroke_events)
            bits = _estimate_entropy_bits(k_bytes)
            return self._record(StageTrace(
                stage="2b. Keystroke Entropy Extraction",
                ok=True,
                details={
                    "output_bytes": len(k_bytes),
                    "output_hex_preview": _hex_preview(k_bytes),
                    "shannon_entropy_bits": round(bits, 2),
                    "unique_byte_values": len(set(k_bytes)),
                },
            )), k_bytes
        except Exception as exc:
            return self._record(StageTrace(
                stage="2b. Keystroke Entropy Extraction", ok=False, error=str(exc)
            )), b""

    def trace_pooling(self, m_bytes: bytes, k_bytes: bytes) -> tuple[StageTrace, bytes]:
        """Stage 3: pool mouse + keystroke entropy into SHA3-256 digest."""
        try:
            pooled = pool_entropy(m_bytes, k_bytes)
            bits = _estimate_entropy_bits(pooled)
            return self._record(StageTrace(
                stage="3. Entropy Pooling (SHA3-256)",
                ok=True,
                details={
                    "mouse_input_bytes": len(m_bytes),
                    "keystroke_input_bytes": len(k_bytes),
                    "pooled_output_bytes": len(pooled),
                    "pooled_hex": pooled.hex(),
                    "shannon_entropy_bits": round(bits, 2),
                },
            )), pooled
        except Exception as exc:
            return self._record(StageTrace(
                stage="3. Entropy Pooling (SHA3-256)", ok=False, error=str(exc)
            )), b""

    def trace_key_derivation(self, pooled: bytes) -> tuple[StageTrace, bytes]:
        """Stage 4: derive cryptographic key via HKDF."""
        try:
            if self.key_mode == "fresh":
                if self.security_level == "quantum":
                    key_bytes = KeyGenerator.generate_fresh_quantum_hardened_key(
                        pooled,
                        personalization=b"pipeline-debug",
                    )
                else:
                    key_bytes = KeyGenerator.generate_fresh_key(
                        pooled,
                        personalization=b"pipeline-debug",
                    )
            elif self.security_level == "quantum":
                key_bytes = KeyGenerator.generate_quantum_hardened_key(pooled)
            else:
                key_bytes = KeyGenerator.generate_key(pooled)

            rng = _derive_random_number(key_bytes)
            bits = _estimate_entropy_bits(key_bytes)

            return self._record(StageTrace(
                stage="4. Key Derivation (HKDF-SHA3)",
                ok=True,
                details={
                    "security_level": self.security_level,
                    "key_mode": self.key_mode,
                    "key_bits": len(key_bytes) * 8,
                    "key_hex_preview": _hex_preview(key_bytes, 24),
                    "random_number": rng,
                    "random_number_hex": hex(rng),
                    "shannon_entropy_bits": round(bits, 2),
                    "unique_byte_values": len(set(key_bytes)),
                },
            )), key_bytes
        except Exception as exc:
            return self._record(StageTrace(
                stage="4. Key Derivation (HKDF-SHA3)", ok=False, error=str(exc)
            )), b""

    # ------------------------------------------------------------------ full run

    def run(
        self,
        mouse_events: list[dict[str, Any]],
        keystroke_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run all debug stages and return a summary dict."""
        if keystroke_events is None:
            keystroke_events = []

        self.traces = []

        print("\n" + "=" * 72)
        print("  SUMIT KEY — Pipeline Debug Trace")
        print("=" * 72)

        t1 = self.trace_capture(mouse_events, keystroke_events)
        _, m_bytes = self.trace_mouse_entropy(mouse_events)
        _, k_bytes = self.trace_keystroke_entropy(keystroke_events)
        _, pooled = self.trace_pooling(m_bytes, k_bytes)
        t4, key_bytes = self.trace_key_derivation(pooled)

        all_passed = all(t.ok for t in self.traces)
        rng = _derive_random_number(key_bytes) if key_bytes else None

        print("\n" + "-" * 72)
        print(f"  Pipeline stages passed : {sum(t.ok for t in self.traces)}/{len(self.traces)}")
        print(f"  Overall status         : {'ALL PASS' if all_passed else 'FAILURES PRESENT'}")
        if key_bytes:
            print(f"  Final key ({len(key_bytes)*8}-bit)   : {key_bytes.hex()}")
            print(f"  Final random number     : {rng} ({hex(rng)})")
        print("=" * 72)

        return {
            "all_passed": all_passed,
            "stages": len(self.traces),
            "key_hex": key_bytes.hex() if key_bytes else None,
            "key_bits": len(key_bytes) * 8 if key_bytes else 0,
            "random_number": rng,
            "mouse_events": len(mouse_events),
            "keystroke_events": len(keystroke_events),
        }


# ---------------------------------------------------------------------------
# Synthetic event generators for offline testing
# ---------------------------------------------------------------------------

def make_synthetic_mouse_events(n: int = 30) -> list[dict[str, Any]]:
    """Generate synthetic mouse events for testing without hardware."""
    events: list[dict[str, Any]] = []
    t = time.time()
    for i in range(n):
        x = 200 + i * 7 + math.sin(i * 0.4) * 40
        y = 300 + i * 4 + math.cos(i * 0.3) * 25
        velocity = abs(20.0 + math.sin(i * 0.7) * 15)
        direction = math.degrees(math.atan2(
            math.cos(i * 0.3), math.sin(i * 0.4)
        ))
        events.append({
            "x": x, "y": y,
            "timestamp": t + i * 0.05,
            "velocity_px_per_s": velocity,
            "direction_angle_deg": direction,
        })
    return events


def make_turn_vibration_mouse_events(
    turns: int = 4,
    samples_per_turn: int = 12,
    vibration_px: float = 1.25,
) -> list[dict[str, Any]]:
    """Generate a few mouse turns with micro-vibration for static-key demos."""

    if turns <= 0:
        raise ValueError("turns must be positive")
    if samples_per_turn < 4:
        raise ValueError("samples_per_turn must be at least 4")
    if vibration_px < 0:
        raise ValueError("vibration_px must be non-negative")

    events: list[dict[str, Any]] = []
    start = time.time()
    total = turns * samples_per_turn
    last_x: float | None = None
    last_y: float | None = None
    last_t: float | None = None

    def append_event(x: float, y: float, timestamp: float) -> None:
        nonlocal last_x, last_y, last_t

        velocity = 0.0
        direction = 0.0
        if last_x is not None and last_y is not None and last_t is not None:
            dt = timestamp - last_t
            dx = x - last_x
            dy = y - last_y
            if dt > 0:
                velocity = math.sqrt(dx * dx + dy * dy) / dt
            direction = math.degrees(math.atan2(dy, dx))

        events.append(
            {
                "x": x,
                "y": y,
                "timestamp": timestamp,
                "velocity_px_per_s": velocity,
                "direction_angle_deg": direction,
            }
        )
        last_x = x
        last_y = y
        last_t = timestamp

    for index in range(total):
        angle = (2.0 * math.pi * index) / samples_per_turn
        radius = 80.0 + 6.0 * math.sin(index * 0.37)
        tremor_x = vibration_px * math.sin(index * 2.7)
        tremor_y = vibration_px * math.cos(index * 3.1)
        x = 500.0 + radius * math.cos(angle) + index * 0.9 + tremor_x
        y = 320.0 + radius * math.sin(angle) + turns * 1.7 + tremor_y
        timestamp = start + index * 0.035

        append_event(x, y, timestamp)

        micro_x = x + vibration_px * 0.45 * math.sin(index * 5.3 + 0.4)
        micro_y = y + vibration_px * 0.45 * math.cos(index * 4.7 + 0.2)
        append_event(micro_x, micro_y, timestamp + 0.012)

    return events


def make_synthetic_keystroke_events(n: int = 8) -> list[dict[str, Any]]:
    """Generate synthetic keystroke events for testing."""
    events: list[dict[str, Any]] = []
    t = time.time()
    keys = list("abcdefghij")
    for i in range(n):
        press_t = t + i * 0.25 + (i % 3) * 0.03
        release_t = press_t + 0.08 + (i % 4) * 0.015
        flight = 0.0 if not events else (press_t - events[-1]["release_timestamp"]) * 1000
        events.append({
            "key": keys[i % len(keys)],
            "press_timestamp": press_t,
            "release_timestamp": release_t,
            "dwell_time_ms": (release_t - press_t) * 1000,
            "flight_time_ms": flight,
        })
    return events


# ---------------------------------------------------------------------------
# Full static key + authenticated encryption chain
# ---------------------------------------------------------------------------

def _derive_static_chain_key(
    combined_entropy: bytes,
    security_level: str,
    domain: bytes = b"SUMIT_STATIC_CHAIN_V1",
) -> bytes:
    """Derive a repeatable static key for the same entropy and domain."""

    if security_level == "quantum":
        config = HKDFConfig.quantum_hardened()
    elif security_level == "standard":
        config = HKDFConfig()
    else:
        raise ValueError("security_level must be 'standard' or 'quantum'")

    KeyGenerator.health_check_entropy(
        combined_entropy,
        min_bytes=config.min_entropy_bytes,
        max_repetition_run=config.min_entropy_bytes,
    )
    return KeyGenerator.derive_key(
        [domain, combined_entropy],
        config,
    )


def framework_checks_for_static_chain(
    *,
    key_bits: int,
    nonce_size: int,
    aad: bytes,
    health_ok: bool,
) -> list[FrameworkCheck]:
    """Return US/NIST-oriented framework checks for the chain."""

    aes_key_bits = min(key_bits, 256)
    return [
        FrameworkCheck(
            "FIPS 197 / SP 800-38D",
            "Use an approved AES mode for authenticated encryption",
            "PASS" if key_bits >= 256 and nonce_size == 12 else "FAIL",
            (
                f"AES-{aes_key_bits}-GCM with {key_bits}-bit derived material; "
                f"{nonce_size * 8}-bit nonce"
            ),
        ),
        FrameworkCheck(
            "SP 800-38D",
            "Bind context with authenticated additional data",
            "PASS" if aad else "WARN",
            "AAD present" if aad else "No AAD label supplied",
        ),
        FrameworkCheck(
            "FIPS 202",
            "Use SHA3 family hashing for entropy pooling",
            "PASS",
            "Mouse and keystroke features are pooled with SHA3-256",
        ),
        FrameworkCheck(
            "SP 800-90B concept",
            "Reject obviously broken entropy input with health checks",
            "PASS" if health_ok else "FAIL",
            "Length, constant-input, repeated-run, and dominant-byte checks",
        ),
        FrameworkCheck(
            "NIST SP 800-22",
            "Use statistical testing only as evidence, not certification",
            "WARN",
            "SP 800-22 is a black-box statistical suite; it does not certify a generator",
        ),
        FrameworkCheck(
            "FIPS 140-3",
            "Use a validated cryptographic module for formal compliance",
            "WARN",
            "Python cryptography/OpenSSL may be strong, but this repo is not a validated module",
        ),
    ]


def run_static_encryption_chain(
    mouse_events: list[dict[str, Any]],
    message: str | bytes,
    keystroke_events: list[dict[str, Any]] | None = None,
    *,
    security_level: str = "quantum",
    label: str = "sumit-static-chain",
) -> dict[str, Any]:
    """Full chain: turns/vibration -> static key -> AES-GCM encryption."""

    if keystroke_events is None:
        keystroke_events = []
    if not mouse_events:
        raise ValueError("mouse_events must not be empty")

    mouse_entropy = extract_mouse_entropy(mouse_events)
    key_entropy = extract_keystroke_entropy(keystroke_events)
    combined_entropy = pool_entropy(mouse_entropy, key_entropy)

    health_ok = True
    health_error = ""
    try:
        key_bytes = _derive_static_chain_key(combined_entropy, security_level)
    except (EntropyHealthError, ValueError) as exc:
        health_ok = False
        health_error = str(exc)
        raise

    aad = label.encode("utf-8")
    encrypted = encrypt_message(key_bytes, message, associated_data=aad)
    decrypted = decrypt_message(key_bytes, encrypted)
    plain_bytes = message.encode("utf-8") if isinstance(message, str) else bytes(message)

    checks = framework_checks_for_static_chain(
        key_bits=len(key_bytes) * 8,
        nonce_size=len(encrypted.nonce),
        aad=aad,
        health_ok=health_ok,
    )

    small_steps = 0
    direction_changes = 0
    last_direction: float | None = None
    for index, event in enumerate(mouse_events):
        direction = float(event.get("direction_angle_deg", 0.0))
        if last_direction is not None and abs(direction - last_direction) >= 20.0:
            direction_changes += 1
        last_direction = direction

        if index > 0:
            prev = mouse_events[index - 1]
            dx = float(event.get("x", 0.0)) - float(prev.get("x", 0.0))
            dy = float(event.get("y", 0.0)) - float(prev.get("y", 0.0))
            if 0.0 < math.sqrt(dx * dx + dy * dy) < 5.0:
                small_steps += 1

    return {
        "status": "ok",
        "security_level": security_level,
        "key_mode": "static-repeatable",
        "mouse_event_count": len(mouse_events),
        "keystroke_event_count": len(keystroke_events),
        "turn_direction_changes": direction_changes,
        "micro_vibration_steps": small_steps,
        "mouse_entropy_hex": mouse_entropy.hex(),
        "keystroke_entropy_hex": key_entropy.hex(),
        "combined_entropy_hex": combined_entropy.hex(),
        "static_key_hex": key_bytes.hex(),
        "static_key_bits": len(key_bytes) * 8,
        "random_number": _derive_random_number(key_bytes),
        "encryption": {
            **message_to_dict(encrypted),
            "algorithm": "AES-256-GCM",
            "aad_label": label,
            "plaintext_length_bytes": len(plain_bytes),
            "ciphertext_length_bytes": len(encrypted.ciphertext),
            "decrypt_verified": decrypted == plain_bytes,
        },
        "framework_checks": [check.__dict__ for check in checks],
        "health_error": health_error or None,
        "certification_note": (
            "This is NIST-aligned engineering evidence, not FIPS/NIST certification. "
            "Formal compliance requires validated entropy assessment and a FIPS 140-3 module."
        ),
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _run_synthetic_demo() -> None:
    print("\n[Mode: Synthetic events — no hardware required]\n")

    mouse_events = make_synthetic_mouse_events(30)
    keystroke_events = make_synthetic_keystroke_events(8)

    # Full pipeline debug trace
    debugger = PipelineDebugger(security_level="quantum")
    result = debugger.run(mouse_events, keystroke_events)

    # Per-move agent analysis
    print("\n\n" + "=" * 72)
    print("  SUMIT KEY — EntropyAgent: Per-Mouse-Movement Analysis")
    print("=" * 72)
    agent = EntropyAgent(security_level="quantum")
    report = agent.analyze(mouse_events, keystroke_events)
    report.print_full(max_rows=30)

    print("\n\n[Single-move answer]")
    if report.records:
        r = report.records[0]
        print(f"  With just 1 mouse movement:")
        print(f"    Keys generated     : 1")
        print(f"    Random numbers     : 1")
        print(f"    Key ({r.key_bits}-bit): {r.key_hex_preview}")
        print(f"    Random number      : {r.random_number}")
        print(f"    Entropy bits est.  : {r.entropy_bits_estimate}")

    print("\n\n[Static chain answer]")
    turn_events = make_turn_vibration_mouse_events(turns=4, samples_per_turn=12)
    chain = run_static_encryption_chain(
        turn_events,
        "SUMIT KEY static encryption demo",
        security_level="quantum",
        label="synthetic-turn-vibration-demo",
    )
    print(f"  Mouse turns/vibration events : {chain['mouse_event_count']}")
    print(f"  Micro-vibration steps        : {chain['micro_vibration_steps']}")
    print(f"  Static key bits              : {chain['static_key_bits']}")
    print(f"  Static key preview           : {chain['static_key_hex'][:48]}...")
    print(f"  AES-GCM nonce                : {chain['encryption']['nonce_hex']}")
    print(f"  Decrypt verified             : {chain['encryption']['decrypt_verified']}")
    print("  Framework checks:")
    for check in chain["framework_checks"]:
        print(f"    {check['status']:<4} {check['framework']}: {check['requirement']}")


def _run_live_demo(duration: float) -> None:
    from capture import capture_behaviour

    print(f"\n[Mode: Live capture — {duration}s]\n")
    print(f"Move your mouse and type for {duration} seconds...")

    mouse_events, keystroke_events = capture_behaviour(duration)

    debugger = PipelineDebugger(security_level="quantum")
    debugger.run(mouse_events, keystroke_events)

    agent = EntropyAgent(security_level="quantum")
    report = agent.analyze(mouse_events, keystroke_events)
    report.print_full()


def _run_per_move_live(duration: float) -> None:
    from capture import capture_behaviour

    print(f"\n[Mode: Per-move live — {duration}s]\n")
    print(f"Move your mouse for {duration} seconds...")

    mouse_events, keystroke_events = capture_behaviour(duration)

    agent = EntropyAgent(security_level="quantum")
    report = agent.analyze(mouse_events, keystroke_events)
    report.print_full()


def _run_static_chain_demo(duration: float | None = None) -> None:
    """Run a static key + encryption chain with live or synthetic events."""

    if duration is None:
        print("\n[Mode: Static chain — synthetic turns/vibration]\n")
        mouse_events = make_turn_vibration_mouse_events(turns=4, samples_per_turn=12)
        keystroke_events = []
    else:
        from capture import capture_behaviour

        print(f"\n[Mode: Static chain — live capture {duration}s]\n")
        print("Move the mouse in a few turns/circles with small vibration.")
        mouse_events, keystroke_events = capture_behaviour(duration)

    chain = run_static_encryption_chain(
        mouse_events,
        "Static key encrypted with AES-256-GCM",
        keystroke_events,
        security_level="quantum",
        label="sumit-static-chain-live" if duration else "sumit-static-chain-synthetic",
    )

    print("=" * 72)
    print("  SUMIT KEY — Full Static Encryption Chain")
    print("=" * 72)
    print(f"  Status                  : {chain['status']}")
    print(f"  Key mode                : {chain['key_mode']}")
    print(f"  Mouse events            : {chain['mouse_event_count']}")
    print(f"  Direction changes       : {chain['turn_direction_changes']}")
    print(f"  Micro-vibration steps   : {chain['micro_vibration_steps']}")
    print(f"  Static key bits         : {chain['static_key_bits']}")
    print(f"  Static key hex          : {chain['static_key_hex']}")
    print(f"  Random number           : {chain['random_number']}")
    print(f"  AES-GCM nonce           : {chain['encryption']['nonce_hex']}")
    print(f"  Ciphertext hex          : {chain['encryption']['ciphertext_hex']}")
    print(f"  Decrypt verified        : {chain['encryption']['decrypt_verified']}")
    print("\n  Framework checks")
    for check in chain["framework_checks"]:
        print(f"    [{check['status']}] {check['framework']} — {check['evidence']}")
    print("\n  " + chain["certification_note"])
    print("=" * 72)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SUMIT KEY pipeline debugger")
    parser.add_argument("--live", type=float, metavar="SECONDS",
                        help="Live capture + full debug trace")
    parser.add_argument("--per-move-live", type=float, metavar="SECONDS",
                        help="Live capture + per-move agent analysis only")
    parser.add_argument("--static-chain", action="store_true",
                        help="Synthetic mouse-turn/vibration static key + AES-GCM chain")
    parser.add_argument("--static-chain-live", type=float, metavar="SECONDS",
                        help="Live capture static key + AES-GCM chain")
    args = parser.parse_args()

    if args.static_chain:
        _run_static_chain_demo()
    elif args.static_chain_live:
        _run_static_chain_demo(args.static_chain_live)
    elif args.live:
        _run_live_demo(args.live)
    elif args.per_move_live:
        _run_per_move_live(args.per_move_live)
    else:
        _run_synthetic_demo()
