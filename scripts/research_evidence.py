"""Export reproducible research evidence for SUMIT KEY.

This script turns the novelty claims into data:
  - validates claim_matrix.json paths and required fields
  - measures BEHAVE-KDF output quality across behavioral scenarios
  - proves platform-context replay rejection
  - proves ghost package open-once behavior

The output is intended for paper tables, appendix material, and reviewer
artifacts. It is engineering evidence, not formal certification.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from behave_kdf import BehaveKDF, mcv_min_entropy, shannon_entropy_per_byte
from sdk.core import SumitKeyError
from sdk.identity import UserIdentity


def _mouse_events(n: int = 64, *, mode: str = "natural", seed: int = 0) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index in range(n):
        if mode == "zero":
            x = y = velocity = direction = 0.0
        elif mode == "low":
            x = float(400 + (index % 2))
            y = float(300 + (index % 2))
            velocity = float(20 + (index % 2))
            direction = float((index % 4) * 90)
        else:
            x = 400.0 + index * 3.1 + math.sin(index * 0.31 + seed) * 23.0
            y = 300.0 + index * 1.7 + math.cos(index * 0.27 + seed) * 19.0
            velocity = abs(80.0 + math.sin(index * 0.53 + seed) * 47.0)
            direction = (index * 17.0 + math.sin(index + seed) * 31.0) % 360
        events.append(
            {
                "x": x,
                "y": y,
                "timestamp": 1000.0 + seed * 10.0 + index * 0.016,
                "velocity_px_per_s": velocity,
                "direction_angle_deg": direction,
            }
        )
    return events


def _key_events(n: int = 32, *, mode: str = "natural", seed: int = 0) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    alphabet = "researchentropy"
    for index in range(n):
        if mode == "zero":
            dwell = 0.0
            flight = 0.0
            key = "a"
        elif mode == "low":
            dwell = 80.0 + (index % 2)
            flight = 40.0 + (index % 2)
            key = "a" if index % 2 == 0 else "b"
        else:
            dwell = 72.0 + (index % 7) * 4.5 + math.sin(index + seed) * 3.0
            flight = 35.0 + (index % 5) * 6.0 + math.cos(index + seed) * 2.5
            key = alphabet[index % len(alphabet)]
        press = 2000.0 + seed * 10.0 + index * 0.21
        release = press + dwell / 1000.0
        events.append(
            {
                "key": key,
                "press_timestamp": press,
                "release_timestamp": release,
                "dwell_time_ms": dwell,
                "flight_time_ms": flight,
            }
        )
    return events


def _unique_ratio(items: list[bytes]) -> float:
    if not items:
        return 0.0
    return len(set(items)) / len(items)


def validate_claim_matrix(path: Path = ROOT / "claim_matrix.json") -> dict[str, Any]:
    matrix = json.loads(path.read_text(encoding="utf-8"))
    claims = matrix.get("claims", [])
    missing_paths: list[str] = []
    missing_fields: list[str] = []
    required = {"id", "claim", "implementation", "tests", "boundary", "validation_status"}

    for claim in claims:
        for field in required:
            if field not in claim:
                missing_fields.append(f"{claim.get('id', '<unknown>')}:{field}")
        for key in ("implementation", "tests"):
            for rel in claim.get(key, []):
                if not (ROOT / rel).exists():
                    missing_paths.append(rel)

    return {
        "claim_count": len(claims),
        "missing_fields": missing_fields,
        "missing_paths": sorted(set(missing_paths)),
        "passed": not missing_fields and not missing_paths and len(claims) >= 4,
    }


def behavioral_kdf_experiment(trials: int = 48) -> dict[str, Any]:
    scenarios = {
        "zero_behavior": "zero",
        "low_behavior": "low",
        "natural_behavior": "natural",
    }
    results: dict[str, Any] = {}

    for label, mode in scenarios.items():
        keys: list[bytes] = []
        pool_hmins: list[float] = []
        derive_ms: list[float] = []
        for seed in range(trials):
            result = BehaveKDF.derive(
                _mouse_events(mode=mode, seed=seed),
                _key_events(mode=mode, seed=seed),
                personalization=f"paper-trial:{label}:{seed}".encode("utf-8"),
            )
            keys.append(result.key_bytes)
            pool_hmins.append(result.h_min_pool)
            derive_ms.append(result.derive_time_ms)

        corpus = b"".join(keys)
        results[label] = {
            "trials": trials,
            "unique_key_ratio": round(_unique_ratio(keys), 4),
            "corpus_mcv_h_min_bits_per_byte": round(mcv_min_entropy(corpus), 4),
            "corpus_shannon_bits_per_byte": round(shannon_entropy_per_byte(corpus), 4),
            "mean_pool_h_min_bits_per_byte": round(statistics.mean(pool_hmins), 4),
            "mean_derive_time_ms": round(statistics.mean(derive_ms), 4),
        }

    passed = all(
        item["unique_key_ratio"] == 1.0
        and item["corpus_mcv_h_min_bits_per_byte"] >= 6.0
        and item["corpus_shannon_bits_per_byte"] >= 7.0
        for item in results.values()
    )
    return {
        "description": "BEHAVE-KDF additive-output evidence across behavioral quality scenarios.",
        "passed": passed,
        "thresholds": {
            "unique_key_ratio": 1.0,
            "corpus_mcv_h_min_bits_per_byte_min": 6.0,
            "corpus_shannon_bits_per_byte_min": 7.0,
        },
        "scenarios": results,
    }


def platform_replay_experiment() -> dict[str, Any]:
    secret_owner = UserIdentity("alice", "whatsapp", device_secret=b"a" * 32)
    secret = secret_owner.new_shared_secret()

    alice_wa = UserIdentity("alice", "whatsapp", device_secret=b"a" * 32)
    bob_wa = UserIdentity("bob", "whatsapp", device_secret=b"b" * 32)
    bob_tg = UserIdentity("bob", "telegram", device_secret=b"b" * 32)

    wa_sender = alice_wa.channel_to(bob_wa.public_id(), shared_secret=secret)
    wa_receiver = bob_wa.channel_to(alice_wa.public_id(), shared_secret=secret)
    tg_receiver = bob_tg.channel_to("telegram:alice", shared_secret=secret)

    envelope = wa_sender.encrypt("platform-bound research message")
    plaintext = wa_receiver.decrypt(envelope)
    replay_rejected = False
    try:
        tg_receiver.decrypt(envelope)
    except SumitKeyError:
        replay_rejected = True

    return {
        "description": "WhatsApp ciphertext cannot be replayed as Telegram context.",
        "same_platform_plaintext": plaintext,
        "cross_platform_replay_rejected": replay_rejected,
        "passed": plaintext == "platform-bound research message" and replay_rejected,
        "sender_channel": wa_sender.info(),
        "receiver_channel": wa_receiver.info(),
    }


def ghost_once_experiment() -> dict[str, Any]:
    from fastapi import HTTPException
    from api import _GhostEncryptBody, _GhostPackageBody, ghost_decrypt_endpoint, ghost_encrypt_endpoint

    request = SimpleNamespace(client=SimpleNamespace(host="research-evidence"))
    created = ghost_encrypt_endpoint(
        request,
        _GhostEncryptBody(
            message="ghost research evidence",
            label="research-evidence",
            ttl_seconds=60,
        ),
    )
    package = created["package"]
    opened = ghost_decrypt_endpoint(request, _GhostPackageBody(**package))

    second_open_status = None
    try:
        ghost_decrypt_endpoint(request, _GhostPackageBody(**package))
    except HTTPException as exc:
        second_open_status = exc.status_code

    return {
        "description": "Ghost package opens once and is then unavailable.",
        "ghost_id": package["ghost_id"],
        "key_fingerprint": package["key_fingerprint"],
        "first_open_plaintext": opened["plaintext"],
        "first_open_key_status": opened["ghost_key_status"],
        "second_open_status": second_open_status,
        "passed": (
            opened["plaintext"] == "ghost research evidence"
            and opened["ghost_key_status"] == "zeroized_and_deleted"
            and second_open_status == 410
        ),
    }


def build_evidence(*, trials: int = 48) -> dict[str, Any]:
    started = time.time()
    evidence = {
        "schema": "sumit-key-research-evidence-v1",
        "generated_at_unix": started,
        "purpose": "Reproducible engineering evidence for paper claims; not formal certification.",
        "claim_matrix": validate_claim_matrix(),
        "experiments": {
            "behavioral_kdf": behavioral_kdf_experiment(trials=trials),
            "platform_replay": platform_replay_experiment(),
            "ghost_once": ghost_once_experiment(),
        },
    }
    evidence["passed"] = evidence["claim_matrix"]["passed"] and all(
        item["passed"] for item in evidence["experiments"].values()
    )
    evidence["elapsed_ms"] = round((time.time() - started) * 1000.0, 3)
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Export SUMIT KEY research evidence.")
    parser.add_argument("--trials", type=int, default=48, help="Trials per behavioral scenario.")
    parser.add_argument(
        "--output",
        default="results/research_evidence.json",
        help="Path to write JSON evidence.",
    )
    args = parser.parse_args()

    if args.trials < 8:
        raise SystemExit("--trials must be at least 8")

    evidence = build_evidence(trials=args.trials)
    out_path = ROOT / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    try:
        display_path = out_path.relative_to(ROOT)
    except ValueError:
        display_path = out_path
    print(f"wrote {display_path}")
    print(f"passed={evidence['passed']}")
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
