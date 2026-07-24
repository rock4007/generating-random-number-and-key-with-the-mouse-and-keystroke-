"""Tests for reproducible SUMIT KEY research evidence export."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import research_evidence


ROOT = Path(__file__).resolve().parents[1]


def test_claim_matrix_paths_are_valid() -> None:
    result = research_evidence.validate_claim_matrix()
    assert result["passed"] is True
    assert result["claim_count"] >= 7
    assert result["missing_paths"] == []
    assert result["missing_fields"] == []


def test_behavioral_kdf_experiment_has_real_thresholds() -> None:
    result = research_evidence.behavioral_kdf_experiment(trials=48)
    assert result["passed"] is True
    for scenario in result["scenarios"].values():
        assert scenario["unique_key_ratio"] == 1.0
        assert scenario["corpus_mcv_h_min_bits_per_byte"] >= 6.0
        assert scenario["corpus_shannon_bits_per_byte"] >= 7.0


def test_platform_replay_experiment_rejects_cross_platform_decrypt() -> None:
    result = research_evidence.platform_replay_experiment()
    assert result["passed"] is True
    assert result["same_platform_plaintext"] == "platform-bound research message"
    assert result["cross_platform_replay_rejected"] is True


def test_ghost_once_experiment_burns_after_first_open() -> None:
    result = research_evidence.ghost_once_experiment()
    assert result["passed"] is True
    assert result["first_open_plaintext"] == "ghost research evidence"
    assert result["first_open_key_status"] == "zeroized_and_deleted"
    assert result["second_open_status"] == 410


def test_research_evidence_cli_writes_json(tmp_path: Path) -> None:
    output = tmp_path / "evidence.json"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/research_evidence.py",
            "--trials",
            "48",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert "passed=True" in completed.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["passed"] is True
    assert data["claim_matrix"]["passed"] is True
    assert set(data["experiments"]) == {"behavioral_kdf", "platform_replay", "ghost_once"}
