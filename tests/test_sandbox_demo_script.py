from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_demo(name: str) -> str:
    result = subprocess.run(
        [sys.executable, "scripts/sandbox_demo.py", "--demo", name],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    return result.stdout


def test_classic_sandbox_demo_runs() -> None:
    output = _run_demo("classic")
    assert "Classical AES-GCM message" in output
    assert "round trip succeeded" in output
    assert "tampered ciphertext was rejected" in output


def test_ghost_sandbox_demo_runs_once_then_blocks_replay() -> None:
    output = _run_demo("ghost")
    assert "One-time ghost package" in output
    assert "first open succeeded" in output
    assert "second open was blocked" in output
