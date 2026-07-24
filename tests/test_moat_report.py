"""Tests for the SUMIT KEY moat report generator."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import moat_report, research_evidence


ROOT = Path(__file__).resolve().parents[1]


def test_moat_report_passes_with_generated_evidence(tmp_path: Path) -> None:
    evidence_path = tmp_path / "research_evidence.json"
    evidence = research_evidence.build_evidence(trials=48)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

    report = moat_report.build_moat_report(evidence_path=evidence_path)
    assert report["passed"] is True
    assert report["evidence_loaded"] is True
    assert report["claim_matrix_passed"] is True
    assert {area["id"] for area in report["areas"]} >= {
        "human_session_kdf",
        "ghost_handoff",
        "platform_bound_encryption",
        "claim_hygiene",
        "reproducible_evidence",
    }


def test_moat_markdown_contains_boundaries(tmp_path: Path) -> None:
    evidence_path = tmp_path / "research_evidence.json"
    evidence_path.write_text(json.dumps(research_evidence.build_evidence(trials=48)), encoding="utf-8")

    report = moat_report.build_moat_report(evidence_path=evidence_path)
    markdown = moat_report.render_markdown(report)
    assert "SUMIT KEY Moat Report" in markdown
    assert "Human-session KDF" in markdown
    assert "official certification" in markdown


def test_moat_report_cli_writes_outputs(tmp_path: Path) -> None:
    evidence_path = tmp_path / "research_evidence.json"
    evidence_path.write_text(json.dumps(research_evidence.build_evidence(trials=48)), encoding="utf-8")
    out_json = tmp_path / "moat.json"
    out_md = tmp_path / "moat.md"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/moat_report.py",
            "--evidence",
            str(evidence_path),
            "--output-json",
            str(out_json),
            "--output-md",
            str(out_md),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert "passed=True" in completed.stdout
    assert json.loads(out_json.read_text(encoding="utf-8"))["passed"] is True
    assert "SUMIT KEY Moat Report" in out_md.read_text(encoding="utf-8")
