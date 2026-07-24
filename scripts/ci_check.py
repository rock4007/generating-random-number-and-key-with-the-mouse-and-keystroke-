"""Local CI pipeline for SUMIT KEY.

Runs syntax checks, JavaScript parse checks, sandbox demos, and the pytest
suite in named groups. Splitting tests makes failures and hangs easier to debug
than a single giant pytest command.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PYTEST_GROUPS: list[tuple[str, list[str], int]] = [
    (
        "security-core",
        [
            "tests/test_adversarial_scenarios.py",
            "tests/test_attack_and_device_scenarios.py",
            "tests/test_blackbox_security.py",
            "tests/test_deep_audit.py",
            "tests/test_file_decrypt_aad.py",
            "tests/test_logical_fixes.py",
            "tests/test_moat_report.py",
            "tests/test_research_evidence.py",
            "tests/test_security_audit.py",
        ],
        180,
    ),
    (
        "deep-entropy",
        [
            "tests/test_blackbox_deep.py",
            "tests/test_entropy_sources_deep.py",
            "tests/test_sandbox_deep.py",
        ],
        240,
    ),
    (
        "connectivity",
        ["tests/test_connectivity.py"],
        180,
    ),
    (
        "ghost-api",
        ["tests/test_ghost_api.py"],
        120,
    ),
    (
        "identity",
        ["tests/test_identity.py"],
        120,
    ),
    (
        "integration-system",
        ["tests/test_integration_system.py"],
        180,
    ),
    (
        "tier1-features",
        ["tests/test_tier1_features.py"],
        120,
    ),
    (
        "browser-and-sandbox",
        [
            "tests/test_browser_extension.py",
            "tests/test_mouse_entropy.py",
            "tests/test_sandbox.py",
            "tests/test_sandbox_demo_script.py",
        ],
        180,
    ),
]

JS_FILES = [
    "browser_extension/background.js",
    "browser_extension/content.js",
    "browser_extension/popup.js",
    "sdk/sumitkey.js",
]


def _run(label: str, cmd: list[str], *, timeout: int) -> None:
    print(f"\n=== {label} ===")
    print("$ " + " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True, timeout=timeout)


def run_pipeline(*, quick: bool = False) -> None:
    _run("python compileall", [sys.executable, "-m", "compileall", "-q", "."], timeout=120)

    for js_file in JS_FILES:
        if (ROOT / js_file).exists():
            _run(f"node syntax: {js_file}", ["node", "--check", js_file], timeout=30)

    _run(
        "sandbox demo: classic",
        [sys.executable, "scripts/sandbox_demo.py", "--demo", "classic"],
        timeout=60,
    )
    _run(
        "sandbox demo: ghost",
        [sys.executable, "scripts/sandbox_demo.py", "--demo", "ghost"],
        timeout=60,
    )

    groups = PYTEST_GROUPS
    if quick:
        groups = [
            PYTEST_GROUPS[0],
            PYTEST_GROUPS[-1],
        ]

    for label, files, timeout in groups:
        existing = [path for path in files if (ROOT / path).exists()]
        if not existing:
            continue
        _run(
            f"pytest: {label}",
            [sys.executable, "-m", "pytest", "-q", *existing],
            timeout=timeout,
        )

    print("\nCI pipeline complete.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SUMIT KEY CI checks locally.")
    parser.add_argument("--quick", action="store_true", help="Run only fast/core groups.")
    args = parser.parse_args()
    run_pipeline(quick=args.quick)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
