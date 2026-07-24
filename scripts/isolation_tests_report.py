"""Run the sandbox/blackbox/identity isolation test files and record structured
per-test results for the dashboard.

These suites are the ones that specifically exercise "two parties using the
same system" scenarios: separate devices, separate user identities, separate
messaging platforms, all proving that one party's key material/ciphertext is
useless to the other.
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

SUITES = {
    "sandbox_deep": "tests/test_sandbox_deep.py",
    "blackbox_deep": "tests/test_blackbox_deep.py",
    "blackbox_security": "tests/test_blackbox_security.py",
    "identity_isolation": "tests/test_identity.py",
}

# Individual tests that directly prove isolation between two distinct
# people/devices/identities sharing the same system.
TWO_PARTY_TESTS = {
    "test_individual_system_identity_separates_keys",
    "test_third_party_cannot_decrypt",
    "test_wrong_shared_secret_cannot_decrypt",
    "test_different_user_ids_different_channels",
    "test_whatsapp_envelope_not_decryptable_on_telegram",
    "test_all_platforms_produce_distinct_channel_keys",
    "test_same_user_id_different_platform_different_identity_hash",
}


def _run_suite(rel_path: str, xml_out: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            rel_path,
            f"--junit-xml={xml_out}",
            "-q",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )


def _parse_junit(xml_path: Path) -> dict:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")

    tests = []
    for case in suite.iter("testcase"):
        name = case.get("name", "")
        failure = case.find("failure") is not None or case.find("error") is not None
        skipped = case.find("skipped") is not None
        tests.append({
            "name": name,
            "classname": case.get("classname", ""),
            "passed": not failure and not skipped,
            "skipped": skipped,
            "time": float(case.get("time", 0.0)),
            "two_party_isolation_test": name in TWO_PARTY_TESTS,
        })

    return {
        "total": int(suite.get("tests", 0)),
        "failures": int(suite.get("failures", 0)),
        "errors": int(suite.get("errors", 0)),
        "skipped": int(suite.get("skipped", 0)),
        "time": float(suite.get("time", 0.0)),
        "tests": tests,
    }


def generate(output_path: str = "results/isolation_tests_report.json") -> dict:
    import json

    results_dir = PROJECT_ROOT / "results"
    results_dir.mkdir(exist_ok=True)

    report = {"suites": {}}
    for suite_name, rel_path in SUITES.items():
        xml_out = results_dir / f"_junit_{suite_name}.xml"
        _run_suite(rel_path, xml_out)
        if xml_out.exists():
            report["suites"][suite_name] = {
                "file": rel_path,
                **_parse_junit(xml_out),
            }
            xml_out.unlink()
        else:
            report["suites"][suite_name] = {"file": rel_path, "error": "junit xml not produced"}

    two_party_tests = [
        {"suite": suite_name, **t}
        for suite_name, data in report["suites"].items()
        for t in data.get("tests", [])
        if t.get("two_party_isolation_test")
    ]
    report["two_party_isolation_tests"] = two_party_tests

    out = PROJECT_ROOT / output_path
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Isolation test report saved to {out}")
    return report


if __name__ == "__main__":
    generate()
