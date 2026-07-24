#!/usr/bin/env python3
"""Dashboard data processor — Extract test results and format for web dashboards.

Reads all JSON test reports and generates comprehensive dashboard data including:
- NIST 800-90B compliance
- Entropy source quality metrics
- Mouse/keystroke capture statistics
- Volunteer test results
- Security audit findings
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List


class DashboardDataProcessor:
    """Process test results and generate dashboard-friendly data."""

    def __init__(self, results_dir: str = "results"):
        self.results_dir = Path(results_dir)
        self.data = {
            "timestamp": datetime.now().isoformat(),
            "nist_800_90b": self._process_nist_report(),
            "entropy_tests": self._process_entropy_tests(),
            "research_evidence": self._process_research_evidence(),
            "moat_report": self._process_moat_report(),
            "tier1_features": self._process_tier1_features(),
            "summary": {}
        }
        self._compute_summary()

    def _process_nist_report(self) -> Dict[str, Any]:
        """Extract NIST 800-90B test results."""
        nist_file = self.results_dir / "nist_800_90b_deep_report.json"
        if not nist_file.exists():
            return {"status": "NOT_FOUND", "message": "NIST report not found"}

        try:
            with open(nist_file) as f:
                report = json.load(f)

            # Extract key NIST metrics
            sources = {}
            for source_name, source_data in report.items():
                if isinstance(source_data, dict):
                    # Count passed/failed tests
                    online_health = source_data.get("online_health", [])
                    iid_tests = source_data.get("iid_tests", [])

                    online_passed = sum(1 for t in online_health if t.get("passed", False))
                    iid_passed = sum(1 for t in iid_tests if t.get("iid", False))

                    sources[source_name] = {
                        "online_health": {
                            "total": len(online_health),
                            "passed": online_passed,
                            "tests": online_health
                        },
                        "iid_tests": {
                            "total": len(iid_tests),
                            "passed": iid_passed,
                            "tests": [
                                {
                                    "name": t.get("test", "Unknown"),
                                    "passed": t.get("iid", False),
                                    "p_value": t.get("p_value", None),
                                    "statistic": t.get("statistic", None)
                                }
                                for t in iid_tests
                            ]
                        }
                    }

            return {
                "status": "SUCCESS",
                "sources": sources,
                "total_sources": len(sources)
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _process_entropy_tests(self) -> Dict[str, Any]:
        """Extract entropy test metrics."""
        entropy_file = self.results_dir / "per_move_generation.json"
        if not entropy_file.exists():
            return {"status": "NOT_FOUND"}

        try:
            with open(entropy_file) as f:
                data = json.load(f)

            if isinstance(data, dict) and "entropy_samples" in data:
                samples = data["entropy_samples"]
                if samples:
                    stats = {
                        "min_bits_per_byte": min(s.get("bits_per_byte", 0) for s in samples),
                        "max_bits_per_byte": max(s.get("bits_per_byte", 0) for s in samples),
                        "mean_bits_per_byte": sum(s.get("bits_per_byte", 0) for s in samples) / len(samples),
                        "total_samples": len(samples)
                    }
                    return {
                        "status": "SUCCESS",
                        "statistics": stats,
                        "sample_count": len(samples)
                    }

            return {"status": "EMPTY"}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _process_research_evidence(self) -> Dict[str, Any]:
        """Extract research evidence results."""
        evidence_file = self.results_dir / "research_evidence.json"
        if not evidence_file.exists():
            return {"status": "NOT_FOUND"}

        try:
            with open(evidence_file) as f:
                data = json.load(f)

            claims = []
            if "claim_matrix" in data:
                cm = data["claim_matrix"]
                claims_passed = sum(1 for exp in data.get("experiments", {}).values()
                                   if exp.get("passed", False))
                claims_total = len(data.get("experiments", {}))

                return {
                    "status": "SUCCESS",
                    "claim_matrix": {
                        "total": cm.get("claim_count", 0),
                        "passed": claims_passed if claims_total > 0 else 0,
                        "claim_count": claims_total
                    },
                    "experiments": {
                        name: {
                            "name": name,
                            "passed": exp.get("passed", False),
                            "description": exp.get("description", "")
                        }
                        for name, exp in data.get("experiments", {}).items()
                    }
                }

            return {"status": "EMPTY"}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _process_moat_report(self) -> Dict[str, Any]:
        """Extract MOAT test results."""
        moat_file = self.results_dir / "moat_report.json"
        if not moat_file.exists():
            return {"status": "NOT_FOUND"}

        try:
            with open(moat_file) as f:
                report = json.load(f)

            if isinstance(report, dict) and isinstance(report.get("areas"), list):
                areas = report["areas"]
                passed = sum(1 for item in areas if item.get("passed", False))
                return {
                    "status": "SUCCESS",
                    "total_tests": len(areas),
                    "passed": passed,
                    "failed": len(areas) - passed,
                    "pass_rate": (passed / len(areas) * 100) if areas else 0,
                    "tests": [
                        {
                            "id": item.get("id", ""),
                            "name": item.get("name", item.get("id", "Unknown")),
                            "passed": item.get("passed", False),
                            "duration_ms": item.get("duration_ms", "n/a"),
                            "thesis": item.get("thesis", ""),
                        }
                        for item in areas
                    ]
                }

            if isinstance(report, list):
                passed = sum(1 for item in report if item.get("passed", False))
                return {
                    "status": "SUCCESS",
                    "total_tests": len(report),
                    "passed": passed,
                    "failed": len(report) - passed,
                    "pass_rate": (passed / len(report) * 100) if report else 0,
                    "tests": [
                        {
                            "name": item.get("test_name", "Unknown"),
                            "passed": item.get("passed", False),
                            "duration_ms": item.get("duration_ms", 0)
                        }
                        for item in report
                    ]
                }
            return {"status": "EMPTY"}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _process_tier1_features(self) -> Dict[str, Any]:
        """Extract Tier 1 feature validation results."""
        tier1_file = self.results_dir / "tier1_validation_report.json"
        if not tier1_file.exists():
            return {"status": "NOT_FOUND"}

        try:
            with open(tier1_file) as f:
                report = json.load(f)

            features = {}
            for feature_name, feature_data in report.items():
                if isinstance(feature_data, dict):
                    features[feature_name] = {
                        "passed": feature_data.get("passed", False),
                        "description": feature_data.get("description", ""),
                        "test_count": len(feature_data.get("tests", []))
                    }

            passed = sum(1 for f in features.values() if f.get("passed"))
            return {
                "status": "SUCCESS",
                "total_features": len(features),
                "passed": passed,
                "features": features
            }
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _compute_summary(self) -> None:
        """Compute overall summary statistics."""
        summary = {
            "overall_status": "PASS",
            "test_suites": [],
            "critical_issues": 0,
            "warnings": 0,
            "last_updated": self.data["timestamp"]
        }

        # Analyze NIST results
        nist = self.data["nist_800_90b"]
        if nist.get("status") == "SUCCESS":
            total_tests = sum(
                source.get("online_health", {}).get("total", 0) +
                source.get("iid_tests", {}).get("total", 0)
                for source in nist.get("sources", {}).values()
            )
            total_passed = sum(
                source.get("online_health", {}).get("passed", 0) +
                source.get("iid_tests", {}).get("passed", 0)
                for source in nist.get("sources", {}).values()
            )
            summary["test_suites"].append({
                "name": "NIST 800-90B",
                "status": "PASS" if total_passed == total_tests else "PARTIAL",
                "passed": total_passed,
                "total": total_tests
            })

        # Analyze research evidence
        evidence = self.data["research_evidence"]
        if evidence.get("status") == "SUCCESS":
            cm = evidence.get("claim_matrix", {})
            summary["test_suites"].append({
                "name": "Research Evidence",
                "status": "PASS" if cm.get("passed") == cm.get("claim_count") else "PARTIAL",
                "passed": cm.get("passed", 0),
                "total": cm.get("claim_count", 0)
            })

        # Analyze MOAT
        moat = self.data["moat_report"]
        if moat.get("status") == "SUCCESS":
            summary["test_suites"].append({
                "name": "MOAT Tests",
                "status": "PASS" if moat.get("passed") == moat.get("total_tests") else "PARTIAL",
                "passed": moat.get("passed", 0),
                "total": moat.get("total_tests", 0)
            })

        # Check for failures
        for suite in summary["test_suites"]:
            if suite["status"] != "PASS":
                summary["overall_status"] = "PARTIAL"
                if suite["status"] == "FAIL":
                    summary["critical_issues"] += 1

        self.data["summary"] = summary

    def to_json(self) -> str:
        """Export as JSON."""
        return json.dumps(self.data, indent=2, default=str)

    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary."""
        return self.data

    def save(self, filepath: str = "dashboard_data.json") -> None:
        """Save dashboard data to file."""
        with open(filepath, "w") as f:
            f.write(self.to_json())
        print(f"Dashboard data saved to {filepath}")


def main():
    """Generate and save dashboard data."""
    processor = DashboardDataProcessor("results")
    processor.save("dashboard_data.json")
    print("\n" + "=" * 60)
    print("Dashboard Data Summary")
    print("=" * 60)
    summary = processor.data["summary"]
    print(f"Overall Status: {summary['overall_status']}")
    print(f"Test Suites: {len(summary['test_suites'])}")
    for suite in summary["test_suites"]:
        print(f"  - {suite['name']}: {suite['passed']}/{suite['total']} passed")


if __name__ == "__main__":
    main()
