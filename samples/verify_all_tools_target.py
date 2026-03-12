"""Verify that the sample target enables the expected non-website tools."""

from __future__ import annotations

import os
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secscan.tools import ALL_TOOLS

def main() -> int:
    sample_root = Path(__file__).resolve().parent / "all-tools-target"
    expected = {
        "npm audit",
        "Bandit",
        "bundler-audit",
        "cargo-audit",
        "Composer Audit",
        "OWASP Dependency-Check",
        "OSV-Scanner",
        "Grype",
        "govulncheck",
        "CycloneDX SBOM",
        "Gitleaks",
        "Semgrep",
        "Trivy",
        "Checkov",
        "pip-audit",
        "Safety",
    }
    if os.name != "nt":
        expected.add("Kube-bench")
        expected.add("Lynis")

    actual = {
        tool.name
        for tool in ALL_TOOLS
        if not tool.requires_website and tool.is_applicable(str(sample_root))
    }

    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)

    print(f"Sample target: {sample_root}")
    print("Applicable non-website tools:")
    for name in sorted(actual):
        print(f"  - {name}")

    if missing:
        print("\nMissing expected tools:")
        for name in missing:
            print(f"  - {name}")

    if unexpected:
        print("\nAdditional tools detected:")
        for name in unexpected:
            print(f"  - {name}")

    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
