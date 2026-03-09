"""OWASP Dependency-Check adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.detect import find_project_files
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase

_DEPENDENCY_MARKERS = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "*.csproj",
    "*.sln",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "Cargo.toml",
)


class DependencyCheckTool(ToolBase):
    name = "OWASP Dependency-Check"
    description = "Multi-ecosystem dependency vulnerability scanner"
    cli_command = "dependency-check"

    def is_applicable(self, project_path: str) -> bool:
        exact = [name for name in _DEPENDENCY_MARKERS if "*" not in name]
        patterns = [name for name in _DEPENDENCY_MARKERS if "*" in name]
        return bool(find_project_files(project_path, names=exact, patterns=patterns))

    def install_instructions(self) -> str:
        return (
            "Install OWASP Dependency-Check:\n"
            "  Windows: winget install OWASP.DependencyCheck\n"
            "  macOS: brew install dependency-check\n"
            "  Or download from https://owasp.org/www-project-dependency-check/"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        output_dir = raw_dir or project_path
        proc = self._run_cmd(
            [
                "dependency-check",
                "--scan",
                project_path,
                "--format",
                "JSON",
                "--out",
                output_dir,
                "--project",
                os.path.basename(os.path.abspath(project_path)) or "secscan-project",
            ],
            timeout=1800,
        )

        self._save_raw(raw_dir, "dependency_check_log.txt", (proc.stdout or "") + (proc.stderr or ""))
        report_file = os.path.join(output_dir, "dependency-check-report.json")
        if not os.path.isfile(report_file):
            return []

        try:
            with open(report_file, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []

        findings: List[Finding] = []
        for dep in data.get("dependencies", []):
            file_name = dep.get("fileName") or dep.get("filePath") or "unknown dependency"
            packages = ", ".join(pkg.get("id", "") for pkg in dep.get("packages", [])[:3] if pkg.get("id"))
            for vuln in dep.get("vulnerabilities", []) or []:
                vuln_name = vuln.get("name", "Unknown vulnerability")
                description = str(vuln.get("description") or "")
                severity = vuln.get("severity") or _score_to_severity(vuln)
                refs = [ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")]
                evidence = packages
                if vuln.get("source"):
                    evidence = f"Source: {vuln['source']}" + (f"\nPackages: {packages}" if packages else "")
                title = vuln_name if not description else f"{vuln_name}: {description[:120]}"

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.DEPENDENCY,
                        severity=severity,
                        title=title,
                        location=file_name,
                        evidence=evidence[:600],
                        remediation="Update or replace the affected dependency with a fixed version.",
                        references=refs[:5],
                    )
                )

        return findings


def _score_to_severity(vuln: dict) -> str:
    for key in ("cvssv3", "cvssv2"):
        metric = vuln.get(key) or {}
        score = metric.get("baseScore")
        if score is None:
            continue
        try:
            value = float(score)
        except (TypeError, ValueError):
            continue
        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"
        if value > 0:
            return "low"
    return "medium"
