"""Grype vulnerability scanner adapter."""

from __future__ import annotations

import json
from typing import List

from secscan.core.detect import find_project_files
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase

_GRYPE_MARKERS = (
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "composer.json",
    "Gemfile",
    "Dockerfile",
    "dockerfile",
    "Containerfile",
    "Dockerfile.*",
    "dockerfile.*",
    "Containerfile.*",
)


class GrypeTool(ToolBase):
    name = "Grype"
    description = "Filesystem and container package vulnerability scanner"
    cli_command = "grype"

    def is_applicable(self, project_path: str) -> bool:
        exact = [name for name in _GRYPE_MARKERS if "*" not in name]
        patterns = [name for name in _GRYPE_MARKERS if "*" in name]
        return bool(find_project_files(project_path, names=exact, patterns=patterns))

    def install_instructions(self) -> str:
        return (
            "Install Grype:\n"
            "  Windows: winget install Anchore.Grype\n"
            "  macOS: brew install grype\n"
            "  Or see https://github.com/anchore/grype"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(
            ["grype", f"dir:{project_path}", "-o", "json"],
            timeout=900,
        )

        raw_output = proc.stdout or proc.stderr or ""
        self._save_raw(raw_dir, "grype.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        for match in data.get("matches", []):
            artifact = match.get("artifact", {})
            vuln = match.get("vulnerability", {})
            package_name = artifact.get("name", "unknown")
            package_version = artifact.get("version", "?")
            locations = artifact.get("locations", []) or []
            location = locations[0].get("path", "") if locations else ""
            fix_versions = ", ".join(vuln.get("fix", {}).get("versions", [])[:5])
            refs = [link for link in vuln.get("urls", []) if link]
            description = str(vuln.get("description") or "")
            title = vuln.get("id", "unknown") if not description else f"{vuln.get('id', 'unknown')}: {description[:120]}"

            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.DEPENDENCY,
                    severity=vuln.get("severity", "medium"),
                    title=title,
                    location=location or f"{package_name}@{package_version}",
                    evidence=f"{package_name}@{package_version}",
                    remediation=f"Upgrade to one of: {fix_versions}" if fix_versions else "No fixed version listed by Grype.",
                    references=refs[:5],
                )
            )

        return findings
