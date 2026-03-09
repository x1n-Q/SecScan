"""Trivy container / filesystem scanner adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.detect import find_project_files
from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class TrivyTool(ToolBase):
    name = "Trivy"
    description = "Scan container images and filesystems for vulnerabilities"
    cli_command = "trivy"

    def is_applicable(self, project_path: str) -> bool:
        return bool(
            find_project_files(
                project_path,
                patterns=(
                    "Dockerfile",
                    "dockerfile",
                    "Containerfile",
                    "Dockerfile.*",
                    "dockerfile.*",
                    "Containerfile.*",
                ),
            )
        )

    def install_instructions(self) -> str:
        return (
            "Install Trivy:\n"
            "  brew install trivy             (macOS)\n"
            "  choco install trivy            (Windows)\n"
            "  Or see https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(
            [
                "trivy", "fs",
                "--format", "json",
                "--scanners", "vuln,secret,misconfig",
                project_path,
            ],
            timeout=300,
        )

        raw_output = proc.stdout or ""
        self._save_raw(raw_dir, "trivy.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        for result in data.get("Results", []):
            target = result.get("Target", "")

            # Vulnerabilities
            for vuln in result.get("Vulnerabilities", []) or []:
                vuln_id = vuln.get("VulnerabilityID", "")
                pkg = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                sev = vuln.get("Severity", "MEDIUM")
                title = vuln.get("Title", vuln_id)
                refs = vuln.get("References", []) or []

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.CONTAINER,
                        severity=sev,
                        title=f"{vuln_id}: {title}",
                        location=f"{target} – {pkg}@{installed}",
                        evidence=f"Fixed in: {fixed}" if fixed else "",
                        remediation=f"Update {pkg} to {fixed}" if fixed else "No fix available yet.",
                        references=refs[:5],
                    )
                )

            # Misconfigurations
            for misconf in result.get("Misconfigurations", []) or []:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.CONTAINER,
                        severity=misconf.get("Severity", "MEDIUM"),
                        title=misconf.get("Title", misconf.get("ID", "")),
                        location=target,
                        evidence=misconf.get("Message", ""),
                        remediation=misconf.get("Resolution", ""),
                        references=misconf.get("References", [])[:5],
                    )
                )

            # Secrets
            for secret in result.get("Secrets", []) or []:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.SECRETS,
                        severity=secret.get("Severity", "HIGH"),
                        title=f"Secret found: {secret.get('Title', 'unknown')}",
                        location=f"{target}:{secret.get('StartLine', '?')}",
                        remediation="Remove the secret and rotate the credential.",
                    )
                )

        return findings
