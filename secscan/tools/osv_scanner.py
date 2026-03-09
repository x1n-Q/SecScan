"""OSV-Scanner adapter – scans dependencies against the OSV database."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class OsvScannerTool(ToolBase):
    name = "OSV-Scanner"
    description = "Scan project dependencies against the OSV vulnerability database"
    cli_command = "osv-scanner"

    def is_applicable(self, project_path: str) -> bool:
        # OSV-Scanner supports many ecosystems; always offer it
        return True

    def install_instructions(self) -> str:
        return (
            "Install OSV-Scanner:\n"
            "  go install github.com/google/osv-scanner/cmd/osv-scanner@latest\n"
            "Or download a binary from https://github.com/google/osv-scanner/releases"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(
            ["osv-scanner", "--format", "json", "--recursive", project_path],
            timeout=180,
        )

        raw_output = proc.stdout or proc.stderr or ""
        self._save_raw(raw_dir, "osv_scanner.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            source_path = result.get("source", {}).get("path", "")
            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                pkg_name = pkg_info.get("name", "unknown")
                pkg_version = pkg_info.get("version", "")
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "")
                    summary = vuln.get("summary", vuln_id)
                    severity = "medium"
                    # Try to extract severity from database_specific or severity list
                    sev_list = vuln.get("severity", [])
                    if sev_list:
                        score = sev_list[0].get("score", "")
                        # CVSS score string – just take the first word
                        severity = _cvss_to_severity(score)
                    refs = [
                        r.get("url", "")
                        for r in vuln.get("references", [])
                        if r.get("url")
                    ]
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.DEPENDENCY,
                            severity=severity,
                            title=f"{vuln_id}: {summary}",
                            location=f"{pkg_name}@{pkg_version} ({source_path})",
                            remediation="Update the affected package to a patched version.",
                            references=refs[:5],
                        )
                    )

        return findings


def _cvss_to_severity(score_str: str) -> str:
    """Rough CVSS v3 score-string to severity mapping."""
    try:
        # score_str might be "CVSS:3.1/AV:N/AC:L/..." or a float
        score = float(score_str)
    except (ValueError, TypeError):
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
