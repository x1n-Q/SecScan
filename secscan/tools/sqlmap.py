"""Sqlmap SQL injection scanner adapter."""

from __future__ import annotations

import os
from typing import List

from secscan.core.schema import Finding, Category, Severity
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class SqlmapTool(ToolBase):
    name = "Sqlmap"
    description = "SQL injection vulnerability scanner"
    cli_command = "sqlmap"
    requires_website = True

    def is_applicable(self, project_path: str) -> bool:
        # Sqlmap is applicable to projects with a website URL
        return True

    def install_instructions(self) -> str:
        return (
            "Install Sqlmap:\n"
            "  Debian/Ubuntu: apt install sqlmap\n"
            "  macOS: brew install sqlmap\n"
            "  Windows: Download from https://sqlmap.org/"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        report_file = os.path.join(raw_dir, "sqlmap.txt") if raw_dir else "sqlmap.txt"

        proc = self._run_cmd(
            [
                "sqlmap", "-u", website_url, "--batch", "--smart", "-v", "1",
                "--output-dir", os.path.dirname(report_file) if raw_dir else "."
            ],
            timeout=600,
        )

        self._save_raw(raw_dir, "sqlmap_log.txt", (proc.stdout or "") + (proc.stderr or ""))

        findings: List[Finding] = []

        # Sqlmap stores results in structured directories
        # We'll check the log file for signs of SQL injection
        log_content = (proc.stdout or "") + (proc.stderr or "")

        if "sql injection" in log_content.lower() or "vulnerable" in log_content.lower():
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.WEB,
                    severity=Severity.CRITICAL,
                    title="Possible SQL Injection Vulnerability",
                    location=website_url,
                    evidence=log_content[:500],  # Take first 500 chars as evidence
                    remediation=(
                        "Validate and sanitize all user input. "
                        "Use prepared statements or parameterized queries."
                    ),
                    references=["https://sqlmap.org/"],
                )
            )

        return findings
