"""OWASP ZAP web vulnerability scanner adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.schema import Finding, Category, Severity
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class ZapTool(ToolBase):
    name = "OWASP ZAP"
    description = "Web vulnerability scanner"
    cli_command = "zap-cli"

    def is_applicable(self, project_path: str) -> bool:
        # ZAP is applicable to projects with a website URL
        return True

    def install_instructions(self) -> str:
        return (
            "Install OWASP ZAP and zap-cli:\n"
            "  Download ZAP from https://www.zaproxy.org/download/\n"
            "  Install zap-cli: pip install zapcli"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        report_file = os.path.join(raw_dir, "zap.json") if raw_dir else "zap.json"

        proc = self._run_cmd(
            [
                "zap-cli", "quick-scan",
                "--spider",
                "--recursive",
                "--risk-level", "high",
                "--scan-policy", "Default Policy",
                "--format", "json",
                "--output", report_file,
                website_url,
            ],
            timeout=600,
        )

        self._save_raw(raw_dir, "zap_log.txt", (proc.stdout or "") + (proc.stderr or ""))

        findings: List[Finding] = []

        if not os.path.isfile(report_file):
            return findings

        try:
            with open(report_file, "r", encoding="utf-8") as fh:
                scan_data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return findings

        if "alerts" in scan_data:
            for alert in scan_data["alerts"]:
                title = alert.get("name", "Unknown Alert")
                description = alert.get("description", "")
                severity = alert.get("risk", "Medium").upper()
                url = alert.get("url", "")
                evidence = alert.get("evidence", "")
                category = alert.get("pluginId", "web-vulnerability")

                # Map ZAP severity to our Severity enum
                if severity == "HIGH":
                    normalized_severity = Severity.HIGH
                elif severity == "MEDIUM":
                    normalized_severity = Severity.MEDIUM
                elif severity == "LOW":
                    normalized_severity = Severity.LOW
                else:
                    normalized_severity = Severity.INFO

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.WEB,
                        severity=normalized_severity,
                        title=title,
                        location=url,
                        evidence=evidence,
                        remediation=alert.get("solution", ""),
                        references=[alert.get("reference", "")] if alert.get("reference") else [],
                    )
                )

        return findings
