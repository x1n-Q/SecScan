"""Bandit Python SAST scanner adapter."""

from __future__ import annotations

import json
from typing import List

from secscan.core.detect import find_project_files
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class BanditTool(ToolBase):
    name = "Bandit"
    description = "Python security scanner for insecure code patterns"
    cli_command = "bandit"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_project_files(project_path, patterns=("*.py",)))

    def install_instructions(self) -> str:
        return (
            "Install Bandit:\n"
            "  pip install bandit\n"
            "  Or see https://bandit.readthedocs.io/"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(
            ["bandit", "-r", project_path, "-f", "json"],
            timeout=600,
        )

        raw_output = proc.stdout or proc.stderr or ""
        self._save_raw(raw_dir, "bandit.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        for issue in data.get("results", []):
            test_id = issue.get("test_id", "")
            issue_text = issue.get("issue_text", test_id or "Bandit finding")
            filename = issue.get("filename", "")
            line_number = issue.get("line_number", "?")
            severity = issue.get("issue_severity", "MEDIUM")
            confidence = issue.get("issue_confidence", "MEDIUM")
            more_info = issue.get("more_info", "")
            code = issue.get("code", "")

            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.SAST,
                    severity=severity,
                    title=f"{test_id}: {issue_text}" if test_id else issue_text,
                    location=f"{filename}:{line_number}",
                    evidence=f"Confidence: {confidence}\n{code}".strip()[:600],
                    remediation="Review the flagged Python code and replace the insecure pattern.",
                    references=[more_info] if more_info else [],
                )
            )

        return findings
