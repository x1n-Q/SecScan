"""Semgrep static analysis adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class SemgrepTool(ToolBase):
    name = "Semgrep"
    description = "Static application security testing (SAST) using Semgrep rules"
    cli_command = "semgrep"

    def is_applicable(self, project_path: str) -> bool:
        # Semgrep supports many languages – always applicable
        return True

    def install_instructions(self) -> str:
        return (
            "Install Semgrep:\n"
            "  pip install semgrep\n"
            "  Or see https://semgrep.dev/docs/getting-started/"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(
            [
                "semgrep", "scan",
                "--config", "auto",
                "--json",
                "--quiet",
                project_path,
            ],
            timeout=600,
        )

        raw_output = proc.stdout or ""
        self._save_raw(raw_dir, "semgrep.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        for result in data.get("results", []):
            check_id = result.get("check_id", "")
            message = result.get("extra", {}).get("message", check_id)
            severity = result.get("extra", {}).get("severity", "WARNING")
            file_path = result.get("path", "")
            start_line = result.get("start", {}).get("line", "?")
            end_line = result.get("end", {}).get("line", "?")
            matched_code = result.get("extra", {}).get("lines", "")
            metadata = result.get("extra", {}).get("metadata", {})
            refs = metadata.get("references", [])
            if isinstance(refs, str):
                refs = [refs]

            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.SAST,
                    severity=severity,
                    title=f"{check_id}: {message[:120]}",
                    location=f"{file_path}:{start_line}-{end_line}",
                    evidence=str(matched_code)[:300],
                    remediation=metadata.get("fix", "Review and fix the flagged code pattern."),
                    references=refs[:5] if isinstance(refs, list) else [],
                )
            )

        return findings
