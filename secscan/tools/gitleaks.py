"""Gitleaks secrets scanner adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class GitleaksTool(ToolBase):
    name = "Gitleaks"
    description = "Scan repository for hardcoded secrets and credentials"
    cli_command = "gitleaks"

    def is_applicable(self, project_path: str) -> bool:
        # Secrets scanning is universally applicable
        return True

    def install_instructions(self) -> str:
        return (
            "Install Gitleaks:\n"
            "  brew install gitleaks          (macOS)\n"
            "  choco install gitleaks         (Windows)\n"
            "  Or download from https://github.com/gitleaks/gitleaks/releases"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        report_file = os.path.join(raw_dir, "gitleaks.json") if raw_dir else "gitleaks.json"

        proc = self._run_cmd(
            [
                "gitleaks", "detect",
                "--source", project_path,
                "--report-format", "json",
                "--report-path", report_file,
                "--no-git",
            ],
            timeout=300,
        )

        self._save_raw(raw_dir, "gitleaks_log.txt", "Raw output omitted for security reasons (preventing secret exposure).")

        findings: List[Finding] = []

        if not os.path.isfile(report_file):
            # Exit code 0 with no report means no leaks found
            return findings

        try:
            with open(report_file, "r", encoding="utf-8") as fh:
                leaks = json.load(fh)
            
            # Secure the stored report by masking secrets
            if isinstance(leaks, list):
                for leak in leaks:
                    if "Match" in leak:
                        match = str(leak["Match"])
                        if match:
                            leak["Match"] = match[:4] + "****" if len(match) > 4 else "****"
                        
            # Overwrite the unencrypted report file with the masked version
            with open(report_file, "w", encoding="utf-8") as fh:
                json.dump(leaks, fh, indent=2)

        except (json.JSONDecodeError, OSError):
            return findings

        if not isinstance(leaks, list):
            return findings

        for leak in leaks:
            rule_id = leak.get("RuleID", "unknown-rule")
            description = leak.get("Description", rule_id)
            file_path = leak.get("File", "")
            line = leak.get("StartLine", "?")
            masked = leak.get("Match", "****")

            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.SECRETS,
                    severity="high",
                    title=f"Secret detected: {description}",
                    location=f"{file_path}:{line}",
                    evidence=f"Matched pattern: {masked}",
                    remediation=(
                        "Remove the secret from source code. "
                        "Rotate the credential immediately. "
                        "Use environment variables or a secrets manager."
                    ),
                    references=["https://github.com/gitleaks/gitleaks"],
                )
            )

        return findings
