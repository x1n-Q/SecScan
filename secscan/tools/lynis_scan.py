"""Lynis system audit adapter."""

from __future__ import annotations

import os
import shutil
from typing import List

from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class LynisTool(ToolBase):
    name = "Lynis"
    description = "Linux host security audit and hardening checks"
    cli_command = "lynis"

    def is_applicable(self, project_path: str) -> bool:
        return os.name != "nt"

    def install_instructions(self) -> str:
        return (
            "Install Lynis on Linux/macOS:\n"
            "  Debian/Ubuntu: apt install lynis\n"
            "  macOS: brew install lynis\n"
            "This scanner audits the current machine, not just the selected folder."
        )

    def install_commands(self) -> List[List[str]]:
        if os.name == "nt":
            return []
        commands: List[List[str]] = []
        if shutil.which("brew"):
            commands.append(["brew", "install", "lynis"])
        if shutil.which("apt-get"):
            commands.append(["apt-get", "update"])
            commands.append(["apt-get", "install", "-y", "lynis"])
        if shutil.which("dnf"):
            commands.append(["dnf", "install", "-y", "lynis"])
        if shutil.which("yum"):
            commands.append(["yum", "install", "-y", "lynis"])
        if shutil.which("pacman"):
            commands.append(["pacman", "-Sy", "--noconfirm", "lynis"])
        return commands

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if os.name == "nt":
            return []

        report_file = os.path.join(raw_dir, "lynis_report.dat") if raw_dir else "lynis_report.dat"
        log_file = os.path.join(raw_dir, "lynis.log") if raw_dir else "lynis.log"
        proc = self._run_cmd(
            [
                "lynis",
                "audit",
                "system",
                "--quick",
                "--no-colors",
                "--report-file",
                report_file,
                "--log-file",
                log_file,
            ],
            timeout=2400,
        )

        self._save_raw(raw_dir, "lynis_cmd_output.txt", (proc.stdout or "") + (proc.stderr or ""))
        if not os.path.isfile(report_file):
            return []

        findings: List[Finding] = []
        try:
            with open(report_file, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    text = line.strip()
                    if text.startswith("warning[]="):
                        value = text.split("=", 1)[1]
                        findings.append(
                            make_finding(
                                tool=self.name,
                                category=Category.SYSTEM,
                                severity="high",
                                title=value[:160],
                                location="system",
                                remediation="Apply the Lynis warning recommendation on the audited host.",
                            )
                        )
                    elif text.startswith("suggestion[]="):
                        value = text.split("=", 1)[1]
                        findings.append(
                            make_finding(
                                tool=self.name,
                                category=Category.SYSTEM,
                                severity="medium",
                                title=value[:160],
                                location="system",
                                remediation="Review the Lynis suggestion and harden the host if applicable.",
                            )
                        )
        except OSError:
            return []

        return findings
