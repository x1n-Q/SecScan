"""Checkov Infrastructure-as-Code scanner adapter."""

from __future__ import annotations

import json
from typing import List

from secscan.core.detect import find_project_files
from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class CheckovTool(ToolBase):
    name = "Checkov"
    description = "Scan Infrastructure-as-Code files for misconfigurations"
    cli_command = "checkov"

    _IAC_MARKERS = (
        "main.tf",
        "*.tf",
        "*.tfvars",
        "template.yaml",
        "serverless.yml",
        "ansible.cfg",
        "playbook.yml",
        "cloudformation",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "render.yaml",
        "vercel.json",
        "Chart.yaml",
        "values.yaml",
        "*.k8s.yaml",
        "*.k8s.yml",
        "*deployment*.yaml",
        "*deployment*.yml",
        "*service*.yaml",
        "*service*.yml",
        "*ingress*.yaml",
        "*ingress*.yml",
        "*daemonset*.yaml",
        "*daemonset*.yml",
        "*statefulset*.yaml",
        "*statefulset*.yml",
    )

    def is_applicable(self, project_path: str) -> bool:
        exact = [marker for marker in self._IAC_MARKERS if not marker.startswith("*")]
        patterns = [marker for marker in self._IAC_MARKERS if marker.startswith("*")]
        return bool(find_project_files(project_path, names=exact, patterns=patterns))

    def install_instructions(self) -> str:
        return (
            "Install Checkov:\n"
            "  pip install checkov\n"
            "  Or see https://www.checkov.io/2.Basics/Installing%20Checkov.html"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(
            [
                "checkov",
                "--directory", project_path,
                "--output", "json",
                "--quiet",
                "--compact",
            ],
            timeout=300,
        )

        raw_output = proc.stdout or ""
        self._save_raw(raw_dir, "checkov.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        # Checkov may return a list or a single dict
        results_list = data if isinstance(data, list) else [data]

        for block in results_list:
            for check_type_key in ("failed_checks", ):
                checks = block.get("results", {}).get(check_type_key, [])
                for chk in checks:
                    check_id = chk.get("check_id", "")
                    name = chk.get("name", check_id)
                    file_path = chk.get("file_path", "")
                    resource = chk.get("resource", "")
                    guideline = chk.get("guideline", "")

                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.IAC,
                            severity="medium",
                            title=f"{check_id}: {name}",
                            location=f"{file_path} ({resource})",
                            remediation=guideline or "Fix the IaC misconfiguration.",
                            references=[guideline] if guideline.startswith("http") else [],
                        )
                    )

        return findings
