"""Safety scanner adapter - Python dependency vulnerability scanning."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.detect import find_python_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class SafetyScanTool(ToolBase):
    name = "Safety"
    description = "Check Python dependencies against the Safety vulnerability database"
    cli_command = "safety"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_python_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "Install Safety:\n"
            "  pip install safety\n"
            "  Or see https://github.com/pyupio/safety"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []

        for py_dir in find_python_projects(project_path):
            rel_dir = os.path.relpath(py_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            req_file = os.path.join(py_dir, "requirements.txt")

            if os.path.isfile(req_file):
                args = ["safety", "check", "--file", req_file, "--json"]
            else:
                args = ["safety", "check", "--json"]

            proc = self._run_cmd(args, cwd=py_dir, timeout=120)

            raw_output = proc.stdout or proc.stderr or ""
            self._save_raw(raw_dir, f"safety_{rel_tag}.json", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        vulns = []
        if isinstance(data, list):
            vulns = data
        elif isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])

        location_suffix = "" if rel_dir == "." else f" ({rel_dir})"

        for vuln in vulns:
            if isinstance(vuln, list) and len(vuln) >= 5:
                pkg_name = vuln[0]
                installed = vuln[1]
                affected = vuln[2]
                vuln_id = str(vuln[3])
                advisory = vuln[4] if len(vuln) > 4 else ""

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.DEPENDENCY,
                        severity="high",
                        title=f"{vuln_id}: {advisory[:120]}",
                        location=f"{pkg_name}=={installed}{location_suffix}",
                        evidence=f"Affected spec: {affected}",
                        remediation=f"Upgrade {pkg_name} to a non-affected version.",
                        references=[f"https://pyup.io/vulnerabilities/{vuln_id}/"],
                    )
                )
            elif isinstance(vuln, dict):
                pkg_name = vuln.get("package_name", "unknown")
                installed = vuln.get("analyzed_version", "?")
                vuln_id = vuln.get("vulnerability_id", "")
                advisory = vuln.get("advisory", "")
                severity = vuln.get("severity", "high")
                cve = vuln.get("CVE", "")

                refs = []
                if cve:
                    refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
                more_info = vuln.get("more_info_path", "")
                if more_info:
                    refs.append(more_info)

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.DEPENDENCY,
                        severity=severity or "high",
                        title=f"{vuln_id}: {advisory[:120]}",
                        location=f"{pkg_name}=={installed}{location_suffix}",
                        evidence=f"CVE: {cve}" if cve else "",
                        remediation=f"Upgrade {pkg_name} to a patched version.",
                        references=refs[:5],
                    )
                )

        return findings
