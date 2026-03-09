"""pip-audit scanner adapter - Python dependency vulnerability scanning."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.detect import find_python_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class PipAuditTool(ToolBase):
    name = "pip-audit"
    description = "Scan Python dependencies for known vulnerabilities"
    cli_command = "pip-audit"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_python_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "Install pip-audit:\n"
            "  pip install pip-audit\n"
            "  Or see https://github.com/pypa/pip-audit"
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
                args = ["pip-audit", "--format", "json", "--requirement", req_file]
            else:
                args = ["pip-audit", "--format", "json"]

            proc = self._run_cmd(args, cwd=py_dir, timeout=180)

            raw_output = proc.stdout or proc.stderr or ""
            self._save_raw(raw_dir, f"pip_audit_{rel_tag}.json", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        location_suffix = "" if rel_dir == "." else f" ({rel_dir})"

        for dep in data.get("dependencies", []):
            pkg_name = dep.get("name", "unknown")
            pkg_version = dep.get("version", "?")
            vulns = dep.get("vulns", [])

            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                fix_versions = vuln.get("fix_versions", [])
                description = vuln.get("description", vuln_id)
                aliases = vuln.get("aliases", [])

                fix_str = ", ".join(fix_versions) if fix_versions else "No fix available"
                refs = [f"https://osv.dev/vulnerability/{vuln_id}"]
                for alias in aliases:
                    if alias.startswith("CVE-"):
                        refs.append(f"https://nvd.nist.gov/vuln/detail/{alias}")

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.DEPENDENCY,
                        severity="high",
                        title=f"{vuln_id}: {description[:120]}",
                        location=f"{pkg_name}=={pkg_version}{location_suffix}",
                        evidence=f"Aliases: {', '.join(aliases)}" if aliases else "",
                        remediation=f"Upgrade {pkg_name} to {fix_str}",
                        references=refs[:5],
                    )
                )

        return findings
