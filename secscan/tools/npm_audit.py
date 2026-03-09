"""npm audit scanner adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.detect import find_npm_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class NpmAuditTool(ToolBase):
    name = "npm audit"
    description = "Scan Node.js dependencies for known vulnerabilities"
    cli_command = "npm"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_npm_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "Install Node.js (https://nodejs.org) which includes npm.\n"
            "Verify with: npm --version"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []
        npm_projects = find_npm_projects(project_path)

        for npm_dir in npm_projects:
            proc = self._run_cmd(
                ["npm", "audit", "--json"],
                cwd=npm_dir,
                timeout=180,
            )

            raw_output = proc.stdout or proc.stderr or ""
            rel_dir = os.path.relpath(npm_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            self._save_raw(raw_dir, f"npm_audit_{rel_tag}.json", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        location_suffix = "(root)" if rel_dir == "." else f"({rel_dir})"
        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln in vulnerabilities.items():
            severity = vuln.get("severity", "info")
            via_list = vuln.get("via", [])

            # "via" can be a list of dicts or strings.
            for via in via_list:
                if isinstance(via, str):
                    title = f"Vulnerable dependency: {pkg_name} (via {via})"
                    recommendation = vuln.get("fixAvailable", "Update the package")
                    if isinstance(recommendation, dict):
                        fix_name = recommendation.get("name", "")
                        fix_ver = recommendation.get("version", "")
                        recommendation = f"Update {fix_name} to {fix_ver}"
                    elif isinstance(recommendation, bool):
                        recommendation = (
                            "A fix is available - run 'npm audit fix'"
                            if recommendation
                            else "No automatic fix available"
                        )
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.DEPENDENCY,
                            severity=severity,
                            title=title,
                            location=f"{pkg_name} {location_suffix}",
                            remediation=str(recommendation),
                        )
                    )
                elif isinstance(via, dict):
                    title = via.get("title", f"Vulnerability in {pkg_name}")
                    url = via.get("url", "")
                    sev = via.get("severity", severity)
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.DEPENDENCY,
                            severity=sev,
                            title=title,
                            location=f"{pkg_name} {location_suffix}",
                            evidence=f"Range: {via.get('range', 'N/A')}",
                            remediation=f"Update {pkg_name}",
                            references=[url] if url else [],
                        )
                    )
        return findings
