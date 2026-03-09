"""CycloneDX SBOM generation adapter (npm)."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.detect import find_npm_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class CycloneDxSbomTool(ToolBase):
    name = "CycloneDX SBOM"
    description = "Generate a Software Bill of Materials (SBOM) for Node.js projects"
    cli_command = "npx"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_npm_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "CycloneDX is run via npx (included with npm).\n"
            "Ensure Node.js and npm are installed: https://nodejs.org"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []

        for npm_dir in find_npm_projects(project_path):
            rel_dir = os.path.relpath(npm_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            out_file = os.path.join(raw_dir, f"sbom_{rel_tag}.json") if raw_dir else f"sbom_{rel_tag}.json"

            proc = self._run_cmd(
                [
                    "npx",
                    "--yes",
                    "@cyclonedx/cyclonedx-npm",
                    "--output-file",
                    out_file,
                    "--spec-version",
                    "1.5",
                    "--output-reproducible",
                ],
                cwd=npm_dir,
                timeout=180,
            )

            combined = (proc.stdout or "") + (proc.stderr or "")
            self._save_raw(raw_dir, f"cyclonedx_{rel_tag}_log.txt", combined)

            location = out_file if rel_dir == "." else f"{rel_dir} -> {out_file}"
            title_suffix = "root" if rel_dir == "." else rel_dir

            if os.path.isfile(out_file):
                try:
                    with open(out_file, "r", encoding="utf-8") as fh:
                        sbom = json.load(fh)
                    comp_count = len(sbom.get("components", []))
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.SBOM,
                            severity="info",
                            title=f"SBOM generated for {title_suffix} - {comp_count} component(s)",
                            location=location,
                            evidence=f"Spec version: {sbom.get('specVersion', '?')}",
                            remediation="Review the SBOM for completeness.",
                        )
                    )
                except Exception:
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.SBOM,
                            severity="info",
                            title=f"SBOM file generated for {title_suffix} (could not parse)",
                            location=location,
                        )
                    )
            else:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.SBOM,
                        severity="low",
                        title=f"SBOM generation failed for {title_suffix}",
                        location=rel_dir,
                        evidence=combined[:500],
                        remediation="Ensure npm dependencies are installed (npm install).",
                    )
                )

        return findings
