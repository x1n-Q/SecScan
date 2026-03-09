"""kube-bench Kubernetes benchmark adapter."""

from __future__ import annotations

import json
from typing import List

from secscan.core.detect import find_kubernetes_files
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class KubeBenchTool(ToolBase):
    name = "Kube-bench"
    description = "Kubernetes CIS benchmark checks for cluster and node security"
    cli_command = "kube-bench"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_kubernetes_files(project_path))

    def install_instructions(self) -> str:
        return (
            "Install kube-bench:\n"
            "  See https://github.com/aquasecurity/kube-bench\n"
            "This scanner audits the current host/cluster, not YAML files directly."
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        proc = self._run_cmd(["kube-bench", "--json"], timeout=1800)

        raw_output = proc.stdout or proc.stderr or ""
        self._save_raw(raw_dir, "kube_bench.json", raw_output)

        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        controls = data.get("Controls", []) or data.get("controls", [])
        for control in controls:
            for test in control.get("tests", []):
                for result in test.get("results", []):
                    status = str(result.get("status", "")).upper()
                    if status not in {"FAIL", "WARN"}:
                        continue

                    severity = "high" if status == "FAIL" else "medium"
                    refs = result.get("references", []) or []
                    if isinstance(refs, str):
                        refs = [refs]

                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.KUBERNETES,
                            severity=severity,
                            title=f"{result.get('test_number', test.get('test_number', 'check'))}: {result.get('test_desc', test.get('desc', 'Kubernetes benchmark finding'))}",
                            location=result.get("node_type", "cluster"),
                            evidence=f"Status: {status}",
                            remediation=result.get("remediation", "Apply the Kubernetes benchmark recommendation."),
                            references=refs[:5] if isinstance(refs, list) else [],
                        )
                    )

        return findings
