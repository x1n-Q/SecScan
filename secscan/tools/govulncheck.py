"""govulncheck scanner adapter."""

from __future__ import annotations

import json
import os
import shutil
from typing import Any, List

from secscan.core.detect import find_go_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class GovulncheckTool(ToolBase):
    name = "govulncheck"
    description = "Scan Go modules for reachable known vulnerabilities"
    cli_command = "govulncheck"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_go_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "Install govulncheck:\n"
            "  go install golang.org/x/vuln/cmd/govulncheck@latest\n"
            "Then ensure your Go bin directory is on PATH."
        )

    def install_commands(self) -> List[List[str]]:
        commands: List[List[str]] = []
        if self._resolve_executable("go") is None and os.name == "nt" and shutil.which("winget"):
            commands.append(
                [
                    "winget",
                    "install",
                    "--id",
                    "GoLang.Go",
                    "-e",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                ]
            )
        elif self._resolve_executable("go") is None and shutil.which("brew"):
            commands.append(["brew", "install", "go"])

        go_exe = self._resolve_executable("go") or "go"
        commands.append([go_exe, "install", "golang.org/x/vuln/cmd/govulncheck@latest"])
        return commands

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []

        for go_dir in find_go_projects(project_path):
            rel_dir = os.path.relpath(go_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            proc = self._run_cmd(
                ["govulncheck", "-json", "./..."],
                cwd=go_dir,
                timeout=600,
            )
            raw_output = proc.stdout or proc.stderr or ""
            self._save_raw(raw_dir, f"govulncheck_{rel_tag}.jsonl", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        osv_by_id: dict[str, dict[str, Any]] = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            osv = entry.get("osv")
            if isinstance(osv, dict):
                osv_id = str(osv.get("id") or "")
                if osv_id:
                    osv_by_id[osv_id] = osv
                continue

            finding = entry.get("finding")
            if not isinstance(finding, dict):
                continue

            osv_id = str(finding.get("osv") or finding.get("id") or "GO-VULN")
            osv = osv_by_id.get(osv_id, {})
            trace = finding.get("trace", [])
            package_name, location = _trace_details(trace)
            if not package_name:
                package_name = str(finding.get("package") or "go package")
            refs = [ref.get("url", "") for ref in osv.get("references", []) if isinstance(ref, dict) and ref.get("url")]
            summary = str(osv.get("summary") or osv.get("details") or osv_id)
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.DEPENDENCY,
                    severity=_severity_from_osv(osv),
                    title=f"{osv_id}: {summary[:120]}",
                    location=location or f"{package_name} ({rel_dir})",
                    evidence=package_name,
                    remediation="Upgrade the affected Go module to a fixed version and rebuild.",
                    references=refs[:5],
                )
            )

        return findings


def _trace_details(trace: Any) -> tuple[str, str]:
    if not isinstance(trace, list) or not trace:
        return "", ""

    package_name = ""
    location = ""
    for frame in trace:
        if not isinstance(frame, dict):
            continue
        function = frame.get("function")
        if isinstance(function, str) and function and not package_name:
            package_name = function.rsplit(".", 1)[0]
        position = frame.get("position")
        if isinstance(position, dict):
            filename = position.get("filename")
            line = position.get("line")
            if filename:
                location = f"{filename}:{line}" if line else str(filename)
                break
    return package_name, location


def _severity_from_osv(osv: dict[str, Any]) -> str:
    db_specific = osv.get("database_specific", {})
    if isinstance(db_specific, dict):
        severity = db_specific.get("severity")
        if isinstance(severity, str) and severity:
            return severity

    severities = osv.get("severity", [])
    if isinstance(severities, list):
        for entry in severities:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score")
            if not isinstance(score, str):
                continue
            try:
                numeric = float(score)
            except ValueError:
                continue
            if numeric >= 9.0:
                return "critical"
            if numeric >= 7.0:
                return "high"
            if numeric >= 4.0:
                return "medium"
            if numeric > 0:
                return "low"
    return "medium"
