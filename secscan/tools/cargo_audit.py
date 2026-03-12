"""cargo-audit scanner adapter."""

from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Any, List

from secscan.core.detect import find_rust_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class CargoAuditTool(ToolBase):
    name = "cargo-audit"
    description = "Scan Rust crates for known vulnerabilities"
    cli_command = "cargo-audit"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_rust_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "Install cargo-audit:\n"
            "  cargo install cargo-audit\n"
            "Then verify with: cargo audit --help"
        )

    def install_commands(self) -> List[List[str]]:
        if os.name == "nt":
            return [[sys.executable, "-m", "secscan.core.self_install", "cargo-audit"]]

        commands: List[List[str]] = []
        cargo_exe = self._resolve_executable("cargo")
        if cargo_exe is not None:
            commands.append([cargo_exe, "install", "cargo-audit"])
        else:
            commands.append(["cargo", "install", "cargo-audit"])
        return commands

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []

        for rust_dir in find_rust_projects(project_path):
            rel_dir = os.path.relpath(rust_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            proc = self._run_cmd(
                ["cargo-audit", "--json"],
                cwd=rust_dir,
                timeout=300,
            )
            raw_output = proc.stdout or proc.stderr or ""
            self._save_raw(raw_dir, f"cargo_audit_{rel_tag}.json", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        location_suffix = "(root)" if rel_dir == "." else f"({rel_dir})"
        vuln_section = data.get("vulnerabilities", {})
        advisories = vuln_section.get("list") if isinstance(vuln_section, dict) else None
        if not isinstance(advisories, list):
            advisories = data.get("advisories", [])
        if not isinstance(advisories, list):
            return findings

        for entry in advisories:
            if not isinstance(entry, dict):
                continue
            advisory = entry.get("advisory", {}) if isinstance(entry.get("advisory"), dict) else entry
            package = entry.get("package", {}) if isinstance(entry.get("package"), dict) else {}
            crate_name = str(package.get("name") or entry.get("crate") or "unknown crate")
            package_version = str(package.get("version") or "")
            vuln_id = str(advisory.get("id") or advisory.get("aliases", ["Rust advisory"])[0])
            title = str(advisory.get("title") or advisory.get("description") or vuln_id)
            patched_versions = advisory.get("patched_versions") or advisory.get("versions", {}).get("patched") or []
            if isinstance(patched_versions, str):
                patched_versions = [patched_versions]
            references = _cargo_references(advisory)
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.DEPENDENCY,
                    severity=_cargo_severity(advisory),
                    title=f"{vuln_id}: {title[:120]}",
                    location=f"{crate_name}@{package_version} {location_suffix}".strip(),
                    evidence=str(advisory.get("cvss") or advisory.get("date") or "")[:300],
                    remediation=(
                        f"Upgrade {crate_name} to one of: {', '.join(patched_versions)}"
                        if patched_versions
                        else f"Upgrade {crate_name} to a fixed version."
                    ),
                    references=references[:5],
                )
            )

        return findings


def _cargo_references(advisory: dict[str, Any]) -> list[str]:
    references: list[str] = []
    url = advisory.get("url")
    if isinstance(url, str) and url:
        references.append(url)
    for ref in advisory.get("references", []):
        if isinstance(ref, str) and ref:
            references.append(ref)
        elif isinstance(ref, dict):
            url = ref.get("url")
            if isinstance(url, str) and url:
                references.append(url)
    return references


def _cargo_severity(advisory: dict[str, Any]) -> str:
    cvss = advisory.get("cvss")
    if isinstance(cvss, dict):
        score = cvss.get("score")
    else:
        score = cvss
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "high"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0:
        return "low"
    return "info"
