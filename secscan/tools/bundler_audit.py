"""bundler-audit scanner adapter."""

from __future__ import annotations

import json
import os
import shutil
from typing import List

from secscan.core.detect import find_ruby_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class BundlerAuditTool(ToolBase):
    name = "bundler-audit"
    description = "Scan Ruby Bundler dependencies for known vulnerabilities"
    cli_command = "bundle-audit"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_ruby_projects(project_path))

    def install_instructions(self) -> str:
        return (
            "Install bundler-audit:\n"
            "  gem install bundler-audit\n"
            "Then verify with: bundle-audit check --help"
        )

    def install_commands(self) -> List[List[str]]:
        commands: List[List[str]] = []
        if self._resolve_executable("gem") is None and os.name == "nt" and shutil.which("winget"):
            commands.append(
                [
                    "winget",
                    "install",
                    "--id",
                    "RubyInstallerTeam.RubyWithDevKit.3.4",
                    "-e",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                ]
            )
        elif self._resolve_executable("ruby") is None and shutil.which("brew"):
            commands.append(["brew", "install", "ruby"])

        gem_exe = self._resolve_executable("gem") or "gem"
        commands.append([gem_exe, "install", "bundler-audit"])
        return commands

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []

        for ruby_dir in find_ruby_projects(project_path):
            rel_dir = os.path.relpath(ruby_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            proc = self._run_cmd(
                ["bundle-audit", "check", "--format", "json"],
                cwd=ruby_dir,
                timeout=300,
            )
            raw_output = proc.stdout or proc.stderr or ""
            self._save_raw(raw_dir, f"bundler_audit_{rel_tag}.json", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        location_suffix = "(root)" if rel_dir == "." else f"({rel_dir})"
        advisories = data.get("advisories")
        if isinstance(advisories, dict):
            advisories = advisories.get("unpatched", [])
        if not isinstance(advisories, list):
            advisories = data.get("vulnerabilities", [])
        if not isinstance(advisories, list):
            return findings

        for entry in advisories:
            if not isinstance(entry, dict):
                continue
            gem = str(entry.get("gem") or entry.get("name") or "unknown gem")
            advisory = entry.get("advisory", {}) if isinstance(entry.get("advisory"), dict) else entry
            vuln_id = str(
                advisory.get("id")
                or advisory.get("cve")
                or advisory.get("osvdb")
                or advisory.get("title")
                or "Ruby advisory"
            )
            title = str(advisory.get("title") or advisory.get("description") or vuln_id)
            patched_versions = advisory.get("patched_versions") or advisory.get("patched version") or []
            if isinstance(patched_versions, str):
                patched_versions = [patched_versions]
            references = []
            url = advisory.get("url")
            if isinstance(url, str) and url:
                references.append(url)
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.DEPENDENCY,
                    severity=str(advisory.get("criticality") or "high"),
                    title=f"{vuln_id}: {title[:120]}",
                    location=f"{gem} {location_suffix}",
                    evidence=str(advisory.get("unaffected_versions") or "")[:300],
                    remediation=(
                        f"Upgrade {gem} to one of: {', '.join(patched_versions)}"
                        if patched_versions
                        else f"Upgrade {gem} to a fixed version."
                    ),
                    references=references,
                )
            )

        return findings
