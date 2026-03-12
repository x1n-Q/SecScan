"""Composer audit scanner adapter."""

from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Any, List

from secscan.core.detect import find_composer_projects
from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class ComposerAuditTool(ToolBase):
    name = "Composer Audit"
    description = "Scan PHP Composer dependencies for known vulnerabilities"
    cli_command = "composer"

    def is_applicable(self, project_path: str) -> bool:
        return bool(find_composer_projects(project_path))

    def is_installed(self) -> bool:
        return (
            self._resolve_executable(self.cli_command) is not None
            and self._resolve_executable("php") is not None
        )

    def install_instructions(self) -> str:
        return (
            "Install Composer:\n"
            "  SecScan can bootstrap PHP on Windows and download the official Composer PHAR.\n"
            "  See https://getcomposer.org/download/"
        )

    def install_commands(self) -> List[List[str]]:
        commands: List[List[str]] = []
        if self._resolve_executable("php") is None and os.name == "nt" and shutil.which("winget"):
            commands.append(
                [
                    "winget",
                    "install",
                    "--id",
                    "PHP.PHP.8.4",
                    "-e",
                    "--accept-source-agreements",
                    "--accept-package-agreements",
                ]
            )
        elif self._resolve_executable("php") is None and shutil.which("brew"):
            commands.append(["brew", "install", "php"])

        commands.append([sys.executable, "-m", "secscan.core.self_install", "composer"])
        return commands

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        findings: List[Finding] = []

        for composer_dir in find_composer_projects(project_path):
            rel_dir = os.path.relpath(composer_dir, project_path)
            rel_tag = "root" if rel_dir == "." else rel_dir.replace("\\", "__").replace("/", "__")
            proc = self._run_cmd(
                ["composer", "audit", "--format=json", "--no-interaction"],
                cwd=composer_dir,
                timeout=240,
            )
            raw_output = proc.stdout or proc.stderr or ""
            self._save_raw(raw_dir, f"composer_audit_{rel_tag}.json", raw_output)
            findings.extend(self._parse_output(raw_output, rel_dir))

        return findings

    def _parse_output(self, raw_output: str, rel_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            return findings

        location_suffix = "(root)" if rel_dir == "." else f"({rel_dir})"
        advisories = data.get("advisories", {})
        if isinstance(advisories, list):
            advisory_groups = [("composer", advisories)]
        elif isinstance(advisories, dict):
            advisory_groups = list(advisories.items())
        else:
            advisory_groups = []

        for package_name, advisory_list in advisory_groups:
            if isinstance(advisory_list, dict):
                advisory_list = advisory_list.get("advisories", [advisory_list])
            if not isinstance(advisory_list, list):
                continue

            for advisory in advisory_list:
                if not isinstance(advisory, dict):
                    continue
                vuln_id = str(
                    advisory.get("advisoryId")
                    or advisory.get("cve")
                    or advisory.get("link")
                    or advisory.get("title")
                    or "Composer advisory"
                )
                title = str(advisory.get("title") or advisory.get("affectedVersions") or vuln_id)
                references = _references_from_advisory(advisory)
                severity = _severity_from_advisory(advisory)
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.DEPENDENCY,
                        severity=severity,
                        title=f"{vuln_id}: {title[:120]}",
                        location=f"{package_name} {location_suffix}",
                        evidence=str(advisory.get("affectedVersions") or advisory.get("reportedAt") or "")[:400],
                        remediation="Update the affected Composer package to a patched version.",
                        references=references[:5],
                    )
                )

        abandoned = data.get("abandoned", {})
        if isinstance(abandoned, dict):
            abandoned_items = abandoned.items()
        elif isinstance(abandoned, list):
            abandoned_items = []
            for item in abandoned:
                if isinstance(item, dict):
                    package_name = str(item.get("package") or item.get("name") or "unknown package")
                    abandoned_items.append((package_name, item))
        else:
            abandoned_items = []

        for package_name, item in abandoned_items:
            replacement = ""
            if isinstance(item, dict):
                replacement = str(item.get("replacement") or item.get("suggestedReplacement") or "")
            elif isinstance(item, str):
                replacement = item
            remediation = "Replace the abandoned package with a maintained alternative."
            if replacement:
                remediation = f"Replace {package_name} with {replacement}."
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.DEPENDENCY,
                    severity="medium",
                    title=f"Abandoned package: {package_name}",
                    location=f"{package_name} {location_suffix}",
                    remediation=remediation,
                )
            )

        return findings


def _references_from_advisory(advisory: dict[str, Any]) -> list[str]:
    references: list[str] = []
    link = advisory.get("link")
    if isinstance(link, str) and link:
        references.append(link)
    for key in ("sources", "references"):
        values = advisory.get(key, [])
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value:
                references.append(value)
            elif isinstance(value, dict):
                url = value.get("url")
                if isinstance(url, str) and url:
                    references.append(url)
    return references


def _severity_from_advisory(advisory: dict[str, Any]) -> str:
    for key in ("severity", "cvssSeverity"):
        value = advisory.get(key)
        if isinstance(value, str) and value:
            return value
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
