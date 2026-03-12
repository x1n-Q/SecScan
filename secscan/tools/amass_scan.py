"""Amass passive subdomain discovery adapter."""

from __future__ import annotations

import json
import os
from typing import List
from urllib.parse import urlparse

from secscan.core.normalize import make_finding
from secscan.core.schema import Category, Finding
from secscan.tools.base import ToolBase


class AmassTool(ToolBase):
    name = "Amass"
    description = "Passive subdomain discovery for web targets"
    cli_command = "amass"
    requires_website = True

    def is_applicable(self, project_path: str) -> bool:
        return True

    def install_instructions(self) -> str:
        return (
            "Install Amass:\n"
            "  Windows: winget install OWASP.Amass\n"
            "  macOS: brew install amass\n"
            "  Or see https://github.com/owasp-amass/amass"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        domain = _extract_domain(website_url)
        if not domain:
            return []

        report_file = os.path.join(raw_dir, "amass.json") if raw_dir else "amass.json"
        proc = self._run_cmd(
            ["amass", "enum", "-passive", "-d", domain, "-json", report_file],
            timeout=1800,
        )

        self._save_raw(raw_dir, "amass_log.txt", (proc.stdout or "") + (proc.stderr or ""))
        if not os.path.isfile(report_file):
            return []

        findings: List[Finding] = []
        try:
            with open(report_file, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    name = entry.get("name")
                    if not name:
                        continue
                    addresses = entry.get("addresses", []) or []
                    ips = ", ".join(addr.get("ip", "") for addr in addresses if addr.get("ip"))
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.RECON,
                            severity="info",
                            title=f"Discovered subdomain: {name}",
                            location=name,
                            evidence=f"IPs: {ips}" if ips else "",
                            remediation="Review exposed subdomains and ensure they are intended and secured.",
                        )
                    )
        except OSError:
            return []

        return findings


def _extract_domain(website_url: str) -> str:
    if not website_url:
        return ""
    parsed = urlparse(website_url if "://" in website_url else f"https://{website_url}")
    hostname = (parsed.hostname or "").strip().lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname
