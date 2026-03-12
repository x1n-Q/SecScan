"""Nmap network scanner adapter."""

from __future__ import annotations

import json
import os
from typing import List

from secscan.core.schema import Finding, Category, Severity
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class NmapTool(ToolBase):
    name = "Nmap"
    description = "Network port and service scanner"
    cli_command = "nmap"
    requires_website = True

    def is_applicable(self, project_path: str) -> bool:
        # Nmap is applicable to projects with a website URL
        return True

    def install_instructions(self) -> str:
        return (
            "Install Nmap:\n"
            "  Debian/Ubuntu: apt install nmap\n"
            "  macOS: brew install nmap\n"
            "  Windows: Download from https://nmap.org/download.html"
        )

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        # Extract hostname from URL
        hostname = website_url.replace("http://", "").replace("https://", "").split("/")[0]
        report_file = os.path.join(raw_dir, "nmap.json") if raw_dir else "nmap.json"

        proc = self._run_cmd(
            [
                "nmap", "-sV", "-oX", report_file, hostname
            ],
            timeout=300,
        )

        self._save_raw(raw_dir, "nmap_log.txt", (proc.stdout or "") + (proc.stderr or ""))

        findings: List[Finding] = []

        if not os.path.isfile(report_file):
            return findings

        try:
            with open(report_file, "r", encoding="utf-8") as fh:
                report_content = fh.read()
        except OSError:
            return findings

        # Simple parsing of Nmap XML output
        # Looking for open ports and services
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(report_content)
        except ET.ParseError:
            return findings

        for port in root.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                portid = port.get("portid")
                protocol = port.get("protocol")

                service = port.find("service")
                service_name = service.get("name", "unknown") if service else "unknown"
                product = service.get("product", "") if service else ""
                version = service.get("version", "") if service else ""

                service_info = service_name
                if product:
                    service_info += f" ({product}"
                    if version:
                        service_info += f" {version}"
                    service_info += ")"

                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.NETWORK,
                        severity=Severity.INFO,
                        title=f"Open port: {portid}/{protocol}",
                        location=f"{hostname}:{portid}",
                        evidence=f"Service: {service_info}",
                        remediation=(
                            "Close unnecessary open ports. "
                            "Restrict access to services on public ports."
                        ),
                        references=["https://nmap.org/"],
                    )
                )

        return findings
