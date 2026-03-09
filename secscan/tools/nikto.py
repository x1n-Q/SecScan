"""Nikto-style web server scanner implemented in pure Python."""

from __future__ import annotations

from typing import List
import re
from urllib.parse import urljoin

import requests
from secscan.core.schema import Finding, Category, Severity
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class NiktoTool(ToolBase):
    name = "Nikto"
    description = "Nikto-style web server checks (pure Python)"
    cli_command = ""

    def is_applicable(self, project_path: str) -> bool:
        # Nikto is applicable to projects with a website URL
        return True

    def install_instructions(self) -> str:
        return "No installation needed - runs built-in web checks with Python requests."

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        findings: List[Finding] = []
        try:
            response = requests.get(website_url, timeout=15)
        except Exception:
            return findings
        self._save_raw(raw_dir, "nikto_response_headers.txt", str(dict(response.headers)))

        server = response.headers.get("Server", "")
        if server and re.search(r"\d", server):
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.WEB,
                    severity=Severity.MEDIUM,
                    title="Server version disclosure",
                    location=website_url,
                    evidence=f"Server: {server}",
                    remediation="Hide server version details at the web server/reverse proxy level.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/"],
                )
            )

        x_powered_by = response.headers.get("X-Powered-By", "")
        if x_powered_by:
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.WEB,
                    severity=Severity.MEDIUM,
                    title="Technology disclosure via X-Powered-By header",
                    location=website_url,
                    evidence=f"X-Powered-By: {x_powered_by}",
                    remediation="Remove or sanitize X-Powered-By headers in production.",
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )

        try:
            options_resp = requests.options(website_url, timeout=15)
            allow_hdr = options_resp.headers.get("Allow", "")
            if allow_hdr and re.search(r"\b(TRACE|PUT|DELETE)\b", allow_hdr, flags=re.IGNORECASE):
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.WEB,
                        severity=Severity.HIGH,
                        title="Potentially dangerous HTTP methods enabled",
                        location=website_url,
                        evidence=f"Allow: {allow_hdr}",
                        remediation="Disable unnecessary methods like TRACE, PUT, and DELETE.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    )
                )
        except Exception:
            pass

        sensitive_paths = [
            "/.env",
            "/.git/HEAD",
            "/phpinfo.php",
            "/server-status",
            "/backup.zip",
        ]
        for rel_path in sensitive_paths:
            target = urljoin(website_url.rstrip("/") + "/", rel_path.lstrip("/"))
            try:
                leak_resp = requests.get(target, timeout=10, allow_redirects=False)
            except Exception:
                continue
            if leak_resp.status_code < 400:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.WEB,
                        severity=Severity.HIGH,
                        title=f"Potential sensitive path exposed: {rel_path}",
                        location=target,
                        evidence=f"HTTP {leak_resp.status_code}",
                        remediation="Restrict public access or remove sensitive files/endpoints.",
                        references=["https://owasp.org/www-project-top-ten/"],
                    )
                )

        return findings
