"""XSS reflection scanner implemented in pure Python."""

from __future__ import annotations

from typing import List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from secscan.core.schema import Finding, Category, Severity
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class XssPyTool(ToolBase):
    name = "XssPy"
    description = "Reflected XSS probe checks (pure Python)"
    cli_command = ""

    def is_applicable(self, project_path: str) -> bool:
        # XssPy is applicable to projects with a website URL
        return True

    def install_instructions(self) -> str:
        return "No installation needed - runs built-in reflected XSS probes."

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        findings: List[Finding] = []
        probe = "__secscan_xss_probe__<script>alert(1)</script>"
        try:
            test_url = self._with_probe_param(website_url, probe)
            resp = requests.get(test_url, timeout=15)
            body = resp.text or ""
            self._save_raw(raw_dir, "xsspy_probe_response.html", body[:20000])
            if probe in body:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.WEB,
                        severity=Severity.HIGH,
                        title="Possible reflected XSS",
                        location=test_url,
                        evidence=f"Probe payload reflected in response (HTTP {resp.status_code})",
                        remediation=(
                            "Validate and sanitize all user input and apply contextual output encoding."
                        ),
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    )
                )
        except Exception:
            return findings

        return findings

    @staticmethod
    def _with_probe_param(url: str, probe: str) -> str:
        parts = urlsplit(url)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        if query_pairs:
            query_pairs = [(k, probe) for (k, _v) in query_pairs]
        else:
            query_pairs = [("secscan_probe", probe)]
        new_query = urlencode(query_pairs, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
