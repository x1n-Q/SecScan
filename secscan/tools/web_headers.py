"""Security headers checker – pure-Python, no external tool required."""

from __future__ import annotations

from typing import List

import requests

from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


# Headers that every production site should have
_EXPECTED_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "remediation": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains' header.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "remediation": "Define a Content-Security-Policy header to mitigate XSS attacks.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "Referrer-Policy": {
        "severity": "low",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": "low",
        "remediation": "Add a Permissions-Policy header to restrict browser features.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "remediation": "Add 'X-XSS-Protection: 0' (modern recommendation) or rely on CSP.",
        "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    },
}


class WebHeadersTool(ToolBase):
    name = "Security Headers"
    description = "Check a website for missing security HTTP headers"
    cli_command = ""  # Pure Python – no external binary

    def is_applicable(self, project_path: str) -> bool:
        # Only applicable when a website URL is provided
        return True  # Checked at runtime via website_url

    def install_instructions(self) -> str:
        return "No installation needed – this check runs with the built-in Python requests library."

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
            resp = requests.get(website_url, timeout=15, allow_redirects=True)
        except requests.RequestException as exc:
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.WEB,
                    severity="info",
                    title=f"Could not reach {website_url}",
                    location=website_url,
                    evidence=str(exc)[:300],
                    remediation="Verify the URL is correct and the server is reachable.",
                )
            )
            return findings

        # Save raw headers
        header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        self._save_raw(raw_dir, "web_headers.txt", header_text)

        response_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, info in _EXPECTED_HEADERS.items():
            if header.lower() not in response_headers:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.WEB,
                        severity=info["severity"],
                        title=f"Missing header: {header}",
                        location=website_url,
                        remediation=info["remediation"],
                        references=[info["ref"]],
                    )
                )

        if not findings:
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.WEB,
                    severity="info",
                    title="All recommended security headers are present",
                    location=website_url,
                )
            )

        return findings
