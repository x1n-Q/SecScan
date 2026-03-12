"""Dirb-style directory scanner implemented in pure Python."""

from __future__ import annotations

from typing import List
import re
from urllib.parse import urljoin

import requests
from secscan.core.schema import Finding, Category, Severity
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class DirbTool(ToolBase):
    name = "Dirb"
    description = "Directory and file discovery checks (pure Python)"
    cli_command = ""
    requires_website = True

    def is_applicable(self, project_path: str) -> bool:
        # Dirb is applicable to projects with a website URL
        return True

    def install_instructions(self) -> str:
        return "No installation needed - runs built-in web path discovery checks."

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        findings: List[Finding] = []
        paths = [
            "/admin",
            "/login",
            "/dashboard",
            "/api",
            "/config",
            "/backup",
            "/.git",
            "/.svn",
            "/debug",
            "/test",
        ]
        sensitive_patterns = [r"/admin", r"/config", r"/backup", r"/\.git", r"/\.svn", r"/debug"]

        for rel_path in paths:
            url = urljoin(website_url.rstrip("/") + "/", rel_path.lstrip("/"))
            try:
                resp = requests.get(url, timeout=10, allow_redirects=False)
            except Exception:
                continue

            code = resp.status_code
            size = len(resp.text or "")
            if code in (200, 401, 403):
                is_sensitive = any(re.search(pattern, url, re.IGNORECASE) for pattern in sensitive_patterns)
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.WEB,
                        severity=Severity.MEDIUM if is_sensitive else Severity.LOW,
                        title=f"Found: {url}",
                        location=url,
                        evidence=f"Status: {code}, Size: {size} bytes",
                        remediation=(
                            "Restrict access to sensitive directories. "
                            "Remove unnecessary files from web root."
                        ),
                        references=["https://tools.kali.org/web-applications/dirb"],
                    )
                )

        if raw_dir:
            self._save_raw(
                raw_dir,
                "dirb_paths_checked.txt",
                "\n".join(urljoin(website_url.rstrip("/") + "/", p.lstrip("/")) for p in paths),
            )

        return findings
