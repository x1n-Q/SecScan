"""TLS certificate checker – pure-Python, no external tool required."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

from secscan.core.schema import Finding, Category
from secscan.core.normalize import make_finding
from secscan.tools.base import ToolBase


class TlsCheckTool(ToolBase):
    name = "TLS Certificate Check"
    description = "Verify TLS certificate validity and expiration for a website"
    cli_command = ""  # Pure Python
    requires_website = True

    def is_applicable(self, project_path: str) -> bool:
        return True  # Applicable when website_url is provided

    def install_instructions(self) -> str:
        return "No installation needed – uses Python's built-in ssl module."

    def run(
        self,
        project_path: str,
        website_url: str = "",
        raw_dir: str = "",
    ) -> List[Finding]:
        if not website_url:
            return []

        findings: List[Finding] = []
        parsed = urlparse(website_url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if not hostname:
            return []

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            if not cert:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.TLS,
                        severity="high",
                        title="No TLS certificate returned",
                        location=f"{hostname}:{port}",
                        remediation="Ensure the server is configured with a valid TLS certificate.",
                    )
                )
                return findings

            # Save raw cert info
            cert_text = "\n".join(f"{k}: {v}" for k, v in _flatten_cert(cert))
            self._save_raw(raw_dir, "tls_cert.txt", cert_text)

            # Check expiration
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = ssl.cert_time_to_seconds(not_after_str)
                expires = datetime.fromtimestamp(not_after, tz=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expires - now).days

                if days_left < 0:
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.TLS,
                            severity="critical",
                            title="TLS certificate has EXPIRED",
                            location=f"{hostname}:{port}",
                            evidence=f"Expired on {not_after_str}",
                            remediation="Renew the TLS certificate immediately.",
                        )
                    )
                elif days_left < 30:
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.TLS,
                            severity="high",
                            title=f"TLS certificate expires in {days_left} day(s)",
                            location=f"{hostname}:{port}",
                            evidence=f"Expires: {not_after_str}",
                            remediation="Renew the TLS certificate before it expires.",
                        )
                    )
                else:
                    findings.append(
                        make_finding(
                            tool=self.name,
                            category=Category.TLS,
                            severity="info",
                            title=f"TLS certificate valid – expires in {days_left} day(s)",
                            location=f"{hostname}:{port}",
                            evidence=f"Expires: {not_after_str}",
                        )
                    )

            # Check subject matches hostname
            subject = dict(x[0] for x in cert.get("subject", ()))
            cn = subject.get("commonName", "")
            san_list = [
                v for t, v in cert.get("subjectAltName", ()) if t == "DNS"
            ]
            if hostname not in san_list and hostname != cn:
                findings.append(
                    make_finding(
                        tool=self.name,
                        category=Category.TLS,
                        severity="high",
                        title="Hostname mismatch in TLS certificate",
                        location=f"{hostname}:{port}",
                        evidence=f"CN={cn}, SANs={san_list}",
                        remediation="Ensure the certificate covers the correct hostname.",
                    )
                )

        except ssl.SSLCertVerificationError as exc:
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.TLS,
                    severity="critical",
                    title="TLS certificate verification failed",
                    location=f"{hostname}:{port}",
                    evidence=str(exc)[:300],
                    remediation="Install a valid, trusted TLS certificate.",
                )
            )
        except Exception as exc:
            findings.append(
                make_finding(
                    tool=self.name,
                    category=Category.TLS,
                    severity="info",
                    title=f"Could not connect to {hostname}:{port}",
                    location=f"{hostname}:{port}",
                    evidence=str(exc)[:300],
                    remediation="Verify the URL and ensure TLS is enabled.",
                )
            )

        return findings


def _flatten_cert(cert: dict) -> list[tuple[str, str]]:
    """Flatten a certificate dict into key-value pairs for raw output."""
    items = []
    for key, value in cert.items():
        items.append((key, str(value)))
    return items
