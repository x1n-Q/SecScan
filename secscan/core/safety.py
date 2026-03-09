# SPDX-License-Identifier: MIT
# Copyright (c) SecScan Contributors
# See LICENSE and SECURITY.md for usage terms
"""Safety helpers for active scanning workflows."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit


DANGEROUS_TOOL_NAMES = {
    "OWASP ZAP",
    "Nikto",
    "Dirb",
    "Nmap",
    "Sqlmap",
    "XssPy",
    "Amass",
}

URL_TOOL_NAMES = {
    "Security Headers",
    "TLS Certificate Check",
    *DANGEROUS_TOOL_NAMES,
}

ACTIVE_SCAN_DELAY_SECONDS = 1.0
_LOCAL_DOMAIN_SUFFIXES = (".local", ".test", ".example", ".invalid")


@dataclass(frozen=True)
class TargetAssessment:
    """Normalized safety assessment for a web target."""

    original_url: str
    normalized_url: str
    hostname: str
    scope: str
    warning: str = ""


def normalize_target_url(raw_url: str) -> TargetAssessment:
    """Validate and normalize a user-supplied website URL."""
    text = (raw_url or "").strip()
    if not text:
        raise ValueError("Target URL is required.")

    if "://" not in text:
        text = f"https://{text}"

    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Target URL must use http or https.")
    if not parts.hostname:
        raise ValueError("Target URL must include a hostname or IP address.")

    normalized = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, parts.fragment))
    hostname = (parts.hostname or "").strip().lower()
    scope, warning = _classify_hostname(hostname)
    return TargetAssessment(
        original_url=raw_url,
        normalized_url=normalized,
        hostname=hostname,
        scope=scope,
        warning=warning,
    )


def dangerous_tools_selected(tools: Sequence | Iterable) -> list[str]:
    """Return dangerous tool names from a sequence of tool objects or names."""
    names: list[str] = []
    for item in tools:
        name = getattr(item, "name", item)
        if name in DANGEROUS_TOOL_NAMES:
            names.append(str(name))
    return sorted(set(names))


def should_throttle(tool_name: str, website_url: str) -> bool:
    """Return True when a scan should pause briefly after running."""
    return bool(website_url) and tool_name in DANGEROUS_TOOL_NAMES


def audit_scan_targets(
    output_dir: str,
    project_path: str,
    website_url: str,
    tools: Sequence | Iterable,
    source: str,
) -> str:
    """Append an audit record for the current scan target selection."""
    os.makedirs(output_dir, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "project_path": os.path.abspath(project_path),
        "website_url": website_url,
        "tools": [getattr(tool, "name", str(tool)) for tool in tools],
    }
    path = os.path.join(output_dir, "scan_audit.log")
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path


def _classify_hostname(hostname: str) -> tuple[str, str]:
    if hostname == "localhost" or hostname.endswith(_LOCAL_DOMAIN_SUFFIXES):
        return "local-lab", ""

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        return (
            "external-domain",
            "Target appears to be an external hostname. Verify written authorization before scanning.",
        )

    if ip_obj.is_loopback:
        return "loopback", ""
    if ip_obj.is_private:
        return "private-network", ""
    if ip_obj.is_link_local:
        return "link-local", ""
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return (
            "special-ip",
            "Target uses a special-purpose IP range. Confirm it is safe and intended before scanning.",
        )
    return (
        "public-ip",
        "Target appears to be a public IP address. Verify written authorization before scanning.",
    )
