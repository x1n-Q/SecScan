"""Scan profiles – predefined tool selections for common use-cases."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import List, Set

from secscan.core.schema import Severity


class ProfileName(str, Enum):
    """Built-in scan profile names."""
    QUICK = "Quick Scan"
    RECOMMENDED = "Recommended Scan"
    FULL = "Full Scan"
    WEB = "Web Scan"


@dataclass
class ScanProfile:
    """Defines which tool categories to include and CI behaviour."""
    name: ProfileName
    description: str
    tool_names: Set[str]
    fail_on_severities: Set[Severity]

    def to_dict(self) -> dict:
        return {
            "name": self.name.value,
            "description": self.description,
            "tool_names": sorted(self.tool_names),
            "fail_on_severities": [s.value for s in self.fail_on_severities],
        }


# --- Tool name constants (must match ToolBase.name in each adapter) -------
_DEPENDENCY_TOOLS = {
    "npm audit", "OWASP Dependency-Check", "OSV-Scanner", "Grype", "pip-audit", "Safety",
}
_SECRET_TOOLS = {
    "Gitleaks",
}
_WEB_TOOLS = {
    "Security Headers", "TLS Certificate Check",
}
_WEB_SCAN_TOOLS = {
    "OWASP ZAP", "Nikto", "Dirb", "XssPy",
}
_SAST_TOOLS = {
    "Semgrep", "Bandit", "Sqlmap",
}
_SBOM_TOOLS = {
    "CycloneDX SBOM",
}
_CONTAINER_TOOLS = {
    "Trivy",
}
_IAC_TOOLS = {
    "Checkov", "Kube-bench",
}
_NETWORK_TOOLS = {
    "Nmap",
}
_HOST_TOOLS = {
    "Lynis",
}
_RECON_TOOLS = {
    "Amass",
}

_ALL_TOOL_NAMES = (
    _DEPENDENCY_TOOLS | _SECRET_TOOLS | _WEB_TOOLS | _WEB_SCAN_TOOLS |
    _SAST_TOOLS | _SBOM_TOOLS | _CONTAINER_TOOLS | _IAC_TOOLS |
    _NETWORK_TOOLS | _HOST_TOOLS | _RECON_TOOLS
)


# --- Profile definitions --------------------------------------------------

PROFILES: dict[ProfileName, ScanProfile] = {
    ProfileName.QUICK: ScanProfile(
        name=ProfileName.QUICK,
        description="Fast scan for common dependency and secret issues",
        tool_names={"npm audit", "OSV-Scanner", "Gitleaks"},
        fail_on_severities=set(),
    ),
    ProfileName.RECOMMENDED: ScanProfile(
        name=ProfileName.RECOMMENDED,
        description="Best default for most projects",
        tool_names={
            "npm audit",
            "OSV-Scanner",
            "Semgrep",
            "Gitleaks",
            "Trivy",
            "Checkov",
        },
        fail_on_severities=set(),
    ),
    ProfileName.FULL: ScanProfile(
        name=ProfileName.FULL,
        description="Complete scan using every available scanner",
        tool_names=_ALL_TOOL_NAMES,
        fail_on_severities=set(),
    ),
    ProfileName.WEB: ScanProfile(
        name=ProfileName.WEB,
        description="Focus on web target checks and exposed attack surface",
        tool_names=_WEB_TOOLS | _WEB_SCAN_TOOLS | _NETWORK_TOOLS | _RECON_TOOLS,
        fail_on_severities=set(),
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Retrieve a profile by name (case-insensitive)."""
    for pname, profile in PROFILES.items():
        if pname.value.lower() == name.strip().lower():
            return profile
    raise ValueError(
        f"Unknown profile '{name}'. "
        f"Available: {', '.join(p.value for p in PROFILES)}"
    )


def filter_tools_by_profile(
    all_tools: list,
    profile: ScanProfile,
) -> list:
    """Return only tools whose names are included in the profile."""
    return [t for t in all_tools if t.name in profile.tool_names]


def check_ci_threshold(
    findings: list,
    profile: ScanProfile,
) -> bool:
    """Return True if the scan should PASS under the CI profile's rules.

    Returns False (fail) if any finding has a severity in the profile's
    fail_on_severities set.
    """
    if not profile.fail_on_severities:
        return True  # No threshold configured → always pass
    for f in findings:
        if f.severity in profile.fail_on_severities:
            return False
    return True
