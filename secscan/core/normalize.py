"""Helpers for normalizing raw tool output into Finding objects."""

from __future__ import annotations

from secscan.core.schema import Finding, Severity, Category


# ---------------------------------------------------------------------------
# Severity mapping helpers
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "warning": Severity.MEDIUM,
    "error": Severity.HIGH,
    "none": Severity.INFO,
}


def map_severity(raw: str) -> Severity:
    """Convert a raw severity string from any tool into a Severity enum."""
    return _SEVERITY_MAP.get(raw.strip().lower(), Severity.INFO)


def make_finding(
    *,
    tool: str,
    category: Category,
    severity: str | Severity,
    title: str,
    location: str = "",
    evidence: str = "",
    remediation: str = "",
    references: list[str] | None = None,
) -> Finding:
    """Create a Finding with automatic severity normalisation."""
    sev = severity if isinstance(severity, Severity) else map_severity(severity)
    return Finding(
        tool=tool,
        category=category,
        severity=sev,
        title=title,
        location=location,
        evidence=evidence,
        remediation=remediation,
        references=references or [],
    )
