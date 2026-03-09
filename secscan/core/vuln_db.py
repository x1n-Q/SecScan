"""Vulnerability database enrichment via the OSV API."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from secscan.core.schema import Finding, Severity
from secscan.core.normalize import map_severity

logger = logging.getLogger(__name__)

_OSV_API_URL = "https://api.osv.dev/v1"
_REQUEST_TIMEOUT = 15


@dataclass
class VulnInfo:
    """Enriched vulnerability metadata from the OSV database."""
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    summary: str = ""
    references: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    affected_packages: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "summary": self.summary,
            "references": self.references,
            "aliases": self.aliases,
            "affected_packages": self.affected_packages,
        }


def lookup_osv(vuln_id: str) -> Optional[VulnInfo]:
    """Query the OSV API for a single vulnerability ID (e.g. GHSA-xxx or CVE-xxx).

    Returns a VulnInfo on success, or None if the lookup fails.
    """
    try:
        resp = requests.get(
            f"{_OSV_API_URL}/vulns/{vuln_id}",
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        logger.debug("OSV lookup failed for %s: %s", vuln_id, exc)
        return None

    return _parse_osv_response(data)


def batch_query_osv(package_name: str, ecosystem: str, version: str) -> List[VulnInfo]:
    """Query the OSV API for all vulnerabilities affecting a specific package version.

    Returns a list of VulnInfo objects.
    """
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
    }
    if version:
        payload["version"] = version

    try:
        resp = requests.post(
            f"{_OSV_API_URL}/query",
            json=payload,
            timeout=_REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        logger.debug("OSV batch query failed for %s: %s", package_name, exc)
        return []

    results = []
    for vuln in data.get("vulns", []):
        info = _parse_osv_response(vuln)
        if info:
            results.append(info)
    return results


def enrich_finding(finding: Finding) -> Finding:
    """Attempt to enrich a Finding with data from the OSV database.

    Looks for known vulnerability IDs in the title, evidence, or references.
    Updates severity if a CVSS score is available.
    """
    vuln_id = _extract_vuln_id(finding)
    if not vuln_id:
        return finding

    info = lookup_osv(vuln_id)
    if not info:
        return finding

    # Update severity from CVSS if available and more severe
    if info.cvss_score > 0:
        new_sev = _cvss_to_severity(info.cvss_score)
        new_sev_enum = map_severity(new_sev)
        if _severity_rank(new_sev_enum) > _severity_rank(finding.severity):
            finding.severity = new_sev_enum

    # Append CVE to evidence
    if info.cve_id and info.cve_id not in finding.evidence:
        cve_info = f"CVE: {info.cve_id}"
        if info.cvss_score > 0:
            cve_info += f" (CVSS: {info.cvss_score})"
        if finding.evidence:
            finding.evidence = f"{finding.evidence} | {cve_info}"
        else:
            finding.evidence = cve_info

    # Merge references
    existing_refs = set(finding.references)
    for ref in info.references:
        if ref not in existing_refs:
            finding.references.append(ref)
            existing_refs.add(ref)

    return finding


def enrich_findings(findings: List[Finding]) -> List[Finding]:
    """Enrich a list of findings using the OSV database.

    Skips lookups for findings that already have CVE information.
    """
    enriched = []
    for f in findings:
        try:
            enriched.append(enrich_finding(f))
        except Exception as exc:
            logger.debug("Enrichment failed for finding %s: %s", f.id, exc)
            enriched.append(f)
    return enriched


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_osv_response(data: dict) -> Optional[VulnInfo]:
    """Parse a single OSV vulnerability object into a VulnInfo."""
    if not data:
        return None

    vuln_id = data.get("id", "")
    aliases = data.get("aliases", [])
    summary = data.get("summary", data.get("details", "")[:300])

    # Extract CVE from aliases
    cve_id = ""
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # Extract CVSS score
    cvss_score = 0.0
    severity_str = ""
    for sev_entry in data.get("severity", []):
        score_str = sev_entry.get("score", "")
        sev_type = sev_entry.get("type", "")
        if sev_type == "CVSS_V3":
            cvss_score = _parse_cvss_vector_score(score_str)
            break

    if cvss_score > 0:
        severity_str = _cvss_to_severity(cvss_score)

    # Collect references
    refs = []
    for ref in data.get("references", []):
        url = ref.get("url", "")
        if url:
            refs.append(url)

    # Affected packages
    affected_pkgs = []
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        if pkg_name:
            affected_pkgs.append(f"{ecosystem}/{pkg_name}" if ecosystem else pkg_name)

    return VulnInfo(
        cve_id=cve_id,
        cvss_score=cvss_score,
        severity=severity_str,
        summary=summary[:300],
        references=refs[:10],
        aliases=aliases,
        affected_packages=affected_pkgs[:20],
    )


def _extract_vuln_id(finding: Finding) -> str:
    """Try to extract a vulnerability ID from a finding's title or references."""
    import re
    # Match common patterns: GHSA-xxxx, CVE-xxxx, PYSEC-xxxx, GO-xxxx, RUSTSEC-xxxx
    pattern = r"((?:GHSA|CVE|PYSEC|GO|RUSTSEC)-[\w\-]+)"
    for text in (finding.title, finding.evidence):
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    # Check references for OSV URLs
    for ref in finding.references:
        if "osv.dev/vulnerability/" in ref:
            parts = ref.rstrip("/").split("/")
            if parts:
                return parts[-1]
    return ""


def _parse_cvss_vector_score(vector: str) -> float:
    """Extract a numeric CVSS score from a vector string or return 0.0."""
    try:
        return float(vector)
    except (ValueError, TypeError):
        pass
    # Try to extract score from CVSS vector string format
    # Some OSV entries include the score at the end or as a separate field
    return 0.0


def _cvss_to_severity(score: float) -> str:
    """Map a CVSS v3 numeric score to a severity string."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _severity_rank(sev: Severity) -> int:
    return _SEVERITY_RANK.get(sev, 0)
