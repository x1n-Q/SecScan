"""Ignore / suppression system for known findings.

Reads a `.secscan-ignore` file from the project root and filters out
findings whose IDs, CVE identifiers, or tool rule IDs match an entry.

File format (one pattern per line):
    CVE-2023-12345
    semgrep.rule.id
    GHSA-xxxx-yyyy-zzzz
    # This is a comment
    CVE-2023-99999  # reason: accepted risk
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

from secscan.core.schema import Finding

IGNORE_FILENAME = ".secscan-ignore"


@dataclass
class IgnoreEntry:
    """A single suppression rule."""
    pattern: str
    reason: str = ""


@dataclass
class IgnoreList:
    """Parsed collection of suppression rules."""
    entries: List[IgnoreEntry] = field(default_factory=list)
    source_path: str = ""

    @property
    def patterns(self) -> Set[str]:
        return {e.pattern for e in self.entries}


def load_ignore_file(project_path: str) -> IgnoreList:
    """Load and parse the .secscan-ignore file from the project root.

    Returns an empty IgnoreList if the file does not exist.
    """
    filepath = os.path.join(project_path, IGNORE_FILENAME)
    if not os.path.isfile(filepath):
        return IgnoreList(source_path=filepath)

    entries: List[IgnoreEntry] = []
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Support inline reason comments: "CVE-2023-12345  # reason: ..."
                reason = ""
                if "#" in line:
                    parts = line.split("#", 1)
                    line = parts[0].strip()
                    reason = parts[1].strip()
                    # Strip optional "reason:" prefix
                    if reason.lower().startswith("reason:"):
                        reason = reason[7:].strip()

                if line:
                    entries.append(IgnoreEntry(pattern=line, reason=reason))
    except OSError:
        pass

    return IgnoreList(entries=entries, source_path=filepath)


def filter_findings(
    findings: List[Finding],
    ignore_list: IgnoreList,
) -> Tuple[List[Finding], List[Finding]]:
    """Separate findings into active and suppressed lists.

    Returns:
        (active_findings, suppressed_findings)
    """
    if not ignore_list.entries:
        return list(findings), []

    patterns = ignore_list.patterns
    active: List[Finding] = []
    suppressed: List[Finding] = []

    for f in findings:
        if _is_suppressed(f, patterns):
            suppressed.append(f)
        else:
            active.append(f)

    return active, suppressed


def _is_suppressed(finding: Finding, patterns: Set[str]) -> bool:
    """Check whether a finding matches any suppression pattern.

    Matches against:
    - finding.id
    - finding.title (substring match for rule IDs)
    - CVE / GHSA identifiers in title or evidence
    """
    # Direct ID match
    if finding.id in patterns:
        return True

    # Check each pattern against title and evidence
    for pattern in patterns:
        # Exact substring match in title
        if pattern in finding.title:
            return True
        # Exact substring match in evidence
        if pattern and pattern in finding.evidence:
            return True
        # Check references
        for ref in finding.references:
            if pattern in ref:
                return True

    return False


def save_ignore_file(project_path: str, ignore_list: IgnoreList) -> str:
    """Write the ignore list back to the .secscan-ignore file.

    Returns the file path.
    """
    filepath = os.path.join(project_path, IGNORE_FILENAME)
    lines: List[str] = [
        "# SecScan ignore file",
        "# Add vulnerability IDs or rule IDs to suppress known findings.",
        "# One pattern per line. Use # for comments.",
        "#",
        "# Examples:",
        "#   CVE-2023-12345",
        "#   semgrep.rule.id",
        "#   GHSA-xxxx-yyyy-zzzz  # reason: accepted risk",
        "",
    ]

    for entry in ignore_list.entries:
        line = entry.pattern
        if entry.reason:
            line += f"  # reason: {entry.reason}"
        lines.append(line)

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    return filepath
