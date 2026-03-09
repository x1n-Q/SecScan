"""Security score calculation based on scan findings.

Uses a weighted, category-aware scoring system with diminishing returns
so that each additional finding of the same severity has progressively
less impact. This prevents the score from immediately dropping to zero
when many findings are reported by comprehensive scans.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List

from secscan.core.schema import Finding, ScanResult, Severity


# ------------------------------------------------------------------ #
# Scoring weights – how much each severity level matters
# ------------------------------------------------------------------ #

# Base penalty for the FIRST finding of each severity.
# Additional findings of the same severity apply diminishing returns.
_BASE_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 12.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 2.5,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}

# Maximum total deduction per severity category (cap).
# This prevents a single category from eating the entire score.
_MAX_CATEGORY_DEDUCTION: dict[Severity, float] = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 5.0,
    Severity.INFO: 0.0,
}

# Grade boundaries (inclusive lower bound)
_GRADES: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]

_MAX_SCORE = 100
_MIN_SCORE = 0


@dataclass
class ScoreResult:
    """Computed security score and letter grade."""
    score: int
    grade: str
    penalties: dict[str, int]
    finding_counts: dict[str, int]
    tool_contributions: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "penalties": self.penalties,
            "finding_counts": self.finding_counts,
            "tool_contributions": self.tool_contributions,
        }


def _diminishing_penalty(base: float, count: int, cap: float) -> float:
    """Compute total penalty for `count` findings with diminishing returns.

    Uses logarithmic scaling:  penalty = base * ln(1 + count)
    Capped at `cap` to prevent one severity from dominating.
    """
    if count <= 0 or base <= 0:
        return 0.0
    raw = base * math.log(1 + count) * 1.8  # 1.8 scaling factor
    return min(raw, cap)


def calculate_score(findings: List[Finding]) -> ScoreResult:
    """Compute a security score from a list of findings.

    Algorithm:
        start_score = 100
        For each severity level, count findings and apply diminishing-
        returns penalty.  Each severity category has its own cap.
        All tools contribute equally to the score through their findings.
    """
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    penalties: dict[str, int] = {}
    tool_penalties: dict[str, float] = {}

    # Count findings per-severity and per-tool
    tool_sev_counts: dict[str, dict[Severity, int]] = {}
    for f in findings:
        sev_name = f.severity.value
        counts[sev_name] = counts.get(sev_name, 0) + 1

        if f.tool not in tool_sev_counts:
            tool_sev_counts[f.tool] = {s: 0 for s in Severity}
        tool_sev_counts[f.tool][f.severity] += 1

    # Calculate total penalties with diminishing returns per severity
    total_penalty = 0.0
    for sev in Severity:
        count = counts.get(sev.value, 0)
        base = _BASE_PENALTY.get(sev, 0)
        cap = _MAX_CATEGORY_DEDUCTION.get(sev, 0)
        penalty = _diminishing_penalty(base, count, cap)
        penalties[sev.value] = round(penalty)
        total_penalty += penalty

    # Calculate per-tool contribution to penalty (proportional)
    for tool_name, sev_counts in tool_sev_counts.items():
        tool_pen = 0.0
        for sev, count in sev_counts.items():
            total_sev = counts.get(sev.value, 1) or 1
            sev_penalty = penalties.get(sev.value, 0)
            # Tool's share of this severity's penalty
            tool_pen += (count / total_sev) * sev_penalty
        tool_penalties[tool_name] = round(tool_pen, 1)

    score = max(_MIN_SCORE, round(_MAX_SCORE - total_penalty))
    grade = _score_to_grade(score)

    return ScoreResult(
        score=score,
        grade=grade,
        penalties=penalties,
        finding_counts=counts,
        tool_contributions=tool_penalties,
    )


def calculate_score_from_result(result: ScanResult) -> ScoreResult:
    """Convenience wrapper that accepts a ScanResult."""
    return calculate_score(result.findings)


def _score_to_grade(score: int) -> str:
    """Map a numeric score to a letter grade."""
    for threshold, grade in _GRADES:
        if score >= threshold:
            return grade
    return "F"
