"""History & trend tracking – stores previous scan results for analysis."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from secscan.core.schema import ScanResult, Severity
from secscan.core.security_score import ScoreResult

HISTORY_DIR = ".secscan-history"


@dataclass
class HistoryEntry:
    """A single historical scan record."""
    date: str
    score: int
    grade: str
    finding_counts: Dict[str, int]
    total_findings: int
    errors: int

    def to_dict(self) -> dict:
        return {
            "date": self.date,
            "score": self.score,
            "grade": self.grade,
            "finding_counts": self.finding_counts,
            "total_findings": self.total_findings,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HistoryEntry:
        return cls(
            date=data.get("date", ""),
            score=data.get("score", 0),
            grade=data.get("grade", "?"),
            finding_counts=data.get("finding_counts", {}),
            total_findings=data.get("total_findings", 0),
            errors=data.get("errors", 0),
        )


@dataclass
class TrendMetrics:
    """Computed trend data comparing current scan to previous."""
    current_score: int = 0
    previous_score: int = 0
    score_delta: int = 0
    current_findings: int = 0
    previous_findings: int = 0
    findings_delta: int = 0
    improvement_pct: float = 0.0
    trend_direction: str = "stable"  # "improving", "declining", "stable"
    history_count: int = 0

    def to_dict(self) -> dict:
        return {
            "current_score": self.current_score,
            "previous_score": self.previous_score,
            "score_delta": self.score_delta,
            "current_findings": self.current_findings,
            "previous_findings": self.previous_findings,
            "findings_delta": self.findings_delta,
            "improvement_pct": round(self.improvement_pct, 1),
            "trend_direction": self.trend_direction,
            "history_count": self.history_count,
        }


def _history_dir(project_path: str) -> str:
    """Return the path to the history directory for a project."""
    return os.path.join(project_path, HISTORY_DIR)


def save_scan_history(
    project_path: str,
    result: ScanResult,
    score_result: ScoreResult,
) -> str:
    """Save a scan result as a history entry. Returns the file path."""
    hist_dir = _history_dir(project_path)
    os.makedirs(hist_dir, exist_ok=True)

    now = datetime.now(timezone.utc)
    filename = now.strftime("%Y-%m-%d_%H%M%S") + ".json"
    filepath = os.path.join(hist_dir, filename)

    entry = HistoryEntry(
        date=now.isoformat(),
        score=score_result.score,
        grade=score_result.grade,
        finding_counts=result.summary,
        total_findings=len(result.findings),
        errors=len(result.errors),
    )

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(entry.to_dict(), fh, indent=2, ensure_ascii=False)

    return filepath


def load_history(project_path: str) -> List[HistoryEntry]:
    """Load all history entries for a project, sorted by date ascending."""
    hist_dir = _history_dir(project_path)
    if not os.path.isdir(hist_dir):
        return []

    entries: List[HistoryEntry] = []
    for filename in sorted(os.listdir(hist_dir)):
        if not filename.endswith(".json"):
            continue
        filepath = os.path.join(hist_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            entries.append(HistoryEntry.from_dict(data))
        except (json.JSONDecodeError, OSError, KeyError):
            continue

    return entries


def compute_trend(
    current_result: ScanResult,
    current_score: ScoreResult,
    project_path: str,
) -> TrendMetrics:
    """Compare current scan against the most recent historical entry."""
    history = load_history(project_path)
    metrics = TrendMetrics(
        current_score=current_score.score,
        current_findings=len(current_result.findings),
        history_count=len(history),
    )

    if not history:
        metrics.trend_direction = "stable"
        return metrics

    previous = history[-1]
    metrics.previous_score = previous.score
    metrics.previous_findings = previous.total_findings
    metrics.score_delta = metrics.current_score - metrics.previous_score
    metrics.findings_delta = metrics.current_findings - metrics.previous_findings

    # Compute improvement percentage based on findings
    if metrics.previous_findings > 0:
        metrics.improvement_pct = (
            (metrics.previous_findings - metrics.current_findings)
            / metrics.previous_findings
        ) * 100
    elif metrics.current_findings == 0:
        metrics.improvement_pct = 0.0
    else:
        metrics.improvement_pct = -100.0

    # Determine direction
    if metrics.score_delta > 0:
        metrics.trend_direction = "improving"
    elif metrics.score_delta < 0:
        metrics.trend_direction = "declining"
    else:
        metrics.trend_direction = "stable"

    return metrics
