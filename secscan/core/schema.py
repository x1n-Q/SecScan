"""Data models for scan findings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Category(str, Enum):
    """Categories of security findings."""
    DEPENDENCY = "dependency"
    SECRETS = "secrets"
    SAST = "sast"
    WEB = "web"
    TLS = "tls"
    CONTAINER = "container"
    IAC = "iac"
    SBOM = "sbom"
    NETWORK = "network"
    KUBERNETES = "kubernetes"
    SYSTEM = "system"
    RECON = "recon"


@dataclass
class Finding:
    """Normalized security finding produced by any scanner."""
    tool: str
    category: Category
    severity: Severity
    title: str
    location: str = ""
    evidence: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Serialize finding to a plain dictionary."""
        data = asdict(self)
        data["category"] = self.category.value
        data["severity"] = self.severity.value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Deserialize a dictionary into a Finding."""
        data = dict(data)
        data["category"] = Category(data["category"])
        data["severity"] = Severity(data["severity"])
        return cls(**data)


@dataclass
class ScanResult:
    """Aggregated result of a full scan session."""
    project_path: str
    project_type: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    @property
    def summary(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        """Serialize the full scan result."""
        return {
            "project_path": self.project_path,
            "project_type": self.project_type,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
