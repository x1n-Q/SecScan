"""JSON report generation."""

from __future__ import annotations

import json
import os
from secscan.core.schema import ScanResult


def export_json(result: ScanResult, output_dir: str) -> str:
    """Write the scan result as a JSON file and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "findings.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
    return path
