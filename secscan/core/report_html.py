"""HTML report generation."""

from __future__ import annotations

import html
import os
from secscan.core.schema import ScanResult, Severity


_SEVERITY_COLORS = {
    Severity.CRITICAL: "#d32f2f",
    Severity.HIGH: "#f57c00",
    Severity.MEDIUM: "#fbc02d",
    Severity.LOW: "#1976d2",
    Severity.INFO: "#607d8b",
}


def _esc(text: str) -> str:
    return html.escape(str(text))


def export_html(result: ScanResult, output_dir: str) -> str:
    """Generate an HTML report and return its file path."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "report.html")

    summary = result.summary
    rows = ""
    for f in result.findings:
        color = _SEVERITY_COLORS.get(f.severity, "#607d8b")
        refs = ", ".join(
            f'<a href="{_esc(r)}" target="_blank">{_esc(r)}</a>'
            for r in f.references
        )
        rows += f"""<tr>
  <td><span class="sev" style="background:{color}">{_esc(f.severity.value)}</span></td>
  <td>{_esc(f.tool)}</td>
  <td>{_esc(f.category.value)}</td>
  <td>{_esc(f.title)}</td>
  <td><code>{_esc(f.location)}</code></td>
  <td>{_esc(f.evidence)}</td>
  <td>{_esc(f.remediation)}</td>
  <td>{refs}</td>
</tr>\n"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>SecScan Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 2rem; background: #f5f5f5; color: #333; }}
  h1 {{ color: #1a237e; }}
  .meta {{ color: #666; margin-bottom: 1.5rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
  .card {{ padding: 1rem 1.5rem; border-radius: 8px; color: #fff; min-width: 100px; text-align: center; }}
  .card h2 {{ margin: 0; font-size: 2rem; }}
  .card p {{ margin: 0.25rem 0 0; font-size: 0.85rem; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
  th {{ background: #1a237e; color: #fff; padding: 0.75rem; text-align: left; font-size: 0.85rem; }}
  td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #e0e0e0; font-size: 0.85rem; }}
  tr:hover {{ background: #f5f5ff; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; color: #fff; font-weight: 600; font-size: 0.8rem; }}
  code {{ background: #eee; padding: 2px 4px; border-radius: 3px; font-size: 0.82rem; }}
  a {{ color: #1565c0; }}
</style>
</head>
<body>
<h1>SecScan Security Report</h1>
<div class="meta">
  <p><strong>Project:</strong> {_esc(result.project_path)}</p>
  <p><strong>Type:</strong> {_esc(result.project_type)}</p>
  <p><strong>Scanned:</strong> {_esc(result.started_at or 'N/A')} &ndash; {_esc(result.finished_at or 'N/A')}</p>
</div>
<div class="summary">
  <div class="card" style="background:#d32f2f"><h2>{summary.get('Critical', 0)}</h2><p>Critical</p></div>
  <div class="card" style="background:#f57c00"><h2>{summary.get('High', 0)}</h2><p>High</p></div>
  <div class="card" style="background:#fbc02d;color:#333"><h2>{summary.get('Medium', 0)}</h2><p>Medium</p></div>
  <div class="card" style="background:#1976d2"><h2>{summary.get('Low', 0)}</h2><p>Low</p></div>
  <div class="card" style="background:#607d8b"><h2>{summary.get('Info', 0)}</h2><p>Info</p></div>
</div>
<table>
<thead><tr>
  <th>Severity</th><th>Tool</th><th>Category</th><th>Title</th><th>Location</th><th>Evidence</th><th>Remediation</th><th>References</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
    return path
