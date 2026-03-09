"""Command-line interface for SecScan - designed for CI/CD pipelines.

Usage:
    python -m secscan.cli scan --repo ./project --format json --profile ci
    python -m secscan.cli scan --repo ./project --url https://example.com --output ./reports
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import List

from secscan.core.detect import detect_project
from secscan.core.ignore import filter_findings, load_ignore_file
from secscan.core.profiles import (
    PROFILES,
    ProfileName,
    check_ci_threshold,
    filter_tools_by_profile,
    get_profile,
)
from secscan.core.report_html import export_html
from secscan.core.report_json import export_json
from secscan.core.schema import Finding, ScanResult
from secscan.core.security_score import calculate_score
from secscan.tools import ALL_TOOLS

_URL_REQUIRED_TOOLS = {
    "Security Headers",
    "TLS Certificate Check",
    "OWASP ZAP",
    "Nikto",
    "Dirb",
    "Nmap",
    "Sqlmap",
    "XssPy",
    "Amass",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="SecScan - CLI security scanner for software projects",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # ---- scan command ----
    scan_cmd = sub.add_parser("scan", help="Run a security scan")
    scan_cmd.add_argument(
        "--repo", "-r",
        required=True,
        help="Path to the project repository to scan",
    )
    scan_cmd.add_argument(
        "--url", "-u",
        default="",
        help="Optional website URL for web security checks",
    )
    scan_cmd.add_argument(
        "--profile", "-p",
        default="full",
        choices=[p.value.lower() for p in ProfileName],
        help="Scan mode: quick scan, recommended scan, full scan, or web scan (default: full)",
    )
    scan_cmd.add_argument(
        "--output", "-o",
        default="",
        help="Output directory for reports (default: <repo>/secscan-results)",
    )
    scan_cmd.add_argument(
        "--format", "-f",
        default="json",
        choices=["json", "html", "both"],
        help="Report format (default: json)",
    )
    scan_cmd.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip vulnerability database enrichment",
    )
    scan_cmd.add_argument(
        "--no-ignore",
        action="store_true",
        help="Do not apply .secscan-ignore suppression rules",
    )

    # ---- list-tools command ----
    sub.add_parser("list-tools", help="List all available scanner tools")

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    """Execute the scan command. Returns exit code 0 or 1."""
    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        print(f"Error: '{repo_path}' is not a valid directory.", file=sys.stderr)
        return 1

    # Detect project
    print(f"Detecting project type in {repo_path}...")
    project_info = detect_project(repo_path, website_url=args.url)
    print(f"  Types: {', '.join(project_info.types)}")
    print(f"  Languages: {', '.join(project_info.languages) or 'unknown'}")
    print(f"  Dependency files: {', '.join(project_info.dependency_files) or 'none'}")

    # Load profile
    profile = get_profile(args.profile)
    print(f"\nUsing profile: {profile.name.value} - {profile.description}")

    # Filter tools by profile and applicability
    applicable = [
        t for t in ALL_TOOLS
        if t.is_applicable(repo_path) and t.is_installed()
    ]
    # URL-driven scanners should only run when a site target is provided.
    if not args.url:
        applicable = [
            t for t in applicable
            if t.name not in _URL_REQUIRED_TOOLS
        ]
    tools = filter_tools_by_profile(applicable, profile)

    if not tools:
        print("No applicable and installed tools found for this profile.", file=sys.stderr)
        print("Installed tools:")
        for t in ALL_TOOLS:
            status = "installed" if t.is_installed() else "MISSING"
            print(f"  - {t.name}: {status}")
        return 1

    print(f"\nRunning {len(tools)} scanner(s):")
    for t in tools:
        print(f"  - {t.name}")

    # Prepare output
    output_dir = args.output or os.path.join(repo_path, "secscan-results")
    raw_dir = os.path.join(output_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    # Run scans
    result = ScanResult(
        project_path=repo_path,
        project_type=", ".join(project_info.types),
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    for tool in tools:
        print(f"\n[>] Running {tool.name}...")
        try:
            findings = tool.run(
                project_path=repo_path,
                website_url=args.url,
                raw_dir=raw_dir,
            )
            result.findings.extend(findings)
            print(f"[OK] {tool.name} finished - {len(findings)} finding(s)")
        except Exception as exc:
            msg = f"[ERROR] {tool.name} failed: {exc}"
            print(msg, file=sys.stderr)
            result.errors.append(msg)

    result.finished_at = datetime.now(timezone.utc).isoformat()

    # Apply ignore list
    suppressed_count = 0
    if not args.no_ignore:
        ignore_list = load_ignore_file(repo_path)
        if ignore_list.entries:
            active, suppressed = filter_findings(result.findings, ignore_list)
            suppressed_count = len(suppressed)
            result.findings = active
            print(f"\n[ignore] {suppressed_count} finding(s) suppressed by .secscan-ignore")

    # Enrich findings
    if not args.no_enrich:
        try:
            from secscan.core.vuln_db import enrich_findings
            print("\nEnriching findings with OSV data...")
            result.findings = enrich_findings(result.findings)
        except Exception as exc:
            print(f"[warn] Enrichment skipped: {exc}", file=sys.stderr)

    # Calculate score
    score_result = calculate_score(result.findings)

    # Export reports
    fmt = args.format
    if fmt in ("json", "both"):
        path = export_json(result, output_dir)
        print(f"\nJSON report: {path}")
    if fmt in ("html", "both"):
        path = export_html(result, output_dir)
        print(f"HTML report: {path}")

    # Summary
    summary = result.summary
    print(f"\n{'='*50}")
    print(f"Security Score: {score_result.score}/100 (Grade: {score_result.grade})")
    print(f"Findings: {len(result.findings)} active, {suppressed_count} suppressed")
    print(f"  Critical: {summary.get('Critical', 0)}")
    print(f"  High:     {summary.get('High', 0)}")
    print(f"  Medium:   {summary.get('Medium', 0)}")
    print(f"  Low:      {summary.get('Low', 0)}")
    print(f"  Info:     {summary.get('Info', 0)}")
    if result.errors:
        print(f"  Errors:   {len(result.errors)}")
    print(f"{'='*50}")

    # Save history
    try:
        from secscan.core.history import save_scan_history
        save_scan_history(repo_path, result, score_result)
    except Exception:
        pass

    # CI threshold check
    if profile.fail_on_severities:
        passed = check_ci_threshold(result.findings, profile)
        if not passed:
            sev_names = ", ".join(s.value for s in profile.fail_on_severities)
            print(f"\n[FAIL] CI FAILED: findings with severity {sev_names} detected.")
            return 1
        else:
            print(f"\n[PASS] CI PASSED: no findings above threshold.")

    return 0


def _list_tools() -> int:
    """Print all available tools and their installation status."""
    print("SecScan - Available Tools\n")
    for tool in ALL_TOOLS:
        installed = "Installed" if tool.is_installed() else "Missing"
        print(f"  {tool.name:25s}  {installed}")
        print(f"    {tool.description}")
        if not tool.is_installed():
            print(f"    Install: {tool.install_instructions().splitlines()[0]}")
        print()
    return 0


def main():
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(_run_scan(args))
    elif args.command == "list-tools":
        sys.exit(_list_tools())
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()

