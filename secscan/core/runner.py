"""Scan engine - orchestrates tool execution in background threads."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Dict, Optional

from PySide6.QtCore import QObject, QThread, Signal

from secscan.core.detect import ProjectInfo
from secscan.core.schema import ScanResult
from secscan.tools.base import ToolBase


class ScanWorker(QObject):
    """Runs selected tools sequentially in a worker thread."""

    log = Signal(str)
    progress = Signal(int)
    finding_found = Signal(object)
    finished = Signal(object)

    def __init__(
        self,
        tools: list,
        project_info: ProjectInfo,
        output_dir: str,
        enable_enrich: bool = True,
        enable_ignore: bool = True,
        verbose_logs: bool = False,
        parent: Optional[QObject] = None,
    ):
        super().__init__(parent)
        self._tools = tools
        self._project_info = project_info
        self._output_dir = output_dir
        self._enable_enrich = enable_enrich
        self._enable_ignore = enable_ignore
        self._verbose_logs = verbose_logs
        self._stopped = False

    def stop(self):
        """Request graceful stop."""
        self._stopped = True

    def run(self):
        """Execute all selected tools and emit results."""
        result = ScanResult(
            project_path=self._project_info.path,
            project_type=", ".join(self._project_info.types),
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        raw_dir = os.path.join(self._output_dir, "raw")
        os.makedirs(raw_dir, exist_ok=True)
        self.log.emit(f"[project] {self._project_info.path}")
        if self._project_info.website_url:
            self.log.emit(f"[url] {self._project_info.website_url}")
        if self._verbose_logs:
            self.log.emit("[full-log] enabled: showing command output and raw tool logs")

        total = max(len(self._tools), 1)
        for idx, tool in enumerate(self._tools):
            if self._stopped:
                self.log.emit("[stop] Scan stopped by user.")
                break

            self.progress.emit(int((idx / total) * 100))
            self.log.emit(f"[run] {tool.name}")
            before_raw = self._snapshot_raw_files(raw_dir)
            ToolBase.configure_live_logging(self.log.emit, self._verbose_logs)

            try:
                findings = tool.run(
                    project_path=self._project_info.path,
                    website_url=self._project_info.website_url,
                    raw_dir=raw_dir,
                )
                for finding in findings:
                    result.findings.append(finding)
                    self.finding_found.emit(finding)
                self.log.emit(f"[ok] {tool.name} -> {len(findings)} finding(s)")
            except Exception as exc:
                msg = f"[error] {tool.name} failed: {exc}"
                self.log.emit(msg)
                result.errors.append(msg)
            finally:
                ToolBase.configure_live_logging(None, False)

            if self._verbose_logs and not self._stopped:
                self._emit_new_raw_logs(raw_dir, before_raw, tool.name)

        if self._enable_ignore and not self._stopped:
            self._apply_ignore_list(result)

        if self._enable_enrich and not self._stopped:
            self._enrich(result)

        result.finished_at = datetime.now(timezone.utc).isoformat()
        self.progress.emit(100)

        self._compute_and_save(result)
        self._save_results(result)
        self.finished.emit(result)

    def _snapshot_raw_files(self, raw_dir: str) -> Dict[str, float]:
        """Capture raw file mtime map for changed/new file detection."""
        snapshot: Dict[str, float] = {}
        try:
            if not os.path.isdir(raw_dir):
                return snapshot
            for name in os.listdir(raw_dir):
                path = os.path.join(raw_dir, name)
                if os.path.isfile(path):
                    snapshot[path] = os.path.getmtime(path)
        except Exception:
            return {}
        return snapshot

    def _emit_new_raw_logs(self, raw_dir: str, before: Dict[str, float], tool_name: str):
        """Emit full text for raw files created/updated by the current tool."""
        after = self._snapshot_raw_files(raw_dir)
        changed = [p for p, mtime in after.items() if p not in before or before[p] != mtime]
        if not changed:
            self.log.emit(f"[full-log] {tool_name}: no new raw output files.")
            return

        for path in sorted(changed):
            rel_path = os.path.relpath(path, raw_dir)
            self.log.emit(f"[full-log] BEGIN {tool_name} :: {rel_path}")
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except Exception as exc:
                self.log.emit(f"[full-log] Could not read {rel_path}: {exc}")
                self.log.emit(f"[full-log] END {tool_name} :: {rel_path}")
                continue

            if content:
                for line in content.splitlines():
                    self.log.emit(line)
            else:
                self.log.emit("(empty)")
            self.log.emit(f"[full-log] END {tool_name} :: {rel_path}")

    def _apply_ignore_list(self, result: ScanResult):
        """Filter findings through the .secscan-ignore file."""
        try:
            from secscan.core.ignore import filter_findings, load_ignore_file

            ignore_list = load_ignore_file(self._project_info.path)
            if ignore_list.entries:
                active, suppressed = filter_findings(result.findings, ignore_list)
                result.findings = active
                if suppressed:
                    self.log.emit(f"[ignore] Suppressed {len(suppressed)} finding(s)")
        except Exception as exc:
            self.log.emit(f"[warn] Ignore processing failed: {exc}")

    def _enrich(self, result: ScanResult):
        """Enrich findings with OSV vulnerability data."""
        try:
            from secscan.core.vuln_db import enrich_findings

            self.log.emit("[enrich] Querying OSV data...")
            result.findings = enrich_findings(result.findings)
            self.log.emit("[enrich] Complete")
        except Exception as exc:
            self.log.emit(f"[warn] Enrichment skipped: {exc}")

    def _compute_and_save(self, result: ScanResult):
        """Compute security score and save history."""
        try:
            from secscan.core.history import save_scan_history
            from secscan.core.security_score import calculate_score_from_result

            score = calculate_score_from_result(result)
            self.log.emit(f"[score] {score.score}/100 (Grade {score.grade})")
            save_scan_history(self._project_info.path, result, score)
            self.log.emit("[history] Saved")
        except Exception as exc:
            self.log.emit(f"[warn] Score/history failed: {exc}")

    def _save_results(self, result: ScanResult):
        """Write findings.json into the output directory."""
        try:
            path = os.path.join(self._output_dir, "findings.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, indent=2, ensure_ascii=False)
        except Exception as exc:
            self.log.emit(f"[warn] Could not save findings.json: {exc}")


class ScanManager(QObject):
    """Convenience wrapper that manages ScanWorker + QThread lifecycle."""

    log = Signal(str)
    progress = Signal(int)
    finding_found = Signal(object)
    finished = Signal(object)

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._thread: Optional[QThread] = None
        self._worker: Optional[ScanWorker] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.isRunning()

    def start(
        self,
        tools: list,
        project_info: ProjectInfo,
        output_dir: str,
        enable_enrich: bool = True,
        enable_ignore: bool = True,
        verbose_logs: bool = False,
    ):
        """Start a scan in a background thread."""
        if self.is_running:
            return

        self._thread = QThread()
        self._worker = ScanWorker(
            tools,
            project_info,
            output_dir,
            enable_enrich=enable_enrich,
            enable_ignore=enable_ignore,
            verbose_logs=verbose_logs,
        )
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.log.connect(self.log.emit)
        self._worker.progress.connect(self.progress.emit)
        self._worker.finding_found.connect(self.finding_found.emit)
        self._worker.finished.connect(self._on_finished)
        self._thread.start()

    def stop(self):
        """Request the worker to stop."""
        if self._worker:
            self._worker.stop()

    def _on_finished(self, result: ScanResult):
        self.finished.emit(result)
        if self._thread:
            self._thread.quit()
            self._thread.wait()
            self._thread = None
            self._worker = None
