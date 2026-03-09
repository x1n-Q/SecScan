"""Run scan page - progress bar, live logs, stop button, and scan mode."""

from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from secscan.core.detect import ProjectInfo
from secscan.core.runner import ScanManager
from secscan.core.schema import ScanResult
from secscan.tools.base import ToolBase
from ui.widgets.log_view import LogView


class RunPage(QWidget):
    """Third page: run the scan with progress, logs, and stop control."""

    scan_finished = Signal(object)  # ScanResult

    def __init__(self, parent=None):
        super().__init__(parent)
        self._manager = ScanManager(self)
        self._log_lines: list[str] = []
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(16)

        header = QLabel("Scan Progress")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setStyleSheet("color: #1a237e;")
        root.addWidget(header)

        options_row = QHBoxLayout()
        self._mode_lbl = QLabel("Scan Mode: Recommended Scan")
        self._mode_lbl.setStyleSheet("color: #424242; font-size: 13px; font-weight: 600;")
        options_row.addWidget(self._mode_lbl)

        options_row.addSpacing(18)
        options_row.addWidget(QLabel("Log Detail:"))
        self._log_mode_combo = QComboBox()
        self._log_mode_combo.addItem("Simple (summary)", "simple")
        self._log_mode_combo.addItem("Full (raw tool logs)", "full")
        self._log_mode_combo.setMinimumWidth(220)
        self._log_mode_combo.setMinimumHeight(32)
        options_row.addWidget(self._log_mode_combo)

        options_row.addStretch()
        root.addLayout(options_row)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setMinimumHeight(28)
        self._progress.setStyleSheet(
            "QProgressBar { border: 1px solid #ccc; border-radius: 6px; "
            "text-align: center; background: #e0e0e0; font-weight: bold; color: #333; }"
            "QProgressBar::chunk { background: #1a237e; border-radius: 5px; }"
        )
        root.addWidget(self._progress)

        self._status_lbl = QLabel("Waiting to start...")
        self._status_lbl.setStyleSheet("color: #424242; font-size: 13px;")
        root.addWidget(self._status_lbl)

        self._target_lbl = QLabel("Target: -")
        self._target_lbl.setWordWrap(True)
        self._target_lbl.setStyleSheet("color: #607d8b; font-size: 12px;")
        root.addWidget(self._target_lbl)

        self._log_view = LogView()
        root.addWidget(self._log_view, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self._stop_btn = QPushButton("Stop Scan")
        self._stop_btn.setMinimumHeight(40)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._stop_btn.setStyleSheet(
            "QPushButton { background: #c62828; color: white; border-radius: 8px; "
            "padding: 8px 24px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background: #d32f2f; }"
            "QPushButton:disabled { background: #bdbdbd; }"
        )
        self._stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(self._stop_btn)

        self._results_btn = QPushButton("View Results  ->")
        self._results_btn.setMinimumHeight(40)
        self._results_btn.setEnabled(False)
        self._results_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._results_btn.setStyleSheet(
            "QPushButton { background: #2e7d32; color: white; border-radius: 8px; "
            "padding: 8px 24px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background: #388e3c; }"
            "QPushButton:disabled { background: #bdbdbd; }"
        )
        btn_row.addWidget(self._results_btn)

        root.addLayout(btn_row)

    def _connect_signals(self):
        self._manager.log.connect(self._on_log)
        self._manager.progress.connect(self._progress.setValue)
        self._manager.finished.connect(self._on_finished)

    def _on_log(self, text: str):
        """Capture log line to list and display in view."""
        self._log_lines.append(text)
        self._log_view.append_log(text)

    def start_scan(
        self,
        tools: List[ToolBase],
        project_info: ProjectInfo,
        output_dir: str,
    ):
        """Begin scanning with the given tools."""
        self._log_view.clear_log()
        self._log_lines.clear()
        self._progress.setValue(0)
        self._status_lbl.setText(f"Running {len(tools)} scanner(s)...")
        self._target_lbl.setText(f"Target: {project_info.path}")
        self._stop_btn.setEnabled(True)
        self._results_btn.setEnabled(False)

        log_mode = self._log_mode_combo.currentData() or "simple"
        self._log_view.append_log(f"[log-mode] {log_mode}")
        self._manager.start(
            tools,
            project_info,
            output_dir,
            verbose_logs=(log_mode == "full"),
        )

    @property
    def results_button(self) -> QPushButton:
        return self._results_btn

    def get_logs(self) -> list[str]:
        """Return collected log lines for transfer to results page."""
        return list(self._log_lines)

    def set_scan_mode(self, mode_label: str):
        self._mode_lbl.setText(f"Scan Mode: {mode_label}")

    def _on_stop(self):
        self._manager.stop()
        self._status_lbl.setText("Stopping...")
        self._stop_btn.setEnabled(False)

    def _on_finished(self, result: ScanResult):
        total = len(result.findings)
        errors = len(result.errors)
        self._status_lbl.setText(f"Scan complete - {total} finding(s), {errors} error(s)")
        self._stop_btn.setEnabled(False)
        self._results_btn.setEnabled(True)
        self.scan_finished.emit(result)
