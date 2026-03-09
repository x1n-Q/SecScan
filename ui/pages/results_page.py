"""Results page – Summary / Full Log toggle, compact banner, filterable table, export."""

from __future__ import annotations

import html as _html_mod
import os
import webbrowser
from typing import Optional

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QMessageBox, QFileDialog, QSizePolicy, QGraphicsDropShadowEffect,
    QStackedWidget, QTextEdit,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QColor, QPainter, QPen, QTextCursor

from secscan.core.schema import ScanResult, Severity
from secscan.core.report_json import export_json
from secscan.core.report_html import export_html
from secscan.core.security_score import calculate_score_from_result, ScoreResult
from secscan.core.history import compute_trend, TrendMetrics
from ui.widgets.finding_table import FindingTable


def _esc(text: str) -> str:
    """Escape HTML entities in text."""
    return _html_mod.escape(str(text))


# ------------------------------------------------------------------ #
# Helper widgets
# ------------------------------------------------------------------ #

class _MiniCard(QFrame):
    """Compact severity count chip."""

    def __init__(self, label: str, color: str, text_color: str = "#fff", parent=None):
        super().__init__(parent)
        self.setFixedHeight(52)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(
            f"_MiniCard {{ background: {color}; border-radius: 10px; border: none; }}"
        )

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        inner = QVBoxLayout()
        inner.setContentsMargins(6, 4, 6, 4)
        inner.setSpacing(0)
        inner.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._count_lbl = QLabel("0")
        self._count_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._count_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self._count_lbl.setStyleSheet(f"color: {text_color}; background: transparent;")
        inner.addWidget(self._count_lbl)

        name_lbl = QLabel(label)
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_lbl.setStyleSheet(
            f"color: {text_color}; font-size: 10px; font-weight: 700;"
            f" background: transparent;"
        )
        inner.addWidget(name_lbl)
        lay.addLayout(inner)

    def set_count(self, value: int):
        self._count_lbl.setText(str(value))


class _ScoreRing(QWidget):
    """Circular arc widget that paints a score."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(56, 56)
        self._score = 0
        self._ring_color = QColor("#9e9e9e")

    def set_data(self, score: int, color: QColor):
        self._score = score
        self._ring_color = color
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(4, 4, -4, -4)

        track_pen = QPen(QColor("#e0e4ed"), 5)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, 0, 360 * 16)

        arc_pen = QPen(self._ring_color, 5)
        arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc_pen)
        span = int((self._score / 100.0) * 360 * 16)
        painter.drawArc(rect, 90 * 16, -span)

        painter.setPen(QPen(QColor("#212121")))
        painter.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter,
                         str(self._score) if self._score else "-")
        painter.end()


class _SummaryBanner(QFrame):
    """Single-row banner: Score ring + Grade + trend + severity mini-cards."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("summaryBanner")
        self.setFixedHeight(80)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(
            "#summaryBanner {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0 #f8f9ff, stop:1 #eef1fb);"
            "  border: 1px solid #d0d7e4;"
            "  border-radius: 12px;"
            "}"
        )

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(16)
        shadow.setOffset(0, 3)
        shadow.setColor(QColor(0, 0, 0, 28))
        self.setGraphicsEffect(shadow)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(10)

        # Score ring
        self._score_ring = _ScoreRing()
        layout.addWidget(self._score_ring)

        # Grade badge
        self._grade_lbl = QLabel("-")
        self._grade_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._grade_lbl.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        self._grade_lbl.setFixedSize(44, 44)
        self._grade_lbl.setStyleSheet(
            "color: #fff; background: #9e9e9e; border-radius: 10px;"
        )
        layout.addWidget(self._grade_lbl)

        # Trend text
        trend_col = QVBoxLayout()
        trend_col.setSpacing(1)
        trend_col.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._trend_lbl = QLabel("No history yet")
        self._trend_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        self._trend_lbl.setStyleSheet("color: #37474f; background: transparent;")
        self._trend_lbl.setWordWrap(True)
        trend_col.addWidget(self._trend_lbl)

        self._trend_detail = QLabel("")
        self._trend_detail.setStyleSheet(
            "color: #78909c; font-size: 10px; background: transparent;"
        )
        self._trend_detail.setWordWrap(True)
        trend_col.addWidget(self._trend_detail)

        layout.addLayout(trend_col, stretch=0)

        # Separator
        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setStyleSheet("background: #c5cdd8; border: none; max-width: 1px;")
        sep.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        layout.addWidget(sep)

        # Severity mini-cards
        self._card_critical = _MiniCard("Critical", "#c62828")
        self._card_high = _MiniCard("High", "#e65100")
        self._card_medium = _MiniCard("Medium", "#f9a825", "#3e2723")
        self._card_low = _MiniCard("Low", "#1565c0")
        self._card_info = _MiniCard("Info", "#546e7a")

        for card in (self._card_critical, self._card_high, self._card_medium,
                     self._card_low, self._card_info):
            layout.addWidget(card)

    def set_score(self, score_result: ScoreResult):
        grade = score_result.grade
        self._grade_lbl.setText(grade)

        grade_colors = {
            "A": "#2e7d32", "B": "#558b2f", "C": "#f9a825",
            "D": "#f57c00", "F": "#c62828",
        }
        bg = grade_colors.get(grade, "#9e9e9e")
        text_col = "#fff" if grade != "C" else "#212121"
        self._grade_lbl.setStyleSheet(
            f"color: {text_col}; background: {bg}; border-radius: 10px;"
        )

        ring_color = (QColor("#2e7d32") if score_result.score >= 80
                      else QColor("#f57c00") if score_result.score >= 60
                      else QColor("#c62828"))
        self._score_ring.set_data(score_result.score, ring_color)

    def set_trend(self, trend: TrendMetrics):
        if trend.history_count == 0:
            self._trend_lbl.setText("First scan")
            self._trend_detail.setText("No trend data yet")
            return

        arrows = {"improving": "▲", "declining": "▼", "stable": "●"}
        colors = {"improving": "#2e7d32", "declining": "#c62828", "stable": "#546e7a"}
        arrow = arrows.get(trend.trend_direction, "●")
        color = colors.get(trend.trend_direction, "#546e7a")

        delta_sign = "+" if trend.score_delta >= 0 else ""
        self._trend_lbl.setText(
            f'<span style="color:{color};">{arrow}</span> '
            f'{delta_sign}{trend.score_delta} pts '
            f'({trend.trend_direction.capitalize()})'
        )

        finding_sign = "+" if trend.findings_delta >= 0 else ""
        pct = f"{trend.improvement_pct:+.0f}%" if trend.improvement_pct else "0%"
        self._trend_detail.setText(
            f"{trend.previous_findings}→{trend.current_findings} "
            f"({finding_sign}{trend.findings_delta}) | "
            f"Imp: {pct} | {trend.history_count} scan(s)"
        )

    def set_counts(self, summary: dict):
        self._card_critical.set_count(summary.get("Critical", 0))
        self._card_high.set_count(summary.get("High", 0))
        self._card_medium.set_count(summary.get("Medium", 0))
        self._card_low.set_count(summary.get("Low", 0))
        self._card_info.set_count(summary.get("Info", 0))


# ------------------------------------------------------------------ #
# Full Log Viewer (read-only, styled like the run page LogView)
# ------------------------------------------------------------------ #

class _FullLogView(QTextEdit):
    """Read-only terminal-style log viewer for the full scan output."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet(
            "QTextEdit {"
            "  background-color: #1e1e2e;"
            "  color: #cdd6f4;"
            "  border: 1px solid #45475a;"
            "  border-radius: 8px;"
            "  padding: 10px;"
            "}"
        )
        self.setPlaceholderText("No scan logs available yet.")

    def set_logs(self, logs: list[str]):
        """Populate with log lines."""
        self.clear()
        if not logs:
            return
        # Build all HTML at once to avoid per-line cursor overhead
        parts: list[str] = []
        for line in logs:
            color = self._color_for_line(line)
            parts.append(f'<span style="color:{color};">{_esc(line)}</span>')
        self.setHtml(
            '<pre style="font-family: Consolas, monospace; font-size: 10pt; '
            'color: #cdd6f4; background: transparent; margin: 0; padding: 0;">'
            + "<br/>".join(parts)
            + "</pre>"
        )
        self.moveCursor(QTextCursor.MoveOperation.End)

    @staticmethod
    def _color_for_line(line: str) -> str:
        """Determine color based on prefix."""
        if line.startswith("[run]"):
            return "#89b4fa"  # blue
        if line.startswith("[ok]"):
            return "#a6e3a1"  # green
        if line.startswith("[error]") or line.startswith("[warn]"):
            return "#f38ba8"  # red
        if line.startswith("[score]"):
            return "#f9e2af"  # yellow
        if line.startswith("[full-log]"):
            return "#94e2d5"  # teal
        if line.startswith("[enrich]") or line.startswith("[history]"):
            return "#b4befe"  # lavender
        if line.startswith("[ignore]"):
            return "#fab387"  # peach
        if line.startswith("[cmd]"):
            return "#74c7ec"  # sapphire
        if line.startswith("[log-mode]"):
            return "#cba6f7"  # mauve
        return "#cdd6f4"  # default


# ------------------------------------------------------------------ #
# Results Page
# ------------------------------------------------------------------ #

class ResultsPage(QWidget):
    """Fourth page: summary banner + findings table / full log toggle + export."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: Optional[ScanResult] = None
        self._output_dir = ""
        self._scan_logs: list[str] = []
        self._is_summary_mode = True
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 10, 14, 8)
        root.setSpacing(6)

        # --- Header row: title + view toggle + export buttons ---
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        header = QLabel("Scan Results")
        header.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        header.setStyleSheet("color: #1a237e;")
        header_row.addWidget(header)

        header_row.addStretch()

        # View mode toggle button
        _TOGGLE_ON = (
            "QPushButton {"
            "  background: #e8eaf6; color: #1a237e;"
            "  border: 2px solid #1a237e; border-radius: 8px;"
            "  padding: 5px 14px; font-weight: bold; font-size: 11px;"
            "}"
            "QPushButton:hover { background: #c5cae9; }"
        )
        _TOGGLE_OFF = (
            "QPushButton {"
            "  background: transparent; color: #546e7a;"
            "  border: 1px solid #b0bec5; border-radius: 8px;"
            "  padding: 5px 14px; font-weight: bold; font-size: 11px;"
            "}"
            "QPushButton:hover { background: #eceff1; }"
        )

        self._btn_summary = QPushButton("Summary")
        self._btn_summary.setMinimumHeight(30)
        self._btn_summary.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_summary.setStyleSheet(_TOGGLE_ON)
        self._btn_summary.clicked.connect(lambda: self._set_view_mode(True))
        header_row.addWidget(self._btn_summary)

        self._btn_full = QPushButton("Full Log")
        self._btn_full.setMinimumHeight(30)
        self._btn_full.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_full.setStyleSheet(_TOGGLE_OFF)
        self._btn_full.clicked.connect(lambda: self._set_view_mode(False))
        header_row.addWidget(self._btn_full)

        # Save references to toggle styles
        self._toggle_on_style = _TOGGLE_ON
        self._toggle_off_style = _TOGGLE_OFF

        # Separator
        sep = QLabel("|")
        sep.setStyleSheet("color: #b0bec5; font-size: 16px;")
        header_row.addWidget(sep)

        # Export + New Scan buttons
        _BTN = (
            "QPushButton {{"
            "  background: {bg}; color: {fg};"
            "  border: none; border-radius: 8px;"
            "  padding: 5px 14px; font-weight: bold; font-size: 11px;"
            "}}"
            "QPushButton:hover {{ background: {hov}; }}"
        )

        for label, bg, hov, slot in [
            ("Export JSON", "#1565c0", "#1976d2", self._export_json),
            ("Export HTML", "#2e7d32", "#388e3c", self._export_html),
            ("New Scan", "#1a237e", "#283593", None),
        ]:
            btn = QPushButton(label)
            btn.setMinimumHeight(30)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(_BTN.format(bg=bg, fg="white", hov=hov))
            if slot:
                btn.clicked.connect(slot)
            else:
                btn.clicked.connect(self._new_scan_requested)
                self._new_scan_btn = btn
            header_row.addWidget(btn)

        root.addLayout(header_row)

        self._meta_lbl = QLabel("Target: -")
        self._meta_lbl.setWordWrap(True)
        self._meta_lbl.setStyleSheet("color: #607d8b; font-size: 11px; padding: 0 2px;")
        root.addWidget(self._meta_lbl)

        # --- Summary banner ---
        self._banner = _SummaryBanner()
        root.addWidget(self._banner)

        # --- Stacked widget: 0 = Findings table, 1 = Full log ---
        self._stack = QStackedWidget()

        self._table = FindingTable()
        self._stack.addWidget(self._table)  # index 0

        self._full_log = _FullLogView()
        self._stack.addWidget(self._full_log)  # index 1

        self._stack.setCurrentIndex(0)
        root.addWidget(self._stack, stretch=1)

    # ------------------------------------------------------------------ #
    def _set_view_mode(self, summary: bool):
        """Switch between summary (table) and full log view."""
        self._is_summary_mode = summary
        if summary:
            self._stack.setCurrentIndex(0)
            self._btn_summary.setStyleSheet(self._toggle_on_style)
            self._btn_full.setStyleSheet(self._toggle_off_style)
        else:
            self._stack.setCurrentIndex(1)
            # Always refresh full log when switching to it
            self._full_log.set_logs(self._scan_logs)
            self._btn_full.setStyleSheet(self._toggle_on_style)
            self._btn_summary.setStyleSheet(self._toggle_off_style)

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #
    def load_result(self, result: ScanResult, output_dir: str):
        """Display the scan result with score and trend data."""
        self._result = result
        self._output_dir = output_dir
        started = result.started_at or "N/A"
        finished = result.finished_at or "N/A"
        self._meta_lbl.setText(
            f"Target: {result.project_path} | Scanned: {started} -> {finished}"
        )

        # Summary counts
        self._banner.set_counts(result.summary)

        # Security score
        try:
            score_result = calculate_score_from_result(result)
            self._banner.set_score(score_result)
        except Exception:
            pass

        # Trend
        try:
            score_result = calculate_score_from_result(result)
            trend = compute_trend(result, score_result, result.project_path)
            self._banner.set_trend(trend)
        except Exception:
            pass

        # Findings table
        self._table.set_findings(result.findings)

        # Reset to summary view
        self._set_view_mode(True)

    def set_scan_logs(self, logs: list[str]):
        """Receive the full scan logs from the run page."""
        self._scan_logs = list(logs)
        # If currently viewing full log, refresh it
        if not self._is_summary_mode:
            self._full_log.set_logs(self._scan_logs)

    @property
    def new_scan_button(self) -> QPushButton:
        return self._new_scan_btn

    # ------------------------------------------------------------------ #
    def _export_json(self):
        if not self._result:
            return
        dir_path = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if dir_path:
            try:
                path = export_json(self._result, dir_path)
                QMessageBox.information(
                    self, "Export Complete",
                    f"JSON report saved to:\n{path}",
                )
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", str(exc))

    def _export_html(self):
        if not self._result:
            return
        dir_path = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if dir_path:
            try:
                path = export_html(self._result, dir_path)
                QMessageBox.information(
                    self, "Export Complete",
                    f"HTML report saved to:\n{path}",
                )
                reply = QMessageBox.question(
                    self, "Open Report",
                    "Open the HTML report in your browser?",
                )
                if reply == QMessageBox.StandardButton.Yes:
                    webbrowser.open(f"file:///{path}")
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", str(exc))

    def _new_scan_requested(self):
        """Handled by MainWindow via signal wiring."""
        pass
