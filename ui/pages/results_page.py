"""Results page – dark-themed summary banner, findings table, full log toggle, export."""

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
from ui import theme as T


def _esc(text: str) -> str:
    return _html_mod.escape(str(text))


# ------------------------------------------------------------------ #
# Helper widgets
# ------------------------------------------------------------------ #

class _MiniCard(QFrame):
    """Compact severity count chip – dark themed."""

    def __init__(self, label: str, color: str, text_color: str = "#fff", parent=None):
        super().__init__(parent)
        self.setFixedHeight(50)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(
            f"_MiniCard {{ background: {color}; border-radius: 8px; border: none; }}"
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
        self._count_lbl.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        self._count_lbl.setStyleSheet(f"color: {text_color}; background: transparent;")
        inner.addWidget(self._count_lbl)

        name_lbl = QLabel(label)
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_lbl.setStyleSheet(
            f"color: {text_color}; font-size: 9px; font-weight: 700; "
            f"background: transparent; text-transform: uppercase;"
        )
        inner.addWidget(name_lbl)
        lay.addLayout(inner)

    def set_count(self, value: int):
        self._count_lbl.setText(str(value))


class _ScoreRing(QWidget):
    """Circular score arc – dark background."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(52, 52)
        self._score = 0
        self._ring_color = QColor(T.TEXT_MUTED)

    def set_data(self, score: int, color: QColor):
        self._score = score
        self._ring_color = color
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(4, 4, -4, -4)

        track_pen = QPen(QColor(T.BORDER_SUBTLE), 5)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(track_pen)
        painter.drawArc(rect, 0, 360 * 16)

        arc_pen = QPen(self._ring_color, 5)
        arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc_pen)
        span = int((self._score / 100.0) * 360 * 16)
        painter.drawArc(rect, 90 * 16, -span)

        painter.setPen(QPen(QColor(T.TEXT_PRIMARY)))
        painter.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter,
                         str(self._score) if self._score else "-")
        painter.end()


class _SummaryBanner(QFrame):
    """Dark gradient banner: Score + Grade + Trend + severity chips."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("summaryBanner")
        self.setFixedHeight(76)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(
            "#summaryBanner {"
            f"  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"    stop:0 {T.BG_CARD}, stop:1 {T.BG_CARD_ALT});"
            f"  border: 1px solid {T.BORDER};"
            f"  border-radius: 10px;"
            "}"
        )

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 4)
        shadow.setColor(QColor(0, 0, 0, 80))
        self.setGraphicsEffect(shadow)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(8)

        self._score_ring = _ScoreRing()
        layout.addWidget(self._score_ring)

        self._grade_lbl = QLabel("-")
        self._grade_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._grade_lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self._grade_lbl.setFixedSize(40, 40)
        self._grade_lbl.setStyleSheet(
            f"color: #fff; background: {T.TEXT_MUTED}; border-radius: 8px;"
        )
        layout.addWidget(self._grade_lbl)

        trend_col = QVBoxLayout()
        trend_col.setSpacing(1)
        trend_col.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._trend_lbl = QLabel("No history yet")
        self._trend_lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        self._trend_lbl.setStyleSheet(f"color: {T.TEXT_PRIMARY}; background: transparent;")
        self._trend_lbl.setWordWrap(True)
        trend_col.addWidget(self._trend_lbl)

        self._trend_detail = QLabel("")
        self._trend_detail.setStyleSheet(
            f"color: {T.TEXT_MUTED}; font-size: 10px; background: transparent;"
        )
        self._trend_detail.setWordWrap(True)
        trend_col.addWidget(self._trend_detail)

        layout.addLayout(trend_col, stretch=0)

        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setStyleSheet(f"background: {T.BORDER_SUBTLE}; border: none; max-width: 1px;")
        sep.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        layout.addWidget(sep)

        self._card_critical = _MiniCard("Critical", T.SEV_CRITICAL_BG, T.SEV_CRITICAL)
        self._card_high = _MiniCard("High", T.SEV_HIGH_BG, T.SEV_HIGH)
        self._card_medium = _MiniCard("Medium", T.SEV_MEDIUM_BG, T.SEV_MEDIUM)
        self._card_low = _MiniCard("Low", T.SEV_LOW_BG, T.SEV_LOW)
        self._card_info = _MiniCard("Info", T.SEV_INFO_BG, T.SEV_INFO)

        for card in (self._card_critical, self._card_high, self._card_medium,
                     self._card_low, self._card_info):
            layout.addWidget(card)

    def set_score(self, score_result: ScoreResult):
        grade = score_result.grade
        self._grade_lbl.setText(grade)

        grade_colors = {
            "A": T.SUCCESS, "B": "#22d3ee", "C": T.WARNING,
            "D": "#fb923c", "F": T.DANGER,
        }
        bg = grade_colors.get(grade, T.TEXT_MUTED)
        text_col = "#fff" if grade != "C" else T.BG_DARKEST
        self._grade_lbl.setStyleSheet(
            f"color: {text_col}; background: {bg}; border-radius: 8px;"
        )

        ring_color = (QColor(T.SUCCESS) if score_result.score >= 80
                      else QColor(T.WARNING) if score_result.score >= 60
                      else QColor(T.DANGER))
        self._score_ring.set_data(score_result.score, ring_color)

    def set_trend(self, trend: TrendMetrics):
        if trend.history_count == 0:
            self._trend_lbl.setText("First scan")
            self._trend_detail.setText("No trend data yet")
            return

        arrows = {"improving": "▲", "declining": "▼", "stable": "●"}
        colors = {"improving": T.SUCCESS, "declining": T.DANGER, "stable": T.TEXT_MUTED}
        arrow = arrows.get(trend.trend_direction, "●")
        color = colors.get(trend.trend_direction, T.TEXT_MUTED)

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
# Full Log Viewer
# ------------------------------------------------------------------ #

class _FullLogView(QTextEdit):
    """Read-only terminal-style log viewer."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet(T.LOG_STYLE)
        self.setPlaceholderText("No scan logs available yet.")

    def set_logs(self, logs: list[str]):
        self.clear()
        if not logs:
            return
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
        if line.startswith("[run]"):
            return "#89b4fa"
        if line.startswith("[ok]"):
            return "#a6e3a1"
        if line.startswith("[error]") or line.startswith("[warn]"):
            return "#f38ba8"
        if line.startswith("[score]"):
            return "#f9e2af"
        if line.startswith("[full-log]"):
            return "#94e2d5"
        if line.startswith("[enrich]") or line.startswith("[history]"):
            return "#b4befe"
        if line.startswith("[ignore]"):
            return "#fab387"
        if line.startswith("[cmd]"):
            return "#74c7ec"
        if line.startswith("[log-mode]"):
            return "#cba6f7"
        return "#cdd6f4"


# ------------------------------------------------------------------ #
# Results Page
# ------------------------------------------------------------------ #

class ResultsPage(QWidget):
    """Fourth page: summary + findings table / full log toggle + export."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._result: Optional[ScanResult] = None
        self._output_dir = ""
        self._scan_logs: list[str] = []
        self._is_summary_mode = True
        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 10)
        root.setSpacing(8)

        # Header row
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        header = QLabel("Scan Results")
        header.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        header.setStyleSheet(f"color: {T.TEXT_PRIMARY};")
        header_row.addWidget(header)
        header_row.addStretch()

        # Toggle buttons
        _TOGGLE_ON = (
            f"QPushButton {{"
            f"  background: {T.ACCENT_BG}; color: {T.ACCENT_HOVER};"
            f"  border: 1.5px solid {T.ACCENT}; border-radius: 6px;"
            f"  padding: 5px 14px; font-weight: bold; font-size: 11px;"
            f"}}"
            f"QPushButton:hover {{ background: {T.ACCENT}; color: #fff; }}"
        )
        _TOGGLE_OFF = (
            f"QPushButton {{"
            f"  background: transparent; color: {T.TEXT_MUTED};"
            f"  border: 1px solid {T.BORDER_SUBTLE}; border-radius: 6px;"
            f"  padding: 5px 14px; font-weight: bold; font-size: 11px;"
            f"}}"
            f"QPushButton:hover {{ background: {T.BG_HOVER}; }}"
        )

        self._btn_summary = QPushButton("Summary")
        self._btn_summary.setMinimumHeight(28)
        self._btn_summary.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_summary.setStyleSheet(_TOGGLE_ON)
        self._btn_summary.clicked.connect(lambda: self._set_view_mode(True))
        header_row.addWidget(self._btn_summary)

        self._btn_full = QPushButton("Full Log")
        self._btn_full.setMinimumHeight(28)
        self._btn_full.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_full.setStyleSheet(_TOGGLE_OFF)
        self._btn_full.clicked.connect(lambda: self._set_view_mode(False))
        header_row.addWidget(self._btn_full)

        self._toggle_on_style = _TOGGLE_ON
        self._toggle_off_style = _TOGGLE_OFF

        sep = QLabel("│")
        sep.setStyleSheet(f"color: {T.BORDER_SUBTLE}; font-size: 16px;")
        header_row.addWidget(sep)

        for label, bg, hov, slot in [
            ("Export JSON", "#0369a1", "#0284c7", self._export_json),
            ("Export HTML", T.SUCCESS_HOVER, T.SUCCESS, self._export_html),
            ("New Scan", T.ACCENT, T.ACCENT_HOVER, None),
        ]:
            btn = QPushButton(label)
            btn.setMinimumHeight(28)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(T.btn_style(bg, hov))
            if slot:
                btn.clicked.connect(slot)
            else:
                btn.clicked.connect(self._new_scan_requested)
                self._new_scan_btn = btn
            header_row.addWidget(btn)

        root.addLayout(header_row)

        self._meta_lbl = QLabel("Target: -")
        self._meta_lbl.setWordWrap(True)
        self._meta_lbl.setStyleSheet(
            f"color: {T.TEXT_MUTED}; font-size: 11px; padding: 0 2px;"
        )
        root.addWidget(self._meta_lbl)

        self._banner = _SummaryBanner()
        root.addWidget(self._banner)

        self._stack = QStackedWidget()

        self._table = FindingTable()
        self._stack.addWidget(self._table)

        self._full_log = _FullLogView()
        self._stack.addWidget(self._full_log)

        self._stack.setCurrentIndex(0)
        root.addWidget(self._stack, stretch=1)

    def _set_view_mode(self, summary: bool):
        self._is_summary_mode = summary
        if summary:
            self._stack.setCurrentIndex(0)
            self._btn_summary.setStyleSheet(self._toggle_on_style)
            self._btn_full.setStyleSheet(self._toggle_off_style)
        else:
            self._stack.setCurrentIndex(1)
            self._full_log.set_logs(self._scan_logs)
            self._btn_full.setStyleSheet(self._toggle_on_style)
            self._btn_summary.setStyleSheet(self._toggle_off_style)

    def load_result(self, result: ScanResult, output_dir: str):
        self._result = result
        self._output_dir = output_dir
        started = result.started_at or "N/A"
        finished = result.finished_at or "N/A"
        self._meta_lbl.setText(
            f"Target: {result.project_path}  ·  Scanned: {started} → {finished}"
        )

        self._banner.set_counts(result.summary)

        try:
            score_result = calculate_score_from_result(result)
            self._banner.set_score(score_result)
        except Exception:
            pass

        try:
            score_result = calculate_score_from_result(result)
            trend = compute_trend(result, score_result, result.project_path)
            self._banner.set_trend(trend)
        except Exception:
            pass

        self._table.set_findings(result.findings)
        self._set_view_mode(True)

    def set_scan_logs(self, logs: list[str]):
        self._scan_logs = list(logs)
        if not self._is_summary_mode:
            self._full_log.set_logs(self._scan_logs)

    @property
    def new_scan_button(self) -> QPushButton:
        return self._new_scan_btn

    def _export_json(self):
        if not self._result:
            return
        dir_path = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if dir_path:
            try:
                path = export_json(self._result, dir_path)
                QMessageBox.information(
                    self, "Export Complete", f"JSON report saved to:\n{path}",
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
                    self, "Export Complete", f"HTML report saved to:\n{path}",
                )
                reply = QMessageBox.question(
                    self, "Open Report", "Open the HTML report in your browser?",
                )
                if reply == QMessageBox.StandardButton.Yes:
                    webbrowser.open(f"file:///{path}")
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", str(exc))

    def _new_scan_requested(self):
        pass
