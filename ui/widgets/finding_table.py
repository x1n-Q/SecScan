"""Filterable findings table widget – dark themed."""

from __future__ import annotations

import html
from typing import List

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFrame,
    QHeaderView, QHBoxLayout, QLabel, QLineEdit,
    QSizePolicy, QSplitter, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from secscan.core.schema import Finding, Severity
from ui import theme as T

_SEV_COLORS = {
    Severity.CRITICAL: QColor(T.SEV_CRITICAL),
    Severity.HIGH: QColor(T.SEV_HIGH),
    Severity.MEDIUM: QColor(T.SEV_MEDIUM),
    Severity.LOW: QColor(T.SEV_LOW),
    Severity.INFO: QColor(T.SEV_INFO),
}

_COLUMNS = ["Severity", "Tool", "Category", "Title", "Location"]


def _esc(text: str) -> str:
    return html.escape(str(text))


class FindingTable(QWidget):
    """Table + detail panel for displaying scan findings."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._findings: List[Finding] = []
        self._filtered: List[Finding] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # ---- Filter bar ----
        filter_row = QHBoxLayout()
        filter_row.setSpacing(6)

        self._count_lbl = QLabel("Showing 0 findings")
        self._count_lbl.setStyleSheet(
            f"color: {T.ACCENT_HOVER}; font-size: 12px; font-weight: 700;"
        )
        filter_row.addWidget(self._count_lbl)
        filter_row.addStretch()

        _LBL = f"color: {T.TEXT_SECONDARY}; font-weight: 600; font-size: 11px;"

        sev_lbl = QLabel("Severity:")
        sev_lbl.setStyleSheet(_LBL)
        filter_row.addWidget(sev_lbl)
        self._sev_combo = QComboBox()
        self._sev_combo.addItem("All")
        for s in Severity:
            self._sev_combo.addItem(s.value)
        self._sev_combo.currentTextChanged.connect(self._apply_filters)
        self._sev_combo.setFixedWidth(100)
        self._sev_combo.setStyleSheet(T.COMBO_STYLE)
        filter_row.addWidget(self._sev_combo)

        cat_lbl = QLabel("Category:")
        cat_lbl.setStyleSheet(_LBL)
        filter_row.addWidget(cat_lbl)
        self._cat_combo = QComboBox()
        self._cat_combo.addItem("All")
        self._cat_combo.currentTextChanged.connect(self._apply_filters)
        self._cat_combo.setFixedWidth(120)
        self._cat_combo.setStyleSheet(T.COMBO_STYLE)
        filter_row.addWidget(self._cat_combo)

        search_lbl = QLabel("Search:")
        search_lbl.setStyleSheet(_LBL)
        filter_row.addWidget(search_lbl)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by keyword…")
        self._search.setFixedWidth(180)
        self._search.textChanged.connect(self._apply_filters)
        self._search.setStyleSheet(T.INPUT_STYLE)
        filter_row.addWidget(self._search)

        layout.addLayout(filter_row)

        # ---- Splitter: table + detail ----
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(
            f"QSplitter::handle {{"
            f"  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            f"    stop:0.35 transparent, stop:0.5 {T.BORDER_SUBTLE}, stop:0.65 transparent);"
            f"  margin: 1px 60px;"
            f"}}"
        )

        # Table
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setMinimumHeight(180)
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setWordWrap(False)
        self._table.currentCellChanged.connect(self._on_row_changed)
        self._table.setStyleSheet(T.TABLE_STYLE)
        splitter.addWidget(self._table)

        # Detail panel
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Segoe UI", 10))
        self._detail.setMinimumHeight(90)
        self._detail.setStyleSheet(
            f"QTextEdit {{"
            f"  background: {T.BG_CARD};"
            f"  color: {T.TEXT_PRIMARY};"
            f"  border: 1px solid {T.BORDER};"
            f"  border-radius: 8px;"
            f"  padding: 8px;"
            f"}}"
        )
        self._detail.setPlaceholderText("Select a finding to view details…")
        splitter.addWidget(self._detail)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter, stretch=1)

    def set_findings(self, findings: List[Finding]):
        self._findings = list(findings)
        self._update_category_filter()
        self._apply_filters()

    def add_finding(self, finding: Finding):
        self._findings.append(finding)
        cat_val = finding.category.value
        if self._cat_combo.findText(cat_val) == -1:
            self._cat_combo.addItem(cat_val)
        self._apply_filters()

    def clear_findings(self):
        self._findings.clear()
        self._filtered.clear()
        self._table.setRowCount(0)
        self._detail.clear()
        self._count_lbl.setText("Showing 0 findings")

    def _update_category_filter(self):
        self._cat_combo.blockSignals(True)
        current = self._cat_combo.currentText()
        self._cat_combo.clear()
        self._cat_combo.addItem("All")
        categories = sorted({f.category.value for f in self._findings})
        for c in categories:
            self._cat_combo.addItem(c)
        idx = self._cat_combo.findText(current)
        if idx >= 0:
            self._cat_combo.setCurrentIndex(idx)
        self._cat_combo.blockSignals(False)

    @Slot()
    def _apply_filters(self):
        sev_filter = self._sev_combo.currentText()
        cat_filter = self._cat_combo.currentText()
        keyword = self._search.text().lower().strip()

        filtered = self._findings
        if sev_filter != "All":
            filtered = [f for f in filtered if f.severity.value == sev_filter]
        if cat_filter != "All":
            filtered = [f for f in filtered if f.category.value == cat_filter]
        if keyword:
            filtered = [
                f for f in filtered
                if keyword in f.title.lower()
                or keyword in f.location.lower()
                or keyword in f.tool.lower()
                or keyword in f.category.value.lower()
            ]

        self._filtered = filtered
        self._populate_table()

    def _populate_table(self):
        self._table.setRowCount(len(self._filtered))
        total = len(self._findings)
        shown = len(self._filtered)
        if total == shown:
            self._count_lbl.setText(f"Showing {shown} finding{'s' if shown != 1 else ''}")
        else:
            self._count_lbl.setText(
                f"Showing {shown} of {total} finding{'s' if total != 1 else ''}"
            )

        for row, finding in enumerate(self._filtered):
            sev_item = QTableWidgetItem(finding.severity.value)
            sev_item.setForeground(_SEV_COLORS.get(finding.severity, QColor(T.TEXT_MUTED)))
            sev_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self._table.setItem(row, 0, sev_item)

            self._table.setItem(row, 1, QTableWidgetItem(finding.tool))
            self._table.setItem(row, 2, QTableWidgetItem(finding.category.value))
            self._table.setItem(row, 3, QTableWidgetItem(finding.title))
            self._table.setItem(row, 4, QTableWidgetItem(finding.location))

        if self._filtered:
            self._table.setCurrentCell(0, 0)
        else:
            self._detail.clear()

    @Slot(int, int, int, int)
    def _on_row_changed(self, row, _col, _prev_row, _prev_col):
        if 0 <= row < len(self._filtered):
            finding = self._filtered[row]
            refs = "\n".join(f"  • {r}" for r in finding.references) or "  None"

            sev_color = _SEV_COLORS.get(finding.severity, QColor(T.TEXT_MUTED)).name()
            self._detail.setHtml(
                f"<div style='font-family: Segoe UI, sans-serif; color: {T.TEXT_PRIMARY};'>"
                f"<h3 style='color:{T.ACCENT_HOVER}; margin:0 0 4px 0;'>{_esc(finding.title)}</h3>"
                f"<p style='margin:2px 0;'>"
                f"<span style='background:{sev_color}; color:#fff; padding:2px 8px;"
                f" border-radius:3px; font-weight:bold; font-size:10px;'>"
                f"{_esc(finding.severity.value)}</span> &nbsp; "
                f"<b>Tool:</b> {_esc(finding.tool)} &nbsp; "
                f"<b>Category:</b> {_esc(finding.category.value)}</p>"
                f"<p style='margin:4px 0;'><b>Location:</b> "
                f"<code style='background:{T.BG_SURFACE}; padding:1px 5px; border-radius:3px;"
                f" color:{T.ACCENT_HOVER};'>"
                f"{_esc(finding.location)}</code></p>"
                f"<p style='margin:4px 0;'><b>Evidence:</b></p>"
                f"<pre style='background:{T.BG_DARKEST}; color:#cdd6f4; padding:6px;"
                f" border-radius:4px; font-size:10px;'>{_esc(finding.evidence)}</pre>"
                f"<p style='margin:4px 0;'><b>Remediation:</b><br/>"
                f"{_esc(finding.remediation)}</p>"
                f"<p style='margin:4px 0;'><b>References:</b></p>"
                f"<pre style='background:{T.BG_DARKEST}; color:#cdd6f4; padding:6px;"
                f" border-radius:4px; font-size:10px;'>{_esc(refs)}</pre>"
                f"<p style='color:{T.TEXT_MUTED}; font-size:9px; margin-top:4px;'>"
                f"ID: {_esc(finding.id)} | Timestamp: {_esc(finding.timestamp)}</p>"
                f"</div>"
            )
        else:
            self._detail.clear()
