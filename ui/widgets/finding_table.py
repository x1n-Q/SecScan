"""Filterable findings table widget."""

from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QGraphicsDropShadowEffect,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from secscan.core.schema import Finding, Severity


_SEV_COLORS = {
    Severity.CRITICAL: QColor("#c62828"),
    Severity.HIGH: QColor("#e65100"),
    Severity.MEDIUM: QColor("#f9a825"),
    Severity.LOW: QColor("#1565c0"),
    Severity.INFO: QColor("#546e7a"),
}

_COLUMNS = ["Severity", "Tool", "Category", "Title", "Location"]


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

        # ---- Compact inline filter bar (no wrapper frame) ----
        filter_row = QHBoxLayout()
        filter_row.setSpacing(6)

        self._count_lbl = QLabel("Showing 0 findings")
        self._count_lbl.setStyleSheet(
            "color: #1a237e; font-size: 12px; font-weight: 700;"
        )
        filter_row.addWidget(self._count_lbl)
        filter_row.addStretch()

        _LBL = "color: #455a64; font-weight: 600; font-size: 11px;"
        _COMBO = (
            "QComboBox {"
            "  color: #212121; background: #f5f7fa;"
            "  border: 1px solid #c7d0db; border-radius: 6px;"
            "  padding: 4px 8px; min-height: 26px; font-size: 11px;"
            "}"
            "QComboBox:focus { border: 1.5px solid #1a237e; background: #fff; }"
            "QComboBox::drop-down { width: 22px; border: none; }"
            "QComboBox QAbstractItemView {"
            "  color: #212121; background: #fff;"
            "  selection-background-color: #c5cae9; selection-color: #1a237e;"
            "}"
        )
        _SEARCH = (
            "QLineEdit {"
            "  color: #212121; background: #f5f7fa;"
            "  border: 1px solid #c7d0db; border-radius: 6px;"
            "  padding: 4px 8px; min-height: 26px; font-size: 11px;"
            "}"
            "QLineEdit:focus { border: 1.5px solid #1a237e; background: #fff; }"
        )

        sev_lbl = QLabel("Severity:")
        sev_lbl.setStyleSheet(_LBL)
        filter_row.addWidget(sev_lbl)
        self._sev_combo = QComboBox()
        self._sev_combo.addItem("All")
        for s in Severity:
            self._sev_combo.addItem(s.value)
        self._sev_combo.currentTextChanged.connect(self._apply_filters)
        self._sev_combo.setFixedWidth(100)
        self._sev_combo.setStyleSheet(_COMBO)
        filter_row.addWidget(self._sev_combo)

        cat_lbl = QLabel("Category:")
        cat_lbl.setStyleSheet(_LBL)
        filter_row.addWidget(cat_lbl)
        self._cat_combo = QComboBox()
        self._cat_combo.addItem("All")
        self._cat_combo.currentTextChanged.connect(self._apply_filters)
        self._cat_combo.setFixedWidth(120)
        self._cat_combo.setStyleSheet(_COMBO)
        filter_row.addWidget(self._cat_combo)

        search_lbl = QLabel("Search:")
        search_lbl.setStyleSheet(_LBL)
        filter_row.addWidget(search_lbl)
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by keyword...")
        self._search.setFixedWidth(180)
        self._search.textChanged.connect(self._apply_filters)
        self._search.setStyleSheet(_SEARCH)
        filter_row.addWidget(self._search)

        layout.addLayout(filter_row)

        # ---- Splitter: table (top) + detail (bottom) ----
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(5)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(
            "QSplitter::handle {"
            "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "    stop:0.35 transparent, stop:0.5 #b0bec5, stop:0.65 transparent);"
            "  margin: 1px 60px;"
            "}"
        )

        # -- Table --
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setMinimumHeight(200)
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self._table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setWordWrap(False)
        self._table.currentCellChanged.connect(self._on_row_changed)
        self._table.setStyleSheet(
            "QTableWidget {"
            "  border: 1px solid #c7d0db; border-radius: 8px;"
            "  color: #212121; background-color: #fff;"
            "  alternate-background-color: #f7f9fc;"
            "  gridline-color: #e8ecf1;"
            "}"
            "QTableWidget::item {"
            "  color: #212121; padding: 5px 8px;"
            "}"
            "QTableWidget::item:selected {"
            "  background-color: #c5cae9; color: #1a237e;"
            "}"
            "QHeaderView::section {"
            "  background: #1a237e; color: white; padding: 7px 8px;"
            "  font-size: 11px; font-weight: bold; border: none;"
            "}"
        )
        splitter.addWidget(self._table)

        # -- Detail panel --
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setFont(QFont("Segoe UI", 10))
        self._detail.setMinimumHeight(100)
        self._detail.setStyleSheet(
            "QTextEdit {"
            "  background: #fafbfd;"
            "  color: #263238;"
            "  border: 1px solid #c7d0db;"
            "  border-radius: 8px;"
            "  padding: 8px;"
            "}"
        )
        self._detail.setPlaceholderText("Select a finding to view details...")
        splitter.addWidget(self._detail)

        # 70% table, 30% detail
        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter, stretch=1)

    def set_findings(self, findings: List[Finding]):
        """Replace current findings and refresh the table."""
        self._findings = list(findings)
        self._update_category_filter()
        self._apply_filters()

    def add_finding(self, finding: Finding):
        """Append a single finding (used during live scan)."""
        self._findings.append(finding)
        cat_val = finding.category.value
        if self._cat_combo.findText(cat_val) == -1:
            self._cat_combo.addItem(cat_val)
        self._apply_filters()

    def clear_findings(self):
        """Remove all findings."""
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
            sev_item.setForeground(_SEV_COLORS.get(finding.severity, QColor("#607d8b")))
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

            sev_color = _SEV_COLORS.get(finding.severity, QColor("#607d8b")).name()
            self._detail.setHtml(
                f"<div style='font-family: Segoe UI, sans-serif;'>"
                f"<h3 style='color:#1a237e; margin:0 0 4px 0;'>{_esc(finding.title)}</h3>"
                f"<p style='margin:2px 0;'>"
                f"<span style='background:{sev_color}; color:#fff; padding:2px 8px;"
                f" border-radius:3px; font-weight:bold; font-size:10px;'>"
                f"{_esc(finding.severity.value)}</span> &nbsp; "
                f"<b>Tool:</b> {_esc(finding.tool)} &nbsp; "
                f"<b>Category:</b> {_esc(finding.category.value)}</p>"
                f"<p style='margin:4px 0;'><b>Location:</b> "
                f"<code style='background:#e8eaf6; padding:1px 5px; border-radius:3px;'>"
                f"{_esc(finding.location)}</code></p>"
                f"<p style='margin:4px 0;'><b>Evidence:</b></p>"
                f"<pre style='background:#f5f5f5; padding:6px; border-radius:4px;"
                f" font-size:10px;'>{_esc(finding.evidence)}</pre>"
                f"<p style='margin:4px 0;'><b>Remediation:</b><br/>"
                f"{_esc(finding.remediation)}</p>"
                f"<p style='margin:4px 0;'><b>References:</b></p>"
                f"<pre style='background:#f5f5f5; padding:6px; border-radius:4px;"
                f" font-size:10px;'>{_esc(refs)}</pre>"
                f"<p style='color:#90a4ae; font-size:9px; margin-top:4px;'>"
                f"ID: {_esc(finding.id)} | Timestamp: {_esc(finding.timestamp)}</p>"
                f"</div>"
            )
        else:
            self._detail.clear()


def _esc(text: str) -> str:
    """HTML-escape helper."""
    import html

    return html.escape(str(text))
