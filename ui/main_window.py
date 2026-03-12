"""Main application window – dark sidebar navigation + stacked pages."""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, Slot, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QAction, QFont, QColor
from PySide6.QtWidgets import (
    QMainWindow, QStackedWidget, QStatusBar, QWidget,
    QHBoxLayout, QVBoxLayout, QLabel, QPushButton, QFrame,
    QGraphicsDropShadowEffect, QSizePolicy,
)

from secscan.core.detect import ProjectInfo
from secscan.core.report_html import export_html
from secscan.core.report_json import export_json
from secscan.core.schema import ScanResult
from ui.pages.project_page import ProjectPage
from ui.pages.results_page import ResultsPage
from ui.pages.run_page import RunPage
from ui.pages.tools_page import ToolsPage
from ui import theme as T

_PAGE_PROJECT = 0
_PAGE_TOOLS = 1
_PAGE_RUN = 2
_PAGE_RESULTS = 3

_NAV_ITEMS = [
    ("🗂", "Project",  _PAGE_PROJECT),
    ("🛠", "Tools",    _PAGE_TOOLS),
    ("▶", "Run",      _PAGE_RUN),
    ("📊", "Results",  _PAGE_RESULTS),
]


class _SidebarButton(QPushButton):
    """A single sidebar navigation button."""

    _NORMAL = (
        f"QPushButton {{ background: transparent; color: {T.TEXT_SECONDARY}; "
        f"border: none; border-left: 3px solid transparent; "
        f"padding: 10px 14px; font-size: 12px; font-weight: 600; text-align: left; }}"
        f"QPushButton:hover {{ background: {T.BG_HOVER}; color: {T.TEXT_PRIMARY}; }}"
    )
    _ACTIVE = (
        f"QPushButton {{ background: {T.ACCENT_BG}; color: {T.ACCENT_HOVER}; "
        f"border: none; border-left: 3px solid {T.ACCENT}; "
        f"padding: 10px 14px; font-size: 12px; font-weight: 700; text-align: left; }}"
    )

    def __init__(self, icon: str, label: str, parent=None):
        super().__init__(f"  {icon}  {label}", parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(self._NORMAL)
        self.setMinimumHeight(42)

    def set_active(self, active: bool):
        self.setStyleSheet(self._ACTIVE if active else self._NORMAL)


class MainWindow(QMainWindow):
    """Top-level window with dark sidebar and stacked pages."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecScan — Security Scanner")
        self.resize(1100, 720)
        self.setMinimumSize(850, 550)

        self._project_info: Optional[ProjectInfo] = None
        self._output_dir = ""

        self._apply_global_style()
        self._build_ui()
        self._connect_signals()

    # ── Global stylesheet ──────────────────────────────────────────
    def _apply_global_style(self):
        self.setStyleSheet(
            f"QMainWindow {{ background: {T.BG_DARK}; }}"
            f"QLabel {{ color: {T.TEXT_PRIMARY}; border: none; background: transparent; }}"
            f"QCheckBox {{ color: {T.TEXT_PRIMARY}; }}"
            f"QCheckBox::indicator {{ width: 16px; height: 16px; }}"
            f"QStatusBar {{ background: {T.BG_DARKEST}; color: {T.TEXT_SECONDARY}; "
            f"border-top: 1px solid {T.BORDER}; font-size: 11px; padding: 2px 12px; }}"
            f"QGroupBox {{ color: {T.TEXT_PRIMARY}; }}"
            f"QGroupBox::title {{ color: {T.ACCENT_HOVER}; }}"
            + T.INPUT_STYLE
            + T.COMBO_STYLE
            + T.SCROLL_STYLE
        )

    # ── Build UI ───────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Sidebar ──
        sidebar = QFrame()
        sidebar.setFixedWidth(170)
        sidebar.setStyleSheet(
            f"QFrame {{ background: {T.BG_DARKEST}; border-right: 1px solid {T.BORDER}; }}"
        )
        sidebar_lay = QVBoxLayout(sidebar)
        sidebar_lay.setContentsMargins(0, 0, 0, 0)
        sidebar_lay.setSpacing(0)

        # Brand
        brand_frame = QFrame()
        brand_frame.setStyleSheet(
            f"QFrame {{ background: {T.BG_DARKEST}; border: none; "
            f"border-bottom: 1px solid {T.BORDER}; }}"
        )
        brand_inner = QVBoxLayout(brand_frame)
        brand_inner.setContentsMargins(16, 14, 16, 12)
        brand_inner.setSpacing(2)

        brand_title = QLabel("🛡 SecScan")
        brand_title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        brand_title.setStyleSheet(f"color: {T.ACCENT_HOVER}; background: transparent;")
        brand_inner.addWidget(brand_title)

        brand_sub = QLabel("Security Scanner")
        brand_sub.setFont(QFont("Segoe UI", 9))
        brand_sub.setStyleSheet(f"color: {T.TEXT_MUTED}; background: transparent;")
        brand_inner.addWidget(brand_sub)

        sidebar_lay.addWidget(brand_frame)

        # Nav label
        nav_label = QLabel("  NAVIGATION")
        nav_label.setFont(QFont("Segoe UI", 8))
        nav_label.setStyleSheet(
            f"color: {T.TEXT_MUTED}; padding: 14px 0 4px 14px; "
            f"letter-spacing: 1px; background: transparent;"
        )
        sidebar_lay.addWidget(nav_label)

        # Nav buttons
        self._nav_btns: list[_SidebarButton] = []
        for icon, label, page_index in _NAV_ITEMS:
            btn = _SidebarButton(icon, label)
            btn.clicked.connect(lambda checked, idx=page_index: self._goto_page(idx))
            sidebar_lay.addWidget(btn)
            self._nav_btns.append(btn)

        sidebar_lay.addStretch()

        # Sidebar footer
        footer = QLabel("v1.0")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet(
            f"color: {T.TEXT_MUTED}; font-size: 9px; padding: 10px; background: transparent;"
        )
        sidebar_lay.addWidget(footer)

        main_layout.addWidget(sidebar)

        # ── Page stack ──
        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"QStackedWidget {{ background: {T.BG_DARK}; }}")

        self._project_page = ProjectPage()
        self._tools_page = ToolsPage()
        self._run_page = RunPage()
        self._results_page = ResultsPage()

        self._stack.addWidget(self._project_page)
        self._stack.addWidget(self._tools_page)
        self._stack.addWidget(self._run_page)
        self._stack.addWidget(self._results_page)
        self._stack.setCurrentIndex(_PAGE_PROJECT)

        main_layout.addWidget(self._stack, stretch=1)

        # Statusbar
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._statusbar.showMessage("Ready — select a project folder to begin.")

        # Initial nav highlight
        self._highlight_nav(0)

    # ── Signals ────────────────────────────────────────────────────
    def _connect_signals(self):
        self._project_page.project_selected.connect(self._on_project_selected)
        self._tools_page.tools_confirmed.connect(self._on_tools_confirmed)
        self._run_page.scan_finished.connect(self._on_scan_finished)
        self._run_page.results_button.clicked.connect(lambda: self._goto_page(_PAGE_RESULTS))
        self._results_page.new_scan_button.clicked.connect(self._on_new_scan)

    # ── Navigation ─────────────────────────────────────────────────
    def _highlight_nav(self, index: int):
        for i, btn in enumerate(self._nav_btns):
            btn.set_active(i == index)

    def _goto_page(self, index: int):
        if index == _PAGE_TOOLS and self._project_info:
            self._tools_page.populate(self._project_info)
        self._stack.setCurrentIndex(index)
        self._highlight_nav(index)

    # ── Callbacks ──────────────────────────────────────────────────
    @Slot(object)
    def _on_project_selected(self, info: ProjectInfo):
        self._project_info = info
        langs = ", ".join(info.languages) if info.languages else "unknown"
        self._statusbar.showMessage(
            f"Project: {info.path}  ·  Type: {', '.join(info.types)}  ·  Languages: {langs}"
        )
        self._tools_page.populate(info)
        self._goto_page(_PAGE_TOOLS)

    @Slot(list)
    def _on_tools_confirmed(self, tools: list):
        if not self._project_info:
            return
        self._output_dir = os.path.join(self._project_info.path, "secscan-results")
        os.makedirs(self._output_dir, exist_ok=True)

        self._statusbar.showMessage(f"Running {len(tools)} scanner(s)…")
        self._run_page.set_scan_mode(self._tools_page.current_mode_label())
        self._goto_page(_PAGE_RUN)
        self._run_page.start_scan(tools, self._project_info, self._output_dir)

    @Slot(object)
    def _on_scan_finished(self, result: ScanResult):
        total = len(result.findings)
        self._statusbar.showMessage(
            f"Scan complete — {total} finding(s). Results saved to {self._output_dir}"
        )
        try:
            export_json(result, self._output_dir)
            export_html(result, self._output_dir)
        except Exception:
            pass

        self._results_page.set_scan_logs(self._run_page.get_logs())
        self._results_page.load_result(result, self._output_dir)

    def _on_new_scan(self):
        self._goto_page(_PAGE_PROJECT)
        self._statusbar.showMessage("Ready — select a project folder to begin.")
