"""Main application window managing page navigation via a stacked widget."""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import QMainWindow, QStackedWidget, QStatusBar, QToolBar, QLabel

from secscan.core.detect import ProjectInfo
from secscan.core.report_html import export_html
from secscan.core.report_json import export_json
from secscan.core.schema import ScanResult
from ui.pages.project_page import ProjectPage
from ui.pages.results_page import ResultsPage
from ui.pages.run_page import RunPage
from ui.pages.tools_page import ToolsPage


_PAGE_PROJECT = 0
_PAGE_TOOLS = 1
_PAGE_RUN = 2
_PAGE_RESULTS = 3


class MainWindow(QMainWindow):
    """Top-level window containing all pages in a QStackedWidget."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecScan - Security Scanner")
        self.resize(1100, 750)
        self.setMinimumSize(800, 550)

        self._project_info: Optional[ProjectInfo] = None
        self._output_dir = ""

        self._setup_toolbar()
        self._setup_pages()
        self._setup_statusbar()
        self._connect_signals()

        self.setStyleSheet(
            "QMainWindow { background: #f5f5f5; }"
            "QLabel { color: #212121; border: none; background: transparent; }"
            "QCheckBox { color: #212121; }"
            "QToolBar { background: #1a237e; spacing: 8px; padding: 4px; }"
            "QToolBar QToolButton { color: white; font-weight: bold; padding: 6px 14px; }"
            "QToolBar QToolButton:hover { background: #283593; border-radius: 4px; }"
            "QStatusBar { background: #e8eaf6; color: #333; }"
            "QGroupBox { color: #212121; }"
            "QGroupBox::title { color: #1a237e; }"
            "QLineEdit { color: #212121; background: #fff; border: 1px solid #bdbdbd; "
            "border-radius: 4px; padding: 4px 8px; }"
            "QLineEdit:focus { border: 1px solid #1a237e; }"
            "QComboBox { color: #212121; background: #fff; border: 1px solid #bdbdbd; "
            "border-radius: 4px; padding: 4px 8px; min-height: 28px; }"
            "QComboBox:focus { border: 1px solid #1a237e; }"
            "QComboBox QAbstractItemView { color: #212121; background: #fff; "
            "selection-background-color: #c5cae9; selection-color: #1a237e; }"
        )

    def _setup_toolbar(self):
        tb = QToolBar("Navigation")
        tb.setMovable(False)
        tb.setFloatable(False)
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)

        brand = QLabel("  SecScan  ")
        brand.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        brand.setStyleSheet("color: white; margin-right: 16px;")
        tb.addWidget(brand)

        self._act_project = QAction("1. Project", self)
        self._act_tools = QAction("2. Tools", self)
        self._act_run = QAction("3. Run", self)
        self._act_results = QAction("4. Results", self)

        self._act_project.triggered.connect(lambda: self._goto_page(_PAGE_PROJECT))
        self._act_tools.triggered.connect(lambda: self._goto_page(_PAGE_TOOLS))
        self._act_run.triggered.connect(lambda: self._goto_page(_PAGE_RUN))
        self._act_results.triggered.connect(lambda: self._goto_page(_PAGE_RESULTS))

        for act in (self._act_project, self._act_tools, self._act_run, self._act_results):
            tb.addAction(act)

        self.addToolBar(tb)

    def _setup_pages(self):
        self._stack = QStackedWidget()

        self._project_page = ProjectPage()
        self._tools_page = ToolsPage()
        self._run_page = RunPage()
        self._results_page = ResultsPage()

        self._stack.addWidget(self._project_page)
        self._stack.addWidget(self._tools_page)
        self._stack.addWidget(self._run_page)
        self._stack.addWidget(self._results_page)

        self.setCentralWidget(self._stack)
        self._stack.setCurrentIndex(_PAGE_PROJECT)

    def _setup_statusbar(self):
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._statusbar.showMessage("Ready - select a project folder to begin.")

    def _connect_signals(self):
        self._project_page.project_selected.connect(self._on_project_selected)
        self._tools_page.tools_confirmed.connect(self._on_tools_confirmed)
        self._run_page.scan_finished.connect(self._on_scan_finished)
        self._run_page.results_button.clicked.connect(lambda: self._goto_page(_PAGE_RESULTS))
        self._results_page.new_scan_button.clicked.connect(self._on_new_scan)

    def _goto_page(self, index: int):
        if index == _PAGE_TOOLS and self._project_info:
            self._tools_page.populate(self._project_info)
        self._stack.setCurrentIndex(index)

    @Slot(object)
    def _on_project_selected(self, info: ProjectInfo):
        self._project_info = info
        langs = ", ".join(info.languages) if info.languages else "unknown"
        self._statusbar.showMessage(
            f"Project: {info.path}  |  Type: {', '.join(info.types)}  |  Languages: {langs}"
        )
        self._tools_page.populate(info)
        self._goto_page(_PAGE_TOOLS)

    @Slot(list)
    def _on_tools_confirmed(self, tools: list):
        if not self._project_info:
            return

        self._output_dir = os.path.join(self._project_info.path, "secscan-results")
        os.makedirs(self._output_dir, exist_ok=True)

        self._statusbar.showMessage(f"Running {len(tools)} scanner(s)...")
        self._run_page.set_scan_mode(self._tools_page.current_mode_label())
        self._goto_page(_PAGE_RUN)
        self._run_page.start_scan(tools, self._project_info, self._output_dir)

    @Slot(object)
    def _on_scan_finished(self, result: ScanResult):
        total = len(result.findings)
        self._statusbar.showMessage(
            f"Scan complete - {total} finding(s). Results saved to {self._output_dir}"
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
        self._statusbar.showMessage("Ready - select a project folder to begin.")
