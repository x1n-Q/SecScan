"""Tools page: list scanners, status, and tool installation controls."""

from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from secscan.core.detect import ProjectInfo
from secscan.core.installer import InstallManager
from secscan.core.profiles import PROFILES, ProfileName
from secscan.tools import ALL_TOOLS
from secscan.tools.base import ToolBase

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


class _ToolCard(QFrame):
    """A single card representing one scanner tool."""

    def __init__(self, tool: ToolBase, applicable: bool, checked: bool = False, parent=None):
        super().__init__(parent)
        self.tool = tool
        self._applicable = applicable

        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            "QFrame { background: #fff; border: 1px solid #ddd; "
            "border-radius: 8px; padding: 12px; }"
        )
        self.setMinimumHeight(70)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(checked)
        self.checkbox.setEnabled(applicable)
        layout.addWidget(self.checkbox)

        info_layout = QVBoxLayout()
        name_lbl = QLabel(tool.name)
        name_lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        name_lbl.setStyleSheet("color: #212121;")
        info_layout.addWidget(name_lbl)

        desc_lbl = QLabel(tool.description)
        desc_lbl.setStyleSheet("color: #616161; font-size: 11px;")
        desc_lbl.setWordWrap(True)
        info_layout.addWidget(desc_lbl)
        layout.addLayout(info_layout, stretch=1)

        self.status_lbl = QLabel()
        layout.addWidget(self.status_lbl)

        self.info_btn = QPushButton("How to install")
        self.info_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.info_btn.setStyleSheet(
            "QPushButton { color: #1565c0; background: transparent; "
            "border: 1px solid #1565c0; border-radius: 4px; padding: 4px 10px; "
            "font-size: 11px; }"
            "QPushButton:hover { background: #e3f2fd; }"
        )
        self.info_btn.clicked.connect(self._show_install_instructions)
        layout.addWidget(self.info_btn)

        self.refresh_status()

    def refresh_status(self):
        """Refresh installed / missing status visuals."""
        installed = self.tool.is_installed()
        if not self._applicable:
            self.status_lbl.setText("Not Applicable")
            self.status_lbl.setStyleSheet(
                "color: #888; background: #eee; border-radius: 4px; "
                "padding: 4px 10px; font-size: 11px; font-weight: bold;"
            )
            self.checkbox.setEnabled(False)
            self.info_btn.setVisible(False)
            return

        self.checkbox.setEnabled(True)
        if installed:
            self.status_lbl.setText("Installed")
            self.status_lbl.setStyleSheet(
                "color: #2e7d32; background: #e8f5e9; border-radius: 4px; "
                "padding: 4px 10px; font-size: 11px; font-weight: bold;"
            )
            self.info_btn.setVisible(False)
        else:
            self.status_lbl.setText("Missing")
            self.status_lbl.setStyleSheet(
                "color: #c62828; background: #ffebee; border-radius: 4px; "
                "padding: 4px 10px; font-size: 11px; font-weight: bold;"
            )
            self.info_btn.setVisible(True)

    def _show_install_instructions(self):
        box = QMessageBox(self)
        box.setWindowTitle(f"Install {self.tool.name}")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText(self.tool.install_instructions())
        box.addButton("Close", QMessageBox.ButtonRole.AcceptRole)
        box.setStyleSheet(
            "QMessageBox { background: #ffffff; }"
            "QLabel { color: #111111; }"
            "QPushButton { min-width: 80px; color: #111111; background: #f3f6f9; "
            "border: 1px solid #90a4ae; border-radius: 4px; padding: 4px 12px; }"
            "QPushButton:hover { background: #e3f2fd; border-color: #64b5f6; }"
        )
        box.exec()


class ToolsPage(QWidget):
    """Second page: list available scanners with status and toggle."""

    tools_confirmed = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: List[_ToolCard] = []
        self._project_info: Optional[ProjectInfo] = None
        self._installer = InstallManager(self)
        self._current_mode_key = ProfileName.RECOMMENDED.value
        self._updating_mode = False
        self._install_last_log = ""
        self._loading_frames = ["Installing", "Installing.", "Installing..", "Installing..."]
        self._loading_index = 0
        self._loading_timer = QTimer(self)
        self._loading_timer.setInterval(260)
        self._loading_timer.timeout.connect(self._on_loading_tick)
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(16)

        header = QLabel("Available Scanners")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setStyleSheet("color: #1a237e;")
        root.addWidget(header)

        subtitle = QLabel(
            "Enable scanners to run. Missing tools can be installed from this page."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #555; font-size: 13px;")
        root.addWidget(subtitle)

        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel("Scan Mode:"))
        self._mode_combo = QComboBox()
        for pname, profile in PROFILES.items():
            self._mode_combo.addItem(
                f"{pname.value} - {profile.description}",
                pname.value,
            )
        self._mode_combo.addItem("Custom - manually selected tools", "custom")
        self._mode_combo.setCurrentIndex(self._mode_combo.findData(self._current_mode_key))
        self._mode_combo.setMinimumWidth(360)
        self._mode_combo.setMinimumHeight(34)
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        mode_row.addWidget(self._mode_combo)
        mode_row.addStretch()
        root.addLayout(mode_row)

        self._install_status_lbl = QLabel("Waiting for install action.")
        self._install_status_lbl.setWordWrap(True)
        root.addWidget(self._install_status_lbl)
        self._set_status("Waiting for install action.", tone="info")

        self._install_progress = QProgressBar()
        self._install_progress.setRange(0, 100)
        self._install_progress.setValue(0)
        self._install_progress.setVisible(False)
        self._install_progress.setStyleSheet(
            "QProgressBar { border: 1px solid #90caf9; border-radius: 6px; "
            "text-align: center; background: #e3f2fd; color: #0d47a1; font-weight: bold; }"
            "QProgressBar::chunk { background: #1976d2; border-radius: 5px; }"
        )
        root.addWidget(self._install_progress)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self._cards_container = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setSpacing(8)
        self._cards_layout.addStretch()
        scroll.setWidget(self._cards_container)
        root.addWidget(scroll, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        self._install_btn = QPushButton("Install Missing Tools")
        self._install_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._install_btn.setStyleSheet(
            "QPushButton { border: 1px solid #1565c0; color: #1565c0; "
            "background: #ffffff; border-radius: 6px; padding: 8px 16px; font-weight: bold; }"
            "QPushButton:hover { background: #e3f2fd; }"
            "QPushButton:disabled { color: #455a64; background: #eceff1; border-color: #b0bec5; }"
        )
        self._install_btn.clicked.connect(self._on_install_missing)
        btn_row.addWidget(self._install_btn)

        self._select_all_btn = QPushButton("Select All Installed")
        self._select_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._select_all_btn.setStyleSheet(
            "QPushButton { border: 1px solid #1a237e; color: #1a237e; "
            "border-radius: 6px; padding: 8px 16px; font-weight: bold; }"
            "QPushButton:hover { background: #e8eaf6; }"
        )
        self._select_all_btn.clicked.connect(self._select_all_installed)
        btn_row.addWidget(self._select_all_btn)

        self._deselect_all_btn = QPushButton("Deselect All")
        self._deselect_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._deselect_all_btn.setStyleSheet(self._select_all_btn.styleSheet())
        self._deselect_all_btn.clicked.connect(self._deselect_all)
        btn_row.addWidget(self._deselect_all_btn)

        self._run_btn = QPushButton("Run Scan  ->")
        self._run_btn.setMinimumHeight(44)
        self._run_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._run_btn.setStyleSheet(
            "QPushButton { background: #2e7d32; color: white; border-radius: 8px; "
            "padding: 8px 24px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background: #388e3c; }"
            "QPushButton:disabled { background: #9e9e9e; }"
        )
        self._run_btn.clicked.connect(self._on_run)
        btn_row.addWidget(self._run_btn)

        root.addLayout(btn_row)

    def _connect_signals(self):
        self._installer.log.connect(self._on_install_log)
        self._installer.progress.connect(self._on_install_progress)
        self._installer.finished.connect(self._on_install_finished)

    def showEvent(self, event):
        super().showEvent(event)
        if self._project_info and not self._installer.is_running:
            self.populate(self._project_info)

    def populate(self, project_info: ProjectInfo):
        """Rebuild tool cards based on the detected project."""
        self._project_info = project_info
        checked_by_name = {
            card.tool.name: card.checkbox.isChecked()
            for card in self._cards
        }

        for card in self._cards:
            self._cards_layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

        for tool in ALL_TOOLS:
            applicable = tool.is_applicable(project_info.path)
            if tool.name in _URL_REQUIRED_TOOLS:
                applicable = bool(project_info.website_url)

            default_checked = applicable and tool.is_installed()
            checked = checked_by_name.get(tool.name, default_checked)
            card = _ToolCard(tool, applicable, checked)
            card.checkbox.stateChanged.connect(self._update_install_button_state)
            card.checkbox.stateChanged.connect(self._on_manual_tool_selection_changed)
            self._cards.append(card)
            self._cards_layout.insertWidget(self._cards_layout.count() - 1, card)

        if self._mode_combo.currentData() == "custom":
            self._restore_manual_selection(checked_by_name)
        else:
            self._apply_mode_selection(self._mode_combo.currentData() or self._current_mode_key)

        self._update_install_button_state()

    def get_selected_tools(self) -> List[ToolBase]:
        """Return tools that are checked and installed."""
        selected = []
        for card in self._cards:
            if card.checkbox.isChecked() and card.tool.is_installed():
                selected.append(card.tool)
        return selected

    def _select_all_installed(self):
        for card in self._cards:
            if card._applicable and card.tool.is_installed():
                card.checkbox.setChecked(True)
        self._set_mode_combo("custom")

    def _deselect_all(self):
        for card in self._cards:
            card.checkbox.setChecked(False)
        self._set_mode_combo("custom")

    def _on_loading_tick(self):
        self._loading_index = (self._loading_index + 1) % len(self._loading_frames)
        self._install_btn.setText(self._loading_frames[self._loading_index])

    def _start_loading(self):
        self._loading_index = 0
        self._install_btn.setText(self._loading_frames[0])
        self._loading_timer.start()

    def _stop_loading(self):
        self._loading_timer.stop()
        self._install_btn.setText("Install Missing Tools")

    def _on_install_missing(self):
        if self._installer.is_running:
            return

        selected_missing = [
            card.tool for card in self._cards
            if card._applicable and card.checkbox.isChecked() and not card.tool.is_installed()
        ]
        missing = selected_missing or [
            card.tool for card in self._cards
            if card._applicable and not card.tool.is_installed()
        ]

        if not missing:
            self._set_status("All applicable tools are already installed.", tone="success")
            self._show_message(
                "No Missing Tools",
                "All applicable tools are already installed.",
                QMessageBox.Icon.Information,
            )
            return

        auto_installable = [tool for tool in missing if tool.supports_auto_install()]
        manual_only = [tool.name for tool in missing if not tool.supports_auto_install()]

        if not auto_installable:
            msg = "No selected missing tool has an automatic installer.\n\n"
            msg += "Use 'How to install' for:\n"
            msg += "\n".join(f"- {name}" for name in manual_only)
            self._set_status("Manual installation required for selected tools.", tone="warn")
            self._show_message("Manual Installation Required", msg, QMessageBox.Icon.Warning)
            return

        mode_txt = "selected missing tools" if selected_missing else "all missing tools"
        names = "\n".join(f"- {tool.name}" for tool in auto_installable)
        msg = (
            f"Install these {mode_txt} now?\n\n"
            f"{names}\n\n"
            "The process may ask for system permissions depending on your machine."
        )
        if manual_only:
            msg += "\n\nManual only:\n" + "\n".join(f"- {name}" for name in manual_only)

        answer = self._ask_yes_no("Install Missing Tools", msg)
        if answer != QMessageBox.StandardButton.Yes:
            return

        self._set_controls_enabled(False)
        self._install_progress.setVisible(True)
        self._install_progress.setValue(0)
        self._start_loading()
        self._install_last_log = "Starting installation..."
        self._set_status("Starting installation...", tone="info")
        self._installer.start(auto_installable)

    def _on_install_log(self, message: str):
        self._install_last_log = message
        self._set_status(message, tone="info")

    def _on_install_progress(self, pct: int):
        self._install_progress.setValue(pct)
        base = self._install_last_log or "Installing tools..."
        self._set_status(f"{base} ({pct}%)", tone="info")

    def _on_install_finished(self, summary: dict):
        self._stop_loading()
        self._set_controls_enabled(True)
        self._install_progress.setValue(100)

        if self._project_info:
            self.populate(self._project_info)

        installed = summary.get("installed", [])
        skipped = summary.get("skipped", [])
        failed = summary.get("failed", [])

        lines = [
            f"Installed: {len(installed)}",
            f"Already installed: {len(skipped)}",
            f"Failed: {len(failed)}",
        ]
        if failed:
            lines.append("")
            lines.append("Failures:")
            for name, reason in failed:
                lines.append(f"- {name}: {reason}")

        if failed:
            self._set_status("Installation finished with some failures.", tone="warn")
        else:
            self._set_status("Installation finished successfully.", tone="success")
        self._install_last_log = ""

        icon = QMessageBox.Icon.Warning if failed else QMessageBox.Icon.Information
        self._show_message("Install Summary", "\n".join(lines), icon)

    def _set_controls_enabled(self, enabled: bool):
        self._install_btn.setEnabled(enabled)
        self._select_all_btn.setEnabled(enabled)
        self._deselect_all_btn.setEnabled(enabled)
        self._run_btn.setEnabled(enabled)
        for card in self._cards:
            card.checkbox.setEnabled(enabled and card._applicable)

    def _missing_count(self) -> int:
        return len(
            [
                card for card in self._cards
                if card._applicable and not card.tool.is_installed()
            ]
        )

    def _update_install_button_state(self, *_):
        if self._installer.is_running:
            return
        count = self._missing_count()
        if count > 0:
            self._install_btn.setText(f"Install Missing Tools ({count})")
            self._install_btn.setEnabled(True)
        else:
            self._install_btn.setText("Install Missing Tools")
            self._install_btn.setEnabled(False)

    def _on_mode_changed(self, *_):
        if self._updating_mode:
            return
        mode_key = self._mode_combo.currentData() or self._current_mode_key
        self._current_mode_key = mode_key
        if mode_key == "custom":
            self._set_status("Custom mode active. Select the scanners you want to run.", tone="info")
            return
        self._apply_mode_selection(mode_key)

    def _apply_mode_selection(self, mode_key: str):
        if mode_key == "custom":
            return

        profile = next(
            (profile for pname, profile in PROFILES.items() if pname.value == mode_key),
            None,
        )
        if profile is None:
            return

        self._updating_mode = True
        try:
            for card in self._cards:
                should_check = card._applicable and card.tool.name in profile.tool_names
                card.checkbox.setChecked(should_check)
        finally:
            self._updating_mode = False

        self._set_status(f"{profile.name.value} selected.", tone="info")
        self._update_install_button_state()

    def _restore_manual_selection(self, checked_by_name: dict[str, bool]):
        self._updating_mode = True
        try:
            for card in self._cards:
                card.checkbox.setChecked(checked_by_name.get(card.tool.name, False))
        finally:
            self._updating_mode = False

    def _on_manual_tool_selection_changed(self, *_):
        if self._updating_mode:
            return
        mode_key = self._mode_combo.currentData()
        if mode_key != "custom":
            self._set_mode_combo("custom")
            self._set_status("Custom mode active. Select the scanners you want to run.", tone="info")

    def _set_mode_combo(self, mode_key: str):
        idx = self._mode_combo.findData(mode_key)
        if idx < 0 or self._mode_combo.currentIndex() == idx:
            self._current_mode_key = mode_key
            return
        self._updating_mode = True
        try:
            self._mode_combo.setCurrentIndex(idx)
        finally:
            self._updating_mode = False
        self._current_mode_key = mode_key

    def current_mode_label(self) -> str:
        data = self._mode_combo.currentData()
        if data == "custom":
            return "Custom"
        return str(data or self._current_mode_key)

    def _set_status(self, text: str, tone: str = "info"):
        styles = {
            "info": (
                "QLabel { color: #0d47a1; background: #e3f2fd; border: 1px solid #90caf9; "
                "border-radius: 6px; padding: 6px 10px; }"
            ),
            "success": (
                "QLabel { color: #1b5e20; background: #e8f5e9; border: 1px solid #a5d6a7; "
                "border-radius: 6px; padding: 6px 10px; }"
            ),
            "warn": (
                "QLabel { color: #b71c1c; background: #ffebee; border: 1px solid #ef9a9a; "
                "border-radius: 6px; padding: 6px 10px; }"
            ),
        }
        self._install_status_lbl.setStyleSheet(styles.get(tone, styles["info"]))
        self._install_status_lbl.setText(text)

    def _show_message(self, title: str, text: str, icon: QMessageBox.Icon):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setIcon(icon)
        box.setText(text)
        box.addButton("Close", QMessageBox.ButtonRole.AcceptRole)
        box.setStyleSheet(
            "QMessageBox { background: #ffffff; }"
            "QLabel { color: #111111; }"
            "QPushButton { min-width: 80px; color: #111111; background: #f3f6f9; "
            "border: 1px solid #90a4ae; border-radius: 4px; padding: 4px 12px; }"
            "QPushButton:hover { background: #e3f2fd; border-color: #64b5f6; }"
        )
        box.exec()

    def _ask_yes_no(self, title: str, text: str) -> QMessageBox.StandardButton:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(text)
        yes_btn = box.addButton("Yes", QMessageBox.ButtonRole.YesRole)
        no_btn = box.addButton("No", QMessageBox.ButtonRole.NoRole)
        box.setDefaultButton(yes_btn)
        box.setStyleSheet(
            "QMessageBox { background: #ffffff; }"
            "QLabel { color: #111111; }"
            "QPushButton { min-width: 80px; color: #111111; background: #f3f6f9; "
            "border: 1px solid #90a4ae; border-radius: 4px; padding: 4px 12px; }"
            "QPushButton:hover { background: #e3f2fd; border-color: #64b5f6; }"
        )
        box.exec()
        if box.clickedButton() == yes_btn:
            return QMessageBox.StandardButton.Yes
        return QMessageBox.StandardButton.No

    def _on_run(self):
        tools = self.get_selected_tools()
        if not tools:
            self._show_message(
                "No tools selected",
                "Please select at least one installed scanner to run.",
                QMessageBox.Icon.Warning,
            )
            return
        self.tools_confirmed.emit(tools)
