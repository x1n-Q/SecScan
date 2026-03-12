# SPDX-License-Identifier: MIT
# Copyright (c) SecScan Contributors
# See LICENSE and SECURITY.md for usage terms
"""Project selection page – dark-themed, compact cards."""

from __future__ import annotations

import os

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from secscan.core.detect import ProjectInfo, detect_project
from secscan.core.github_repo import clone_or_update_github_repo
from secscan.core.safety import normalize_target_url
from ui import theme as T


def _btn(text: str, bg: str, hover: str, fg: str = T.TEXT_PRIMARY) -> QPushButton:
    b = QPushButton(text)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    b.setStyleSheet(T.btn_style(bg, hover, fg))
    return b


def _lbl(text: str, muted: bool = False) -> QLabel:
    lbl = QLabel(text)
    color = T.TEXT_MUTED if muted else T.TEXT_SECONDARY
    lbl.setStyleSheet(
        f"color: {color}; font-size: 12px; font-weight: 600; "
        f"background: transparent; border: none; padding: 0px;"
    )
    return lbl


def _section_header(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
    lbl.setStyleSheet(
        f"color: {T.ACCENT_HOVER}; background: transparent; border: none;"
    )
    return lbl


class _CloneWorker(QObject):
    """Background worker for git clone/pull operations."""
    success = Signal(str, str)
    error = Signal(str)
    finished = Signal()

    def __init__(self, repo_url: str, dest_root: str, branch: str, token: str):
        super().__init__()
        self._repo_url = repo_url
        self._dest_root = dest_root
        self._branch = branch
        self._token = token

    def run(self):
        try:
            local_path, action = clone_or_update_github_repo(
                repo_url=self._repo_url,
                dest_root=self._dest_root,
                branch=self._branch,
                token=self._token,
            )
            self.success.emit(local_path, action)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self._token = ""
            self.finished.emit()


class ProjectPage(QWidget):
    """First page: select project folder and optional website URL."""

    project_selected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._project_info: ProjectInfo | None = None
        self._default_repo_root = os.path.join(os.path.expanduser("~"), "SecScanProjects")
        self._clone_thread: QThread | None = None
        self._clone_worker: _CloneWorker | None = None
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(T.SCROLL_STYLE)
        scroll.viewport().setStyleSheet(f"background: {T.BG_DARK};")
        outer.addWidget(scroll)

        container = QWidget()
        container.setStyleSheet(f"background: {T.BG_DARK};")
        root = QVBoxLayout(container)
        root.setContentsMargins(28, 22, 28, 16)
        root.setSpacing(12)
        scroll.setWidget(container)

        # Page title
        title = QLabel("Project Setup")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet(
            f"color: {T.TEXT_PRIMARY}; background: transparent; border: none;"
        )
        root.addWidget(title)

        subtitle = QLabel(
            "Select a local project folder or import from GitHub, then add an optional website URL."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(
            f"color: {T.TEXT_MUTED}; font-size: 12px; background: transparent; border: none;"
        )
        root.addWidget(subtitle)

        # ── Local Project Folder Card ──────────────────
        folder_card = QFrame()
        folder_card.setStyleSheet(T.CARD_STYLE)
        f_lay = QVBoxLayout(folder_card)
        f_lay.setContentsMargins(14, 12, 14, 12)
        f_lay.setSpacing(8)
        f_lay.addWidget(_section_header("📁  Local Project Folder"))

        f_row = QHBoxLayout()
        self._folder_edit = QLineEdit()
        self._folder_edit.setReadOnly(True)
        self._folder_edit.setPlaceholderText("Choose a project folder…")
        self._folder_edit.setStyleSheet(T.INPUT_STYLE)
        f_row.addWidget(self._folder_edit, 1)
        browse_btn = _btn("Browse…", T.ACCENT, T.ACCENT_HOVER)
        browse_btn.clicked.connect(self._browse_folder)
        f_row.addWidget(browse_btn)
        f_lay.addLayout(f_row)
        root.addWidget(folder_card)

        # ── GitHub Import Card ─────────────────────────
        gh_card = QFrame()
        gh_card.setStyleSheet(T.CARD_STYLE)
        g_lay = QVBoxLayout(gh_card)
        g_lay.setContentsMargins(14, 12, 14, 12)
        g_lay.setSpacing(8)
        g_lay.addWidget(_section_header("🔗  GitHub Import"))
        g_lay.addWidget(_lbl(
            "Enter a repo URL and click Clone / Pull. "
            "For private repos, paste a Personal Access Token (PAT).",
            muted=True,
        ))

        # Repo URL row
        repo_row = QHBoxLayout()
        repo_row.addWidget(_lbl("Repository:"))
        self._repo_url_edit = QLineEdit()
        self._repo_url_edit.setPlaceholderText("https://github.com/owner/repo  or  owner/repo")
        self._repo_url_edit.setStyleSheet(T.INPUT_STYLE)
        repo_row.addWidget(self._repo_url_edit, 1)
        repo_row.addWidget(_lbl("Branch:"))
        self._repo_branch_edit = QLineEdit()
        self._repo_branch_edit.setPlaceholderText("Optional")
        self._repo_branch_edit.setStyleSheet(T.INPUT_STYLE)
        self._repo_branch_edit.setMaximumWidth(140)
        repo_row.addWidget(self._repo_branch_edit)
        g_lay.addLayout(repo_row)

        # Token row
        token_row = QHBoxLayout()
        token_row.addWidget(_lbl("Access Token:"))
        self._repo_token_edit = QLineEdit()
        self._repo_token_edit.setPlaceholderText("Paste GitHub PAT for private repos (leave blank for public)")
        self._repo_token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._repo_token_edit.setStyleSheet(T.INPUT_STYLE)
        token_row.addWidget(self._repo_token_edit, 1)
        self._show_token_btn = _btn("Show", T.BG_SURFACE, T.BG_HOVER)
        self._show_token_btn.setFixedWidth(56)
        self._show_token_btn.clicked.connect(self._toggle_token_visibility)
        token_row.addWidget(self._show_token_btn)
        g_lay.addLayout(token_row)

        # Destination + clone
        dest_row = QHBoxLayout()
        dest_row.addWidget(_lbl("Clone to:"))
        self._repo_root_edit = QLineEdit(self._default_repo_root)
        self._repo_root_edit.setStyleSheet(T.INPUT_STYLE)
        dest_row.addWidget(self._repo_root_edit, 1)
        change_btn = _btn("Change…", T.BG_SURFACE, T.BG_HOVER)
        change_btn.clicked.connect(self._browse_repo_root)
        dest_row.addWidget(change_btn)
        self._import_btn = _btn("Clone / Pull", T.INFO_BG, T.INFO)
        self._import_btn.setStyleSheet(T.btn_style("#0369a1", "#0284c7"))
        self._import_btn.clicked.connect(self._import_from_github)
        dest_row.addWidget(self._import_btn)
        g_lay.addLayout(dest_row)

        self._import_status = QLabel("Ready")
        self._import_status.setStyleSheet(
            f"color: {T.TEXT_MUTED}; font-size: 11px; background: transparent; border: none;"
        )
        self._import_status.setWordWrap(True)
        g_lay.addWidget(self._import_status)
        root.addWidget(gh_card)

        # ── Website URL Card ───────────────────────────
        url_card = QFrame()
        url_card.setStyleSheet(T.CARD_STYLE)
        u_lay = QVBoxLayout(url_card)
        u_lay.setContentsMargins(14, 12, 14, 12)
        u_lay.setSpacing(8)
        u_lay.addWidget(_section_header("🌐  Website URL (optional)"))
        self._url_edit = QLineEdit()
        self._url_edit.setPlaceholderText("https://example.com")
        self._url_edit.setStyleSheet(T.INPUT_STYLE)
        u_lay.addWidget(self._url_edit)
        root.addWidget(url_card)

        # ── Detected Info Card ─────────────────────────
        self._info_card = QFrame()
        self._info_card.setStyleSheet(T.CARD_STYLE)
        i_lay = QVBoxLayout(self._info_card)
        i_lay.setContentsMargins(14, 12, 14, 12)
        i_lay.setSpacing(6)
        i_lay.addWidget(_section_header("🔍  Detected Project Info"))

        grid = QGridLayout()
        grid.setSpacing(4)
        self._lbl_types = QLabel("-")
        self._lbl_languages = QLabel("-")
        self._lbl_dep_files = QLabel("-")
        self._lbl_frameworks = QLabel("-")
        self._lbl_docker = QLabel("-")
        self._lbl_iac = QLabel("-")
        values = [
            ("Project type(s):", self._lbl_types),
            ("Languages:", self._lbl_languages),
            ("Dependency files:", self._lbl_dep_files),
            ("Frameworks:", self._lbl_frameworks),
            ("Dockerfile:", self._lbl_docker),
            ("IaC files:", self._lbl_iac),
        ]
        val_style = (
            f"color: {T.TEXT_PRIMARY}; font-size: 12px; font-weight: bold; "
            f"background: transparent; border: none; padding: 0px;"
        )
        for r, (k, v) in enumerate(values):
            grid.addWidget(_lbl(k), r, 0)
            v.setStyleSheet(val_style)
            v.setWordWrap(True)
            grid.addWidget(v, r, 1)
        i_lay.addLayout(grid)
        self._info_card.setVisible(False)
        root.addWidget(self._info_card)

        # ── Continue button ────────────────────────────
        bottom = QHBoxLayout()
        bottom.addStretch()
        self._continue_btn = _btn("Continue to Tools  →", T.SUCCESS_HOVER, T.SUCCESS)
        self._continue_btn.setStyleSheet(T.btn_style(T.SUCCESS_HOVER, T.SUCCESS))
        self._continue_btn.setMinimumHeight(40)
        self._continue_btn.setEnabled(False)
        self._continue_btn.clicked.connect(self._on_continue)
        bottom.addWidget(self._continue_btn)
        root.addLayout(bottom)
        root.addStretch()

    # ── Actions ────────────────────────────────────────────────────
    def _toggle_token_visibility(self):
        if self._repo_token_edit.echoMode() == QLineEdit.EchoMode.Password:
            self._repo_token_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self._show_token_btn.setText("Hide")
        else:
            self._repo_token_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self._show_token_btn.setText("Show")

    def _browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Project Folder")
        if path:
            self._folder_edit.setText(path)
            self._detect(path)

    def _browse_repo_root(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select Local Folder for GitHub Repositories",
            self._repo_root_edit.text().strip() or self._default_repo_root,
        )
        if path:
            self._repo_root_edit.setText(path)

    def _import_from_github(self):
        repo_url = self._repo_url_edit.text().strip()
        branch = self._repo_branch_edit.text().strip()
        repo_root = self._repo_root_edit.text().strip() or self._default_repo_root
        token = self._repo_token_edit.text().strip()

        if not repo_url:
            self._show_message(
                "GitHub Import",
                "Please enter a repository URL.",
                icon=QMessageBox.Icon.Information,
            )
            return

        if self._clone_thread is not None:
            return

        self._import_btn.setEnabled(False)
        self._import_status.setText("⏳ Cloning / pulling repository…")
        self._import_status.setStyleSheet(
            f"color: {T.INFO}; font-size: 11px; font-weight: bold; "
            f"background: transparent; border: none;"
        )

        self._clone_thread = QThread()
        self._clone_worker = _CloneWorker(repo_url, repo_root, branch, token)
        self._clone_worker.moveToThread(self._clone_thread)
        self._clone_thread.started.connect(self._clone_worker.run)
        self._clone_worker.success.connect(self._on_clone_success)
        self._clone_worker.error.connect(self._on_clone_error)
        self._clone_worker.finished.connect(self._on_clone_finished)
        self._clone_thread.start()

    def _on_clone_success(self, local_path: str, action: str):
        self._repo_token_edit.clear()
        self._folder_edit.setText(local_path)
        self._detect(local_path)
        self._import_status.setText(f"✅ {action} Ready to scan: {local_path}")
        self._import_status.setStyleSheet(
            f"color: {T.SUCCESS}; font-size: 11px; font-weight: bold; "
            f"background: transparent; border: none;"
        )

    def _on_clone_error(self, message: str):
        self._repo_token_edit.clear()
        self._import_status.setText("❌ Import failed.")
        self._import_status.setStyleSheet(
            f"color: {T.DANGER}; font-size: 11px; font-weight: bold; "
            f"background: transparent; border: none;"
        )
        self._show_message("GitHub Import Failed", message, icon=QMessageBox.Icon.Critical)

    def _on_clone_finished(self):
        if self._clone_thread:
            self._clone_thread.quit()
            self._clone_thread.wait()
        self._clone_thread = None
        self._clone_worker = None
        self._import_btn.setEnabled(True)

    def _detect(self, path: str):
        info = detect_project(path, website_url=self._url_edit.text().strip())
        self._project_info = info
        self._lbl_types.setText(", ".join(info.types))
        self._lbl_languages.setText(", ".join(info.languages) or "-")
        self._lbl_dep_files.setText(", ".join(info.dependency_files) or "-")
        self._lbl_frameworks.setText(", ".join(info.frameworks) or "-")
        self._lbl_docker.setText("Yes" if info.has_dockerfile else "No")
        self._lbl_iac.setText(
            ", ".join(info.iac_types) if info.iac_types
            else ("Yes" if info.has_iac else "No")
        )
        self._info_card.setVisible(True)
        self._continue_btn.setEnabled(True)

    def _on_continue(self):
        if self._project_info:
            website_url = self._url_edit.text().strip()
            if website_url:
                try:
                    assessment = normalize_target_url(website_url)
                except ValueError as exc:
                    self._show_message("Invalid Target URL", str(exc), icon=QMessageBox.Icon.Warning)
                    return
                self._project_info.website_url = assessment.normalized_url
                self._url_edit.setText(assessment.normalized_url)
            else:
                self._project_info.website_url = ""
            self.project_selected.emit(self._project_info)

    def _show_message(self, title: str, text: str, icon: QMessageBox.Icon = QMessageBox.Icon.Warning):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setIcon(icon)
        box.setText(text)
        box.addButton("OK", QMessageBox.ButtonRole.AcceptRole)
        box.setStyleSheet(T.DIALOG_STYLE)
        box.exec()

    @property
    def project_info(self) -> ProjectInfo | None:
        return self._project_info
