"""Live log viewer widget."""

from __future__ import annotations

from PySide6.QtWidgets import QTextEdit
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtCore import Slot


class LogView(QTextEdit):
    """Read-only text area that displays scan logs with auto-scroll."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet(
            "QTextEdit {"
            "  background-color: #1e1e2e;"
            "  color: #cdd6f4;"
            "  border: 1px solid #45475a;"
            "  border-radius: 6px;"
            "  padding: 8px;"
            "}"
        )

    @Slot(str)
    def append_log(self, text: str):
        """Append a log line and scroll to the bottom."""
        self.moveCursor(QTextCursor.MoveOperation.End)
        self.insertPlainText(f"{text}\n")
        self.moveCursor(QTextCursor.MoveOperation.End)
        self.ensureCursorVisible()

    def clear_log(self):
        """Clear all log content."""
        self.clear()
