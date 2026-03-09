"""Application entry point."""

import sys
import os

from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QIcon

from ui.main_window import MainWindow


def main():
    """Launch the SecScan GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("SecScan")
    app.setOrganizationName("SecScan")
    app.setApplicationVersion("1.0.0")

    # Set application icon if available
    icon_path = os.path.join(os.path.dirname(__file__), "..", "assets", "icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
