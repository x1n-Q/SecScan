"""Centralized dark theme design system for SecScan GUI."""

from __future__ import annotations

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Color Palette
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BG_DARKEST  = "#0b0e14"
BG_DARK     = "#10141c"
BG_CARD     = "#161b26"
BG_CARD_ALT = "#1a2030"
BG_HOVER    = "#1e2738"
BG_INPUT    = "#111827"
BG_SURFACE  = "#1e293b"

BORDER      = "#1e293b"
BORDER_FOCUS = "#6366f1"
BORDER_SUBTLE = "#374151"

TEXT_PRIMARY   = "#f1f5f9"
TEXT_SECONDARY = "#94a3b8"
TEXT_MUTED     = "#64748b"
TEXT_ACCENT    = "#818cf8"

ACCENT         = "#6366f1"  # Indigo
ACCENT_HOVER   = "#818cf8"
ACCENT_BG      = "#312e81"

SUCCESS        = "#22c55e"
SUCCESS_BG     = "#14532d"
SUCCESS_HOVER  = "#16a34a"

WARNING        = "#f59e0b"
WARNING_BG     = "#78350f"

DANGER         = "#ef4444"
DANGER_BG      = "#7f1d1d"
DANGER_HOVER   = "#dc2626"

INFO           = "#38bdf8"
INFO_BG        = "#0c4a6e"

# Severity colors
SEV_CRITICAL   = "#ff3b5c"
SEV_CRITICAL_BG = "#450a1a"
SEV_HIGH       = "#ff6b35"
SEV_HIGH_BG    = "#431408"
SEV_MEDIUM     = "#fbbf24"
SEV_MEDIUM_BG  = "#422006"
SEV_LOW        = "#38bdf8"
SEV_LOW_BG     = "#0c4a6e"
SEV_INFO       = "#64748b"
SEV_INFO_BG    = "#1e293b"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Style Factories
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def btn_style(bg: str, hover: str, fg: str = TEXT_PRIMARY) -> str:
    return (
        f"QPushButton {{ background: {bg}; color: {fg}; border: none; "
        f"border-radius: 6px; padding: 7px 16px; font-size: 12px; font-weight: 600; }}"
        f"QPushButton:hover {{ background: {hover}; }}"
        f"QPushButton:disabled {{ background: {BORDER_SUBTLE}; color: {TEXT_MUTED}; }}"
    )


def outline_btn_style(color: str, hover_bg: str) -> str:
    return (
        f"QPushButton {{ background: transparent; color: {color}; "
        f"border: 1px solid {color}; border-radius: 6px; "
        f"padding: 7px 16px; font-size: 12px; font-weight: 600; }}"
        f"QPushButton:hover {{ background: {hover_bg}; }}"
        f"QPushButton:disabled {{ color: {TEXT_MUTED}; border-color: {BORDER_SUBTLE}; }}"
    )


INPUT_STYLE = (
    f"QLineEdit {{ color: {TEXT_PRIMARY}; background: {BG_INPUT}; "
    f"border: 1px solid {BORDER_SUBTLE}; border-radius: 6px; "
    f"padding: 7px 12px; font-size: 12px; }}"
    f"QLineEdit:focus {{ border: 1.5px solid {ACCENT}; background: {BG_CARD}; }}"
    f"QLineEdit:read-only {{ background: {BG_DARK}; color: {TEXT_MUTED}; }}"
    f"QLineEdit::placeholder {{ color: {TEXT_MUTED}; }}"
)

COMBO_STYLE = (
    f"QComboBox {{ color: {TEXT_PRIMARY}; background: {BG_INPUT}; "
    f"border: 1px solid {BORDER_SUBTLE}; border-radius: 6px; "
    f"padding: 6px 10px; min-height: 28px; font-size: 12px; }}"
    f"QComboBox:focus {{ border: 1.5px solid {ACCENT}; }}"
    f"QComboBox::drop-down {{ width: 24px; border: none; }}"
    f"QComboBox QAbstractItemView {{ color: {TEXT_PRIMARY}; background: {BG_CARD}; "
    f"selection-background-color: {ACCENT_BG}; selection-color: {ACCENT_HOVER}; "
    f"border: 1px solid {BORDER_SUBTLE}; }}"
)

CARD_STYLE = (
    f"QFrame {{ background: {BG_CARD}; "
    f"border: 1px solid {BORDER}; border-radius: 10px; }}"
)

SCROLL_STYLE = (
    f"QScrollArea {{ background: {BG_DARK}; border: none; }}"
    f"QScrollBar:vertical {{ background: {BG_DARK}; width: 8px; border: none; }}"
    f"QScrollBar::handle:vertical {{ background: {BORDER_SUBTLE}; border-radius: 4px; min-height: 30px; }}"
    f"QScrollBar::handle:vertical:hover {{ background: {TEXT_MUTED}; }}"
    f"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}"
    f"QScrollBar:horizontal {{ background: {BG_DARK}; height: 8px; border: none; }}"
    f"QScrollBar::handle:horizontal {{ background: {BORDER_SUBTLE}; border-radius: 4px; min-width: 30px; }}"
    f"QScrollBar::handle:horizontal:hover {{ background: {TEXT_MUTED}; }}"
    f"QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0px; }}"
)

DIALOG_STYLE = (
    f"QMessageBox {{ background: {BG_CARD}; }}"
    f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 12px; }}"
    f"QPushButton {{ min-width: 88px; color: {TEXT_PRIMARY}; background: {BG_SURFACE}; "
    f"border: 1px solid {BORDER_SUBTLE}; border-radius: 6px; padding: 5px 12px; }}"
    f"QPushButton:hover {{ background: {ACCENT_BG}; border-color: {ACCENT}; }}"
)

PROGRESS_STYLE = (
    f"QProgressBar {{ border: 1px solid {BORDER_SUBTLE}; border-radius: 6px; "
    f"text-align: center; background: {BG_SURFACE}; font-weight: bold; color: {TEXT_PRIMARY}; }}"
    f"QProgressBar::chunk {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, "
    f"stop:0 {ACCENT}, stop:1 {ACCENT_HOVER}); border-radius: 5px; }}"
)

TABLE_STYLE = (
    f"QTableWidget {{"
    f"  border: 1px solid {BORDER}; border-radius: 8px;"
    f"  color: {TEXT_PRIMARY}; background-color: {BG_CARD};"
    f"  alternate-background-color: {BG_CARD_ALT};"
    f"  gridline-color: {BORDER};"
    f"}}"
    f"QTableWidget::item {{"
    f"  color: {TEXT_PRIMARY}; padding: 5px 8px;"
    f"}}"
    f"QTableWidget::item:selected {{"
    f"  background-color: {ACCENT_BG}; color: {ACCENT_HOVER};"
    f"}}"
    f"QHeaderView::section {{"
    f"  background: {BG_SURFACE}; color: {TEXT_PRIMARY}; padding: 7px 8px;"
    f"  font-size: 11px; font-weight: bold; border: none;"
    f"  border-bottom: 2px solid {ACCENT};"
    f"}}"
)

LOG_STYLE = (
    f"QTextEdit {{"
    f"  background-color: {BG_DARKEST};"
    f"  color: #cdd6f4;"
    f"  border: 1px solid {BORDER};"
    f"  border-radius: 8px;"
    f"  padding: 8px;"
    f"}}"
)
