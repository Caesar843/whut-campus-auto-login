from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QLabel, QLineEdit


class AccountLineEdit(QLineEdit):
    """Line edit with a small locally painted account icon."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setPlaceholderText("请输入校园网账号")
        self.setClearButtonEnabled(True)
        self.addAction(_account_icon(), QLineEdit.ActionPosition.LeadingPosition)
        self.setMinimumHeight(44)


class PasswordLineEdit(QLineEdit):
    """Password line edit with a trailing show/hide action."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setPlaceholderText("请输入校园网密码")
        self.setClearButtonEnabled(True)
        self.setEchoMode(QLineEdit.EchoMode.Password)
        self.setMinimumHeight(44)
        self._visible = False
        self._toggle_action = QAction(_eye_icon(hidden=False), "显示密码", self)
        self._toggle_action.setToolTip("显示密码")
        self._toggle_action.triggered.connect(self.toggle_password_visible)
        self.addAction(self._toggle_action, QLineEdit.ActionPosition.TrailingPosition)

    @property
    def password_visible(self) -> bool:
        return self._visible

    def toggle_password_visible(self) -> None:
        cursor_position = self.cursorPosition()
        self._visible = not self._visible
        if self._visible:
            self.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_action.setIcon(_eye_icon(hidden=True))
            self._toggle_action.setText("隐藏密码")
            self._toggle_action.setToolTip("隐藏密码")
        else:
            self.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_action.setIcon(_eye_icon(hidden=False))
            self._toggle_action.setText("显示密码")
            self._toggle_action.setToolTip("显示密码")
        self.setCursorPosition(cursor_position)


class StatusLabel(QLabel):
    """Compact status label with variants for neutral/success/error feedback."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(text, parent)
        self.setWordWrap(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setMinimumHeight(34)
        self.set_variant("neutral")

    def set_variant(self, variant: str) -> None:
        colors = {
            "neutral": ("#334155", "#E2E8F0", "#F8FAFC"),
            "success": ("#166534", "#BBF7D0", "#F0FDF4"),
            "warning": ("#92400E", "#FDE68A", "#FFFBEB"),
            "error": ("#991B1B", "#FECACA", "#FEF2F2"),
        }
        fg, border, bg = colors.get(variant, colors["neutral"])
        self.setStyleSheet(
            f"""
            QLabel {{
                color: {fg};
                background: {bg};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 8px 10px;
                font-size: 13px;
                line-height: 1.5;
            }}
            """
        )


def _account_icon() -> QIcon:
    size = QSize(22, 22)
    pixmap = QPixmap(size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor("#0369A1"), 1.8))
    painter.setBrush(QColor("#E0F2FE"))
    painter.drawEllipse(7, 4, 8, 8)
    painter.drawArc(4, 11, 14, 10, 20 * 16, 140 * 16)
    painter.end()
    return QIcon(pixmap)


def _eye_icon(*, hidden: bool) -> QIcon:
    size = QSize(28, 28)
    pixmap = QPixmap(size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor("#111827"), 2.2)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawEllipse(5, 8, 18, 12)
    painter.setBrush(QColor("#111827"))
    painter.drawEllipse(11, 12, 6, 6)
    if hidden:
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawLine(6, 22, 22, 6)
    painter.end()
    return QIcon(pixmap)
