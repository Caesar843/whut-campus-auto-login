from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from desktop_app.runtime_logs import (
    DIAGNOSTIC_LOG_LIMIT,
    RuntimeLogStore,
    UI_LOG_DISPLAY_LIMIT,
    format_log_entry_block,
    get_default_log_store,
)


class RuntimeLogWindow(QDialog):
    def __init__(
        self,
        *,
        log_store: Optional[RuntimeLogStore] = None,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self._log_store = log_store or get_default_log_store()
        self._build_ui()
        self.refresh_logs()

    def _build_ui(self) -> None:
        self.setWindowTitle("运行日志")
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setModal(False)
        self.resize(900, 620)
        self.setMinimumSize(760, 480)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(14)

        title = QLabel("运行日志")
        title.setObjectName("title")
        layout.addWidget(title)

        notice = QLabel(
            "运行日志仅保存在本机，默认保留 7 天，最多 200 条。不会记录密码、完整账号或授权 token。"
        )
        notice.setObjectName("notice")
        notice.setWordWrap(True)
        layout.addWidget(notice)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.log_text.setFont(font)
        self.log_text.document().setDocumentMargin(8)
        layout.addWidget(self.log_text, 1)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.copy_status_label = QLabel("")
        self.copy_status_label.setObjectName("copyStatus")
        actions.addWidget(self.copy_status_label)
        actions.addStretch(1)
        self.refresh_button = QPushButton("刷新")
        self.copy_button = QPushButton("复制诊断信息")
        self.clear_button = QPushButton("清除")
        self.close_button = QPushButton("关闭")
        for button in (
            self.refresh_button,
            self.copy_button,
            self.clear_button,
            self.close_button,
        ):
            button.setMinimumHeight(36)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            actions.addWidget(button)
        layout.addLayout(actions)

        self.refresh_button.clicked.connect(self.refresh_logs)
        self.copy_button.clicked.connect(self.copy_diagnostic_info)
        self.clear_button.clicked.connect(self.confirm_clear_logs)
        self.close_button.clicked.connect(self.close)
        self.setStyleSheet(_style_sheet())

    @Slot()
    def refresh_logs(self) -> None:
        rows = self._log_store.read_recent(limit=UI_LOG_DISPLAY_LIMIT)
        if not rows:
            self.log_text.setPlainText("暂无运行日志。")
            return
        self.log_text.setPlainText(
            "\n\n".join(format_log_entry_block(row) for row in rows)
        )

    @Slot()
    def copy_diagnostic_info(self) -> None:
        QApplication.clipboard().setText(
            self._log_store.build_diagnostic_text(limit=DIAGNOSTIC_LOG_LIMIT)
        )
        self.copy_status_label.setText("诊断信息已复制")

    @Slot()
    def confirm_clear_logs(self) -> None:
        answer = QMessageBox.question(
            self,
            "清除日志",
            "确认清除本机运行日志？\n清除后无法恢复，但不会影响账号配置和自动登录功能。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != self._yes_button():
            return
        if self._log_store.clear():
            self.refresh_logs()
            self.copy_status_label.setText("运行日志已清除")
        else:
            QMessageBox.warning(self, "清除日志", "清除运行日志失败，请稍后重试。")

    def show_for_owner(self, owner: Optional[QWidget] = None) -> None:
        if owner is not None:
            self._center_on(owner)
        self.show()
        self.raise_()
        self.activateWindow()

    def _center_on(self, owner: QWidget) -> None:
        owner_geometry = owner.frameGeometry()
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(owner_geometry.center())
        self.move(window_geometry.topLeft())

    def _yes_button(self) -> QMessageBox.StandardButton:
        return QMessageBox.StandardButton.Yes


def _style_sheet() -> str:
    return """
    QWidget {
        background: #F8FAFC;
        color: #020617;
        font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
        font-size: 14px;
    }
    QLabel#title {
        color: #0F172A;
        font-size: 20px;
        font-weight: 700;
    }
    QLabel#notice {
        color: #475569;
        background: #EFF6FF;
        border: 1px solid #BFDBFE;
        border-radius: 8px;
        padding: 10px;
    }
    QLabel#copyStatus {
        color: #0369A1;
        font-size: 13px;
    }
    QPlainTextEdit {
        background: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        padding: 10px;
        color: #0F172A;
        selection-background-color: #BAE6FD;
    }
    QPushButton {
        background: #0F172A;
        border: 1px solid #0F172A;
        border-radius: 8px;
        color: #FFFFFF;
        font-weight: 600;
        padding: 8px 12px;
    }
    QPushButton:hover {
        background: #0369A1;
        border-color: #0369A1;
    }
    """
