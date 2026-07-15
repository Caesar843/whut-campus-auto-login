from __future__ import annotations

import logging
import time
from dataclasses import dataclass, replace
from typing import Callable, Optional

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from desktop_app.widgets import StatusLabel
from license_client.device_fingerprint import generate_device_fingerprint_hash
from license_client.license_api import LicenseApiClient
from license_client.license_state import LicenseDecision, LicenseStatus, evaluate_local_license
from license_client.payment_api import (
    ANNUAL_AMOUNT_FEN,
    ANNUAL_PRODUCT_CODE,
    PaymentApiClient,
    PaymentApiError,
    PaymentOrderResult,
    PaymentRefreshResult,
    payment_error_message,
)
from license_client.payment_state import PaymentStateStore, new_payment_state
from license_client.public_key import resolve_license_public_key
from license_client.token_store import save_signed_license_token
from license_client.token_verify import verify_signed_license_token


LOGGER = logging.getLogger(__name__)
POLL_INTERVAL_MS = 3_000
POLL_TIMEOUT_SECONDS = 120
ORDER_STATUSES_TO_POLL = {"WAITING_PAYMENT"}
REFRESH_COOLDOWN_DEFAULT_SECONDS = 10
REFRESH_COOLDOWN_MAX_SECONDS = 120


class PaymentRefreshError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class PaymentRequestResult:
    kind: str
    value: object


class _PaymentWorker(QObject):
    finished = Signal(int, str, object, object)

    def __init__(self, generation: int, kind: str, action: Callable[[], object]):
        super().__init__()
        self._generation = generation
        self._kind = kind
        self._action = action

    @Slot()
    def run(self) -> None:
        try:
            self.finished.emit(self._generation, self._kind, self._action(), None)
        except Exception as exc:
            self.finished.emit(self._generation, self._kind, None, exc)


class PaymentWindow(QDialog):
    activated = Signal(object)

    def __init__(
        self,
        *,
        api_client: Optional[PaymentApiClient] = None,
        state_store: Optional[PaymentStateStore] = None,
        refresh_license_func: Optional[Callable[[], LicenseDecision]] = None,
        save_license_token_func: Optional[Callable[[str], None]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._api_client = api_client or PaymentApiClient()
        self._state_store = state_store or PaymentStateStore()
        self._refresh_license = refresh_license_func or refresh_license_after_payment
        self._save_license_token = save_license_token_func or save_signed_license_token
        self._request_in_flight = False
        self._generation = 0
        self._closed = False
        self._current_order_id: Optional[str] = None
        self._last_order: Optional[PaymentOrderResult] = None
        self._poll_started_at: Optional[float] = None
        self._refresh_failed = False
        self._manual_refresh_blocked = False
        self._refresh_cooldown_generation: Optional[int] = None
        self._threads: list[QThread] = []
        self._workers: list[_PaymentWorker] = []
        self._build_ui()
        self._restore_saved_order()

    def closeEvent(self, event) -> None:
        self._closed = True
        self._generation += 1
        self._stop_polling()
        self._cancel_refresh_cooldown()
        for thread in list(self._threads):
            thread.quit()
        super().closeEvent(event)

    def _build_ui(self) -> None:
        self.setWindowTitle("购买或续费授权")
        self.setMinimumWidth(460)
        self.setMinimumHeight(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(14)

        title = QLabel("购买或续费授权")
        title.setObjectName("paymentTitle")
        subtitle = QLabel("支付成功后会自动刷新正式版授权，无需输入激活码。")
        subtitle.setObjectName("paymentSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(subtitle)

        card = QFrame()
        card.setObjectName("paymentCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(10)

        self.product_label = QLabel("产品名称：一年授权")
        self.price_label = QLabel("价格：等待服务端返回")
        self.order_label = QLabel("订单号：未创建")
        self.expires_label = QLabel("过期时间：未创建")
        self.server_status_label = QLabel("当前状态：未创建")
        for label in (
            self.product_label,
            self.price_label,
            self.order_label,
            self.expires_label,
            self.server_status_label,
        ):
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            label.setWordWrap(True)
            card_layout.addWidget(label)

        self.payment_area = StatusLabel("点击“立即创建订单”后显示支付信息。")
        card_layout.addWidget(self.payment_area)

        self.error_label = StatusLabel("")
        self.error_label.hide()
        card_layout.addWidget(self.error_label)
        layout.addWidget(card)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.create_button = QPushButton("立即创建订单")
        self.refresh_button = QPushButton("手动刷新")
        self.close_button = QPushButton("关闭")
        for button in (self.create_button, self.refresh_button, self.close_button):
            button.setMinimumHeight(38)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            actions.addWidget(button)
        layout.addLayout(actions)

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(POLL_INTERVAL_MS)
        self._poll_timer.timeout.connect(self._poll_once)

        self._refresh_cooldown_timer = QTimer(self)
        self._refresh_cooldown_timer.setSingleShot(True)
        self._refresh_cooldown_timer.timeout.connect(self._finish_refresh_cooldown)

        self.create_button.clicked.connect(self._create_order)
        self.refresh_button.clicked.connect(self._manual_refresh)
        self.close_button.clicked.connect(self.close)
        self._refresh_buttons()
        self.setStyleSheet(_style_sheet())

    def _restore_saved_order(self) -> None:
        state = self._state_store.load()
        if state is None:
            return
        self._current_order_id = state.order_id
        self.order_label.setText(f"订单号：{state.order_id}")
        self.expires_label.setText(f"过期时间：{state.expires_at}")
        self.server_status_label.setText(f"当前状态：{_status_text(state.status)}")
        self.payment_area.setText("正在恢复订单状态...")
        self.payment_area.set_variant("warning")
        self._query_order()

    @Slot()
    def _create_order(self) -> None:
        if self._request_in_flight:
            return
        self._generation += 1
        self._manual_refresh_blocked = False
        self._cancel_refresh_cooldown()
        self._refresh_failed = False
        self._clear_error()
        self.payment_area.setText("正在创建支付订单...")
        self.payment_area.set_variant("neutral")
        self._start_request(
            "create_order",
            lambda: self._api_client.create_or_resume_order(ANNUAL_PRODUCT_CODE),
        )

    @Slot()
    def _manual_refresh(self) -> None:
        if (
            self._request_in_flight
            or self._refresh_cooldown_timer.isActive()
            or self._manual_refresh_blocked
        ):
            return
        self._clear_error()
        if self._refresh_failed:
            self._start_refresh_license()
            return
        if not self._current_order_id:
            self._refresh_buttons()
            return
        order_id = self._current_order_id
        self._poll_timer.stop()
        self._start_request(
            "refresh_order",
            lambda: self._api_client.refresh_order(order_id),
        )

    def _query_order(self) -> None:
        if self._request_in_flight or not self._current_order_id:
            return
        order_id = self._current_order_id
        self._start_request("get_order", lambda: self._api_client.get_order(order_id))

    @Slot()
    def _poll_once(self) -> None:
        if self._request_in_flight or not self._current_order_id:
            return
        if self._poll_started_at is not None:
            elapsed = time.monotonic() - self._poll_started_at
            if elapsed >= POLL_TIMEOUT_SECONDS:
                self._stop_polling()
                self.payment_area.setText(
                    "暂未确认支付结果。若你已经付款，请不要重复支付，可点击“我已支付，刷新状态”或稍后重新打开软件刷新授权。"
                )
                self.payment_area.set_variant("warning")
                return
        self._query_order()

    def _start_refresh_license(self) -> None:
        if self._request_in_flight:
            return
        self._refresh_failed = False
        self._stop_polling()
        self.server_status_label.setText("当前状态：支付成功，正在刷新授权")
        self.payment_area.setText("支付成功，正在刷新授权...")
        self.payment_area.set_variant("success")
        self._start_request("refresh_license", self._refresh_license)

    def _start_request(self, kind: str, action: Callable[[], object]) -> None:
        if self._request_in_flight:
            return
        self._request_in_flight = True
        self._refresh_buttons()
        generation = self._generation
        thread = QThread(self)
        worker = _PaymentWorker(generation, kind, action)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._finish_request)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        worker.finished.connect(lambda *_args, item=worker: self._remove_worker(item))
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(lambda item=thread: self._remove_thread(item))
        self._threads.append(thread)
        self._workers.append(worker)
        thread.start()

    @Slot(int, str, object, object)
    def _finish_request(
        self,
        generation: int,
        kind: str,
        result: object,
        error: object,
    ) -> None:
        self._request_in_flight = False
        if generation != self._generation or self._closed:
            return
        self._refresh_buttons()
        if error is not None:
            self._handle_error(kind, error)
            return
        if kind in {"create_order", "get_order"}:
            self._apply_order(result)
            return
        if kind == "refresh_order":
            self._apply_refresh_result(result)
            return
        if kind == "refresh_license":
            self._apply_license_refresh(result)

    def _apply_order(
        self,
        result: object,
        *,
        refresh_license_for_paid: bool = True,
    ) -> None:
        if not isinstance(result, PaymentOrderResult):
            self._handle_error("get_order", PaymentApiError("invalid_response"))
            return
        self._last_order = result
        self._current_order_id = result.order_id
        self.order_label.setText(f"订单号：{result.order_id}")
        self.price_label.setText(f"价格：{_format_amount(result.amount_fen)}")
        self.expires_label.setText(f"过期时间：{result.expires_at}")
        self.server_status_label.setText(f"当前状态：{_status_text(result.status)}")
        self._show_payment_area(result)

        if not _trusted_annual_order(result):
            self._stop_polling()
            self._show_error("订单金额或产品信息异常，已停止支付。")
            return

        if result.status not in {"CREATED", "WAITING_PAYMENT", "PAID", "CLOSED", "ABNORMAL"}:
            self._stop_polling()
            self._show_error("订单状态未知，请稍后重试或联系支持。")
            return

        self._state_store.save(
            new_payment_state(
                order_id=result.order_id,
                product_code=result.product_code,
                status=result.status,
                created_at=result.created_at,
                expires_at=result.expires_at,
            )
        )
        if result.status in ORDER_STATUSES_TO_POLL:
            self._start_polling()
        elif result.status == "PAID":
            self._cancel_refresh_cooldown()
            self._stop_polling()
            if refresh_license_for_paid:
                self._start_refresh_license()
            else:
                self.payment_area.setText("支付状态已确认。")
                self.payment_area.set_variant("warning")
        elif result.status in {"CLOSED", "ABNORMAL"}:
            self._cancel_refresh_cooldown()
            self._stop_polling()
        self._refresh_buttons()

    def _apply_refresh_result(self, result: object) -> None:
        if (
            not isinstance(result, PaymentRefreshResult)
            or self._last_order is None
            or result.order_id != self._current_order_id
            or result.order_id != self._last_order.order_id
        ):
            self._handle_error("refresh_order", PaymentApiError("invalid_response"))
            return
        order = replace(
            self._last_order,
            status=result.status,
            amount_fen=result.amount_fen,
            currency=result.currency,
            expires_at=result.expires_at,
            paid_at=result.paid_at,
        )
        self._apply_order(
            order,
            refresh_license_for_paid=result.license_refresh_required,
        )
        if result.http_status == 202 and result.status not in {"PAID", "CLOSED", "ABNORMAL"}:
            self.payment_area.setText("正在确认支付结果，请稍后")
            self.payment_area.set_variant("warning")
            self._resume_polling_if_waiting()
            self._start_refresh_cooldown(result.retry_after_seconds)

    def _apply_license_refresh(self, result: object) -> None:
        if (
            not isinstance(result, LicenseDecision)
            or result.status != LicenseStatus.PAID_ACTIVE
            or not result.signed_license_token
        ):
            self._handle_error("refresh_license", PaymentRefreshError("license_refresh_invalid"))
            return
        try:
            self._save_license_token(result.signed_license_token)
        except Exception as exc:
            LOGGER.warning("Payment license token save failed: %s", exc.__class__.__name__)
            self._handle_error("refresh_license", PaymentRefreshError("token_save_failed"))
            return
        self._state_store.clear()
        self._refresh_failed = False
        self.payment_area.setText(result.message_for_ui or "正式版已激活。")
        self.payment_area.set_variant("success")
        self.server_status_label.setText("当前状态：正式版已激活")
        self.create_button.setText("续费一年")
        self.activated.emit(result)
        self._refresh_buttons()

    def _handle_error(self, kind: str, error: object) -> None:
        if kind == "refresh_license":
            self._refresh_failed = True
            self._stop_polling()
            self.payment_area.setText("支付已确认，但授权刷新暂时失败。请稍后点击刷新授权。")
            self.payment_area.set_variant("warning")
            self._show_error(_refresh_error_message(error))
        elif kind == "refresh_order":
            self._handle_refresh_error(error)
        elif isinstance(error, PaymentApiError):
            self._show_error(payment_error_message(error))
        else:
            LOGGER.warning("Payment request failed: %s", error.__class__.__name__)
            self._show_error("支付请求失败，请稍后再试。")
        self._refresh_buttons()

    def _handle_refresh_error(self, error: object) -> None:
        code = error.code if isinstance(error, PaymentApiError) else ""
        status_code = error.status_code if isinstance(error, PaymentApiError) else None
        if code == "payment_refresh_rate_limited":
            self.payment_area.setText("操作较频繁，请稍后再试")
            self.payment_area.set_variant("warning")
            self._resume_polling_if_waiting()
            self._start_refresh_cooldown(error.retry_after_seconds)
            return
        if code == "PAYMENT_ORDER_PROCESSING":
            self.payment_area.setText("订单正在处理中，请稍后再试")
            self.payment_area.set_variant("warning")
            self._resume_polling_if_waiting()
            self._start_refresh_cooldown(REFRESH_COOLDOWN_DEFAULT_SECONDS)
            return
        if code in {
            "PAYMENT_ORDER_REQUIRES_REVIEW",
            "PAYMENT_RECONCILIATION_REQUIRES_REVIEW",
        }:
            self.payment_area.setText("暂时无法自动确认，请联系售后处理")
            self.payment_area.set_variant("warning")
            self._manual_refresh_blocked = True
            self._stop_polling()
            return
        if code == "payment_order_not_found":
            self.payment_area.setText("当前支付状态无法刷新，请重新打开支付窗口")
            self.payment_area.set_variant("warning")
            self._manual_refresh_blocked = True
            self._stop_polling()
            return
        if code == "payment_refresh_contract_error":
            self.payment_area.setText("当前支付状态暂时无法刷新")
            self.payment_area.set_variant("warning")
            self._manual_refresh_blocked = True
            self._stop_polling()
            return
        if status_code == 409:
            self.payment_area.setText("当前订单无法自动刷新")
            self.payment_area.set_variant("warning")
            self._manual_refresh_blocked = True
            self._stop_polling()
            return
        self.payment_area.setText("暂时无法确认支付结果，请稍后再试")
        self.payment_area.set_variant("warning")
        self._resume_polling_if_waiting()

    def _show_payment_area(self, order: PaymentOrderResult) -> None:
        variant = "success" if order.status == "PAID" else "neutral"
        text = _status_text(order.status)
        if order.status == "WAITING_PAYMENT" and order.code_url:
            text = _code_url_text(order.code_url)
        self.payment_area.setText(text)
        self.payment_area.set_variant(variant)

    def _start_polling(self) -> None:
        if self._poll_started_at is None:
            self._poll_started_at = time.monotonic()
        if not self._poll_timer.isActive():
            self._poll_timer.start()

    def _stop_polling(self) -> None:
        self._poll_timer.stop()
        self._poll_started_at = None

    def _resume_polling_if_waiting(self) -> None:
        if (
            not self._closed
            and self._last_order is not None
            and self._last_order.status == "WAITING_PAYMENT"
        ):
            self._start_polling()

    def _start_refresh_cooldown(self, seconds: object) -> None:
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 1:
            bounded_seconds = REFRESH_COOLDOWN_DEFAULT_SECONDS
        else:
            bounded_seconds = min(seconds, REFRESH_COOLDOWN_MAX_SECONDS)
        self._refresh_cooldown_generation = self._generation
        self._refresh_cooldown_timer.start(bounded_seconds * 1_000)
        self._refresh_buttons()

    @Slot()
    def _finish_refresh_cooldown(self) -> None:
        generation = self._refresh_cooldown_generation
        self._refresh_cooldown_generation = None
        if self._closed or generation != self._generation:
            return
        self._refresh_buttons()

    def _cancel_refresh_cooldown(self) -> None:
        self._refresh_cooldown_timer.stop()
        self._refresh_cooldown_generation = None

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.set_variant("error")
        self.error_label.show()

    def _clear_error(self) -> None:
        self.error_label.clear()
        self.error_label.hide()

    def _refresh_buttons(self) -> None:
        busy = self._request_in_flight
        current_status = self._last_order.status if self._last_order else ""
        can_create = current_status in {"", "CLOSED"} and not self._refresh_failed
        self.create_button.setEnabled((not busy) and can_create)
        can_refresh_order = (
            bool(self._current_order_id)
            and current_status in {"CREATED", "WAITING_PAYMENT"}
            and not self._manual_refresh_blocked
            and not self._refresh_cooldown_timer.isActive()
        )
        self.refresh_button.setEnabled(
            (not busy) and (self._refresh_failed or can_refresh_order)
        )
        self.refresh_button.setText(
            "重新刷新授权" if self._refresh_failed else "我已支付，刷新状态"
        )
        if current_status == "CLOSED":
            self.create_button.setText("重新创建订单")
        elif current_status == "PAID":
            self.create_button.setText("续费一年")
        else:
            self.create_button.setText("立即创建订单")

    def _remove_thread(self, thread: QThread) -> None:
        if thread in self._threads:
            self._threads.remove(thread)

    def _remove_worker(self, worker: _PaymentWorker) -> None:
        if worker in self._workers:
            self._workers.remove(worker)


def refresh_license_after_payment() -> LicenseDecision:
    device_hash = generate_device_fingerprint_hash()
    api_result = LicenseApiClient().refresh_license(device_fingerprint_hash=device_hash)
    if not api_result.reachable:
        raise PaymentRefreshError("server_unreachable")
    if not api_result.signed_license_token:
        raise PaymentRefreshError("missing_signed_license_token")
    public_key_b64 = resolve_license_public_key()
    if not public_key_b64:
        raise PaymentRefreshError("missing_public_key")
    verification = verify_signed_license_token(
        api_result.signed_license_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash=device_hash,
    )
    decision = evaluate_local_license(verification)
    if decision.status != LicenseStatus.PAID_ACTIVE:
        raise PaymentRefreshError(verification.error or decision.reason or "license_refresh_invalid")
    return LicenseDecision(
        status=decision.status,
        allowed=decision.allowed,
        reason=decision.reason,
        license_type=decision.license_type,
        expires_at=decision.expires_at,
        days_remaining=decision.days_remaining,
        message_for_ui=decision.message_for_ui,
        signed_license_token=api_result.signed_license_token,
    )


def _trusted_annual_order(order: PaymentOrderResult) -> bool:
    return (
        order.product_code == ANNUAL_PRODUCT_CODE
        and order.amount_fen == ANNUAL_AMOUNT_FEN
        and order.currency == "CNY"
    )


def _format_amount(amount_fen: int) -> str:
    whole, cents = divmod(amount_fen, 100)
    return f"{whole}.{cents:02d} 元"


def _status_text(status: str) -> str:
    return {
        "CREATED": "正在准备支付订单",
        "WAITING_PAYMENT": "等待支付",
        "PAID": "支付成功，正在刷新授权",
        "CLOSED": "订单已关闭或过期",
        "ABNORMAL": "订单状态异常，请稍后重试或联系支持。",
    }.get(status, "未知订单状态")


def _code_url_text(code_url: str) -> str:
    if code_url.startswith("mock://"):
        return f"测试订单已创建：{_truncate(code_url)}"
    return "支付订单已创建。真实微信 Native 二维码将在后续阶段接入。"


def _truncate(value: str, limit: int = 56) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _refresh_error_message(error: object) -> str:
    if isinstance(error, PaymentRefreshError):
        return {
            "server_unreachable": "授权服务器暂时不可用，请稍后重新刷新授权。",
            "missing_signed_license_token": "授权服务器未返回可用授权凭证，请稍后重试。",
            "missing_public_key": "客户端缺少授权验签公钥，请检查配置。",
            "license_refresh_invalid": "授权刷新结果无效，请稍后重试或联系支持。",
            "token_save_failed": "授权凭证保存失败，请稍后重新刷新授权。",
        }.get(error.code, "授权刷新失败，请稍后重试。")
    return "授权刷新失败，请稍后重试。"


def _style_sheet() -> str:
    return """
    QDialog {
        background: #F8FAFC;
        color: #0F172A;
        font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif;
        font-size: 14px;
    }
    QLabel#paymentTitle {
        color: #0F172A;
        font-size: 22px;
        font-weight: 700;
        letter-spacing: 0;
    }
    QLabel#paymentSubtitle {
        color: #475569;
    }
    QFrame#paymentCard {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
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
    QPushButton:disabled {
        background: #CBD5E1;
        border-color: #CBD5E1;
        color: #64748B;
    }
    """
