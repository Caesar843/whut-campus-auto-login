import os
from pathlib import Path
import sys
import time


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication

from desktop_app.payment_window import (
    POLL_INTERVAL_MS,
    PaymentRefreshError,
    PaymentWindow,
    refresh_license_after_payment,
)
from license_client.license_api import LicenseApiResult
from license_client.license_state import LicenseDecision, LicenseStatus
from license_client.payment_api import PaymentApiError, PaymentOrderResult
from license_client.payment_state import PaymentStateStore
from tests.license_client.test_public_key_config import _key_pair, _signed_license_token


ORDER_ID = "pay_" + "1" * 32


def _app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["test-payment-window"])
    return app


class FakePaymentApi:
    def __init__(self):
        self.created = 0
        self.queried = []
        self.next_create = _order()
        self.next_query = _order()

    def create_or_resume_order(self, product_code):
        self.created += 1
        return self.next_create

    def get_order(self, order_id):
        self.queried.append(order_id)
        if isinstance(self.next_query, Exception):
            raise self.next_query
        return self.next_query


def _order(**overrides):
    values = {
        "order_id": ORDER_ID,
        "product_code": "annual_v1",
        "amount_fen": 990,
        "currency": "CNY",
        "provider": "mock",
        "status": "WAITING_PAYMENT",
        "code_url": f"mock://whut-payment/{ORDER_ID}",
        "created_at": "2026-07-06T08:00:00Z",
        "expires_at": "2026-07-06T08:15:00Z",
        "paid_at": None,
    }
    values.update(overrides)
    return PaymentOrderResult(**values)


def _paid_decision():
    return LicenseDecision(
        status=LicenseStatus.PAID_ACTIVE,
        allowed=True,
        reason="paid_active",
        license_type="paid",
        expires_at="2027-07-06T08:00:00Z",
        message_for_ui="授权状态：正式版，有效期至 2027-07-06",
    )


def _window(tmp_path, api=None, refresh=None):
    _app()
    window = PaymentWindow(
        api_client=api or FakePaymentApi(),
        state_store=PaymentStateStore(tmp_path / "payment_state.json"),
        refresh_license_func=refresh or _paid_decision,
    )
    _make_requests_sync(window)
    return window


def _make_requests_sync(window):
    def sync_start(kind, action):
        if window._request_in_flight:
            return
        window._request_in_flight = True
        try:
            result = action()
            error = None
        except Exception as exc:
            result = None
            error = exc
        window._finish_request(window._generation, kind, result, error)

    window._start_request = sync_start


def test_initial_payment_window_state(tmp_path):
    window = _window(tmp_path)

    assert window.create_button.text() == "立即创建订单"
    assert window.create_button.isEnabled() is True
    assert window.refresh_button.isEnabled() is False
    assert "未创建" in window.order_label.text()


def test_create_order_displays_server_amount_and_starts_polling(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)

    window._create_order()

    assert api.created == 1
    assert ORDER_ID in window.order_label.text()
    assert "9.90 元" in window.price_label.text()
    assert "测试订单已创建" in window.payment_area.text()
    assert f"mock://whut-payment/{ORDER_ID}" in window.payment_area.text()
    assert window._poll_timer.interval() == POLL_INTERVAL_MS
    assert window._poll_timer.isActive() is True
    assert PaymentStateStore(tmp_path / "payment_state.json").load().order_id == ORDER_ID


def test_created_order_does_not_auto_poll_and_can_be_refreshed_manually(tmp_path):
    api = FakePaymentApi()
    api.next_create = _order(status="CREATED", code_url=None)
    window = _window(tmp_path, api=api)

    window._create_order()

    assert api.created == 1
    assert window._poll_timer.isActive() is False
    assert PaymentStateStore(tmp_path / "payment_state.json").load().status == "CREATED"

    api.next_query = _order(status="WAITING_PAYMENT")
    window._manual_refresh()

    assert api.created == 1
    assert api.queried == [ORDER_ID]
    assert window._poll_timer.isActive() is True


def test_duplicate_create_click_is_ignored_while_request_is_in_flight(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)
    window._request_in_flight = True

    window._create_order()

    assert api.created == 0


def test_polling_stops_after_timeout_without_creating_second_order(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)
    window._create_order()
    window._poll_started_at = time.monotonic() - 121

    window._poll_once()

    assert window._poll_timer.isActive() is False
    assert api.created == 1
    assert api.queried == []
    assert "不要重复支付" in window.payment_area.text()


def test_closed_and_abnormal_orders_stop_polling(tmp_path):
    for status in ("CLOSED", "ABNORMAL"):
        api = FakePaymentApi()
        api.next_create = _order(status=status)
        window = _window(tmp_path / status, api=api)

        window._create_order()

        assert window._poll_timer.isActive() is False
        stored = PaymentStateStore(tmp_path / status / "payment_state.json").load()
        if status == "CLOSED":
            assert stored is None
        else:
            assert stored.status == "ABNORMAL"


def test_paid_order_refreshes_license_and_clears_recovery_state(tmp_path):
    api = FakePaymentApi()
    api.next_query = _order(status="PAID", paid_at="2026-07-06T08:01:00Z")
    activated = []
    window = _window(tmp_path, api=api)
    window.activated.connect(lambda decision: activated.append(decision.status.value))
    window._create_order()

    window._manual_refresh()

    assert activated == ["paid_active"]
    assert "正式版" in window.payment_area.text()
    assert PaymentStateStore(tmp_path / "payment_state.json").load() is None
    assert window._poll_timer.isActive() is False


def test_payment_window_reports_amount_mismatch_without_refreshing(tmp_path):
    api = FakePaymentApi()
    api.next_create = _order(amount_fen=1)
    refreshed = []
    window = _window(tmp_path, api=api, refresh=lambda: refreshed.append("refresh"))

    window._create_order()

    assert refreshed == []
    assert "订单金额" in window.error_label.text()
    assert window._poll_timer.isActive() is False


def test_unknown_order_status_is_not_treated_as_success(tmp_path):
    api = FakePaymentApi()
    api.next_create = _order(status="SUCCESS")
    refreshed = []
    window = _window(tmp_path, api=api, refresh=lambda: refreshed.append("refresh"))

    window._create_order()

    assert refreshed == []
    assert "状态未知" in window.error_label.text()
    assert PaymentStateStore(tmp_path / "payment_state.json").load() is None


def test_network_error_keeps_order_for_manual_refresh(tmp_path):
    api = FakePaymentApi()
    api.next_query = PaymentApiError("network_unreachable")
    window = _window(tmp_path, api=api)
    window._create_order()

    window._manual_refresh()

    assert "无法连接" in window.error_label.text()
    assert PaymentStateStore(tmp_path / "payment_state.json").load().order_id == ORDER_ID


def test_paid_refresh_failure_can_retry_without_creating_or_querying_again(tmp_path):
    api = FakePaymentApi()
    api.next_query = _order(status="PAID", paid_at="2026-07-06T08:01:00Z")
    refresh_calls = []

    def refresh():
        refresh_calls.append("refresh")
        if len(refresh_calls) == 1:
            raise PaymentRefreshError("server_unreachable")
        return _paid_decision()

    activated = []
    window = _window(tmp_path, api=api, refresh=refresh)
    window.activated.connect(lambda decision: activated.append(decision.status.value))
    window._create_order()

    window._manual_refresh()

    assert refresh_calls == ["refresh"]
    assert api.created == 1
    assert api.queried == [ORDER_ID]
    assert window._poll_timer.isActive() is False
    assert "支付成功" in window.payment_area.text()
    assert window._last_order.status == "PAID"

    window._manual_refresh()

    assert refresh_calls == ["refresh", "refresh"]
    assert api.created == 1
    assert api.queried == [ORDER_ID]
    assert activated == ["paid_active"]
    assert PaymentStateStore(tmp_path / "payment_state.json").load() is None


def test_close_stops_timer_and_ignores_late_result(tmp_path):
    window = _window(tmp_path)
    window._create_order()
    activated = []
    window.activated.connect(lambda decision: activated.append(decision))
    old_generation = window._generation

    window.close()
    window._finish_request(
        old_generation,
        "get_order",
        _order(status="PAID", paid_at="2026-07-06T08:01:00Z"),
        None,
    )

    assert window._poll_timer.isActive() is False
    assert activated == []


def test_refresh_license_after_payment_uses_packaged_release_public_key(monkeypatch):
    private_key, public_key_b64 = _key_pair()
    _malicious_private_key, malicious_public_key_b64 = _key_pair()
    signed_token = _signed_license_token(
        private_key,
        device_fingerprint_hash="device-payment",
    )
    saved_tokens = []

    class FakeLicenseApiClient:
        def refresh_license(self, *, device_fingerprint_hash):
            assert device_fingerprint_hash == "device-payment"
            return LicenseApiResult(
                reachable=True,
                status="ok",
                signed_license_token=signed_token,
            )

    monkeypatch.setenv("LICENSE_PUBLIC_KEY", malicious_public_key_b64)
    monkeypatch.setattr(
        "license_client.public_key._load_embedded_build_config",
        lambda: ("production", public_key_b64),
    )
    monkeypatch.setattr(
        "desktop_app.payment_window.generate_device_fingerprint_hash",
        lambda: "device-payment",
    )
    monkeypatch.setattr(
        "desktop_app.payment_window.LicenseApiClient",
        FakeLicenseApiClient,
    )
    monkeypatch.setattr(
        "desktop_app.payment_window.save_signed_license_token",
        lambda token: saved_tokens.append(token),
    )

    decision = refresh_license_after_payment()

    assert decision.status == LicenseStatus.PAID_ACTIVE
    assert saved_tokens == [signed_token]
