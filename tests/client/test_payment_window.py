import os
from pathlib import Path
import sys
import time

import pytest


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
from license_client.payment_api import (
    PaymentApiError,
    PaymentOrderResult,
    PaymentRefreshResult,
)
from license_client.payment_state import PaymentStateStore
from tests.license_client.test_public_key_config import _key_pair, _signed_license_token


ORDER_ID = "pay_" + "1" * 32
ORDER_ID_B = "pay_" + "2" * 32


def _app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["test-payment-window"])
    return app


class FakePaymentApi:
    def __init__(self):
        self.created = 0
        self.queried = []
        self.refreshed = []
        self.next_create = _order()
        self.next_query = _order()
        self.next_refresh = _refresh_result()

    def create_or_resume_order(self, product_code):
        self.created += 1
        return self.next_create

    def get_order(self, order_id):
        self.queried.append(order_id)
        if isinstance(self.next_query, Exception):
            raise self.next_query
        return self.next_query

    def refresh_order(self, order_id):
        self.refreshed.append(order_id)
        if isinstance(self.next_refresh, Exception):
            raise self.next_refresh
        return self.next_refresh


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


def _refresh_result(**overrides):
    values = {
        "order_id": ORDER_ID,
        "status": "WAITING_PAYMENT",
        "amount_fen": 990,
        "currency": "CNY",
        "expires_at": "2026-07-06T08:15:00Z",
        "paid_at": None,
        "license_refresh_required": False,
        "refresh_result": "WAITING_PAYMENT",
        "retry_after_seconds": None,
        "http_status": 200,
    }
    values.update(overrides)
    return PaymentRefreshResult(**values)


def _paid_decision():
    return LicenseDecision(
        status=LicenseStatus.PAID_ACTIVE,
        allowed=True,
        reason="paid_active",
        license_type="paid",
        expires_at="2027-07-06T08:00:00Z",
        message_for_ui="授权状态：正式版，有效期至 2027-07-06",
        signed_license_token="signed-token",
    )


def _window(tmp_path, api=None, refresh=None, save=None):
    _app()
    window = PaymentWindow(
        api_client=api or FakePaymentApi(),
        state_store=PaymentStateStore(tmp_path / "payment_state.json"),
        refresh_license_func=refresh or _paid_decision,
        save_license_token_func=save or (lambda _token: None),
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
    assert window.refresh_button.text() == "我已支付，刷新状态"
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

    api.next_refresh = _refresh_result(status="WAITING_PAYMENT")
    window._manual_refresh()

    assert api.created == 1
    assert api.queried == []
    assert api.refreshed == [ORDER_ID]
    assert window._poll_timer.isActive() is True


def test_manual_refresh_never_creates_order_without_order_id(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)

    window._manual_refresh()

    assert api.created == 0
    assert api.queried == []
    assert api.refreshed == []


def test_manual_refresh_starts_post_and_disables_button_immediately(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)
    window._create_order()
    started = []

    def capture_start(kind, action):
        window._request_in_flight = True
        window._refresh_buttons()
        started.append((kind, action))

    window._start_request = capture_start

    window._manual_refresh()
    window._manual_refresh()

    assert [kind for kind, _action in started] == ["refresh_order"]
    assert window.refresh_button.isEnabled() is False
    assert api.created == 1
    assert api.queried == []
    assert api.refreshed == []


def test_periodic_poll_remains_get_and_skips_while_request_in_flight(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)
    window._create_order()

    window._poll_once()

    assert api.queried == [ORDER_ID]
    assert api.refreshed == []

    window._request_in_flight = True
    window._poll_once()

    assert api.queried == [ORDER_ID]
    assert api.refreshed == []


def test_manual_refresh_pauses_get_then_resumes_original_polling(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)
    window._create_order()
    poll_started_at = window._poll_started_at
    poll_states = []

    def refresh_order(order_id):
        poll_states.append(window._poll_timer.isActive())
        return _refresh_result(order_id=order_id)

    api.refresh_order = refresh_order

    window._manual_refresh()

    assert poll_states == [False]
    assert window._poll_timer.isActive() is True
    assert window._poll_started_at == poll_started_at


def test_paid_without_license_refresh_flag_does_not_activate(tmp_path):
    api = FakePaymentApi()
    api.next_refresh = _refresh_result(
        status="PAID",
        paid_at="2026-07-06T08:01:00Z",
        license_refresh_required=False,
        refresh_result="ALREADY_PAID",
    )
    refresh_calls = []
    window = _window(
        tmp_path,
        api=api,
        refresh=lambda: refresh_calls.append("refresh"),
    )
    window._create_order()

    window._manual_refresh()

    assert refresh_calls == []
    assert window._last_order.status == "PAID"
    assert "已激活" not in window.payment_area.text()


def test_202_shows_processing_and_allows_periodic_get_without_repeat_post(tmp_path):
    api = FakePaymentApi()
    api.next_refresh = _refresh_result(
        http_status=202,
        refresh_result="REFRESH_IN_PROGRESS",
        retry_after_seconds=6,
    )
    window = _window(tmp_path, api=api)
    window._create_order()

    window._manual_refresh()

    assert "正在确认支付结果，请稍后" in window.payment_area.text()
    assert api.refreshed == [ORDER_ID]
    assert window._poll_timer.isActive() is True
    assert window.refresh_button.isEnabled() is False

    window._poll_once()

    assert api.queried == [ORDER_ID]
    assert api.refreshed == [ORDER_ID]


def test_429_uses_non_blocking_bounded_cooldown_and_keeps_get_polling(tmp_path):
    api = FakePaymentApi()
    api.next_refresh = PaymentApiError(
        "payment_refresh_rate_limited",
        status_code=429,
        retry_after_seconds=999999,
    )
    window = _window(tmp_path, api=api)
    window._create_order()

    window._manual_refresh()

    assert "操作较频繁，请稍后再试" in window.payment_area.text()
    assert window._refresh_cooldown_timer.isActive() is True
    assert window._refresh_cooldown_timer.interval() == 120_000
    assert window.refresh_button.isEnabled() is False
    assert window._poll_timer.isActive() is True

    window._refresh_cooldown_timer.stop()
    window._finish_refresh_cooldown()

    assert window.refresh_button.isEnabled() is True


def test_old_cooldown_cannot_restore_new_generation_button(tmp_path):
    api = FakePaymentApi()
    window = _window(tmp_path, api=api)
    window._create_order()
    old_generation = window._generation
    window._start_refresh_cooldown(30)

    api.next_create = _order(order_id=ORDER_ID_B)
    window._create_order()

    assert window._generation == old_generation + 1
    assert window._current_order_id == ORDER_ID_B
    assert window._refresh_cooldown_timer.isActive() is False
    refresh_calls = []
    window._refresh_buttons = lambda: refresh_calls.append("buttons")
    window._refresh_cooldown_generation = old_generation

    window._finish_refresh_cooldown()

    assert refresh_calls == []


@pytest.mark.parametrize("status", ["PAID", "CLOSED"])
def test_terminal_get_cancels_manual_refresh_cooldown(tmp_path, status):
    api = FakePaymentApi()
    api.next_query = _order(
        status=status,
        paid_at="2026-07-06T08:01:00Z" if status == "PAID" else None,
    )
    window = _window(tmp_path, api=api)
    window._create_order()
    window._start_refresh_cooldown(30)

    window._poll_once()

    assert window._refresh_cooldown_timer.isActive() is False


@pytest.mark.parametrize(
    ("error", "expected_text"),
    [
        (
            PaymentApiError("PAYMENT_ORDER_PROCESSING", status_code=409),
            "订单正在处理中，请稍后再试",
        ),
        (
            PaymentApiError("PAYMENT_ORDER_REQUIRES_REVIEW", status_code=409),
            "暂时无法自动确认，请联系售后处理",
        ),
        (
            PaymentApiError(
                "PAYMENT_RECONCILIATION_REQUIRES_REVIEW",
                status_code=409,
            ),
            "暂时无法自动确认，请联系售后处理",
        ),
        (
            PaymentApiError("payment_order_not_found", status_code=404),
            "当前支付状态无法刷新，请重新打开支付窗口",
        ),
        (
            PaymentApiError("payment_refresh_contract_error", status_code=422),
            "当前支付状态暂时无法刷新",
        ),
        (
            PaymentApiError("server_error", status_code=503),
            "暂时无法确认支付结果，请稍后再试",
        ),
        (
            PaymentApiError("network_unreachable"),
            "暂时无法确认支付结果，请稍后再试",
        ),
    ],
)
def test_manual_refresh_errors_use_fixed_safe_messages_without_new_order(
    tmp_path,
    error,
    expected_text,
):
    api = FakePaymentApi()
    api.next_refresh = error
    refresh_calls = []
    window = _window(
        tmp_path,
        api=api,
        refresh=lambda: refresh_calls.append("license"),
    )
    window._create_order()

    window._manual_refresh()

    assert expected_text in window.payment_area.text()
    assert error.code not in window.payment_area.text()
    assert api.created == 1
    assert api.queried == []
    assert api.refreshed == [ORDER_ID]
    assert refresh_calls == []


def test_closed_window_ignores_late_manual_refresh_and_cooldown(tmp_path):
    saved_tokens = []
    window = _window(tmp_path, save=saved_tokens.append)
    activated = []
    window.activated.connect(lambda decision: activated.append(decision))
    window._create_order()
    old_generation = window._generation
    window._request_in_flight = True
    label_text = window.payment_area.text()
    refresh_calls = []

    window.close()
    window._refresh_buttons = lambda: refresh_calls.append("buttons")
    window._finish_request(
        old_generation,
        "refresh_order",
        _refresh_result(
            status="PAID",
            license_refresh_required=True,
            refresh_result="PAID",
        ),
        None,
    )
    window._request_in_flight = True
    window._finish_request(old_generation, "refresh_license", _paid_decision(), None)
    window._finish_refresh_cooldown()

    assert window._request_in_flight is False
    assert window.payment_area.text() == label_text
    assert window._poll_timer.isActive() is False
    assert refresh_calls == []
    assert activated == []
    assert saved_tokens == []


def test_old_generation_manual_and_license_results_are_ignored(tmp_path):
    activated = []
    saved_tokens = []
    window = _window(tmp_path, save=saved_tokens.append)
    window.activated.connect(lambda decision: activated.append(decision))
    window._create_order()
    old_generation = window._generation
    label_text = window.payment_area.text()
    window._generation += 1

    window._request_in_flight = True
    window._finish_request(
        old_generation,
        "refresh_order",
        _refresh_result(
            status="PAID",
            license_refresh_required=True,
            refresh_result="PAID",
        ),
        None,
    )
    window._request_in_flight = True
    window._finish_request(old_generation, "refresh_license", _paid_decision(), None)

    assert window._request_in_flight is False
    assert window.payment_area.text() == label_text
    assert activated == []
    assert saved_tokens == []


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
    api.next_refresh = _refresh_result(
        status="PAID",
        paid_at="2026-07-06T08:01:00Z",
        license_refresh_required=True,
        refresh_result="PAID",
    )
    activated = []
    saved_tokens = []
    window = _window(tmp_path, api=api, save=saved_tokens.append)
    window.activated.connect(lambda decision: activated.append(decision.status.value))
    window._create_order()

    window._manual_refresh()

    assert activated == ["paid_active"]
    assert saved_tokens == ["signed-token"]
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
    api.next_refresh = PaymentApiError("network_unreachable")
    window = _window(tmp_path, api=api)
    window._create_order()

    window._manual_refresh()

    assert "暂时无法确认支付结果，请稍后再试" in window.payment_area.text()
    assert PaymentStateStore(tmp_path / "payment_state.json").load().order_id == ORDER_ID


def test_paid_refresh_failure_can_retry_without_creating_or_querying_again(tmp_path):
    api = FakePaymentApi()
    api.next_refresh = _refresh_result(
        status="PAID",
        paid_at="2026-07-06T08:01:00Z",
        license_refresh_required=True,
        refresh_result="PAID",
    )
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
    assert api.queried == []
    assert api.refreshed == [ORDER_ID]
    assert window._poll_timer.isActive() is False
    assert window.payment_area.text() == "支付已确认，但授权刷新暂时失败。请稍后点击刷新授权。"
    assert window._last_order.status == "PAID"

    window._manual_refresh()

    assert refresh_calls == ["refresh", "refresh"]
    assert api.created == 1
    assert api.queried == []
    assert api.refreshed == [ORDER_ID]
    assert activated == ["paid_active"]
    assert PaymentStateStore(tmp_path / "payment_state.json").load() is None


def test_paid_activation_waits_for_successful_token_save(tmp_path):
    api = FakePaymentApi()
    api.next_refresh = _refresh_result(
        status="PAID",
        paid_at="2026-07-06T08:01:00Z",
        license_refresh_required=True,
        refresh_result="PAID",
    )
    activated = []

    def fail_save(_token):
        raise OSError("private path")

    window = _window(tmp_path, api=api, save=fail_save)
    window.activated.connect(lambda decision: activated.append(decision))
    window._create_order()

    window._manual_refresh()

    assert activated == []
    assert window.payment_area.text() == "支付已确认，但授权刷新暂时失败。请稍后点击刷新授权。"
    assert window._refresh_failed is True


def test_close_stops_timer_and_ignores_late_result(tmp_path):
    window = _window(tmp_path)
    window._create_order()
    activated = []
    window.activated.connect(lambda decision: activated.append(decision))
    old_generation = window._generation
    create_enabled = window.create_button.isEnabled()
    refresh_enabled = window.refresh_button.isEnabled()
    refresh_calls = []

    window.close()
    window._refresh_buttons = lambda: refresh_calls.append("refresh_buttons")
    window._finish_request(
        old_generation,
        "get_order",
        _order(status="PAID", paid_at="2026-07-06T08:01:00Z"),
        None,
    )

    assert window._poll_timer.isActive() is False
    assert window._request_in_flight is False
    assert window.create_button.isEnabled() is create_enabled
    assert window.refresh_button.isEnabled() is refresh_enabled
    assert refresh_calls == []
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
    assert decision.signed_license_token == signed_token
    assert saved_tokens == []


def test_refresh_license_after_payment_rejects_invalid_signature_before_save(monkeypatch):
    _private_key, public_key_b64 = _key_pair()
    attacker_private_key, _attacker_public_key_b64 = _key_pair()
    signed_token = _signed_license_token(
        attacker_private_key,
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

    monkeypatch.setattr(
        "desktop_app.payment_window.generate_device_fingerprint_hash",
        lambda: "device-payment",
    )
    monkeypatch.setattr(
        "desktop_app.payment_window.LicenseApiClient",
        FakeLicenseApiClient,
    )
    monkeypatch.setattr(
        "desktop_app.payment_window.resolve_license_public_key",
        lambda: public_key_b64,
    )
    monkeypatch.setattr(
        "desktop_app.payment_window.save_signed_license_token",
        lambda token: saved_tokens.append(token),
    )

    with pytest.raises(PaymentRefreshError):
        refresh_license_after_payment()

    assert saved_tokens == []
