from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event, Lock

import pytest

from license_server.db import connect
from license_server.payment import ANNUAL_V1, OrderStatus, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_gateway import (
    MOCK_APP_ID,
    MOCK_MCH_ID,
    GatewayOrder,
    MockPaymentGateway,
    QueryOrderOutcome,
    QueryOrderResult,
)
from license_server.payment_service import (
    PaymentServiceError,
    confirm_paid_order,
    create_or_restore_order,
)
from license_server.signer import datetime_text
from license_server.wechat_payment import WechatPaymentError
from tests.license_server.test_license_server import _client, _register_payload


def test_confirm_paid_order_creates_paid_license_grant_and_paid_order(tmp_path):
    order = _mock_order(tmp_path)
    result = confirm_paid_order(tmp_path / "license.sqlite3", _evidence(order.order_id))

    assert result.status == OrderStatus.PAID.value
    assert result.idempotent is False
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        paid_order = connection.execute(
            "SELECT status, open_slot, provider_transaction_id FROM payment_orders WHERE order_id = ?",
            (order.order_id,),
        ).fetchone()

    assert tuple(paid_order) == ("PAID", None, f"mock_txn_{order.order_id}")


def test_repeated_confirm_is_idempotent_and_does_not_extend_twice(tmp_path):
    order = _mock_order(tmp_path)

    first = confirm_paid_order(tmp_path / "license.sqlite3", _evidence(order.order_id))
    second = confirm_paid_order(tmp_path / "license.sqlite3", _evidence(order.order_id))

    assert second.idempotent is True
    assert second.license_id == first.license_id
    assert second.expires_at == first.expires_at
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_amount_mismatch_marks_open_order_abnormal_without_grant(tmp_path):
    order = _mock_order(tmp_path)

    with pytest.raises(PaymentServiceError, match="amount_mismatch"):
        confirm_paid_order(
            tmp_path / "license.sqlite3",
            _evidence(order.order_id, amount_fen=1),
        )

    with connect(tmp_path / "license.sqlite3") as connection:
        row = connection.execute(
            "SELECT status, open_slot, security_error_code FROM payment_orders WHERE order_id = ?",
            (order.order_id,),
        ).fetchone()
        assert tuple(row) == ("ABNORMAL", "open", "amount_mismatch")
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_closed_order_cannot_be_confirmed_paid(tmp_path):
    order = _mock_order(tmp_path)
    with connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            "UPDATE payment_orders SET status = 'CLOSED', open_slot = NULL WHERE order_id = ?",
            (order.order_id,),
        )
        connection.commit()

    with pytest.raises(PaymentServiceError, match="closed_order"):
        confirm_paid_order(tmp_path / "license.sqlite3", _evidence(order.order_id))


def test_expired_waiting_order_cannot_be_confirmed_paid(tmp_path):
    order = _mock_order(tmp_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            "UPDATE payment_orders SET expires_at = ? WHERE order_id = ?",
            (datetime_text(now - timedelta(minutes=1)), order.order_id),
        )
        connection.commit()

    with pytest.raises(PaymentServiceError, match="payment_order_expired"):
        confirm_paid_order(
            tmp_path / "license.sqlite3",
            _evidence(order.order_id),
            now=now,
        )

    with connect(tmp_path / "license.sqlite3") as connection:
        row = connection.execute(
            "SELECT status, open_slot, security_error_code FROM payment_orders WHERE order_id = ?",
            (order.order_id,),
        ).fetchone()
        assert tuple(row) == ("CLOSED", None, "expired")
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_unexpired_paid_license_renews_from_existing_expiry(tmp_path):
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    future = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=40)
    with connect(tmp_path / "license.sqlite3") as connection:
        device_id = connection.execute("SELECT id FROM devices").fetchone()[0]
        connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                order_id, created_at, revoked_at
            ) VALUES (?, 'paid', 'active', ?, ?, 'admin', NULL, ?, NULL)
            """,
            (
                device_id,
                datetime_text(future - timedelta(days=1)),
                datetime_text(future),
                datetime_text(future - timedelta(days=1)),
            ),
        )
        connection.commit()
    order = create_or_restore_order(
        tmp_path / "license.sqlite3",
        device_fingerprint_hash="device-a",
        product_code=ANNUAL_V1.product_code,
        provider="mock",
        ttl_minutes=15,
        gateway=MockPaymentGateway(),
    )

    result = confirm_paid_order(tmp_path / "license.sqlite3", _evidence(order.order_id))

    assert result.expires_at == datetime_text(future + timedelta(days=365))


def test_transaction_rolls_back_when_license_creation_fails(tmp_path, monkeypatch):
    order = _mock_order(tmp_path)

    def fail_create_license(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("license_server.payment_service.create_license", fail_create_license)
    with pytest.raises(RuntimeError, match="boom"):
        confirm_paid_order(tmp_path / "license.sqlite3", _evidence(order.order_id))

    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?",
            (order.order_id,),
        ).fetchone()[0] == OrderStatus.WAITING_PAYMENT.value


def test_notification_status_updates_in_same_confirmation(tmp_path):
    order = _mock_order(tmp_path)
    with connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, provider, process_status, received_at
            ) VALUES ('notice-1', 'mock', 'RECEIVED', ?)
            """,
            (datetime_text(datetime.now(timezone.utc)),),
        )
        connection.commit()

    confirm_paid_order(
        tmp_path / "license.sqlite3",
        _evidence(order.order_id),
        notification_id="notice-1",
    )

    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute(
            "SELECT process_status FROM payment_notifications WHERE provider_notification_id = 'notice-1'"
        ).fetchone()[0] == "PROCESSED"


def test_gateway_http_phase_does_not_hold_sqlite_write_transaction(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())

    class WritingGateway(MockPaymentGateway):
        def create_native_order(self, request):
            with connect(database_path) as connection:
                connection.execute("PRAGMA busy_timeout = 20")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "UPDATE devices SET last_seen_at = last_seen_at "
                    "WHERE device_fingerprint_hash = 'device-a'"
                )
                connection.commit()
            return super().create_native_order(request)

    result = create_or_restore_order(
        database_path,
        device_fingerprint_hash="device-a",
        product_code=ANNUAL_V1.product_code,
        provider="mock",
        ttl_minutes=15,
        gateway=WritingGateway(),
    )

    assert result.status == OrderStatus.WAITING_PAYMENT.value


def test_concurrent_same_device_create_keeps_one_order_and_one_gateway_result(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())

    class ConcurrentGateway(MockPaymentGateway):
        def __init__(self):
            self.entered = Event()
            self.release = Event()
            self.lock = Lock()
            self.order_ids = []

        def create_native_order(self, request):
            with self.lock:
                self.order_ids.append(request.out_trade_no)
            self.entered.set()
            assert self.release.wait(timeout=5)
            return GatewayOrder(
                code_url="weixin://wxpay/test-1",
                provider_order_id=request.out_trade_no,
                provider_trade_state="NOTPAY",
            )

    gateway = ConcurrentGateway()

    def create():
        return _create_wechat_order(database_path, gateway)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(create)
        assert gateway.entered.wait(timeout=5)
        second = executor.submit(create)
        second_result = second.result(timeout=5)
        gateway.release.set()
        first_result = first.result(timeout=5)

    assert gateway.order_ids == [first_result.order_id]
    assert second_result.order_id == first_result.order_id
    assert second_result.status == OrderStatus.CREATED.value
    assert second_result.code_url is None
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT order_id, status, open_slot, provider_code_url, "
            "provider_create_attempt_count FROM payment_orders"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == OrderStatus.WAITING_PAYMENT.value
        assert rows[0]["open_slot"] == "open"
        assert rows[0]["provider_code_url"] == "weixin://wxpay/test-1"
        assert rows[0]["provider_create_attempt_count"] == 1


def test_unknown_create_result_queries_same_order_and_schedules_retry(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    gateway = UnknownResultGateway(QueryOrderOutcome.HTTP_UNKNOWN)

    with pytest.raises(PaymentServiceError, match="payment_result_unknown"):
        create_or_restore_order(
            database_path,
            device_fingerprint_hash="device-a",
            product_code=ANNUAL_V1.product_code,
            provider="wechat_native",
            ttl_minutes=15,
            gateway=gateway,
            notify_url="https://pay.example.test/wechat/notify",
            expected_appid="wx-test-app",
            expected_mchid="1900000109",
        )

    assert gateway.queried == [gateway.created_order_id]
    with connect(database_path) as connection:
        rows = connection.execute("SELECT * FROM payment_orders").fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == OrderStatus.CREATED.value
        assert rows[0]["provider_query_attempt_count"] == 1
        assert rows[0]["last_provider_query_at"] is not None
        assert rows[0]["next_provider_query_at"] is not None
        assert rows[0]["security_error_code"] == "payment_result_unknown"
        assert rows[0]["provider_create_attempt_count"] == 1
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_unknown_create_result_second_request_never_creates_again(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    gateway = UnknownResultGateway(QueryOrderOutcome.HTTP_UNKNOWN)

    with pytest.raises(PaymentServiceError, match="payment_result_unknown"):
        _create_wechat_order(database_path, gateway)

    result = _create_wechat_order(database_path, gateway)

    assert gateway.created == [result.order_id]
    assert gateway.queried == [result.order_id]
    assert result.status == OrderStatus.CREATED.value
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM payment_orders").fetchone()[0] == 1
        assert connection.execute(
            "SELECT provider_create_attempt_count FROM payment_orders"
        ).fetchone()[0] == 1


def test_request_not_sent_error_does_not_clear_create_claim(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    gateway = UnknownResultGateway(
        QueryOrderOutcome.NOT_FOUND,
        create_error="PAYMENT_REQUEST_NOT_SENT",
        result_unknown=False,
    )

    with pytest.raises(PaymentServiceError, match="payment_request_not_sent"):
        _create_wechat_order(database_path, gateway)

    result = _create_wechat_order(database_path, gateway)

    assert gateway.created == [result.order_id]
    assert gateway.queried == []
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT provider_create_attempt_count FROM payment_orders"
        ).fetchone()[0] == 1


def test_claim_survives_restart_and_only_queries_same_order(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    first_gateway = UnknownResultGateway(QueryOrderOutcome.HTTP_UNKNOWN)

    with pytest.raises(PaymentServiceError, match="payment_result_unknown"):
        _create_wechat_order(database_path, first_gateway, now=now)

    restarted_gateway = QueryOnlyGateway(QueryOrderOutcome.HTTP_UNKNOWN)
    with pytest.raises(PaymentServiceError, match="payment_result_unknown"):
        _create_wechat_order(
            database_path,
            restarted_gateway,
            now=now + timedelta(seconds=31),
        )

    assert restarted_gateway.queried == [first_gateway.created[0]]
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*), provider_create_attempt_count FROM payment_orders"
        ).fetchone()
        assert tuple(row) == (1, 1)


def test_concurrent_recovery_claims_only_one_provider_query(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    gateway = BlockingRecoveryGateway()

    with pytest.raises(PaymentServiceError, match="payment_result_unknown"):
        _create_wechat_order(database_path, gateway, now=now)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(
            _create_wechat_order,
            database_path,
            gateway,
            now=now + timedelta(seconds=31),
        )
        assert gateway.query_entered.wait(timeout=5)
        second = executor.submit(
            _create_wechat_order,
            database_path,
            gateway,
            now=now + timedelta(seconds=31),
        )
        second_result = second.result(timeout=5)
        gateway.query_release.set()
        with pytest.raises(PaymentServiceError, match="payment_result_unknown"):
            first.result(timeout=5)

    assert gateway.created == [second_result.order_id]
    assert gateway.queried == [second_result.order_id, second_result.order_id]
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT provider_create_attempt_count, provider_query_attempt_count "
            "FROM payment_orders"
        ).fetchone()
        assert tuple(row) == (1, 2)


def test_untrusted_create_response_cannot_change_trusted_business_state(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    gateway = UnknownResultGateway(
        QueryOrderOutcome.SIGNATURE_INVALID,
        create_error="PAYMENT_RESPONSE_SIGNATURE_INVALID",
    )

    with pytest.raises(PaymentServiceError, match="payment_response_signature_invalid"):
        _create_wechat_order(database_path, gateway)

    with connect(database_path) as connection:
        order = connection.execute("SELECT * FROM payment_orders").fetchone()
        assert order["status"] == OrderStatus.CREATED.value
        assert order["provider_code_url"] is None
        assert order["provider_order_id"] is None
        assert order["provider_transaction_id"] is None
        assert order["provider_create_attempt_count"] == 1
        assert order["security_error_code"] == "payment_response_signature_invalid"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == 0


def test_create_result_for_different_order_is_not_persisted(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())

    class MismatchedGateway(MockPaymentGateway):
        def create_native_order(self, request):
            return GatewayOrder(
                code_url="weixin://wxpay/untrusted",
                provider_order_id="different-order",
                provider_trade_state="NOTPAY",
            )

    with pytest.raises(PaymentServiceError, match="payment_create_order_mismatch"):
        _create_wechat_order(database_path, MismatchedGateway())

    with connect(database_path) as connection:
        order = connection.execute("SELECT * FROM payment_orders").fetchone()
        assert order["status"] == OrderStatus.CREATED.value
        assert order["provider_code_url"] is None
        assert order["provider_order_id"] is None
        assert order["provider_create_attempt_count"] == 1
        assert order["security_error_code"] == "payment_create_order_mismatch"


def test_unknown_create_result_recovers_verified_paid_query_once(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    gateway = UnknownResultGateway(QueryOrderOutcome.PAID)

    result = create_or_restore_order(
        database_path,
        device_fingerprint_hash="device-a",
        product_code=ANNUAL_V1.product_code,
        provider="wechat_native",
        ttl_minutes=15,
        gateway=gateway,
        notify_url="https://pay.example.test/wechat/notify",
        expected_appid="wx-test-app",
        expected_mchid="1900000109",
    )

    assert result.status == OrderStatus.PAID.value
    assert gateway.queried == [gateway.created_order_id]
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM payment_orders").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("out_trade_no", "different-order"),
        ("amount_total", 1),
        ("currency", "USD"),
        ("appid", "wrong-app"),
        ("mchid", "wrong-mch"),
    ),
)
def test_paid_query_conflicts_never_issue_license(tmp_path, field, value):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    gateway = UnknownResultGateway(QueryOrderOutcome.PAID, **{field: value})

    with pytest.raises(PaymentServiceError, match="payment_query_conflict"):
        create_or_restore_order(
            database_path,
            device_fingerprint_hash="device-a",
            product_code=ANNUAL_V1.product_code,
            provider="wechat_native",
            ttl_minutes=15,
            gateway=gateway,
            notify_url="https://pay.example.test/wechat/notify",
            expected_appid="wx-test-app",
            expected_mchid="1900000109",
        )

    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "ABNORMAL"


@pytest.mark.parametrize("newer_status", ("PAID", "CLOSED"))
def test_late_create_result_does_not_downgrade_terminal_order(tmp_path, newer_status):
    database_path = tmp_path / "license.sqlite3"
    _client(tmp_path)[0].post("/device/register", json=_register_payload())

    class RacingGateway(MockPaymentGateway):
        def create_native_order(self, request):
            with connect(database_path) as connection:
                connection.execute(
                    "UPDATE payment_orders SET status = ?, open_slot = NULL WHERE order_id = ?",
                    (newer_status, request.out_trade_no),
                )
                connection.commit()
            return super().create_native_order(request)

    result = create_or_restore_order(
        database_path,
        device_fingerprint_hash="device-a",
        product_code=ANNUAL_V1.product_code,
        provider="mock",
        ttl_minutes=15,
        gateway=RacingGateway(),
    )

    assert result.status == newer_status
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT status, provider_code_url FROM payment_orders"
        ).fetchone()
        assert tuple(row) == (newer_status, None)


def _mock_order(tmp_path):
    _client(tmp_path)[0].post("/device/register", json=_register_payload())
    return create_or_restore_order(
        tmp_path / "license.sqlite3",
        device_fingerprint_hash="device-a",
        product_code=ANNUAL_V1.product_code,
        provider="mock",
        ttl_minutes=15,
        gateway=MockPaymentGateway(),
    )


def _evidence(order_id: str, **overrides):
    data = {
        "source": PaymentEvidenceSource.MOCK,
        "out_trade_no": order_id,
        "provider_transaction_id": f"mock_txn_{order_id}",
        "trade_type": "NATIVE",
        "trade_state": "SUCCESS",
        "amount_fen": ANNUAL_V1.amount_fen,
        "currency": ANNUAL_V1.currency,
        "paid_at": datetime.now(timezone.utc).replace(microsecond=0),
        "appid": MOCK_APP_ID,
        "mchid": MOCK_MCH_ID,
    }
    data.update(overrides)
    return PaymentEvidence(**data)


class UnknownResultGateway:
    def __init__(
        self,
        outcome,
        *,
        create_error="PAYMENT_RESULT_UNKNOWN",
        result_unknown=True,
        **overrides,
    ):
        self.outcome = outcome
        self.create_error = create_error
        self.result_unknown = result_unknown
        self.overrides = overrides
        self.created_order_id = None
        self.created = []
        self.queried = []

    def create_native_order(self, request):
        self.created_order_id = request.out_trade_no
        self.created.append(request.out_trade_no)
        raise WechatPaymentError(
            self.create_error,
            result_unknown=self.result_unknown,
        )

    def query_order(self, order_id):
        self.queried.append(order_id)
        values = {
            "outcome": self.outcome,
            "out_trade_no": order_id,
        }
        if self.outcome is QueryOrderOutcome.PAID:
            values.update(
                transaction_id="4200000001",
                trade_state="SUCCESS",
                trade_type="NATIVE",
                amount_total=990,
                currency="CNY",
                success_time=datetime.now(timezone.utc).replace(microsecond=0),
                appid="wx-test-app",
                mchid="1900000109",
            )
        values.update(self.overrides)
        return QueryOrderResult(**values)

    def close_order(self, order_id):
        raise AssertionError("close is not expected")

    def parse_and_verify_notification(self, headers, body, *, now=None):
        raise AssertionError("notification is not expected")


class QueryOnlyGateway:
    def __init__(self, outcome):
        self.outcome = outcome
        self.queried = []

    def create_native_order(self, request):
        raise AssertionError("claimed order must never be created again")

    def query_order(self, order_id):
        self.queried.append(order_id)
        return QueryOrderResult(outcome=self.outcome, out_trade_no=order_id)

    def close_order(self, order_id):
        raise AssertionError("close is not expected")

    def parse_and_verify_notification(self, headers, body, *, now=None):
        raise AssertionError("notification is not expected")


class BlockingRecoveryGateway:
    def __init__(self):
        self.created = []
        self.queried = []
        self.query_entered = Event()
        self.query_release = Event()

    def create_native_order(self, request):
        self.created.append(request.out_trade_no)
        raise WechatPaymentError("PAYMENT_RESULT_UNKNOWN", result_unknown=True)

    def query_order(self, order_id):
        self.queried.append(order_id)
        if len(self.queried) == 2:
            self.query_entered.set()
            assert self.query_release.wait(timeout=5)
        return QueryOrderResult(
            outcome=QueryOrderOutcome.HTTP_UNKNOWN,
            out_trade_no=order_id,
        )

    def close_order(self, order_id):
        raise AssertionError("close is not expected")

    def parse_and_verify_notification(self, headers, body, *, now=None):
        raise AssertionError("notification is not expected")


def _create_wechat_order(database_path, gateway, *, now=None):
    return create_or_restore_order(
        database_path,
        device_fingerprint_hash="device-a",
        product_code=ANNUAL_V1.product_code,
        provider="wechat_native",
        ttl_minutes=15,
        gateway=gateway,
        notify_url="https://pay.example.test/wechat/notify",
        expected_appid="wx-test-app",
        expected_mchid="1900000109",
        now=now,
    )
