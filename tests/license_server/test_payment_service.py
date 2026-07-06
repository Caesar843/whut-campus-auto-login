from datetime import datetime, timedelta, timezone

import pytest

from license_server.db import connect
from license_server.payment import ANNUAL_V1, OrderStatus, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_gateway import MOCK_APP_ID, MOCK_MCH_ID, MockPaymentGateway
from license_server.payment_service import (
    PaymentServiceError,
    confirm_paid_order,
    create_or_restore_order,
)
from license_server.signer import datetime_text
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
