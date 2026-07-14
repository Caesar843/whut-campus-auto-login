import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from license_server.app import create_app
from license_server.config import WechatPayConfig
from license_server.db import connect
from license_server.payment_notification_repository import (
    PaymentNotificationRepositoryError,
)
from license_server.wechat_payment import WeChatNativePaymentGateway
from tests.license_server.test_license_server import _private_key_b64


NOTIFY_PATH = "/api/v1/payment/wechat/notify"
API_V3_KEY = b"0123456789abcdef0123456789abcdef"
PUBLIC_KEY_ID = "PUB_KEY_ID_NOTIFY_TEST"
APP_ID = "wx-notify-test"
MCH_ID = "1900000109"
BODY_LIMIT = 65536
SQLITE_INT64_MAX = (1 << 63) - 1
SENSITIVE_OPENID = "SENSITIVE_OPENID_MARKER"
SENSITIVE_BANK = "SENSITIVE_BANK_MARKER"
SENSITIVE_PROMOTION = "SENSITIVE_PROMOTION_MARKER"


@pytest.fixture
def wechat(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "merchant.pem"
    public_path = tmp_path / "wechat-public.pem"
    private_path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            Encoding.PEM,
            PublicFormat.SubjectPublicKeyInfo,
        )
    )
    config = WechatPayConfig(
        app_id=APP_ID,
        mch_id=MCH_ID,
        merchant_serial_no="MERCHANT-SERIAL",
        merchant_private_key_path=private_path,
        public_key_id=PUBLIC_KEY_ID,
        public_key_path=public_path,
        api_v3_key=API_V3_KEY,
        notify_url="https://pay.example.test/api/v1/payment/wechat/notify",
    )
    database_path = tmp_path / "license.sqlite3"
    gateway = WeChatNativePaymentGateway(
        config,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: pytest.fail("notification route made an HTTP request")
            )
        ),
    )
    app = create_app(
        database_path=database_path,
        private_key_b64=_private_key_b64(),
        payment_provider="wechat_native",
        wechat_pay_config=config,
        payment_gateway=gateway,
    )
    return SimpleNamespace(
        client=TestClient(app),
        database_path=database_path,
        private_key=private_key,
        config=config,
    )


def test_valid_notification_is_minimized_without_changing_business_state(wechat):
    _insert_waiting_order(wechat.database_path)
    body = _notification_body()

    response = _post(wechat, body)

    assert response.status_code == 204
    assert response.content == b""
    with connect(wechat.database_path) as connection:
        row = connection.execute("SELECT * FROM payment_notifications").fetchone()
        assert row is not None
        assert row["provider_notification_id"] == "notice-route-1"
        assert row["order_id"] == "order-route-1"
        assert row["provider"] == "wechat_native"
        assert row["payload_digest_sha256"] == hashlib.sha256(body).hexdigest()
        assert row["signature_valid"] == 1
        assert row["merchant_identity_valid"] == 1
        assert row["process_status"] == "RECEIVED"
        assert row["attempt_count"] == 0
        assert row["worker_id"] is None
        assert row["claim_token"] is None
        assert row["processing_started_at"] is None
        assert row["lease_expires_at"] is None
        assert row["processed_at"] is None
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = 'order-route-1'"
        ).fetchone()[0] == "WAITING_PAYMENT"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0] == 0
        columns = {
            item["name"]
            for item in connection.execute("PRAGMA table_xinfo(payment_notifications)")
        }
        assert columns.isdisjoint(
            {"raw_body", "decrypted_body", "openid", "bank_type", "signature", "nonce"}
        )
        rendered = repr(dict(row))
        assert SENSITIVE_OPENID not in rendered
        assert SENSITIVE_BANK not in rendered
        assert SENSITIVE_PROMOTION not in rendered


def test_notification_route_is_absent_for_disabled_and_mock_providers(tmp_path):
    disabled = TestClient(
        create_app(
            database_path=tmp_path / "disabled.sqlite3",
            private_key_b64=_private_key_b64(),
        )
    )
    mock = TestClient(
        create_app(
            database_path=tmp_path / "mock.sqlite3",
            private_key_b64=_private_key_b64(),
            payment_provider="mock",
            payment_mock_admin_token="mockR4ndomValue123456",
        )
    )

    assert disabled.post(NOTIFY_PATH).status_code == 404
    assert mock.post(NOTIFY_PATH).status_code == 404


@pytest.mark.parametrize(
    "header",
    (
        "Wechatpay-Serial",
        "Wechatpay-Signature",
        "Wechatpay-Timestamp",
        "Wechatpay-Nonce",
    ),
)
@pytest.mark.parametrize("mode", ("missing", "empty"))
def test_notification_rejects_missing_or_empty_signature_headers(wechat, header, mode):
    body = _notification_body()
    headers = _signed_headers(wechat.private_key, body)
    if mode == "missing":
        headers.pop(header)
    else:
        headers[header] = ""

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(response, 401, "PAYMENT_NOTIFY_HEADERS_INVALID")
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize(
    "timestamp",
    (
        "not-an-int",
        str(10**1000),
        pytest.param("9" * 4300, id="4300-digits"),
        pytest.param("9" * 4301, id="4301-digits"),
        pytest.param("9" * 5000, id="5000-digits"),
    ),
)
def test_notification_rejects_invalid_timestamp(wechat, timestamp):
    body = _notification_body()
    headers = _signed_headers(wechat.private_key, body, timestamp=timestamp)

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(response, 401, "PAYMENT_NOTIFY_TIMESTAMP_INVALID")
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize("offset", (-301, 301))
def test_notification_rejects_stale_and_future_timestamp(wechat, offset):
    body = _notification_body()
    timestamp = int((datetime.now(timezone.utc) + timedelta(seconds=offset)).timestamp())
    headers = _signed_headers(wechat.private_key, body, timestamp=str(timestamp))

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(response, 401, "PAYMENT_NOTIFY_TIMESTAMP_INVALID")


@pytest.mark.parametrize("failure", ("serial", "signature", "body"))
def test_notification_rejects_untrusted_signature_evidence(wechat, failure):
    body = _notification_body()
    headers = _signed_headers(wechat.private_key, body)
    if failure == "serial":
        headers["Wechatpay-Serial"] = "OTHER_KEY"
    elif failure == "signature":
        headers["Wechatpay-Signature"] = base64.b64encode(b"invalid").decode()
    else:
        body += b" "

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(response, 401, "PAYMENT_NOTIFY_SIGN_INVALID")
    _assert_no_notifications(wechat.database_path)


def test_notification_headers_are_case_insensitive(wechat):
    body = _notification_body()
    headers = {
        key.lower(): value
        for key, value in _signed_headers(wechat.private_key, body).items()
    }

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    assert response.status_code == 204


@pytest.mark.parametrize(
    ("header", "invalid_value"),
    (
        ("Wechatpay-Serial", "OTHER_KEY"),
        ("Wechatpay-Signature", base64.b64encode(b"invalid").decode()),
        ("Wechatpay-Timestamp", "0"),
        ("Wechatpay-Nonce", "invalid-nonce"),
    ),
)
@pytest.mark.parametrize(
    "mode",
    ("invalid_valid", "valid_invalid", "same", "mixed_case"),
)
def test_notification_rejects_duplicate_signature_headers(
    wechat,
    header,
    invalid_value,
    mode,
):
    body = _notification_body()
    valid_headers = _signed_headers(wechat.private_key, body)
    valid_value = valid_headers.pop(header)
    if mode == "invalid_valid":
        duplicate_values = ((header, invalid_value), (header, valid_value))
    elif mode == "valid_invalid":
        duplicate_values = ((header, valid_value), (header, invalid_value))
    elif mode == "same":
        duplicate_values = ((header, valid_value), (header, valid_value))
    else:
        duplicate_values = ((header, valid_value), (header.swapcase(), valid_value))
    headers = [*valid_headers.items(), *duplicate_values]

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(response, 401, "PAYMENT_NOTIFY_HEADERS_INVALID")
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize(
    "content_length",
    ("invalid", "-1", "+65536", "1.0", "1e3", "65536,65536"),
)
def test_notification_rejects_invalid_content_length(wechat, content_length):
    response = wechat.client.post(
        NOTIFY_PATH,
        content=b"{}",
        headers={"Content-Length": content_length},
    )

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")


def test_notification_rejects_unicode_decimal_content_length(wechat):
    response = wechat.client.post(
        NOTIFY_PATH,
        content=b"",
        headers=[(b"content-length", "１２".encode("utf-8"))],
    )

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize("length", (4300, 4301, 5000))
def test_notification_rejects_oversized_decimal_content_length(wechat, length):
    response = wechat.client.post(
        NOTIFY_PATH,
        content=b"",
        headers={"Content-Length": "9" * length},
    )

    _assert_error(response, 413, "PAYMENT_NOTIFY_BODY_TOO_LARGE")
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize(
    "values",
    (("2", "2"), ("2", "3"), ("2", str(BODY_LIMIT + 1))),
)
@pytest.mark.parametrize("mixed_case", (False, True))
def test_notification_rejects_duplicate_content_length(wechat, values, mixed_case):
    names = ("Content-Length", "content-length" if mixed_case else "Content-Length")
    response = wechat.client.post(
        NOTIFY_PATH,
        content=b"{}",
        headers=list(zip(names, values)),
    )

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize(
    ("content_length", "body_size", "expected_status"),
    (
        ("0" * 5000 + str(BODY_LIMIT), BODY_LIMIT, 400),
        ("0" * 5000 + str(BODY_LIMIT + 1), 0, 413),
    ),
)
def test_notification_handles_long_zero_padded_content_length(
    wechat,
    content_length,
    body_size,
    expected_status,
):
    body = b"x" * body_size
    headers = _signed_headers(wechat.private_key, body)
    headers["Content-Length"] = content_length

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    assert response.status_code == expected_status
    assert response.status_code != 500
    _assert_no_notifications(wechat.database_path)


def test_invalid_numeric_headers_are_not_returned_or_logged(wechat, caplog):
    marker = "SENSITIVE_NUMERIC_HEADER_MARKER"
    content_length_response = wechat.client.post(
        NOTIFY_PATH,
        content=b"",
        headers={"Content-Length": marker},
    )
    body = _notification_body()
    headers = _signed_headers(wechat.private_key, body)
    headers["Wechatpay-Timestamp"] = marker
    timestamp_response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(content_length_response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")
    _assert_error(timestamp_response, 401, "PAYMENT_NOTIFY_TIMESTAMP_INVALID")
    assert marker not in content_length_response.text
    assert marker not in timestamp_response.text
    assert marker not in caplog.text
    _assert_no_notifications(wechat.database_path)


def test_notification_rejects_declared_and_actual_oversize_bodies(wechat, caplog):
    declared = wechat.client.post(
        NOTIFY_PATH,
        content=b"",
        headers={"Content-Length": str(BODY_LIMIT + 1)},
    )
    marker = b"SENSITIVE_OVERSIZE_MARKER"
    actual_body = marker + b"x" * (BODY_LIMIT + 1 - len(marker))
    actual = wechat.client.post(
        NOTIFY_PATH,
        content=actual_body,
        headers={"Content-Length": "1"},
    )

    _assert_error(declared, 413, "PAYMENT_NOTIFY_BODY_TOO_LARGE")
    _assert_error(actual, 413, "PAYMENT_NOTIFY_BODY_TOO_LARGE")
    assert marker.decode() not in caplog.text


def test_notification_exact_body_limit_is_not_reported_as_oversize(wechat):
    body = b"x" * BODY_LIMIT
    headers = _signed_headers(wechat.private_key, body)

    response = wechat.client.post(NOTIFY_PATH, content=body, headers=headers)

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")


def test_notification_streams_when_content_length_is_missing(wechat):
    body = _notification_body()
    request = wechat.client.build_request(
        "POST",
        NOTIFY_PATH,
        content=body,
        headers=_signed_headers(wechat.private_key, body),
    )
    del request.headers["content-length"]

    response = wechat.client.send(request)

    assert response.status_code == 204


@pytest.mark.parametrize(
    ("body", "code"),
    (
        (b"not-json", "PAYMENT_NOTIFY_SCHEMA_INVALID"),
        (b"[]", "PAYMENT_NOTIFY_SCHEMA_INVALID"),
        (lambda: _notification_body(outer_overrides={"id": None}), "PAYMENT_NOTIFY_SCHEMA_INVALID"),
        (
            lambda: _notification_body(
                outer_overrides={"event_type": "TRANSACTION.CLOSED"}
            ),
            "PAYMENT_NOTIFY_SCHEMA_INVALID",
        ),
        (
            lambda: _notification_body(
                outer_overrides={"resource_type": "plaintext"}
            ),
            "PAYMENT_NOTIFY_SCHEMA_INVALID",
        ),
        (
            lambda: _notification_body(outer_overrides={"resource": None}),
            "PAYMENT_NOTIFY_SCHEMA_INVALID",
        ),
        (
            lambda: _notification_body(
                resource_overrides={"algorithm": "AEAD_AES_128_GCM"}
            ),
            "PAYMENT_NOTIFY_SCHEMA_INVALID",
        ),
        (
            lambda: _notification_body(resource_overrides={"nonce": None}),
            "PAYMENT_NOTIFY_DECRYPT_FAILED",
        ),
        (
            lambda: _notification_body(
                resource_overrides={"associated_data": None}
            ),
            "PAYMENT_NOTIFY_DECRYPT_FAILED",
        ),
        (
            lambda: _notification_body(resource_overrides={"ciphertext": None}),
            "PAYMENT_NOTIFY_DECRYPT_FAILED",
        ),
        (
            lambda: _notification_body(
                resource_overrides={"ciphertext": "not-base64***"}
            ),
            "PAYMENT_NOTIFY_DECRYPT_FAILED",
        ),
    ),
)
def test_notification_rejects_invalid_outer_structure(wechat, body, code):
    body = body() if callable(body) else body
    response = _post(wechat, body)

    _assert_error(response, 400, code)
    _assert_no_notifications(wechat.database_path)


@pytest.mark.parametrize("plaintext", (b"\xff", b"not-json", b"[]"))
def test_notification_rejects_invalid_decrypted_payload(wechat, plaintext):
    body = _notification_body(plaintext=plaintext)

    response = _post(wechat, body)

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")


def test_notification_rejects_invalid_gcm_tag(wechat):
    body = _notification_body(tamper_ciphertext=True)

    response = _post(wechat, body)

    _assert_error(response, 400, "PAYMENT_NOTIFY_DECRYPT_FAILED")


@pytest.mark.parametrize(
    "transaction_overrides",
    (
        {"appid": None},
        {"mchid": None},
        {"out_trade_no": None},
        {"transaction_id": None},
        {"trade_type": "JSAPI"},
        {"trade_state": "NOTPAY"},
        {"amount": {"total": True, "currency": "CNY"}},
        {"amount": {"total": "990", "currency": "CNY"}},
        {"amount": {"total": 990.0, "currency": "CNY"}},
        {"amount": {"total": 0, "currency": "CNY"}},
        {"amount": {"total": -1, "currency": "CNY"}},
        {"amount": {"total": 1 << 63, "currency": "CNY"}},
        {"amount": {"total": (1 << 63) + 1, "currency": "CNY"}},
        {"amount": {"total": 10**100, "currency": "CNY"}},
        {"amount": {"total": 990, "currency": 1}},
        {"success_time": "not-a-time"},
    ),
)
def test_notification_rejects_invalid_transaction_schema(wechat, transaction_overrides):
    body = _notification_body(transaction_overrides=transaction_overrides)

    response = _post(wechat, body)

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")
    _assert_no_notifications(wechat.database_path)


def test_notification_accepts_sqlite_int64_max_without_business_side_effects(wechat):
    _insert_waiting_order(wechat.database_path)
    body = _notification_body(
        transaction_overrides={
            "amount": {"total": SQLITE_INT64_MAX, "currency": "CNY"}
        }
    )

    response = _post(wechat, body)

    assert response.status_code == 204
    assert response.content == b""
    with connect(wechat.database_path) as connection:
        assert connection.execute(
            "SELECT reported_amount_fen FROM payment_notifications"
        ).fetchone()[0] == SQLITE_INT64_MAX
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = 'order-route-1'"
        ).fetchone()[0] == "WAITING_PAYMENT"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0] == 0


def test_notification_rejects_amount_above_sqlite_int64_without_business_side_effects(
    wechat,
):
    _insert_waiting_order(wechat.database_path)
    body = _notification_body(
        transaction_overrides={
            "amount": {"total": SQLITE_INT64_MAX + 1, "currency": "CNY"}
        }
    )

    response = _post(wechat, body)

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")
    _assert_no_notifications(wechat.database_path)
    with connect(wechat.database_path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = 'order-route-1'"
        ).fetchone()[0] == "WAITING_PAYMENT"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0] == 0


def test_notification_rejects_invalid_provider_create_time(wechat):
    body = _notification_body(outer_overrides={"create_time": "not-a-time"})

    response = _post(wechat, body)

    _assert_error(response, 400, "PAYMENT_NOTIFY_SCHEMA_INVALID")


@pytest.mark.parametrize(
    "transaction_overrides",
    (
        {"appid": "wrong-app"},
        {"mchid": "wrong-merchant"},
        {"appid": "wrong-app", "mchid": "wrong-merchant"},
    ),
)
def test_notification_rejects_merchant_mismatch_without_leaking_values(
    wechat,
    transaction_overrides,
):
    body = _notification_body(transaction_overrides=transaction_overrides)

    response = _post(wechat, body)

    _assert_error(response, 400, "PAYMENT_NOTIFY_MERCHANT_MISMATCH")
    assert APP_ID not in response.text
    assert MCH_ID not in response.text
    assert "wrong-app" not in response.text
    assert "wrong-merchant" not in response.text
    _assert_no_notifications(wechat.database_path)


def test_notification_same_digest_is_idempotent_without_resetting_state(wechat):
    body = _notification_body()

    first = _post(wechat, body)
    with connect(wechat.database_path) as connection:
        connection.execute(
            "UPDATE payment_notifications SET process_status = 'RETRY', "
            "failure_code = 'TEMPORARY_DATABASE_ERROR', next_attempt_at = ?, "
            "attempt_count = 1 WHERE provider_notification_id = 'notice-route-1'",
            ("2099-01-01T00:00:00Z",),
        )
        connection.commit()
    second = _post(wechat, body)

    assert first.status_code == second.status_code == 204
    with connect(wechat.database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*), process_status, attempt_count, failure_code "
            "FROM payment_notifications"
        ).fetchone()
        assert tuple(row) == (1, "RETRY", 1, "TEMPORARY_DATABASE_ERROR")


def test_notification_digest_conflict_returns_204_without_overwrite(
    wechat,
    caplog,
):
    first_body = _notification_body()
    second_body = _notification_body(
        transaction_overrides={
            "transaction_id": "transaction-conflict-secret",
            "amount": {"total": 991, "currency": "CNY"},
        }
    )

    with caplog.at_level("WARNING"):
        first = _post(wechat, first_body)
        second = _post(wechat, second_body)

    assert first.status_code == second.status_code == 204
    assert "payment_notification_digest_conflict" in caplog.text
    assert "notice-route-1" not in caplog.text
    assert "order-route-1" not in caplog.text
    assert "transaction-conflict-secret" not in caplog.text
    assert hashlib.sha256(first_body).hexdigest() not in caplog.text
    assert hashlib.sha256(second_body).hexdigest() not in caplog.text
    with connect(wechat.database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*), provider_transaction_id, reported_amount_fen, "
            "payload_digest_sha256 FROM payment_notifications"
        ).fetchone()
        assert tuple(row) == (
            1,
            "transaction-route-1",
            990,
            hashlib.sha256(first_body).hexdigest(),
        )


def test_notification_database_failure_returns_safe_500(wechat, monkeypatch):
    def fail_insert(_database_path, _notification):
        raise PaymentNotificationRepositoryError("sensitive sqlite detail")

    monkeypatch.setattr(
        "license_server.payment_notification_routes.insert_received_notification",
        fail_insert,
    )

    response = _post(wechat, _notification_body())

    _assert_error(response, 500, "PAYMENT_NOTIFICATION_PERSIST_FAILED")
    assert "sqlite" not in response.text.lower()
    with connect(wechat.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0] == 0


def _post(wechat, body, *, headers=None):
    return wechat.client.post(
        NOTIFY_PATH,
        content=body,
        headers=headers or _signed_headers(wechat.private_key, body),
    )


def _signed_headers(private_key, body, *, timestamp=None):
    timestamp = str(
        int(datetime.now(timezone.utc).timestamp()) if timestamp is None else timestamp
    )
    nonce = "SENSITIVE_NONCE_MARKER"
    message = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body + b"\n"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return {
        "Wechatpay-Timestamp": timestamp,
        "Wechatpay-Nonce": nonce,
        "Wechatpay-Signature": base64.b64encode(signature).decode(),
        "Wechatpay-Serial": PUBLIC_KEY_ID,
    }


def _notification_body(
    *,
    outer_overrides=None,
    resource_overrides=None,
    transaction_overrides=None,
    plaintext=None,
    tamper_ciphertext=False,
):
    transaction = {
        "appid": APP_ID,
        "mchid": MCH_ID,
        "out_trade_no": "order-route-1",
        "transaction_id": "transaction-route-1",
        "trade_type": "NATIVE",
        "trade_state": "SUCCESS",
        "success_time": "2026-07-13T12:00:00+08:00",
        "amount": {"total": 990, "currency": "CNY"},
        "payer": {"openid": SENSITIVE_OPENID},
        "bank_type": SENSITIVE_BANK,
        "promotion_detail": [{"name": SENSITIVE_PROMOTION}],
        "attach": "not-persisted",
    }
    _apply_overrides(transaction, transaction_overrides)
    plaintext = (
        json.dumps(transaction, separators=(",", ":")).encode()
        if plaintext is None
        else plaintext
    )
    nonce = "abcdefghijkl"
    associated_data = "transaction"
    ciphertext = bytearray(
        AESGCM(API_V3_KEY).encrypt(
            nonce.encode(),
            plaintext,
            associated_data.encode(),
        )
    )
    if tamper_ciphertext:
        ciphertext[-1] ^= 1
    resource = {
        "algorithm": "AEAD_AES_256_GCM",
        "nonce": nonce,
        "associated_data": associated_data,
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    _apply_overrides(resource, resource_overrides)
    outer = {
        "id": "notice-route-1",
        "event_type": "TRANSACTION.SUCCESS",
        "resource_type": "encrypt-resource",
        "create_time": "2026-07-13T12:00:00+08:00",
        "resource": resource,
        "summary": "sensitive summary not persisted",
    }
    _apply_overrides(outer, outer_overrides)
    return json.dumps(outer, separators=(",", ":")).encode()


def _apply_overrides(values, overrides):
    for key, value in (overrides or {}).items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value


def _insert_waiting_order(database_path):
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at
            ) VALUES (
                'order-route-1', 'device-route-1', 'annual_v1', 990,
                'CNY', 'wechat_native', 'WAITING_PAYMENT', 'open',
                '2026-07-13T04:00:00Z', '2026-07-13T04:00:00Z',
                '2026-07-13T04:15:00Z'
            )
            """
        )
        connection.commit()


def _assert_error(response, status_code, code):
    assert response.status_code == status_code
    assert response.json() == {"detail": code}


def _assert_no_notifications(database_path):
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM payment_notifications").fetchone()[0] == 0
