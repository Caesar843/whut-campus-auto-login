import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from license_server.wechat_payment import (
    WechatPaymentError,
    build_authorization_header,
    canonical_request_message,
    decrypt_notification_resource,
    parse_and_verify_notification,
    sign_request,
    verify_response_signature,
)


API_V3_KEY = b"0123456789abcdef0123456789abcdef"
PUBLIC_KEY_ID = "PUB_KEY_ID_TEST"
NOTIFICATION_NONCE = "abcdefghijkl"
NOTIFICATION_AAD = "transaction"
TRANSACTION_PLAINTEXT = (
    b'{"appid":"wx-test","mchid":"1900000109",'
    b'"out_trade_no":"pay_test","transaction_id":"4200000001",'
    b'"trade_type":"NATIVE","trade_state":"SUCCESS",'
    b'"success_time":"2026-07-13T12:00:00+08:00",'
    b'"amount":{"total":990,"currency":"CNY"}}'
)
TRANSACTION_CIPHERTEXT = (
    "Eu6oz7uMCfFZPoVpJ+09TCgTlz3U4wcyepwEvuNl/tpc+JDNHm3Qj2gV5dRR5/"
    "W8+jDj2tR8TNmunjYS2Mj7Me7fq7mIkQg+ZDp3AUYGu1Se19FWnK0XOeFhQOIRj"
    "lgZk/uB253NFXrZvw29QJIu7l/zqhsJflMOjUXzNuc/OWulfRQ3K6w7940n1Fnc"
    "Kfqb4ZdEmbmzAmKtmr3zkMUoSsrJELYxktzkvnonekSGrAWJaSE8qK7lihDB0L6E"
    "Isn73ywDVvFoGMwi35fIBxvalv1WTKiVsPEcQLA76pmTyC6m00CV62sOcqRJOpoL"
    "Cdrefw=="
)


@pytest.fixture(scope="module")
def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_request_canonical_message_and_authorization_are_verifiable(rsa_private_key):
    body = '{"description":"武汉理工校园网"}'.encode("utf-8")
    message = canonical_request_message(
        "POST",
        "/v3/pay/transactions/native?test=1",
        1783905600,
        "fixed-nonce",
        body,
    )

    assert message == (
        b"POST\n/v3/pay/transactions/native?test=1\n1783905600\n"
        b"fixed-nonce\n" + body + b"\n"
    )
    signature = sign_request(rsa_private_key, message)
    rsa_private_key.public_key().verify(
        base64.b64decode(signature, validate=True),
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    authorization = build_authorization_header(
        mchid="1900000109",
        serial_no="MERCHANT-SERIAL",
        nonce="fixed-nonce",
        timestamp=1783905600,
        signature=signature,
    )
    assert authorization.startswith("WECHATPAY2-SHA256-RSA2048 ")
    for field in ("mchid", "nonce_str", "timestamp", "serial_no", "signature"):
        assert f'{field}="' in authorization


def test_response_signature_uses_original_body_bytes(rsa_private_key):
    body = b'{"b":2,"a":1}'
    headers = _signed_headers(rsa_private_key, body)

    verify_response_signature(
        headers,
        body,
        public_key_id=PUBLIC_KEY_ID,
        public_key=rsa_private_key.public_key(),
    )
    with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_SIGNATURE_INVALID"):
        verify_response_signature(
            headers,
            b'{"a":1,"b":2}',
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
        )


@pytest.mark.parametrize("changed", ("timestamp", "nonce", "signature"))
def test_response_signature_rejects_tampered_headers(rsa_private_key, changed):
    body = b"{}"
    headers = _signed_headers(rsa_private_key, body)
    if changed == "signature":
        headers["Wechatpay-Signature"] = base64.b64encode(b"invalid").decode()
    else:
        header = f"Wechatpay-{changed.title()}"
        headers[header] += "x"

    with pytest.raises(WechatPaymentError, match="PAYMENT_RESPONSE_SIGNATURE_INVALID"):
        verify_response_signature(
            headers,
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
        )


def test_response_signature_rejects_bad_base64_serial_and_missing_header(rsa_private_key):
    body = b"{}"
    headers = _signed_headers(rsa_private_key, body)
    cases = []
    bad_base64 = dict(headers)
    bad_base64["Wechatpay-Signature"] = "***not-base64***"
    cases.append((bad_base64, "PAYMENT_RESPONSE_SIGNATURE_INVALID"))
    bad_serial = dict(headers)
    bad_serial["Wechatpay-Serial"] = "OTHER_KEY"
    cases.append((bad_serial, "PAYMENT_RESPONSE_KEY_ID_MISMATCH"))
    missing = dict(headers)
    missing.pop("Wechatpay-Nonce")
    cases.append((missing, "PAYMENT_RESPONSE_SIGNATURE_MISSING"))

    for candidate, code in cases:
        with pytest.raises(WechatPaymentError, match=code):
            verify_response_signature(
                candidate,
                body,
                public_key_id=PUBLIC_KEY_ID,
                public_key=rsa_private_key.public_key(),
            )


def test_known_aes_gcm_vector_decrypts_to_transaction_whitelist_source():
    result = decrypt_notification_resource(
        {
            "algorithm": "AEAD_AES_256_GCM",
            "nonce": NOTIFICATION_NONCE,
            "associated_data": NOTIFICATION_AAD,
            "ciphertext": TRANSACTION_CIPHERTEXT,
        },
        API_V3_KEY,
    )

    assert result == json.loads(TRANSACTION_PLAINTEXT)


@pytest.mark.parametrize("field", ("associated_data", "nonce", "ciphertext"))
def test_aes_gcm_rejects_tampering_without_leaking_sensitive_data(field):
    resource = {
        "algorithm": "AEAD_AES_256_GCM",
        "nonce": NOTIFICATION_NONCE,
        "associated_data": NOTIFICATION_AAD,
        "ciphertext": TRANSACTION_CIPHERTEXT,
    }
    resource[field] = resource[field] + "x"

    with pytest.raises(WechatPaymentError) as exc_info:
        decrypt_notification_resource(resource, API_V3_KEY)

    rendered = str(exc_info.value)
    assert rendered == "PAYMENT_NOTIFY_DECRYPT_FAILED"
    assert TRANSACTION_CIPHERTEXT not in rendered
    assert API_V3_KEY.decode() not in rendered


@pytest.mark.parametrize("plaintext", (b"\xff", b"not-json", b"[]"))
def test_notification_plaintext_must_be_utf8_json_object(plaintext):
    resource = _resource_for_plaintext(plaintext)

    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_PAYLOAD_INVALID"):
        decrypt_notification_resource(resource, API_V3_KEY)


def test_notification_signature_timestamp_and_whitelist_extraction(rsa_private_key):
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    outer = {
        "id": "notice-1",
        "event_type": "TRANSACTION.SUCCESS",
        "resource_type": "encrypt-resource",
        "create_time": "2026-07-13T12:00:00+08:00",
        "resource": {
            "algorithm": "AEAD_AES_256_GCM",
            "nonce": NOTIFICATION_NONCE,
            "associated_data": NOTIFICATION_AAD,
            "ciphertext": TRANSACTION_CIPHERTEXT,
        },
    }
    body = json.dumps(outer, separators=(",", ":")).encode()
    headers = _signed_headers(
        rsa_private_key,
        body,
        timestamp=int(now.timestamp()),
    )

    notification = parse_and_verify_notification(
        headers,
        body,
        public_key_id=PUBLIC_KEY_ID,
        public_key=rsa_private_key.public_key(),
        api_v3_key=API_V3_KEY,
        now=now,
    )

    assert notification.notification_id == "notice-1"
    assert notification.out_trade_no == "pay_test"
    assert notification.amount_total == 990
    assert not hasattr(notification, "openid")
    assert not hasattr(notification, "raw_body")

    stale_headers = _signed_headers(
        rsa_private_key,
        body,
        timestamp=int((now - timedelta(minutes=6)).timestamp()),
    )
    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_TIMESTAMP_INVALID"):
        parse_and_verify_notification(
            stale_headers,
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
            api_v3_key=API_V3_KEY,
            now=now,
        )


def test_notification_rejects_stale_timestamp_before_rsa_verification(rsa_private_key):
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    body = _notification_body()
    headers = _signed_headers(
        rsa_private_key,
        body,
        timestamp=int((now - timedelta(seconds=301)).timestamp()),
    )
    headers["Wechatpay-Signature"] = base64.b64encode(b"invalid").decode()

    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_TIMESTAMP_INVALID"):
        parse_and_verify_notification(
            headers,
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
            api_v3_key=API_V3_KEY,
            now=now,
        )


@pytest.mark.parametrize(
    "timestamp",
    (
        "9" * 4300,
        "9" * 4301,
        "9" * 5000,
        "１２３",
        "+123",
        "-1",
        "1.0",
        "1e3",
        "1 2",
        "99999999999999999999",
    ),
)
def test_notification_rejects_invalid_timestamp_before_rsa_verification(
    rsa_private_key,
    monkeypatch,
    timestamp,
):
    body = _notification_body()
    headers = _signed_headers(rsa_private_key, body)
    headers["Wechatpay-Timestamp"] = timestamp

    def fail_verify(*_args, **_kwargs):
        pytest.fail("RSA verification should not run for an invalid timestamp")

    monkeypatch.setattr(
        "license_server.wechat_payment.verify_response_signature",
        fail_verify,
    )

    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_TIMESTAMP_INVALID"):
        parse_and_verify_notification(
            headers,
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
            api_v3_key=API_V3_KEY,
        )


@pytest.mark.parametrize(
    "outer_overrides",
    (
        {"event_type": "TRANSACTION.CLOSED"},
        {"resource_type": "plaintext-resource"},
        {"resource_type": None},
        {"resource": {"algorithm": "AEAD_AES_128_GCM"}},
    ),
)
def test_notification_requires_success_encrypted_resource(
    rsa_private_key,
    outer_overrides,
):
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    body = _notification_body(outer_overrides=outer_overrides)

    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_PAYLOAD_INVALID"):
        parse_and_verify_notification(
            _signed_headers(rsa_private_key, body, timestamp=int(now.timestamp())),
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
            api_v3_key=API_V3_KEY,
            now=now,
        )


@pytest.mark.parametrize(
    "transaction_overrides",
    (
        {"trade_type": "JSAPI"},
        {"trade_state": "NOTPAY"},
        {"transaction_id": ""},
        {"out_trade_no": ""},
        {"appid": ""},
        {"mchid": ""},
        {"amount": {"total": True, "currency": "CNY"}},
        {"amount": {"total": "990", "currency": "CNY"}},
        {"amount": {"total": 990.0, "currency": "CNY"}},
        {"amount": {"total": 0, "currency": "CNY"}},
        {"amount": {"total": -1, "currency": "CNY"}},
        {"amount": {"total": 990, "currency": 1}},
        {"amount": {"total": 990, "currency": ""}},
        {"success_time": "not-a-time"},
    ),
)
def test_notification_requires_strict_success_transaction_fields(
    rsa_private_key,
    transaction_overrides,
):
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    body = _notification_body(transaction_overrides=transaction_overrides)

    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_PAYLOAD_INVALID"):
        parse_and_verify_notification(
            _signed_headers(rsa_private_key, body, timestamp=int(now.timestamp())),
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
            api_v3_key=API_V3_KEY,
            now=now,
        )


def test_notification_requires_valid_provider_create_time(rsa_private_key):
    now = datetime(2026, 7, 13, 4, 0, tzinfo=timezone.utc)
    body = _notification_body(outer_overrides={"create_time": "not-a-time"})

    with pytest.raises(WechatPaymentError, match="PAYMENT_NOTIFY_PAYLOAD_INVALID"):
        parse_and_verify_notification(
            _signed_headers(rsa_private_key, body, timestamp=int(now.timestamp())),
            body,
            public_key_id=PUBLIC_KEY_ID,
            public_key=rsa_private_key.public_key(),
            api_v3_key=API_V3_KEY,
            now=now,
        )


def _signed_headers(private_key, body: bytes, *, timestamp: int = 1783905600):
    nonce = "response-nonce"
    message = f"{timestamp}\n{nonce}\n".encode() + body + b"\n"
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return {
        "Wechatpay-Timestamp": str(timestamp),
        "Wechatpay-Nonce": nonce,
        "Wechatpay-Signature": base64.b64encode(signature).decode(),
        "Wechatpay-Serial": PUBLIC_KEY_ID,
    }


def _resource_for_plaintext(plaintext: bytes) -> dict[str, str]:
    encrypted = AESGCM(API_V3_KEY).encrypt(
        NOTIFICATION_NONCE.encode(),
        plaintext,
        NOTIFICATION_AAD.encode(),
    )
    return {
        "algorithm": "AEAD_AES_256_GCM",
        "nonce": NOTIFICATION_NONCE,
        "associated_data": NOTIFICATION_AAD,
        "ciphertext": base64.b64encode(encrypted).decode(),
    }


def _notification_body(*, outer_overrides=None, transaction_overrides=None) -> bytes:
    transaction = {
        "appid": "wx-test",
        "mchid": "1900000109",
        "out_trade_no": "pay_test",
        "transaction_id": "4200000001",
        "trade_type": "NATIVE",
        "trade_state": "SUCCESS",
        "success_time": "2026-07-13T12:00:00+08:00",
        "amount": {"total": 990, "currency": "CNY"},
    }
    transaction.update(transaction_overrides or {})
    outer = {
        "id": "notice-1",
        "event_type": "TRANSACTION.SUCCESS",
        "resource_type": "encrypt-resource",
        "create_time": "2026-07-13T12:00:00+08:00",
        "resource": _resource_for_plaintext(
            json.dumps(transaction, separators=(",", ":")).encode()
        ),
    }
    for key, value in (outer_overrides or {}).items():
        if key == "resource" and isinstance(value, dict):
            outer["resource"].update(value)
        elif value is None:
            outer.pop(key, None)
        else:
            outer[key] = value
    return json.dumps(outer, separators=(",", ":")).encode()
