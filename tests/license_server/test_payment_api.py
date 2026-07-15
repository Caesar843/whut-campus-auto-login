import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event

import pytest

import license_server.payment_routes as payment_routes
from license_server.db import connect
from license_server.config import WechatPayConfig
from license_server.payment_gateway import MockPaymentGateway
from license_server.payment_reconciliation_repository import (
    ClaimOrderOutcome,
    ClaimOrderResult,
    EnsureReadyOutcome,
    EnsureReadyResult,
    PaymentReconciliationRepositoryError,
    claim_order,
    ensure_ready,
    terminate_claim,
)
from license_server.payment_reconciliation_service import (
    PaymentReconciliationService,
    ReconciliationOutcome,
    ReconciliationResult,
)
from license_server.signer import datetime_text
from tests.license_server.test_license_server import _client, _register_payload


MOCK_TOKEN = "mockR4ndomValue123456"


def test_create_order_uses_bearer_token_and_returns_mock_code_url(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["product_code"] == "annual_v1"
    assert payload["amount_fen"] == 990
    assert payload["currency"] == "CNY"
    assert payload["provider"] == "mock"
    assert payload["status"] == "WAITING_PAYMENT"
    assert payload["code_url"] == f"mock://whut-payment/{payload['order_id']}"
    assert "device_fingerprint_hash" not in payload
    assert "id" not in payload


def test_create_order_rejects_client_controlled_amount(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1", "amount_fen": 1},
    )

    assert response.status_code == 422


def test_create_order_requires_configured_provider(tmp_path):
    client, _public_key = _client(tmp_path)
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "payment_provider_not_configured"


def test_query_order_requires_configured_provider(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.get("/api/v1/payment/orders/missing")

    assert response.status_code == 503
    assert response.json()["detail"] == "payment_provider_not_configured"


def test_wechat_provider_uses_injected_gateway_and_notify_url(tmp_path):
    gateway = CapturingGateway()
    config = WechatPayConfig(
        app_id="wx-test-app",
        mch_id="1900000109",
        merchant_serial_no="merchant-serial",
        merchant_private_key_path=Path("unused-merchant-key.pem"),
        public_key_id="wechat-public-key-id",
        public_key_path=Path("unused-wechat-key.pem"),
        api_v3_key=b"a" * 32,
        notify_url="https://pay.example.test/wechat/notify",
    )
    client, _public_key = _client(
        tmp_path,
        payment_provider="wechat_native",
        wechat_pay_config=config,
        payment_gateway=gateway,
    )
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 200
    assert response.json()["provider"] == "wechat_native"
    assert response.json()["code_url"].startswith("mock://whut-payment/")
    assert gateway.request.notify_url == config.notify_url


def test_wechat_provider_without_config_refuses_startup(tmp_path):
    import pytest

    with pytest.raises(RuntimeError, match="wechat_native configuration"):
        _client(tmp_path, payment_provider="wechat_native")


def test_same_device_reuses_open_order(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    first = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()
    second = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    assert second["order_id"] == first["order_id"]


def test_different_devices_create_separate_orders(tmp_path):
    client, first_token = _registered_mock_client(tmp_path)
    second_token = client.post("/device/register", json=_register_payload("device-b")).json()[
        "signed_license_token"
    ]

    first = client.post(
        "/api/v1/payment/orders",
        headers=_auth(first_token),
        json={"product_code": "annual_v1"},
    ).json()
    second = client.post(
        "/api/v1/payment/orders",
        headers=_auth(second_token),
        json={"product_code": "annual_v1"},
    ).json()

    assert second["order_id"] != first["order_id"]


def test_query_order_requires_own_device_token(tmp_path):
    client, first_token = _registered_mock_client(tmp_path)
    second_token = client.post("/device/register", json=_register_payload("device-b")).json()[
        "signed_license_token"
    ]
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(first_token),
        json={"product_code": "annual_v1"},
    ).json()

    owner = client.get(f"/api/v1/payment/orders/{order['order_id']}", headers=_auth(first_token))
    other = client.get(f"/api/v1/payment/orders/{order['order_id']}", headers=_auth(second_token))

    assert owner.status_code == 200
    assert owner.json()["status"] == "WAITING_PAYMENT"
    assert other.status_code == 404
    assert other.json()["detail"] == "payment_order_not_found"


def test_query_order_remains_read_only_for_expired_waiting_order(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()
    with connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            "UPDATE payment_orders SET expires_at=? WHERE order_id=?",
            (
                datetime_text(datetime.now(timezone.utc) - timedelta(seconds=1)),
                order["order_id"],
            ),
        )
        connection.commit()

    response = client.get(
        f"/api/v1/payment/orders/{order['order_id']}",
        headers=_auth(token),
    )

    assert response.status_code == 200
    assert response.json()["status"] == "WAITING_PAYMENT"
    assert gateway.query_count == 0
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM payment_reconciliations"
        ).fetchone()[0] == 0


def test_refresh_waiting_order_claims_and_reschedules_with_safe_payload(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 200
    assert response.json() == {
        "order_id": order["order_id"],
        "status": "WAITING_PAYMENT",
        "amount_fen": 990,
        "currency": "CNY",
        "expires_at": order["expires_at"],
        "paid_at": None,
        "license_refresh_required": False,
        "refresh_result": "WAITING_PAYMENT",
        "retry_after_seconds": None,
    }
    assert gateway.query_count == 1
    with connect(tmp_path / "license.sqlite3") as connection:
        row = connection.execute(
            "SELECT reconcile_status, query_attempt_count FROM payment_reconciliations"
        ).fetchone()
    assert tuple(row) == ("READY", 1)


def test_refresh_rejects_client_payment_fact_before_claim_or_gateway(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={"paid": True},
    )

    assert response.status_code == 422
    assert gateway.query_count == 0
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM payment_reconciliations"
        ).fetchone()[0] == 0


def test_refresh_rejects_explicit_json_null_body(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers={**_auth(token), "Content-Type": "application/json"},
        content=b"null",
    )

    assert response.status_code == 422
    assert gateway.query_count == 0
    assert _reconciliation_count(tmp_path) == 0


@pytest.mark.parametrize("body", [None, {}])
def test_refresh_accepts_missing_or_empty_body(tmp_path, body):
    client, token = _registered_mock_client(tmp_path)
    order = _create_order(client, token)
    kwargs = {} if body is None else {"json": body}

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        **kwargs,
    )

    assert response.status_code == 200
    assert response.json()["refresh_result"] == "WAITING_PAYMENT"


@pytest.mark.parametrize(
    "field",
    [
        "payment_status",
        "status",
        "amount",
        "amount_fen",
        "currency",
        "transaction_id",
        "trade_state",
        "success_time",
        "expires_at",
        "license_days",
        "appid",
        "mchid",
    ],
)
def test_refresh_rejects_every_client_payment_fact(tmp_path, field):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={field: "client-controlled"},
    )

    assert response.status_code == 422
    assert gateway.query_count == 0
    assert _reconciliation_count(tmp_path) == 0


@pytest.mark.parametrize("authorization", [None, "Bearer invalid-token"])
def test_refresh_rejects_invalid_device_proof_without_side_effects(
    tmp_path,
    authorization,
):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=headers,
        json={},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_device_proof"
    assert gateway.query_count == 0
    assert _reconciliation_count(tmp_path) == 0


def test_refresh_hides_other_device_order_like_missing_order(tmp_path):
    gateway = CountingGateway()
    client, owner_token = _registered_mock_client(tmp_path, gateway=gateway)
    other_token = client.post(
        "/device/register",
        json=_register_payload("device-b"),
    ).json()["signed_license_token"]
    order = _create_order(client, owner_token)

    other = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(other_token),
        json={},
    )
    missing = client.post(
        "/api/v1/payment/orders/pay_missing/refresh",
        headers=_auth(other_token),
        json={},
    )

    assert (other.status_code, other.json()) == (missing.status_code, missing.json())
    assert other.status_code == 404
    assert other.json()["detail"] == "payment_order_not_found"
    assert gateway.query_count == 0
    assert _reconciliation_count(tmp_path) == 0


def test_refresh_paid_order_returns_immediately_without_gateway_or_task(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    paid = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )
    assert paid.status_code == 200

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "PAID"
    assert response.json()["refresh_result"] == "ALREADY_PAID"
    assert response.json()["license_refresh_required"] is True
    assert gateway.query_count == 0
    assert _reconciliation_count(tmp_path) == 0


@pytest.mark.parametrize(
    ("status", "expected_detail"),
    [
        ("CLOSED", None),
        ("ABNORMAL", "PAYMENT_ORDER_REQUIRES_REVIEW"),
        ("CREATED", "PAYMENT_ORDER_PROCESSING"),
    ],
)
def test_refresh_non_waiting_order_never_enters_reconciliation(
    tmp_path,
    status,
    expected_detail,
):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    _set_order_status(tmp_path, order["order_id"], status)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == (200 if status == "CLOSED" else 409)
    if status == "CLOSED":
        assert response.json()["refresh_result"] == "ALREADY_CLOSED"
        assert response.json()["license_refresh_required"] is False
    else:
        assert response.json()["detail"] == expected_detail
    assert gateway.query_count == 0
    assert _reconciliation_count(tmp_path) == 0


def test_refresh_not_due_returns_429_without_mutating_task(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    first = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )
    assert first.status_code == 200
    before = _reconciliation_state(tmp_path, order["order_id"])

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )
    after = _reconciliation_state(tmp_path, order["order_id"])

    assert response.status_code == 429
    assert response.json()["detail"] == "PAYMENT_REFRESH_RATE_LIMITED"
    assert int(response.headers["Retry-After"]) >= 1
    assert int(response.headers["Retry-After"]) <= 10
    assert _reconciliation_retry_window(tmp_path, order["order_id"]) == 10
    assert gateway.query_count == 1
    assert after == before


def test_refresh_in_progress_returns_202_without_stealing_claim(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ensure_ready(tmp_path / "license.sqlite3", order["order_id"], now, now)
    claimed = claim_order(
        tmp_path / "license.sqlite3",
        order_id=order["order_id"],
        worker_id="existing-worker",
        now=now,
        lease_seconds=60,
    )
    assert claimed.claim is not None
    before = _reconciliation_state(tmp_path, order["order_id"])

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )
    after = _reconciliation_state(tmp_path, order["order_id"])

    assert response.status_code == 202
    assert response.json()["refresh_result"] == "REFRESH_IN_PROGRESS"
    assert response.json()["retry_after_seconds"] >= 1
    assert gateway.query_count == 0
    assert after == before


def test_refresh_terminal_task_requires_review_without_resurrection(tmp_path):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    ensure_ready(tmp_path / "license.sqlite3", order["order_id"], now, now)
    claimed = claim_order(
        tmp_path / "license.sqlite3",
        order_id=order["order_id"],
        worker_id="terminal-worker",
        now=now,
        lease_seconds=60,
    ).claim
    assert claimed is not None
    terminate_claim(
        tmp_path / "license.sqlite3",
        claim_token=claimed.claim_token,
        expected_state_version=claimed.state_version,
        terminal_at=now,
        terminal_reason="MANUAL_REVIEW",
    )
    before = _reconciliation_state(tmp_path, order["order_id"])

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )
    after = _reconciliation_state(tmp_path, order["order_id"])

    assert response.status_code == 409
    assert response.json()["detail"] == "PAYMENT_RECONCILIATION_REQUIRES_REVIEW"
    assert gateway.query_count == 0
    assert after == before


def test_refresh_route_is_not_registered_when_provider_is_disabled(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.post("/api/v1/payment/orders/missing/refresh", json={})

    assert response.status_code == 404
    assert _reconciliation_count(tmp_path) == 0


@pytest.mark.parametrize("stage", ["ensure", "claim"])
def test_refresh_missing_reconciliation_state_returns_safe_503(
    tmp_path,
    monkeypatch,
    stage,
):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    if stage == "ensure":
        monkeypatch.setattr(
            payment_routes,
            "ensure_ready",
            lambda *args: EnsureReadyResult(EnsureReadyOutcome.NOT_FOUND, None),
        )
    else:
        monkeypatch.setattr(
            payment_routes,
            "claim_order",
            lambda *args, **kwargs: ClaimOrderResult(ClaimOrderOutcome.NOT_FOUND, None),
        )

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "PAYMENT_REFRESH_UNAVAILABLE"
    assert gateway.query_count == 0


@pytest.mark.parametrize("stage", ["ensure", "claim"])
def test_refresh_not_eligible_reloads_latest_paid_order(
    tmp_path,
    monkeypatch,
    stage,
):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)

    if stage == "ensure":

        def become_ineligible(*args):
            _set_order_status(tmp_path, order["order_id"], "PAID")
            return EnsureReadyResult(EnsureReadyOutcome.NOT_ELIGIBLE, None)

        monkeypatch.setattr(payment_routes, "ensure_ready", become_ineligible)
    else:

        def become_ineligible(*args, **kwargs):
            _set_order_status(tmp_path, order["order_id"], "PAID")
            return ClaimOrderResult(ClaimOrderOutcome.NOT_ELIGIBLE, None)

        monkeypatch.setattr(payment_routes, "claim_order", become_ineligible)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "PAID"
    assert response.json()["license_refresh_required"] is True
    assert gateway.query_count == 0


def test_refresh_repository_error_uses_fixed_public_error(tmp_path, monkeypatch):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)

    def fail(*args):
        raise PaymentReconciliationRepositoryError("SECRET_DATABASE_DETAIL")

    monkeypatch.setattr(payment_routes, "ensure_ready", fail)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "PAYMENT_REFRESH_UNAVAILABLE"
    assert "SECRET_DATABASE_DETAIL" not in response.text
    assert gateway.query_count == 0


def test_refresh_gateway_timeout_is_safely_rescheduled(tmp_path):
    gateway = TimeoutGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 200
    assert response.json()["refresh_result"] == "WAITING_PAYMENT"
    assert "timeout" not in response.text.lower()
    assert gateway.query_count == 1


def test_wechat_provider_registers_refresh_with_injected_gateway(tmp_path):
    gateway = CountingGateway()
    config = WechatPayConfig(
        app_id="wx-test-app",
        mch_id="1900000109",
        merchant_serial_no="merchant-serial",
        merchant_private_key_path=Path("unused-merchant-key.pem"),
        public_key_id="wechat-public-key-id",
        public_key_path=Path("unused-wechat-key.pem"),
        api_v3_key=b"a" * 32,
        notify_url="https://pay.example.test/wechat/notify",
    )
    client, _public_key = _client(
        tmp_path,
        payment_provider="wechat_native",
        wechat_pay_config=config,
        payment_gateway=gateway,
    )
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]
    order = _create_order(client, token)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == 200
    assert response.json()["refresh_result"] == "WAITING_PAYMENT"
    assert gateway.query_count == 1


@pytest.mark.parametrize(
    (
        "outcome",
        "local_status",
        "expected_status_code",
        "expected_result",
        "license_refresh_required",
    ),
    [
        (ReconciliationOutcome.PAID, "PAID", 200, "PAID", True),
        (
            ReconciliationOutcome.ALREADY_PAID,
            "PAID",
            200,
            "ALREADY_PAID",
            True,
        ),
        (
            ReconciliationOutcome.RESCHEDULED,
            "WAITING_PAYMENT",
            200,
            "WAITING_PAYMENT",
            False,
        ),
        (ReconciliationOutcome.CLOSED, "CLOSED", 200, "CLOSED", False),
        (
            ReconciliationOutcome.ALREADY_CLOSED,
            "CLOSED",
            200,
            "ALREADY_CLOSED",
            False,
        ),
        (
            ReconciliationOutcome.TERMINAL_ABNORMAL,
            "ABNORMAL",
            409,
            "PAYMENT_ORDER_REQUIRES_REVIEW",
            None,
        ),
        (
            ReconciliationOutcome.LOST_CLAIM,
            "WAITING_PAYMENT",
            202,
            "REFRESH_IN_PROGRESS",
            False,
        ),
        (
            ReconciliationOutcome.LOST_CLAIM,
            "PAID",
            202,
            "REFRESH_IN_PROGRESS",
            True,
        ),
        (
            ReconciliationOutcome.LOST_CLAIM_AFTER_PAYMENT,
            "WAITING_PAYMENT",
            202,
            "REFRESH_IN_PROGRESS",
            False,
        ),
        (
            ReconciliationOutcome.LOST_CLAIM_AFTER_PAYMENT,
            "PAID",
            200,
            "PAID",
            True,
        ),
    ],
)
def test_refresh_maps_every_service_outcome_from_latest_local_order(
    tmp_path,
    monkeypatch,
    outcome,
    local_status,
    expected_status_code,
    expected_result,
    license_refresh_required,
):
    gateway = CountingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)

    def reconcile(_service, claim, *, now):
        _set_order_status(tmp_path, claim.order_id, local_status)
        return ReconciliationResult(outcome)

    monkeypatch.setattr(PaymentReconciliationService, "reconcile_claim", reconcile)

    response = client.post(
        f"/api/v1/payment/orders/{order['order_id']}/refresh",
        headers=_auth(token),
        json={},
    )

    assert response.status_code == expected_status_code
    if expected_status_code == 409:
        assert response.json()["detail"] == expected_result
    else:
        assert response.json()["refresh_result"] == expected_result
        assert response.json()["license_refresh_required"] is license_refresh_required
    assert gateway.query_count == 0


def test_concurrent_refresh_calls_gateway_once_and_preserves_active_claim(tmp_path):
    gateway = BlockingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    path = f"/api/v1/payment/orders/{order['order_id']}/refresh"

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_future = executor.submit(
            client.post,
            path,
            headers=_auth(token),
            json={},
        )
        assert gateway.query_started.wait(timeout=5)
        second = client.post(path, headers=_auth(token), json={})
        gateway.release_query.set()
        first = first_future.result(timeout=5)

    assert first.status_code == 200
    assert second.status_code == 202
    assert second.json()["refresh_result"] == "REFRESH_IN_PROGRESS"
    assert gateway.query_count == 1
    state = _reconciliation_state(tmp_path, order["order_id"])
    assert state[0] == "READY"
    assert state[2] == 1
    assert state[-1] == 2


def test_callback_paid_race_is_never_overwritten_by_refresh(tmp_path):
    gateway = BlockingGateway()
    client, token = _registered_mock_client(tmp_path, gateway=gateway)
    order = _create_order(client, token)
    path = f"/api/v1/payment/orders/{order['order_id']}/refresh"

    with ThreadPoolExecutor(max_workers=1) as executor:
        first_future = executor.submit(
            client.post,
            path,
            headers=_auth(token),
            json={},
        )
        assert gateway.query_started.wait(timeout=5)
        paid = client.post(
            f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
            headers={"X-Mock-Payment-Token": MOCK_TOKEN},
            json={},
        )
        second = client.post(path, headers=_auth(token), json={})
        gateway.release_query.set()
        first = first_future.result(timeout=5)

    assert paid.status_code == 200
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["status"] == "PAID"
    assert second.json()["status"] == "PAID"
    assert gateway.query_count == 1
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id=?",
            (order["order_id"],),
        ).fetchone()[0] == "PAID"
        assert connection.execute(
            "SELECT COUNT(*) FROM license_grants WHERE source_order_id=?",
            (order["order_id"],),
        ).fetchone()[0] == 1


def test_tampered_bearer_token_is_rejected(tmp_path):
    client, token = _registered_mock_client(tmp_path)

    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(_tamper(token)),
        json={"product_code": "annual_v1"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_device_proof"


def test_mock_payment_loop_refreshes_to_paid_token_and_is_idempotent(tmp_path):
    client, token = _registered_mock_client(tmp_path)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    paid = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )
    duplicate = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )
    queried = client.get(
        f"/api/v1/payment/orders/{order['order_id']}",
        headers=_auth(token),
    )
    refreshed = client.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
        },
    )

    assert paid.status_code == 200
    assert paid.json()["status"] == "PAID"
    assert paid.json()["idempotent"] is False
    assert duplicate.status_code == 200
    assert duplicate.json()["idempotent"] is True
    assert queried.json()["status"] == "PAID"
    assert refreshed.json()["status"] == "paid_active"
    assert refreshed.json()["license_type"] == "paid"
    with connect(tmp_path / "license.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_mock_pay_requires_admin_token_and_rejects_amount_body(tmp_path):
    client, token = _registered_mock_client(tmp_path)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()

    missing = client.post(f"/api/v1/payment/mock/orders/{order['order_id']}/pay", json={})
    extra = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={"amount_fen": 1},
    )

    assert missing.status_code == 403
    assert missing.json()["detail"] == "invalid_mock_payment_token"
    assert extra.status_code == 422


def test_mock_route_is_not_registered_without_mock_provider(tmp_path):
    client, _public_key = _client(tmp_path)

    response = client.post(
        "/api/v1/payment/mock/orders/missing/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )

    assert response.status_code == 404


def test_closed_order_cannot_be_mock_paid(tmp_path):
    client, token = _registered_mock_client(tmp_path)
    order = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    ).json()
    with sqlite3.connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            "UPDATE payment_orders SET status = 'CLOSED', open_slot = NULL WHERE order_id = ?",
            (order["order_id"],),
        )

    response = client.post(
        f"/api/v1/payment/mock/orders/{order['order_id']}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "closed_order"


def _registered_mock_client(tmp_path, *, gateway=None):
    client, _public_key = _client(
        tmp_path,
        payment_provider="mock",
        payment_mock_admin_token=MOCK_TOKEN,
        payment_gateway=gateway,
    )
    token = client.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]
    return client, token


def _create_order(client, token):
    response = client.post(
        "/api/v1/payment/orders",
        headers=_auth(token),
        json={"product_code": "annual_v1"},
    )
    assert response.status_code == 200
    return response.json()


def _set_order_status(tmp_path, order_id, status):
    with connect(tmp_path / "license.sqlite3") as connection:
        connection.execute(
            "UPDATE payment_orders SET status=?, open_slot=? WHERE order_id=?",
            (
                status,
                "open" if status in {"CREATED", "WAITING_PAYMENT"} else None,
                order_id,
            ),
        )
        connection.commit()


def _reconciliation_count(tmp_path):
    with connect(tmp_path / "license.sqlite3") as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM payment_reconciliations"
        ).fetchone()[0]


def _reconciliation_state(tmp_path, order_id):
    with connect(tmp_path / "license.sqlite3") as connection:
        row = connection.execute(
            """
            SELECT reconcile_status, next_attempt_at, query_attempt_count,
                   claim_token, claimed_by, claimed_at, lease_expires_at,
                   terminal_reason, terminal_at, state_version
            FROM payment_reconciliations WHERE order_id=?
            """,
            (order_id,),
        ).fetchone()
    return tuple(row)


def _reconciliation_retry_window(tmp_path, order_id):
    with connect(tmp_path / "license.sqlite3") as connection:
        row = connection.execute(
            """
            SELECT last_query_at, next_attempt_at
            FROM payment_reconciliations WHERE order_id=?
            """,
            (order_id,),
        ).fetchone()
    last_query_at = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
    next_attempt_at = datetime.fromisoformat(row[1].replace("Z", "+00:00"))
    return int((next_attempt_at - last_query_at).total_seconds())


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _tamper(token: str) -> str:
    replacement = "A" if token[0] != "A" else "B"
    return replacement + token[1:]


class CapturingGateway(MockPaymentGateway):
    def __init__(self):
        self.request = None

    def create_native_order(self, request):
        self.request = request
        return super().create_native_order(request)


class CountingGateway(MockPaymentGateway):
    def __init__(self):
        self.query_count = 0

    def query_order(self, order_id):
        self.query_count += 1
        return super().query_order(order_id)


class BlockingGateway(CountingGateway):
    def __init__(self):
        super().__init__()
        self.query_started = Event()
        self.release_query = Event()

    def query_order(self, order_id):
        self.query_count += 1
        self.query_started.set()
        if not self.release_query.wait(timeout=5):
            raise TimeoutError("test gateway was not released")
        return MockPaymentGateway.query_order(self, order_id)


class TimeoutGateway(CountingGateway):
    def query_order(self, order_id):
        self.query_count += 1
        raise TimeoutError("upstream timeout detail")
