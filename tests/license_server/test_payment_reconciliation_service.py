import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event

import pytest

from license_server import payment_service
from license_server.db import connect, initialize_database
from license_server.payment import ANNUAL_V1, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_gateway import (
    CloseOrderOutcome,
    CloseOrderResult,
    QueryOrderOutcome,
    QueryOrderResult,
)
from license_server.payment_reconciliation_repository import (
    UpdateOutcome,
    claim_order,
    claim_next_due,
    ensure_ready,
    get,
)
from license_server.payment_reconciliation_service import (
    PaymentReconciliationPolicy,
    PaymentReconciliationService,
    ReconciliationOutcome,
)
from license_server.payment_service import confirm_paid_order
from license_server.wechat_payment import WechatPaymentError
from license_server.signer import datetime_text


NOW = datetime(2026, 7, 15, 6, 0, tzinfo=timezone.utc)
APP_ID = "wx-test-app"
MCH_ID = "1900000109"
POLICY = PaymentReconciliationPolicy(
    query_retry_base_seconds=2,
    query_retry_max_seconds=8,
    max_query_attempts=3,
    close_retry_base_seconds=3,
    close_retry_max_seconds=9,
    max_close_attempts=2,
)


def test_policy_rejects_invalid_or_unbounded_values():
    values = dict(
        query_retry_base_seconds=2,
        query_retry_max_seconds=8,
        max_query_attempts=3,
        close_retry_base_seconds=3,
        close_retry_max_seconds=9,
        max_close_attempts=2,
    )
    for field, value in (
        ("query_retry_base_seconds", 0),
        ("query_retry_max_seconds", 86_401),
        ("max_query_attempts", 101),
        ("close_retry_base_seconds", True),
        ("close_retry_max_seconds", -1),
        ("max_close_attempts", 0),
    ):
        invalid = values | {field: value}
        with pytest.raises(ValueError, match="PAYMENT_RECONCILIATION_POLICY_INVALID"):
            PaymentReconciliationPolicy(**invalid)


def test_success_confirms_payment_once_and_terminates_reconciliation(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(_success(claim.order_id))

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.PAID
    assert gateway.queried == [claim.order_id]
    assert gateway.closed == []
    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, provider_transaction_id FROM payment_orders"
        ).fetchone()
        grant = connection.execute(
            "SELECT issued_by FROM license_grants"
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1
    record = get(path, claim.order_id)
    assert tuple(order) == ("PAID", None, "4200000001")
    assert grant["issued_by"] == "payment_query"
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PAYMENT_CONFIRMED"
    assert record.trusted_trade_state == "SUCCESS"
    assert record.last_query_at == NOW


def test_notpay_before_expiry_reschedules_without_closing_or_grant(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW + timedelta(minutes=1))
    gateway = FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.NOTPAY))

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    with connect(path) as connection:
        order = connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
    record = get(path, claim.order_id)
    assert tuple(order) == ("WAITING_PAYMENT", "open")
    assert record.reconcile_status == "READY"
    assert record.next_attempt_at == NOW + timedelta(seconds=2)
    assert record.last_query_at == NOW
    assert record.trusted_trade_state == "NOTPAY"
    assert record.last_error_code is None
    assert gateway.closed == []


def test_query_result_after_lease_expiry_without_reclaimer_loses_claim(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(tmp_path, lease_seconds=1)
    before_order = _order_state(path)
    before_task = get(path, claim.order_id)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        on_query=lambda: clock.set(NOW + timedelta(seconds=1)),
    )

    result = _service(path, gateway, clock=clock).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert _order_state(path) == before_order
    expired = get(path, claim.order_id)
    assert expired == before_task
    reclaimed = claim_order(
        path,
        order_id=claim.order_id,
        worker_id="worker-2",
        now=NOW + timedelta(seconds=1),
        lease_seconds=60,
    )
    assert reclaimed.claim is not None
    assert reclaimed.claim.claim_token != claim.claim_token


def test_expired_notpay_closes_upstream_then_locally_and_terminates(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.CLOSED
    assert gateway.queried == gateway.closed == [claim.order_id]
    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, closed_at FROM payment_orders"
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
    record = get(path, claim.order_id)
    assert tuple(order) == ("CLOSED", None, datetime_text(NOW))
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PROVIDER_CLOSED"
    assert record.trusted_trade_state == "CLOSED"
    assert record.last_query_at == NOW
    assert record.last_close_at == NOW


def test_close_result_after_lease_expiry_without_reclaimer_does_not_close(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(tmp_path, expires_at=NOW, lease_seconds=1)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
        on_close=lambda: clock.set(NOW + timedelta(seconds=1)),
    )

    result = _service(path, gateway, clock=clock).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    record = get(path, claim.order_id)
    assert record.reconcile_status == "CLAIMED"
    assert record.claim_token == claim.claim_token
    assert record.last_close_at is None
    assert record.close_attempt_count == 1


@pytest.mark.parametrize(
    "failing_sql",
    ("UPDATE payment_orders", "UPDATE payment_reconciliations"),
)
def test_abnormal_and_terminal_roll_back_together_on_each_write_failure(
    tmp_path, monkeypatch, failing_sql
):
    path, claim = _claimed_order(tmp_path)
    before = get(path, claim.order_id)
    real_connect = payment_service.connect
    monkeypatch.setattr(
        payment_service,
        "connect",
        lambda database_path: _FailAfterExecuteConnection(
            real_connect(database_path), failing_sql
        ),
    )
    service = PaymentReconciliationService(
        database_path=path,
        gateway=FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.UNKNOWN)),
        expected_appid=APP_ID,
        expected_mchid=MCH_ID,
        policy=POLICY,
        clock=lambda: NOW,
    )

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        service.reconcile_claim(claim, now=NOW)

    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    after = get(path, claim.order_id)
    assert after == before
    recovered = claim_order(
        path,
        order_id=claim.order_id,
        worker_id="worker-2",
        now=NOW + timedelta(seconds=60),
        lease_seconds=60,
    )
    assert recovered.claim is not None
    assert recovered.claim.claim_token != claim.claim_token
    with connect(path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_callback_during_success_query_keeps_one_grant_and_finishes_idempotently(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(
        _success(claim.order_id),
        on_query=lambda: confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        ),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        grant = connection.execute("SELECT issued_by FROM license_grants").fetchone()[0]
    assert grant == "wechat_callback"
    assert get(path, claim.order_id).terminal_reason == "ORDER_ALREADY_PAID"


def test_callback_and_query_threads_issue_exactly_one_grant(tmp_path):
    path, claim = _claimed_order(tmp_path)
    entered = Event()
    release = Event()

    class BlockingGateway(FakeGateway):
        def query_order(self, order_id):
            self.queried.append(order_id)
            entered.set()
            assert release.wait(timeout=5)
            return self.query_result

    gateway = BlockingGateway(_success(claim.order_id))
    with ThreadPoolExecutor(max_workers=2) as executor:
        query_future = executor.submit(
            _service(path, gateway).reconcile_claim,
            claim,
            now=NOW,
        )
        assert entered.wait(timeout=5)
        callback_future = executor.submit(
            confirm_paid_order,
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        )
        callback_future.result(timeout=5)
        release.set()
        result = query_future.result(timeout=5)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1


def test_success_payment_commits_even_when_old_claim_was_reclaimed(tmp_path):
    path, old_claim = _claimed_order(tmp_path)
    reclaimed = []

    def reclaim():
        result = claim_order(
            path,
            order_id=old_claim.order_id,
            worker_id="worker-2",
            now=NOW + timedelta(seconds=60),
            lease_seconds=60,
        )
        reclaimed.append(result.claim)

    result = _service(
        path,
        FakeGateway(_success(old_claim.order_id), on_query=reclaim),
    ).reconcile_claim(old_claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM_AFTER_PAYMENT
    assert reclaimed[0] is not None
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
    record = get(path, old_claim.order_id)
    assert record.claim_token == reclaimed[0].claim_token
    assert record.reconcile_status == "CLAIMED"

    follow_up = _service(
        path,
        FakeGateway(_success(old_claim.order_id)),
    ).reconcile_claim(reclaimed[0], now=NOW + timedelta(seconds=60))

    assert follow_up.outcome is ReconciliationOutcome.ALREADY_PAID
    assert get(path, old_claim.order_id).reconcile_status == "TERMINAL"
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("overrides", "prepare"),
    (
        ({"appid": "wrong-app"}, None),
        ({"mchid": "wrong-mch"}, None),
        ({"out_trade_no": "wrong-order"}, None),
        ({"transaction_id": None}, None),
        ({"trade_type": "JSAPI"}, None),
        ({"amount_total": 1}, None),
        ({"currency": "USD"}, None),
        ({"success_time": None}, None),
        ({}, "remove_device"),
        ({}, "transaction_conflict"),
    ),
)
def test_success_mismatch_marks_open_order_abnormal_without_grant(
    tmp_path, overrides, prepare
):
    path, claim = _claimed_order(tmp_path)
    if prepare == "remove_device":
        with connect(path) as connection:
            connection.execute("DELETE FROM devices")
            connection.commit()
    elif prepare == "transaction_conflict":
        _insert_transaction_conflict(path)

    result = _service(path, FakeGateway(_success(claim.order_id, **overrides))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot FROM payment_orders WHERE order_id=?",
            (claim.order_id,),
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 0
    assert tuple(order) == ("ABNORMAL", "open")
    assert get(path, claim.order_id).reconcile_status == "TERMINAL"


def test_mismatched_success_cannot_overwrite_concurrent_paid_order(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(
        _success(claim.order_id, amount_total=1),
        on_query=lambda: confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        ),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_notpay_at_query_limit_terminates_without_changing_order(tmp_path):
    path, claim = _claimed_order(tmp_path, query_attempt_count=2)
    result = _service(
        path,
        FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.NOTPAY)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    assert get(path, claim.order_id).terminal_reason == "QUERY_RETRY_EXHAUSTED"
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "WAITING_PAYMENT",
            "open",
        )


def test_notpay_backoff_is_capped(tmp_path):
    path, claim = _claimed_order(tmp_path, query_attempt_count=4)
    policy = PaymentReconciliationPolicy(2, 8, 10, 3, 9, 2)

    result = _service(
        path,
        FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.NOTPAY)),
        policy,
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert get(path, claim.order_id).next_attempt_at == NOW + timedelta(seconds=8)


def test_trusted_closed_query_closes_locally_without_close_http(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(_closed_query(claim.order_id))

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.CLOSED
    assert gateway.closed == []
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "CLOSED",
            None,
        )
    record = get(path, claim.order_id)
    assert record.terminal_reason == "PROVIDER_CLOSED"
    assert record.trusted_trade_state == "CLOSED"
    assert record.last_query_at == NOW


def test_closed_query_cannot_overwrite_concurrent_paid_order(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(
        _closed_query(claim.order_id),
        on_query=lambda: confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        ),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
    assert gateway.closed == []


def test_stale_closed_query_cannot_close_order_after_claim_is_reclaimed(tmp_path):
    path, claim = _claimed_order(tmp_path)
    new_claims = []

    def reclaim():
        new_claims.append(
            claim_order(
                path,
                order_id=claim.order_id,
                worker_id="worker-2",
                now=NOW + timedelta(seconds=60),
                lease_seconds=60,
            ).claim
        )

    result = _service(
        path,
        FakeGateway(_closed_query(claim.order_id), on_query=reclaim),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "WAITING_PAYMENT",
            "open",
        )
    assert get(path, claim.order_id).claim_token == new_claims[0].claim_token


def test_closed_query_does_not_close_order_with_existing_grant(tmp_path):
    path, claim = _claimed_order(tmp_path)
    confirm_paid_order(
        path,
        _callback_evidence(claim.order_id),
        issued_by="wechat_callback",
        now=NOW,
    )
    with connect(path) as connection:
        connection.execute(
            "UPDATE payment_orders SET status='WAITING_PAYMENT', open_slot='open' WHERE order_id=?",
            (claim.order_id,),
        )
        connection.commit()

    result = _service(path, FakeGateway(_closed_query(claim.order_id))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_closed_query_does_not_close_order_with_provider_transaction_fact(tmp_path):
    path, claim = _claimed_order(tmp_path)
    with connect(path) as connection:
        connection.execute(
            "UPDATE payment_orders SET provider_transaction_id=? WHERE order_id=?",
            ("4200000001", claim.order_id),
        )
        connection.commit()

    result = _service(path, FakeGateway(_closed_query(claim.order_id))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, provider_transaction_id FROM payment_orders"
        ).fetchone()
    assert tuple(order) == ("WAITING_PAYMENT", "open", "4200000001")


def test_userpaying_reschedules_even_after_local_expiry(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.USERPAYING))

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert gateway.closed == []
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.trusted_trade_state == "USERPAYING"
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_userpaying_at_query_limit_terminates_without_changing_order(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW, query_attempt_count=2)
    result = _service(
        path,
        FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.USERPAYING)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    assert get(path, claim.order_id).terminal_reason == "QUERY_RETRY_EXHAUSTED"
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


@pytest.mark.parametrize(
    ("outcome", "reason"),
    (
        (QueryOrderOutcome.REFUND, "REFUND_REVIEW_REQUIRED"),
        (QueryOrderOutcome.REVOKED, "REVOKED_REVIEW_REQUIRED"),
        (QueryOrderOutcome.PAYERROR, "PAYERROR_REVIEW_REQUIRED"),
        (QueryOrderOutcome.UNKNOWN, "UNKNOWN_REVIEW_REQUIRED"),
    ),
)
def test_abnormal_trade_states_mark_open_order_abnormal_and_terminate(
    tmp_path, outcome, reason
):
    path, claim = _claimed_order(tmp_path)

    result = _service(
        path,
        FakeGateway(_simple_query(claim.order_id, outcome)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "ABNORMAL",
            "open",
        )
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
    record = get(path, claim.order_id)
    assert record.terminal_reason == reason
    assert record.trusted_trade_state == outcome.value


@pytest.mark.parametrize(
    "outcome",
    (
        QueryOrderOutcome.REFUND,
        QueryOrderOutcome.REVOKED,
        QueryOrderOutcome.PAYERROR,
        QueryOrderOutcome.UNKNOWN,
    ),
)
def test_abnormal_trade_states_preserve_concurrent_paid_license(tmp_path, outcome):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(
        _simple_query(claim.order_id, outcome),
        on_query=lambda: confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        ),
    )

    _service(path, gateway).reconcile_claim(claim, now=NOW)

    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1


def test_retryable_query_error_reschedules_with_safe_code(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(
        WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True, result_unknown=True)
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.last_error_code == "QUERY_GATEWAY_RETRYABLE"
    assert record.trusted_trade_state is None
    assert record.last_query_at == NOW


def test_retryable_query_error_at_limit_terminates_without_order_change(tmp_path):
    path, claim = _claimed_order(tmp_path, query_attempt_count=2)

    result = _service(
        path,
        FakeGateway(WechatPaymentError("PAYMENT_CONNECT_TIMEOUT", retryable=True)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    assert get(path, claim.order_id).terminal_reason == "QUERY_RETRY_EXHAUSTED"
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_retryable_query_error_after_callback_finishes_paid_race(tmp_path):
    path, claim = _claimed_order(tmp_path)
    gateway = FakeGateway(
        WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True),
        on_query=lambda: confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        ),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    assert get(path, claim.order_id).terminal_reason == "ORDER_ALREADY_PAID"


@pytest.mark.parametrize(
    "code",
    (
        "PAYMENT_RESPONSE_SIGNATURE_INVALID",
        "PAYMENT_RESPONSE_INVALID",
        "PAYMENT_CONFIG_PRIVATE_KEY_INVALID",
        "PAYMENT_UPSTREAM_REJECTED",
    ),
)
def test_nonretryable_query_error_is_terminal_untrusted_and_safe(tmp_path, code):
    path, claim = _claimed_order(tmp_path)

    result = _service(path, FakeGateway(WechatPaymentError(code))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    record = get(path, claim.order_id)
    assert record.terminal_reason == "QUERY_GATEWAY_REJECTED"
    assert record.trusted_trade_state is None
    assert record.last_error_code == "QUERY_GATEWAY_NON_RETRYABLE"
    assert claim.order_id not in repr(result)
    assert code not in repr(result)
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "ABNORMAL"


def test_close_unknown_reschedules_and_records_close_completion(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.UNKNOWN),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.last_query_at == record.last_close_at == NOW
    assert record.last_error_code == "CLOSE_RESULT_UNKNOWN"
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


@pytest.mark.parametrize("retryable", (True, False))
def test_close_gateway_error_retries_without_local_close(tmp_path, retryable):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        WechatPaymentError("PAYMENT_CLOSE_FAILED", retryable=retryable),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert get(path, claim.order_id).last_error_code == (
        "CLOSE_GATEWAY_RETRYABLE" if retryable else "CLOSE_GATEWAY_NON_RETRYABLE"
    )
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_close_error_at_limit_terminates_but_keeps_waiting_order(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW, close_attempt_count=1)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        WechatPaymentError("PAYMENT_CLOSE_FAILED"),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    assert get(path, claim.order_id).terminal_reason == "CLOSE_RETRY_EXHAUSTED"
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_lost_claim_before_close_never_calls_close_http(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)

    def reclaim():
        assert claim_order(
            path,
            order_id=claim.order_id,
            worker_id="worker-2",
            now=NOW + timedelta(seconds=60),
            lease_seconds=60,
        ).claim is not None

    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
        on_query=reclaim,
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert gateway.closed == []


def test_close_result_cannot_overwrite_callback_paid_race(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
        on_close=lambda: confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW - timedelta(seconds=1),
        ),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_stale_close_result_cannot_close_order_after_claim_is_reclaimed(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    new_claims = []

    def reclaim():
        new_claims.append(
            claim_order(
                path,
                order_id=claim.order_id,
                worker_id="worker-2",
                now=NOW + timedelta(seconds=60),
                lease_seconds=60,
            ).claim
        )

    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
        on_close=reclaim,
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "WAITING_PAYMENT",
            "open",
        )
    assert get(path, claim.order_id).claim_token == new_claims[0].claim_token


def test_stale_worker_cannot_reschedule_over_reclaimed_state(tmp_path):
    path, claim = _claimed_order(tmp_path)
    new_claims = []

    def reclaim():
        new_claims.append(
            claim_order(
                path,
                order_id=claim.order_id,
                worker_id="worker-2",
                now=NOW + timedelta(seconds=60),
                lease_seconds=60,
            ).claim
        )

    result = _service(
        path,
        FakeGateway(
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY), on_query=reclaim
        ),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert get(path, claim.order_id).claim_token == new_claims[0].claim_token


def test_stale_worker_cannot_mark_order_abnormal_or_terminate_new_claim(tmp_path):
    path, claim = _claimed_order(tmp_path)
    new_claims = []

    def reclaim():
        new_claims.append(
            claim_order(
                path,
                order_id=claim.order_id,
                worker_id="worker-2",
                now=NOW + timedelta(seconds=60),
                lease_seconds=60,
            ).claim
        )

    result = _service(
        path,
        FakeGateway(
            _simple_query(claim.order_id, QueryOrderOutcome.UNKNOWN),
            on_query=reclaim,
        ),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"
    record = get(path, claim.order_id)
    assert record.claim_token == new_claims[0].claim_token
    assert record.reconcile_status == "CLAIMED"


def test_stale_success_worker_cannot_mark_missing_device_order_abnormal(tmp_path):
    path, claim = _claimed_order(tmp_path)
    with connect(path) as connection:
        connection.execute("DELETE FROM devices")
        connection.commit()
    new_claims = []

    def reclaim():
        new_claims.append(
            claim_order(
                path,
                order_id=claim.order_id,
                worker_id="worker-2",
                now=NOW + timedelta(seconds=60),
                lease_seconds=60,
            ).claim
        )

    result = _service(
        path,
        FakeGateway(_success(claim.order_id), on_query=reclaim),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"
    assert get(path, claim.order_id).claim_token == new_claims[0].claim_token


def test_closed_query_reports_already_closed_and_finishes_task(tmp_path):
    path, claim = _claimed_order(tmp_path)
    with connect(path) as connection:
        connection.execute(
            "UPDATE payment_orders SET status='CLOSED', open_slot=NULL, closed_at=?",
            (datetime_text(NOW),),
        )
        connection.commit()

    result = _service(path, FakeGateway(_closed_query(claim.order_id))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.ALREADY_CLOSED
    assert get(path, claim.order_id).terminal_reason == "PROVIDER_CLOSED"


def test_query_and_close_http_do_not_hold_sqlite_write_transaction(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)

    class WritingGateway(FakeGateway):
        def _write(self):
            with connect(path) as connection:
                connection.execute("PRAGMA busy_timeout=20")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE devices SET last_seen_at=last_seen_at")
                connection.commit()

        def query_order(self, order_id):
            self._write()
            return super().query_order(order_id)

        def close_order(self, order_id):
            self._write()
            return super().close_order(order_id)

    gateway = WritingGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
    )

    assert _service(path, gateway).reconcile_claim(claim, now=NOW).outcome is ReconciliationOutcome.CLOSED


def test_success_with_unexpected_product_is_abnormal_without_grant(tmp_path):
    path, claim = _claimed_order(tmp_path)
    with connect(path) as connection:
        connection.execute("UPDATE payment_orders SET product_code='unexpected'")
        connection.commit()

    result = _service(path, FakeGateway(_success(claim.order_id))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "ABNORMAL"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_success_for_missing_order_is_terminal_without_grant(tmp_path):
    path, claim = _claimed_order(tmp_path)
    with connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DELETE FROM payment_orders WHERE order_id=?", (claim.order_id,))
        connection.commit()

    result = _service(path, FakeGateway(_success(claim.order_id))).reconcile_claim(
        claim,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.TERMINAL_ABNORMAL
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


class FakeGateway:
    def __init__(self, query_result, close_result=None, *, on_query=None, on_close=None):
        self.query_result = query_result
        self.close_result = close_result
        self.on_query = on_query
        self.on_close = on_close
        self.queried = []
        self.closed = []

    def create_native_order(self, request):
        raise AssertionError("create is outside reconciliation")

    def query_order(self, order_id):
        self.queried.append(order_id)
        if self.on_query is not None:
            self.on_query()
        if isinstance(self.query_result, Exception):
            raise self.query_result
        return self.query_result

    def close_order(self, order_id):
        self.closed.append(order_id)
        if self.on_close is not None:
            self.on_close()
        if isinstance(self.close_result, Exception):
            raise self.close_result
        assert self.close_result is not None
        return self.close_result

    def parse_and_verify_notification(self, headers, body, *, now=None):
        raise AssertionError("notifications are outside reconciliation")


def _service(path, gateway, policy=POLICY, clock=None):
    return PaymentReconciliationService(
        database_path=path,
        gateway=gateway,
        expected_appid=APP_ID,
        expected_mchid=MCH_ID,
        policy=policy,
        clock=clock or (lambda: NOW),
    )


def _claimed_order(
    tmp_path,
    *,
    expires_at=NOW + timedelta(minutes=1),
    order_id="order-1",
    query_attempt_count=0,
    close_attempt_count=0,
    lease_seconds=60,
):
    path = tmp_path / "license.sqlite3"
    initialize_database(path)
    with connect(path) as connection:
        connection.execute(
            "INSERT INTO devices (product_id, device_fingerprint_hash, first_seen_at, last_seen_at) "
            "VALUES ('whut-campus-auto-login', 'device-a', ?, ?)",
            (datetime_text(NOW), datetime_text(NOW)),
        )
        connection.execute(
            """INSERT INTO payment_orders (
                   order_id, device_fingerprint_hash, product_code, amount_fen,
                   currency, provider, status, open_slot, provider_order_id,
                   provider_trade_state, created_at, updated_at, expires_at
               ) VALUES (?, 'device-a', ?, ?, ?, 'wechat_native',
                         'WAITING_PAYMENT', 'open', ?, 'NOTPAY', ?, ?, ?)""",
            (
                order_id,
                ANNUAL_V1.product_code,
                ANNUAL_V1.amount_fen,
                ANNUAL_V1.currency,
                order_id,
                datetime_text(NOW - timedelta(minutes=1)),
                datetime_text(NOW - timedelta(minutes=1)),
                datetime_text(expires_at),
            ),
        )
        connection.commit()
    ensure_ready(path, order_id, NOW, NOW)
    if query_attempt_count or close_attempt_count:
        with connect(path) as connection:
            connection.execute(
                "UPDATE payment_reconciliations SET query_attempt_count=?, close_attempt_count=? WHERE order_id=?",
                (query_attempt_count, close_attempt_count, order_id),
            )
            connection.commit()
    result = claim_order(
        path,
        order_id=order_id,
        worker_id="worker-1",
        now=NOW,
        lease_seconds=lease_seconds,
    )
    assert result.claim is not None
    return path, result.claim


def _order_state(path):
    with connect(path) as connection:
        return tuple(
            connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()
        )


class _MutableClock:
    def __init__(self, current):
        self.current = current

    def __call__(self):
        return self.current

    def set(self, value):
        self.current = value


class _FailAfterExecuteConnection:
    def __init__(self, connection, failing_sql):
        self._connection = connection
        self._failing_sql = failing_sql

    def execute(self, sql, parameters=()):
        cursor = self._connection.execute(sql, parameters)
        if self._failing_sql in " ".join(sql.split()):
            raise sqlite3.OperationalError("database is locked")
        return cursor

    def __getattr__(self, name):
        return getattr(self._connection, name)


def _success(order_id, **overrides):
    values = dict(
        outcome=QueryOrderOutcome.SUCCESS,
        out_trade_no=order_id,
        transaction_id="4200000001",
        trade_state="SUCCESS",
        trade_type="NATIVE",
        amount_total=ANNUAL_V1.amount_fen,
        currency=ANNUAL_V1.currency,
        success_time=NOW,
        appid=APP_ID,
        mchid=MCH_ID,
    )
    values.update(overrides)
    return QueryOrderResult(**values)


def _closed_query(order_id):
    return QueryOrderResult(
        outcome=QueryOrderOutcome.CLOSED,
        out_trade_no=order_id,
        trade_state="CLOSED",
        trade_type="NATIVE",
        amount_total=ANNUAL_V1.amount_fen,
        currency=ANNUAL_V1.currency,
        appid=APP_ID,
        mchid=MCH_ID,
    )


def _simple_query(order_id, outcome):
    return QueryOrderResult(
        outcome=outcome,
        out_trade_no=order_id,
        trade_state=outcome.value,
    )


def _callback_evidence(order_id):
    return PaymentEvidence(
        source=PaymentEvidenceSource.WECHAT_CALLBACK,
        out_trade_no=order_id,
        provider_transaction_id="4200000001",
        trade_type="NATIVE",
        trade_state="SUCCESS",
        amount_fen=ANNUAL_V1.amount_fen,
        currency=ANNUAL_V1.currency,
        paid_at=NOW,
        appid=APP_ID,
        mchid=MCH_ID,
    )


def _insert_transaction_conflict(path):
    with connect(path) as connection:
        connection.execute(
            """INSERT INTO payment_orders (
                   order_id, device_fingerprint_hash, product_code, amount_fen,
                   currency, provider, status, open_slot,
                   provider_transaction_id, created_at, updated_at, expires_at
               ) VALUES ('other-order', 'device-other', ?, ?, ?, 'wechat_native',
                         'CLOSED', NULL, '4200000001', ?, ?, ?)""",
            (
                ANNUAL_V1.product_code,
                ANNUAL_V1.amount_fen,
                ANNUAL_V1.currency,
                datetime_text(NOW),
                datetime_text(NOW),
                datetime_text(NOW),
            ),
        )
        connection.commit()
