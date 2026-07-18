import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Event

import pytest

from license_server import payment_reconciliation_service as reconciliation_service_module
from license_server import payment_service
from license_server import payment_reconciliation_repository as reconciliation_repository
from license_server.config import (
    DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS,
    DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS,
    DEFAULT_PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS,
    DEFAULT_PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS,
    DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS,
    DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS,
)
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
from license_server.payment_routes import _REFRESH_POLICY
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
DEFAULT_WORKER_SERVICE_POLICY = PaymentReconciliationPolicy(
    query_retry_base_seconds=DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS,
    query_retry_max_seconds=DEFAULT_PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS,
    max_query_attempts=DEFAULT_PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS,
    close_retry_base_seconds=DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS,
    close_retry_max_seconds=DEFAULT_PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS,
    max_close_attempts=DEFAULT_PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS,
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
            "SELECT status, open_slot, provider_transaction_id, paid_at FROM payment_orders"
        ).fetchone()
        grant = connection.execute(
            "SELECT issued_by FROM license_grants"
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1
    record = get(path, claim.order_id)
    assert tuple(order) == ("PAID", None, "4200000001", datetime_text(NOW))
    assert grant["issued_by"] == "payment_query"
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PAYMENT_CONFIRMED"
    assert record.trusted_trade_state == "SUCCESS"
    assert record.last_query_at == NOW
    assert record.claim_token is None
    assert record.claimed_by is None
    assert record.claimed_at is None
    assert record.lease_expires_at is None
    assert record.state_version == claim.state_version + 1


@pytest.mark.parametrize(
    "failing_sql",
    (
        "INSERT INTO licenses",
        "INSERT INTO license_grants",
        "UPDATE payment_orders",
        "UPDATE payment_reconciliations",
    ),
)
def test_success_and_terminal_roll_back_together_on_each_write_failure(
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

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        _service(path, FakeGateway(_success(claim.order_id))).reconcile_claim(
            claim,
            now=NOW,
        )

    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, provider_transaction_id, paid_at FROM payment_orders"
        ).fetchone()
        assert tuple(order) == ("WAITING_PAYMENT", "open", None, None)
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert get(path, claim.order_id) == before
    recovered = claim_order(
        path,
        order_id=claim.order_id,
        worker_id="worker-2",
        now=NOW + timedelta(seconds=60),
        lease_seconds=60,
    )
    assert recovered.claim is not None
    assert recovered.claim.claim_token != claim.claim_token


@pytest.mark.parametrize("claim_kind", ("token", "version"))
def test_success_with_stale_claim_does_not_commit_payment(tmp_path, claim_kind):
    path, claim = _claimed_order(tmp_path)
    stale = replace(
        claim,
        claim_token="stale-token" if claim_kind == "token" else claim.claim_token,
        state_version=claim.state_version + (claim_kind == "version"),
    )
    before = get(path, claim.order_id)

    result = _service(path, FakeGateway(_success(claim.order_id))).reconcile_claim(
        stale,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    assert get(path, claim.order_id) == before
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 0


def test_success_at_lease_boundary_does_not_commit_payment(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(tmp_path, lease_seconds=1)
    before = get(path, claim.order_id)
    gateway = FakeGateway(
        _success(claim.order_id),
        on_query=lambda: clock.set(NOW + timedelta(seconds=1)),
    )

    result = _service(path, gateway, clock=clock).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    assert get(path, claim.order_id) == before
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


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


def test_default_worker_policy_keeps_notpay_queryable_until_order_expiry(tmp_path):
    _assert_notpay_lifecycle_reaches_close(
        tmp_path,
        DEFAULT_WORKER_SERVICE_POLICY,
        order_id="worker-policy-order",
    )


def test_manual_refresh_policy_keeps_notpay_queryable_until_order_expiry(tmp_path):
    _assert_notpay_lifecycle_reaches_close(
        tmp_path,
        _REFRESH_POLICY,
        order_id="manual-policy-order",
    )


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
    assert record.claim_token is None
    assert record.claimed_by is None
    assert record.claimed_at is None
    assert record.lease_expires_at is None
    assert record.state_version == claim.state_version + 2


def test_close_paid_forces_one_follow_up_query_and_confirms_success(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _success(claim.order_id),
        ],
        CloseOrderResult(CloseOrderOutcome.PAID),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.PAID
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 1
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PAYMENT_CONFIRMED"


def test_close_paid_follow_up_closed_uses_existing_atomic_close(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _closed_query(claim.order_id),
        ],
        CloseOrderResult(CloseOrderOutcome.PAID),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.CLOSED
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]
    assert _order_state(path) == ("CLOSED", None)
    assert get(path, claim.order_id).terminal_reason == "PROVIDER_CLOSED"


@pytest.mark.parametrize(
    "follow_up",
    ("NOTPAY", "USERPAYING", "UNKNOWN", "RETRYABLE"),
)
def test_close_paid_uncertain_follow_up_stays_queryable_without_second_close(
    tmp_path, follow_up
):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    query_result = (
        WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)
        if follow_up == "RETRYABLE"
        else _simple_query(claim.order_id, QueryOrderOutcome[follow_up])
    )
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            query_result,
        ],
        CloseOrderResult(CloseOrderOutcome.PAID),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_last_close_attempt_paid_returns_to_query_instead_of_exhausting(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
    )
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        ],
        CloseOrderResult(CloseOrderOutcome.PAID),
    )

    service = _service(path, gateway, clock=clock)
    result = service.reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.close_attempt_count == POLICY.max_close_attempts
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]

    clock.set(record.next_attempt_at)
    next_claim = claim_order(
        path,
        order_id=claim.order_id,
        worker_id="next-worker",
        now=clock.current,
        lease_seconds=60,
    ).claim
    assert next_claim is not None

    result = service.reconcile_claim(next_claim, now=clock.current)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert gateway.queried == [claim.order_id] * 3
    assert gateway.closed == [claim.order_id]
    record = get(path, claim.order_id)
    assert record.close_attempt_count == POLICY.max_close_attempts
    assert record.reconcile_status == "READY"


def test_callback_between_close_paid_and_follow_up_query_remains_idempotent(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _success(claim.order_id),
        ],
        CloseOrderResult(CloseOrderOutcome.PAID),
        on_queries=[
            None,
            lambda: confirm_paid_order(
                path,
                _callback_evidence(claim.order_id),
                issued_by="wechat_callback",
                now=NOW - timedelta(seconds=1),
            ),
        ],
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 1
    assert get(path, claim.order_id).terminal_reason in {
        "ORDER_ALREADY_PAID",
        "PAYMENT_CONFIRMED",
    }


def test_close_paid_follow_up_crossing_lease_has_no_side_effects(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(tmp_path, expires_at=NOW, lease_seconds=1)
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _success(claim.order_id),
        ],
        CloseOrderResult(CloseOrderOutcome.PAID),
        on_close=lambda: clock.set(NOW + timedelta(seconds=1)),
    )

    result = _service(path, gateway, clock=clock).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    record = get(path, claim.order_id)
    assert record.reconcile_status == "CLAIMED"
    assert record.claim_token == claim.claim_token
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


@pytest.mark.parametrize(
    "failing_sql",
    ("UPDATE payment_orders", "UPDATE payment_reconciliations"),
)
def test_closed_and_terminal_roll_back_together_on_each_write_failure(
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

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        _service(path, FakeGateway(_closed_query(claim.order_id))).reconcile_claim(
            claim,
            now=NOW,
        )

    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, closed_at FROM payment_orders"
        ).fetchone()
        assert tuple(order) == ("WAITING_PAYMENT", "open", None)
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert get(path, claim.order_id) == before
    recovered = claim_order(
        path,
        order_id=claim.order_id,
        worker_id="worker-2",
        now=NOW + timedelta(seconds=60),
        lease_seconds=60,
    )
    assert recovered.claim is not None
    assert recovered.claim.claim_token != claim.claim_token


@pytest.mark.parametrize("claim_kind", ("token", "version"))
def test_closed_with_stale_claim_does_not_close_order(tmp_path, claim_kind):
    path, claim = _claimed_order(tmp_path)
    stale = replace(
        claim,
        claim_token="stale-token" if claim_kind == "token" else claim.claim_token,
        state_version=claim.state_version + (claim_kind == "version"),
    )
    before = get(path, claim.order_id)

    result = _service(path, FakeGateway(_closed_query(claim.order_id))).reconcile_claim(
        stale,
        now=NOW,
    )

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    assert get(path, claim.order_id) == before
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


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
    assert get(path, claim.order_id).terminal_reason in {
        "ORDER_ALREADY_PAID",
        "PAYMENT_CONFIRMED",
    }


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
    assert get(path, claim.order_id).reconcile_status == "TERMINAL"


def test_query_write_lock_before_callback_still_issues_one_grant(tmp_path, monkeypatch):
    path, claim = _claimed_order(tmp_path)
    query_locked = Event()
    release_query = Event()
    callback_attempted = Event()
    real_connect = payment_service.connect
    connect_count = 0

    def connect_factory(database_path):
        nonlocal connect_count
        connect_count += 1
        connection = real_connect(database_path)
        if connect_count == 1:
            return _PauseAfterBeginConnection(
                connection,
                query_locked,
                release_query,
            )
        if connect_count == 2:
            return _SignalBeforeBeginConnection(connection, callback_attempted)
        return connection

    monkeypatch.setattr(payment_service, "connect", connect_factory)
    with ThreadPoolExecutor(max_workers=2) as executor:
        query_future = executor.submit(
            _service(path, FakeGateway(_success(claim.order_id))).reconcile_claim,
            claim,
            now=NOW,
        )
        assert query_locked.wait(timeout=5)
        callback_future = executor.submit(
            confirm_paid_order,
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        )
        assert callback_attempted.wait(timeout=5)
        release_query.set()
        query_result = query_future.result(timeout=5)
        callback_result = callback_future.result(timeout=5)

    assert query_result.outcome is ReconciliationOutcome.PAID
    assert callback_result.idempotent is True
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 1
    assert get(path, claim.order_id).reconcile_status == "TERMINAL"


def test_success_payment_does_not_commit_when_old_claim_was_reclaimed(tmp_path):
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

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert reclaimed[0] is not None
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
    record = get(path, old_claim.order_id)
    assert record.claim_token == reclaimed[0].claim_token
    assert record.reconcile_status == "CLAIMED"


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


def test_mismatched_success_reports_concurrent_paid_order_as_already_paid(tmp_path):
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

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 1
    assert get(path, claim.order_id).terminal_reason in {
        "ORDER_ALREADY_PAID",
        "PAYMENT_CONFIRMED",
    }


def test_notpay_at_query_limit_remains_ready_without_changing_order(tmp_path):
    path, claim = _claimed_order(tmp_path, query_attempt_count=2)
    result = _service(
        path,
        FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.NOTPAY)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.next_attempt_at <= NOW + timedelta(minutes=1)
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
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason in {"ORDER_ALREADY_PAID", "PAYMENT_CONFIRMED"}
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


@pytest.mark.parametrize(
    "expires_at",
    (NOW + timedelta(minutes=1), NOW, NOW - timedelta(minutes=1)),
)
def test_userpaying_at_query_limit_remains_ready_without_closing(
    tmp_path, expires_at
):
    path, claim = _claimed_order(
        tmp_path,
        expires_at=expires_at,
        query_attempt_count=POLICY.max_query_attempts - 1,
    )
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.USERPAYING)
    )
    result = _service(
        path,
        gateway,
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.next_attempt_at == NOW + timedelta(seconds=8)
    assert gateway.closed == []
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_huge_pending_attempt_count_keeps_backoff_finite_and_bounded(tmp_path):
    path, claim = _claimed_order(
        tmp_path,
        query_attempt_count=10**9,
    )

    result = _service(
        path,
        FakeGateway(_simple_query(claim.order_id, QueryOrderOutcome.USERPAYING)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.next_attempt_at == NOW + timedelta(seconds=8)
    assert record.reconcile_status == "READY"


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

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1
    assert get(path, claim.order_id).terminal_reason in {
        "ORDER_ALREADY_PAID",
        "PAYMENT_CONFIRMED",
    }


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


def test_retryable_query_error_at_limit_stays_ready_without_order_change(tmp_path):
    path, claim = _claimed_order(tmp_path, query_attempt_count=2)

    result = _service(
        path,
        FakeGateway(WechatPaymentError("PAYMENT_CONNECT_TIMEOUT", retryable=True)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.terminal_at is None
    assert record.claim_token is None
    assert NOW < record.next_attempt_at <= NOW + timedelta(seconds=POLICY.query_retry_max_seconds)
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "WAITING_PAYMENT",
            "open",
        )
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 0


def test_retryable_query_errors_past_limit_stay_bounded_for_three_cycles(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(tmp_path, query_attempt_count=2)
    gateway = SequenceGateway(
        [WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)] * 3,
        None,
    )
    service = _service(path, gateway, clock=clock)

    for cycle in range(3):
        result = service.reconcile_claim(claim, now=clock.current)
        assert result.outcome is ReconciliationOutcome.RESCHEDULED
        record = get(path, claim.order_id)
        assert record.reconcile_status == "READY"
        assert record.terminal_reason is None
        assert clock.current < record.next_attempt_at <= clock.current + timedelta(
            seconds=POLICY.query_retry_max_seconds
        )
        assert len(gateway.queried) == cycle + 1
        with connect(path) as connection:
            assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
                "WAITING_PAYMENT",
                "open",
            )
            assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        if cycle < 2:
            claim = _claim_at_next_attempt(
                path,
                claim.order_id,
                clock,
                f"retryable-{cycle}",
            )


def test_huge_retryable_query_attempt_count_uses_bounded_backoff(tmp_path):
    path, claim = _claimed_order(tmp_path, query_attempt_count=10**9)

    result = _service(
        path,
        FakeGateway(WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.next_attempt_at == NOW + timedelta(seconds=POLICY.query_retry_max_seconds)


@pytest.mark.parametrize(
    ("follow_up", "expected_outcome", "order_state", "terminal_reason", "grants"),
    (
        (
            "SUCCESS",
            ReconciliationOutcome.PAID,
            ("PAID", None),
            "PAYMENT_CONFIRMED",
            1,
        ),
        (
            "CLOSED",
            ReconciliationOutcome.CLOSED,
            ("CLOSED", None),
            "PROVIDER_CLOSED",
            0,
        ),
    ),
)
def test_retryable_query_exhaustion_later_accepts_terminal_fact(
    tmp_path,
    follow_up,
    expected_outcome,
    order_state,
    terminal_reason,
    grants,
):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(tmp_path, query_attempt_count=2)
    gateway = SequenceGateway(
        [
            WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True),
            _success(claim.order_id) if follow_up == "SUCCESS" else _closed_query(claim.order_id),
        ],
        None,
    )
    service = _service(path, gateway, clock=clock)

    assert service.reconcile_claim(claim, now=NOW).outcome is ReconciliationOutcome.RESCHEDULED
    next_claim = _claim_at_next_attempt(path, claim.order_id, clock, "terminal-fact")
    result = service.reconcile_claim(next_claim, now=clock.current)

    assert result.outcome is expected_outcome
    assert _order_state(path) == order_state
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == terminal_reason
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == grants
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == grants


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
    assert get(path, claim.order_id).terminal_reason in {
        "ORDER_ALREADY_PAID",
        "PAYMENT_CONFIRMED",
    }


def test_callback_between_retry_snapshot_and_resolution_converges_paid(
    tmp_path, monkeypatch
):
    path, claim = _claimed_order(tmp_path)
    entered = Event()
    release = Event()
    target_name = (
        "resolve_retry_claim"
        if hasattr(reconciliation_service_module, "resolve_retry_claim")
        else "reschedule_claim"
    )
    real_resolution = getattr(reconciliation_service_module, target_name)

    def paused_resolution(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return real_resolution(*args, **kwargs)

    monkeypatch.setattr(
        reconciliation_service_module,
        target_name,
        paused_resolution,
    )
    service = _service(
        path,
        FakeGateway(WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        retry_future = executor.submit(service.reconcile_claim, claim, now=NOW)
        assert entered.wait(timeout=5)
        confirm_paid_order(
            path,
            _callback_evidence(claim.order_id),
            issued_by="wechat_callback",
            now=NOW,
        )
        release.set()
        result = retry_future.result(timeout=5)

    assert result.outcome is ReconciliationOutcome.ALREADY_PAID
    assert _order_state(path) == ("PAID", None)
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason in {"ORDER_ALREADY_PAID", "PAYMENT_CONFIRMED"}
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1


@pytest.mark.parametrize(
    ("order_status", "expected_outcome", "terminal_reason"),
    (
        ("CLOSED", ReconciliationOutcome.ALREADY_CLOSED, "PROVIDER_CLOSED"),
        ("ABNORMAL", ReconciliationOutcome.TERMINAL_ABNORMAL, "ORDER_ALREADY_ABNORMAL"),
    ),
)
def test_retry_resolution_never_reschedules_closed_or_abnormal_order(
    tmp_path, order_status, expected_outcome, terminal_reason
):
    path, claim = _claimed_order(tmp_path)

    def change_order_state():
        with connect(path) as connection:
            values = (
                ("CLOSED", None, datetime_text(NOW))
                if order_status == "CLOSED"
                else ("ABNORMAL", "open", None)
            )
            connection.execute(
                "UPDATE payment_orders SET status=?, open_slot=?, closed_at=? "
                "WHERE order_id=?",
                (*values, claim.order_id),
            )
            connection.commit()

    result = _service(
        path,
        FakeGateway(
            WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True),
            on_query=change_order_state,
        ),
    ).reconcile_claim(claim, now=NOW)

    assert result.outcome is expected_outcome
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == terminal_reason
    assert record.claim_token is None
    assert _order_state(path) == (
        ("CLOSED", None) if order_status == "CLOSED" else ("ABNORMAL", "open")
    )


def test_retry_ready_then_callback_converges_paid_terminal(tmp_path):
    path, claim = _claimed_order(tmp_path)
    result = _service(
        path,
        FakeGateway(WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)),
    ).reconcile_claim(claim, now=NOW)
    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert get(path, claim.order_id).reconcile_status == "READY"

    confirm_paid_order(
        path,
        _callback_evidence(claim.order_id),
        issued_by="wechat_callback",
        now=NOW,
    )

    assert _order_state(path) == ("PAID", None)
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PAYMENT_CONFIRMED"
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1


@pytest.mark.parametrize("first_writer", ("callback", "retry"))
def test_retry_and_callback_competing_write_locks_converge_paid_terminal(
    tmp_path, monkeypatch, first_writer
):
    path, claim = _claimed_order(tmp_path)
    lock_held = Event()
    release_first = Event()
    second_attempted = Event()
    service = _service(
        path,
        FakeGateway(WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)),
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        if first_writer == "callback":
            real_connect = payment_service.connect
            connect_count = 0

            def connect_factory(database_path):
                nonlocal connect_count
                connect_count += 1
                connection = real_connect(database_path)
                if connect_count == 1:
                    return _PauseAfterBeginConnection(
                        connection,
                        lock_held,
                        release_first,
                    )
                return connection

            monkeypatch.setattr(payment_service, "connect", connect_factory)
            target_name = (
                "resolve_retry_claim"
                if hasattr(reconciliation_service_module, "resolve_retry_claim")
                else "reschedule_claim"
            )
            real_resolution = getattr(reconciliation_service_module, target_name)

            def observed_resolution(*args, **kwargs):
                second_attempted.set()
                return real_resolution(*args, **kwargs)

            monkeypatch.setattr(
                reconciliation_service_module,
                target_name,
                observed_resolution,
            )
            callback_future = executor.submit(
                confirm_paid_order,
                path,
                _callback_evidence(claim.order_id),
                issued_by="wechat_callback",
                now=NOW,
            )
            assert lock_held.wait(timeout=5)
            retry_future = executor.submit(service.reconcile_claim, claim, now=NOW)
            assert second_attempted.wait(timeout=5)
        else:
            real_write_transaction = reconciliation_repository.write_transaction

            @contextmanager
            def paused_write_transaction(database_path):
                with real_write_transaction(database_path) as connection:
                    lock_held.set()
                    assert release_first.wait(timeout=5)
                    yield connection

            monkeypatch.setattr(
                reconciliation_repository,
                "write_transaction",
                paused_write_transaction,
            )
            retry_future = executor.submit(service.reconcile_claim, claim, now=NOW)
            assert lock_held.wait(timeout=5)
            real_connect = payment_service.connect
            monkeypatch.setattr(
                payment_service,
                "connect",
                lambda database_path: _SignalBeforeBeginConnection(
                    real_connect(database_path),
                    second_attempted,
                ),
            )
            callback_future = executor.submit(
                confirm_paid_order,
                path,
                _callback_evidence(claim.order_id),
                issued_by="wechat_callback",
                now=NOW,
            )
            assert second_attempted.wait(timeout=5)

        release_first.set()
        retry_result = retry_future.result(timeout=5)
        callback_result = callback_future.result(timeout=5)

    assert retry_result.outcome is (
        ReconciliationOutcome.ALREADY_PAID
        if first_writer == "callback"
        else ReconciliationOutcome.RESCHEDULED
    )
    assert callback_result.idempotent is False
    assert _order_state(path) == ("PAID", None)
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PAYMENT_CONFIRMED"
    assert record.claim_token is None
    assert record.state_version == claim.state_version + (
        1 if first_writer == "callback" else 2
    )
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1


@pytest.mark.parametrize(
    "code",
    (
        "PAYMENT_RESPONSE_SIGNATURE_INVALID",
        "PAYMENT_RESPONSE_INVALID",
        "PAYMENT_CONFIG_PRIVATE_KEY_INVALID",
        "PAYMENT_UPSTREAM_REJECTED",
    ),
)
def test_nonretryable_query_error_fails_fast_without_business_write(tmp_path, code):
    path, claim = _claimed_order(tmp_path)
    before = get(path, claim.order_id)

    with pytest.raises(WechatPaymentError, match=code):
        _service(path, FakeGateway(WechatPaymentError(code))).reconcile_claim(
            claim,
            now=NOW,
        )

    assert get(path, claim.order_id) == before
    with connect(path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "WAITING_PAYMENT",
            "open",
        )
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


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


def test_retryable_close_gateway_error_retries_without_local_close(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        WechatPaymentError("PAYMENT_CLOSE_FAILED", retryable=True),
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert get(path, claim.order_id).last_error_code == "CLOSE_GATEWAY_RETRYABLE"
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_nonretryable_close_gateway_error_fails_fast_without_business_terminal(tmp_path):
    path, claim = _claimed_order(tmp_path, expires_at=NOW)
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        WechatPaymentError("PAYMENT_CONFIG_PRIVATE_KEY_INVALID"),
    )

    with pytest.raises(WechatPaymentError, match="PAYMENT_CONFIG_PRIVATE_KEY_INVALID"):
        _service(path, gateway).reconcile_claim(claim, now=NOW)

    record = get(path, claim.order_id)
    assert record.reconcile_status == "CLAIMED"
    assert record.terminal_reason is None
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


@pytest.mark.parametrize(
    ("close_result", "error_code"),
    (
        (CloseOrderResult(CloseOrderOutcome.UNKNOWN), "CLOSE_RESULT_UNKNOWN"),
        (
            WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True),
            "CLOSE_GATEWAY_RETRYABLE",
        ),
        (CloseOrderResult(CloseOrderOutcome.REJECTED), "CLOSE_RESULT_UNKNOWN"),
        (CloseOrderResult(CloseOrderOutcome.NOT_FOUND), "CLOSE_RESULT_UNKNOWN"),
    ),
)
def test_last_close_uncertain_result_returns_to_query_only_without_terminal(
    tmp_path, close_result, error_code
):
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
    )
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        close_result,
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert gateway.queried == gateway.closed == [claim.order_id]
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.terminal_at is None
    assert record.claim_token is None
    assert record.claimed_by is None
    assert record.claimed_at is None
    assert record.lease_expires_at is None
    assert record.close_attempt_count == POLICY.max_close_attempts
    assert NOW < record.next_attempt_at <= NOW + timedelta(
        seconds=POLICY.query_retry_max_seconds
    )
    assert record.last_error_code == error_code
    with connect(path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, closed_at, paid_at FROM payment_orders"
        ).fetchone()
        assert tuple(order) == ("WAITING_PAYMENT", "open", None, None)
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == 0


def test_close_exhaustion_runs_three_query_only_cycles_without_more_close(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
    )
    gateway = SequenceGateway(
        [_simple_query(claim.order_id, QueryOrderOutcome.NOTPAY)] * 4,
        CloseOrderResult(CloseOrderOutcome.UNKNOWN),
    )
    service = _service(path, gateway, clock=clock)

    assert service.reconcile_claim(claim, now=NOW).outcome is ReconciliationOutcome.RESCHEDULED
    for cycle in range(3):
        claim = _claim_at_next_attempt(path, claim.order_id, clock, f"query-only-{cycle}")
        assert service.reconcile_claim(
            claim, now=clock.current
        ).outcome is ReconciliationOutcome.RESCHEDULED
        record = get(path, claim.order_id)
        assert record.reconcile_status == "READY"
        assert record.terminal_reason is None
        assert record.close_attempt_count == POLICY.max_close_attempts
        assert clock.current < record.next_attempt_at <= clock.current + timedelta(
            seconds=POLICY.query_retry_max_seconds
        )
        assert gateway.closed == [claim.order_id]
        assert len(gateway.queried) == cycle + 2
    assert _order_state(path) == ("WAITING_PAYMENT", "open")


@pytest.mark.parametrize(
    ("follow_up", "expected_outcome", "order_state", "terminal_reason", "grants"),
    (
        (
            "SUCCESS",
            ReconciliationOutcome.PAID,
            ("PAID", None),
            "PAYMENT_CONFIRMED",
            1,
        ),
        (
            "CLOSED",
            ReconciliationOutcome.CLOSED,
            ("CLOSED", None),
            "PROVIDER_CLOSED",
            0,
        ),
    ),
)
def test_query_only_after_close_exhaustion_accepts_trusted_terminal_query(
    tmp_path, follow_up, expected_outcome, order_state, terminal_reason, grants
):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
    )
    gateway = SequenceGateway(
        [
            _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
            _success(claim.order_id)
            if follow_up == "SUCCESS"
            else _closed_query(claim.order_id),
        ],
        CloseOrderResult(CloseOrderOutcome.UNKNOWN),
    )
    service = _service(path, gateway, clock=clock)

    assert service.reconcile_claim(claim, now=NOW).outcome is ReconciliationOutcome.RESCHEDULED
    next_claim = _claim_at_next_attempt(path, claim.order_id, clock, "terminal-query")
    result = service.reconcile_claim(next_claim, now=clock.current)

    assert result.outcome is expected_outcome
    assert _order_state(path) == order_state
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == terminal_reason
    assert record.close_attempt_count == POLICY.max_close_attempts
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == grants
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0] == grants


@pytest.mark.parametrize(
    "follow_up",
    ("USERPAYING", "UNKNOWN", "RETRYABLE"),
    ids=("userpaying", "unknown", "retryable-error"),
)
def test_query_only_after_close_exhaustion_keeps_uncertain_queryable(
    tmp_path, follow_up
):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
    )
    follow_up_result = (
        WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)
        if follow_up == "RETRYABLE"
        else _simple_query(claim.order_id, QueryOrderOutcome[follow_up])
    )
    gateway = SequenceGateway(
        [_simple_query(claim.order_id, QueryOrderOutcome.NOTPAY), follow_up_result],
        CloseOrderResult(CloseOrderOutcome.UNKNOWN),
    )
    service = _service(path, gateway, clock=clock)

    assert service.reconcile_claim(claim, now=NOW).outcome is ReconciliationOutcome.RESCHEDULED
    next_claim = _claim_at_next_attempt(path, claim.order_id, clock, "uncertain-query")
    result = service.reconcile_claim(next_claim, now=clock.current)

    assert result.outcome is ReconciliationOutcome.RESCHEDULED
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    record = get(path, claim.order_id)
    assert record.reconcile_status == "READY"
    assert record.terminal_reason is None
    assert record.close_attempt_count == POLICY.max_close_attempts
    assert record.next_attempt_at > clock.current
    assert gateway.queried == [claim.order_id, claim.order_id]
    assert gateway.closed == [claim.order_id]
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


def test_last_uncertain_close_after_lease_expiry_loses_claim_without_reschedule(tmp_path):
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
        lease_seconds=1,
    )
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.UNKNOWN),
        on_close=lambda: clock.set(NOW + timedelta(seconds=1)),
    )

    result = _service(path, gateway, clock=clock).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert _order_state(path) == ("WAITING_PAYMENT", "open")
    record = get(path, claim.order_id)
    assert record.reconcile_status == "CLAIMED"
    assert record.claim_token == claim.claim_token
    assert record.close_attempt_count == POLICY.max_close_attempts
    assert record.terminal_reason is None
    assert record.next_attempt_at is None


def test_stale_uncertain_close_cannot_reschedule_reclaimed_token_or_version(tmp_path):
    path, claim = _claimed_order(
        tmp_path,
        expires_at=NOW,
        close_attempt_count=POLICY.max_close_attempts - 1,
    )
    reclaimed = []

    def reclaim():
        reclaimed.append(
            claim_order(
                path,
                order_id=claim.order_id,
                worker_id="replacement",
                now=NOW + timedelta(seconds=60),
                lease_seconds=60,
            ).claim
        )

    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.UNKNOWN),
        on_close=reclaim,
    )

    result = _service(path, gateway).reconcile_claim(claim, now=NOW)

    assert result.outcome is ReconciliationOutcome.LOST_CLAIM
    assert reclaimed[0] is not None
    record = get(path, claim.order_id)
    assert record.reconcile_status == "CLAIMED"
    assert record.claim_token == reclaimed[0].claim_token
    assert record.state_version == reclaimed[0].state_version
    assert record.terminal_reason is None
    assert _order_state(path) == ("WAITING_PAYMENT", "open")


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
    record = get(path, claim.order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason in {"ORDER_ALREADY_PAID", "PAYMENT_CONFIRMED"}


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


class SequenceGateway(FakeGateway):
    def __init__(
        self,
        query_results,
        close_result,
        *,
        on_queries=None,
        on_close=None,
    ):
        super().__init__(None, close_result, on_close=on_close)
        self.query_results = list(query_results)
        self.on_queries = list(on_queries or [None] * len(self.query_results))

    def query_order(self, order_id):
        index = len(self.queried)
        self.queried.append(order_id)
        assert index < len(self.query_results)
        callback = self.on_queries[index]
        if callback is not None:
            callback()
        result = self.query_results[index]
        if isinstance(result, Exception):
            raise result
        return result


def _service(path, gateway, policy=POLICY, clock=None):
    return PaymentReconciliationService(
        database_path=path,
        gateway=gateway,
        expected_appid=APP_ID,
        expected_mchid=MCH_ID,
        policy=policy,
        clock=clock or (lambda: NOW),
    )


def _claim_at_next_attempt(path, order_id, clock, worker_id):
    record = get(path, order_id)
    assert record.next_attempt_at is not None
    clock.set(record.next_attempt_at)
    claim = claim_order(
        path,
        order_id=order_id,
        worker_id=worker_id,
        now=clock.current,
        lease_seconds=60,
    ).claim
    assert claim is not None
    return claim


def _assert_notpay_lifecycle_reaches_close(tmp_path, policy, *, order_id):
    expires_at = NOW + timedelta(seconds=900)
    clock = _MutableClock(NOW)
    path, claim = _claimed_order(
        tmp_path,
        expires_at=expires_at,
        order_id=order_id,
    )
    gateway = FakeGateway(
        _simple_query(claim.order_id, QueryOrderOutcome.NOTPAY),
        CloseOrderResult(CloseOrderOutcome.CLOSED),
    )
    service = _service(path, gateway, policy, clock=clock)

    while clock.current < expires_at:
        result = service.reconcile_claim(claim, now=clock.current)
        assert result.outcome is ReconciliationOutcome.RESCHEDULED
        assert _order_state(path) == ("WAITING_PAYMENT", "open")
        record = get(path, claim.order_id)
        assert record.reconcile_status == "READY"
        assert record.terminal_reason is None
        assert clock.current < record.next_attempt_at <= expires_at
        clock.set(record.next_attempt_at)
        claimed = claim_order(
            path,
            order_id=claim.order_id,
            worker_id="next-worker",
            now=clock.current,
            lease_seconds=60,
        )
        assert claimed.claim is not None
        claim = claimed.claim

    result = service.reconcile_claim(claim, now=clock.current)
    assert result.outcome is ReconciliationOutcome.CLOSED
    assert gateway.closed == [claim.order_id]
    assert _order_state(path) == ("CLOSED", None)
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0


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


class _PauseAfterBeginConnection:
    def __init__(self, connection, entered, release):
        self._connection = connection
        self._entered = entered
        self._release = release

    def execute(self, sql, parameters=()):
        cursor = self._connection.execute(sql, parameters)
        if " ".join(sql.split()) == "BEGIN IMMEDIATE":
            self._entered.set()
            assert self._release.wait(timeout=5)
        return cursor

    def __getattr__(self, name):
        return getattr(self._connection, name)


class _SignalBeforeBeginConnection:
    def __init__(self, connection, attempted):
        self._connection = connection
        self._attempted = attempted

    def execute(self, sql, parameters=()):
        if " ".join(sql.split()) == "BEGIN IMMEDIATE":
            self._attempted.set()
        return self._connection.execute(sql, parameters)

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
