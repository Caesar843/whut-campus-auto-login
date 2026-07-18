import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest

from license_server import payment_reconciliation_repository as repository
from license_server.db import connect, initialize_database
from license_server.payment_reconciliation_repository import (
    EnsureReadyOutcome,
    ClaimOrderOutcome,
    PaymentReconciliationRepositoryError,
    UpdateOutcome,
    begin_close_attempt,
    claim_next_due,
    claim_order,
    ensure_ready,
    get,
    reschedule_claim,
    terminate_claim,
)
from license_server.signer import datetime_text


NOW = datetime(2026, 7, 15, tzinfo=timezone.utc)


def test_ensure_ready_creates_initial_record_without_changing_order(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-1", "WAITING_PAYMENT")
    before = _order_row(database_path, "order-1")

    result = ensure_ready(
        database_path,
        order_id="order-1",
        now=NOW,
        next_attempt_at=NOW,
    )

    assert result.outcome is EnsureReadyOutcome.CREATED
    assert result.record == get(database_path, "order-1")
    record = result.record
    assert record is not None
    assert record.order_id == "order-1"
    assert record.reconcile_status == "READY"
    assert record.next_attempt_at == NOW
    assert record.query_attempt_count == 0
    assert record.close_attempt_count == 0
    assert record.state_version == 0
    assert record.claim_token is None
    assert record.terminal_reason is None
    assert record.updated_at == NOW
    assert _order_row(database_path, "order-1") == before


def test_ensure_ready_is_idempotent_and_preserves_existing_state(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-1", "WAITING_PAYMENT")
    first = ensure_ready(
        database_path,
        order_id="order-1",
        now=NOW,
        next_attempt_at=NOW + timedelta(seconds=10),
    )
    with connect(database_path) as connection:
        connection.execute(
            """
            UPDATE payment_reconciliations
            SET last_query_at = ?, query_attempt_count = 2,
                trusted_trade_state = 'NOTPAY', last_error_code = 'TEMPORARY_ERROR',
                state_version = 3
            WHERE order_id = 'order-1'
            """,
            (datetime_text(NOW),),
        )
        connection.commit()
    before = get(database_path, "order-1")

    second = ensure_ready(
        database_path,
        order_id="order-1",
        now=NOW + timedelta(seconds=5),
        next_attempt_at=NOW + timedelta(seconds=99),
    )

    assert first.outcome is EnsureReadyOutcome.CREATED
    assert second.outcome is EnsureReadyOutcome.EXISTING
    assert second.record == before
    assert get(database_path, "order-1") == before


@pytest.mark.parametrize("status", ("CREATED", "PAID", "CLOSED", "ABNORMAL"))
def test_ensure_ready_rejects_ineligible_order_without_creating_task(
    tmp_path, status
):
    database_path = tmp_path / f"{status}.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-1", status)
    before = _order_row(database_path, "order-1")

    result = ensure_ready(
        database_path,
        order_id="order-1",
        now=NOW,
        next_attempt_at=NOW,
    )

    assert result.outcome is EnsureReadyOutcome.NOT_ELIGIBLE
    assert result.record is None
    assert get(database_path, "order-1") is None
    assert _order_row(database_path, "order-1") == before


def test_ensure_ready_reports_missing_order_without_creating_task(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    result = ensure_ready(
        database_path,
        order_id="missing",
        now=NOW,
        next_attempt_at=NOW,
    )

    assert result.outcome is EnsureReadyOutcome.NOT_FOUND
    assert result.record is None
    assert get(database_path, "missing") is None


def test_get_is_read_only_and_missing_returns_none(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-1", "WAITING_PAYMENT")
    ensure_ready(database_path, "order-1", NOW, NOW)
    before = _raw_task(database_path, "order-1")

    assert get(database_path, "order-1") is not None
    assert get(database_path, "missing") is None
    assert _raw_task(database_path, "order-1") == before


@pytest.mark.parametrize(
    "field,value",
    (
        ("order_id", ""),
        ("order_id", "x" * 129),
        ("now", datetime(2026, 7, 15)),
        ("next_attempt_at", datetime(2026, 7, 15)),
    ),
)
def test_ensure_ready_rejects_invalid_input(tmp_path, field, value):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    values = {
        "order_id": "order-1",
        "now": NOW,
        "next_attempt_at": NOW,
    }
    values[field] = value

    with pytest.raises(PaymentReconciliationRepositoryError) as exc_info:
        ensure_ready(database_path, **values)

    assert exc_info.value.code == "PAYMENT_RECONCILIATION_INPUT_INVALID"
    assert not exc_info.value.retryable


def test_claim_next_due_uses_stable_order_and_claims_one_at_a_time(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    for order_id in ("order-b", "order-a", "order-c"):
        _insert_order(path, order_id, "WAITING_PAYMENT")
        ensure_ready(path, order_id, NOW, NOW)

    first = claim_next_due(path, worker_id="worker-1", now=NOW, lease_seconds=30)
    second = claim_next_due(path, worker_id="worker-2", now=NOW, lease_seconds=30)
    third = claim_next_due(path, worker_id="worker-3", now=NOW, lease_seconds=30)
    none = claim_next_due(path, worker_id="worker-4", now=NOW, lease_seconds=30)

    assert [first.order_id, second.order_id, third.order_id] == ["order-a", "order-b", "order-c"]
    assert len({first.claim_token, second.claim_token, third.claim_token}) == 3
    assert all(claim.query_attempt_count == 1 and claim.state_version == 1 for claim in (first, second, third))
    assert none is None


def test_claim_due_and_expired_boundaries_and_order_eligibility(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    for order_id in ("future", "equal", "expired", "paid"):
        _insert_order(path, order_id, "WAITING_PAYMENT")
        ensure_ready(path, order_id, NOW, NOW + (timedelta(seconds=1) if order_id == "future" else timedelta()))
    old = claim_order(path, order_id="expired", worker_id="old", now=NOW, lease_seconds=10).claim
    equal = claim_order(path, order_id="equal", worker_id="old", now=NOW, lease_seconds=10).claim
    with connect(path) as connection:
        connection.execute(
            "UPDATE payment_reconciliations SET claimed_at=?, lease_expires_at=? WHERE order_id='expired'",
            (datetime_text(NOW - timedelta(seconds=1)), datetime_text(NOW)),
        )
        connection.execute("UPDATE payment_orders SET status='PAID', open_slot=NULL, paid_at=? WHERE order_id='paid'", (datetime_text(NOW),))
        connection.commit()

    assert claim_order(path, order_id="missing", worker_id="w", now=NOW, lease_seconds=10).outcome is ClaimOrderOutcome.NOT_FOUND
    assert claim_order(path, order_id="future", worker_id="w", now=NOW, lease_seconds=10).outcome is ClaimOrderOutcome.NOT_DUE
    assert claim_order(path, order_id="equal", worker_id="w", now=NOW + timedelta(seconds=9), lease_seconds=10).outcome is ClaimOrderOutcome.IN_PROGRESS
    reclaimed = claim_order(path, order_id="expired", worker_id="new", now=NOW, lease_seconds=10)
    assert reclaimed.outcome is ClaimOrderOutcome.CLAIMED
    assert reclaimed.claim.claim_token != old.claim_token
    assert reclaimed.claim.query_attempt_count == 2
    assert claim_order(path, order_id="paid", worker_id="w", now=NOW, lease_seconds=10).outcome is ClaimOrderOutcome.NOT_ELIGIBLE
    assert equal is not None


def test_claim_next_skips_future_and_each_ineligible_order_status(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "future", "WAITING_PAYMENT")
    ensure_ready(path, "future", NOW, NOW + timedelta(seconds=1))
    for status in ("PAID", "CLOSED", "ABNORMAL"):
        order_id = status.lower()
        _insert_order(path, order_id, "WAITING_PAYMENT")
        ensure_ready(path, order_id, NOW, NOW)
        with connect(path) as connection:
            if status == "PAID":
                connection.execute(
                    "UPDATE payment_orders SET status='PAID', open_slot=NULL, paid_at=? WHERE order_id=?",
                    (datetime_text(NOW), order_id),
                )
            elif status == "CLOSED":
                connection.execute(
                    "UPDATE payment_orders SET status='CLOSED', open_slot=NULL, closed_at=? WHERE order_id=?",
                    (datetime_text(NOW), order_id),
                )
            else:
                connection.execute(
                    "UPDATE payment_orders SET status='ABNORMAL' WHERE order_id=?",
                    (order_id,),
                )
            connection.commit()

    assert claim_next_due(path, worker_id="w", now=NOW, lease_seconds=10) is None


@pytest.mark.parametrize("race_kind", ("next_next", "reclaim_reclaim", "next_order"))
def test_concurrent_claimers_never_receive_same_order(tmp_path, race_kind):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "one", "WAITING_PAYMENT")
    ensure_ready(path, "one", NOW, NOW)
    race_now = NOW
    expected_count = 1
    if race_kind == "reclaim_reclaim":
        claim_next_due(path, worker_id="old", now=NOW, lease_seconds=10)
        race_now = NOW + timedelta(seconds=10)
        expected_count = 2
    barrier = Barrier(2)

    def run(index):
        barrier.wait()
        if race_kind == "next_order" and index == 1:
            return claim_order(
                path, order_id="one", worker_id="manual", now=race_now,
                lease_seconds=30,
            ).claim
        return claim_next_due(
            path, worker_id=f"w-{index}", now=race_now, lease_seconds=30
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(run, range(2)))

    claimed = [claim for claim in claims if claim is not None]
    assert len(claimed) == 1
    record = get(path, "one")
    assert record.query_attempt_count == expected_count
    assert record.state_version == expected_count
    assert record.claim_token == claimed[0].claim_token


def test_begin_close_and_reschedule_use_strict_lease_and_cas(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    before_order = _order_row(path, "order-1")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="w", now=NOW, lease_seconds=30)

    close = begin_close_attempt(path, claim_token=claim.claim_token, expected_state_version=claim.state_version, now=NOW + timedelta(seconds=1))
    assert close.outcome is UpdateOutcome.UPDATED
    assert close.claim.close_attempt_count == 1
    assert close.claim.state_version == 2
    assert get(path, "order-1").last_close_at is None
    stale = reschedule_claim(path, claim_token=claim.claim_token, expected_state_version=1, completed_at=NOW + timedelta(seconds=2), next_attempt_at=NOW + timedelta(seconds=10))
    assert stale.outcome is UpdateOutcome.LOST_CLAIM
    result = reschedule_claim(
        path, claim_token=claim.claim_token, expected_state_version=2,
        completed_at=NOW + timedelta(seconds=2), next_attempt_at=NOW + timedelta(seconds=10),
        trusted_trade_state="NOTPAY", last_error_code="QUERY_TIMEOUT",
        query_completed=True, close_completed=True,
    )
    assert result.outcome is UpdateOutcome.UPDATED
    assert result.record.reconcile_status == "READY"
    assert result.record.state_version == 3
    assert result.record.claim_token is None
    assert result.record.last_query_at == NOW + timedelta(seconds=2)
    assert result.record.last_close_at == NOW + timedelta(seconds=2)
    assert _order_row(path, "order-1") == before_order


@pytest.mark.parametrize("operation", ("close", "reschedule", "terminate"))
def test_completion_at_lease_boundary_loses_claim_without_mutation(tmp_path, operation):
    path = tmp_path / f"{operation}.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="w", now=NOW, lease_seconds=10)
    before = _raw_task(path, "order-1")
    common = dict(claim_token=claim.claim_token, expected_state_version=claim.state_version)
    if operation == "close":
        result = begin_close_attempt(path, now=NOW + timedelta(seconds=10), **common)
    elif operation == "reschedule":
        result = reschedule_claim(path, completed_at=NOW + timedelta(seconds=10), next_attempt_at=NOW + timedelta(seconds=20), **common)
    else:
        result = terminate_claim(path, terminal_at=NOW + timedelta(seconds=10), terminal_reason="ORDER_CLOSED", **common)
    assert result.outcome is UpdateOutcome.LOST_CLAIM
    assert _raw_task(path, "order-1") == before


def test_expired_old_token_cannot_mutate_reclaimed_task_and_new_token_can_terminate(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    old = claim_next_due(path, worker_id="old", now=NOW, lease_seconds=10)
    new = claim_next_due(path, worker_id="new", now=NOW + timedelta(seconds=10), lease_seconds=10)
    before = _raw_task(path, "order-1")
    assert begin_close_attempt(path, claim_token=old.claim_token, expected_state_version=old.state_version, now=NOW + timedelta(seconds=11)).outcome is UpdateOutcome.LOST_CLAIM
    assert reschedule_claim(path, claim_token=old.claim_token, expected_state_version=old.state_version, completed_at=NOW + timedelta(seconds=11), next_attempt_at=NOW + timedelta(seconds=20)).outcome is UpdateOutcome.LOST_CLAIM
    assert terminate_claim(path, claim_token=old.claim_token, expected_state_version=old.state_version, terminal_at=NOW + timedelta(seconds=11), terminal_reason="ORDER_CLOSED").outcome is UpdateOutcome.LOST_CLAIM
    assert _raw_task(path, "order-1") == before
    done = terminate_claim(path, claim_token=new.claim_token, expected_state_version=new.state_version, terminal_at=NOW + timedelta(seconds=11), terminal_reason="ORDER_CLOSED", trusted_trade_state="CLOSED", query_completed=True)
    assert done.outcome is UpdateOutcome.UPDATED
    assert done.record.reconcile_status == "TERMINAL"
    assert done.record.terminal_reason == "ORDER_CLOSED"
    assert done.record.state_version == new.state_version + 1
    assert claim_next_due(path, worker_id="third", now=NOW + timedelta(days=1), lease_seconds=10) is None
    assert claim_order(
        path, order_id="order-1", worker_id="third",
        now=NOW + timedelta(days=1), lease_seconds=10,
    ).outcome is ClaimOrderOutcome.TERMINAL


@pytest.mark.parametrize("operation", ("close", "reschedule", "terminate"))
@pytest.mark.parametrize("offset,expected", ((9, UpdateOutcome.UPDATED), (10, UpdateOutcome.LOST_CLAIM), (11, UpdateOutcome.LOST_CLAIM)))
def test_each_cas_operation_enforces_strict_lease(tmp_path, operation, offset, expected):
    path = tmp_path / f"{operation}-{offset}.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="w", now=NOW, lease_seconds=10)
    common = dict(claim_token=claim.claim_token, expected_state_version=claim.state_version)
    at = NOW + timedelta(seconds=offset)
    if operation == "close":
        result = begin_close_attempt(path, now=at, **common)
    elif operation == "reschedule":
        result = reschedule_claim(path, completed_at=at, next_attempt_at=at + timedelta(seconds=1), **common)
    else:
        result = terminate_claim(path, terminal_at=at, terminal_reason="ORDER_CLOSED", **common)
    assert result.outcome is expected


def test_reschedule_reads_operation_clock_after_write_lock(tmp_path, monkeypatch):
    from license_server import payment_reconciliation_repository as repository

    path = tmp_path / "clock.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="worker-1", now=NOW, lease_seconds=10)
    lock_held = False
    real_write_transaction = repository.write_transaction

    @contextmanager
    def tracked_write_transaction(database_path):
        nonlocal lock_held
        with real_write_transaction(database_path) as connection:
            lock_held = True
            try:
                yield connection
            finally:
                lock_held = False

    def clock():
        assert lock_held
        return NOW + timedelta(seconds=1)

    monkeypatch.setattr(repository, "write_transaction", tracked_write_transaction)
    result = reschedule_claim(
        path,
        claim_token=claim.claim_token,
        expected_state_version=claim.state_version,
        completed_at=NOW,
        next_attempt_at=NOW + timedelta(seconds=2),
        query_completed=True,
        clock=clock,
    )

    assert result.outcome is UpdateOutcome.UPDATED
    assert result.record.updated_at == NOW + timedelta(seconds=1)
    assert result.record.last_query_at == NOW + timedelta(seconds=1)


@pytest.mark.parametrize(
    ("order_status", "expected_outcome", "expected_status", "terminal_reason"),
    (
        ("WAITING_PAYMENT", "rescheduled", "READY", None),
        ("PAID", "already_paid", "TERMINAL", "ORDER_ALREADY_PAID"),
        ("CLOSED", "already_closed", "TERMINAL", "PROVIDER_CLOSED"),
        ("ABNORMAL", "already_abnormal", "TERMINAL", "ORDER_ALREADY_ABNORMAL"),
    ),
)
def test_resolve_retry_claim_uses_authoritative_order_state(
    tmp_path,
    order_status,
    expected_outcome,
    expected_status,
    terminal_reason,
):
    path = tmp_path / f"retry-{order_status}.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="worker-1", now=NOW, lease_seconds=30)
    if order_status != "WAITING_PAYMENT":
        with connect(path) as connection:
            values = {
                "PAID": ("PAID", None, datetime_text(NOW), None),
                "CLOSED": ("CLOSED", None, None, datetime_text(NOW)),
                "ABNORMAL": ("ABNORMAL", "open", None, None),
            }[order_status]
            connection.execute(
                "UPDATE payment_orders SET status=?, open_slot=?, paid_at=?, closed_at=? "
                "WHERE order_id='order-1'",
                values,
            )
            connection.commit()

    result = repository.resolve_retry_claim(
        path,
        order_id=claim.order_id,
        claim_token=claim.claim_token,
        expected_state_version=claim.state_version,
        completed_at=NOW + timedelta(seconds=1),
        next_attempt_at=NOW + timedelta(seconds=5),
        last_error_code="QUERY_GATEWAY_RETRYABLE",
        query_completed=True,
    )

    assert result.outcome.value == expected_outcome
    record = get(path, "order-1")
    assert record.reconcile_status == expected_status
    assert record.terminal_reason == terminal_reason
    assert record.claim_token is None
    assert record.claimed_by is None
    assert record.claimed_at is None
    assert record.lease_expires_at is None
    assert record.state_version == claim.state_version + 1
    if expected_status == "READY":
        assert record.next_attempt_at == NOW + timedelta(seconds=5)
        assert record.terminal_at is None
    else:
        assert record.next_attempt_at is None
        assert record.terminal_at == NOW + timedelta(seconds=1)


@pytest.mark.parametrize("stale_kind", ("token", "version", "lease"))
def test_resolve_retry_claim_rejects_stale_claim_without_side_effects(
    tmp_path, stale_kind
):
    path = tmp_path / f"stale-{stale_kind}.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="worker-1", now=NOW, lease_seconds=10)
    before_order = _order_row(path, "order-1")
    before_task = _raw_task(path, "order-1")
    token = "stale-token" if stale_kind == "token" else claim.claim_token
    version = claim.state_version + 1 if stale_kind == "version" else claim.state_version
    completed_at = NOW + timedelta(seconds=10 if stale_kind == "lease" else 1)

    result = repository.resolve_retry_claim(
        path,
        order_id=claim.order_id,
        claim_token=token,
        expected_state_version=version,
        completed_at=completed_at,
        next_attempt_at=completed_at + timedelta(seconds=1),
        query_completed=True,
    )

    assert result.outcome.value == "lost_claim"
    assert _order_row(path, "order-1") == before_order
    assert _raw_task(path, "order-1") == before_task


def test_resolve_retry_claim_write_failure_rolls_back_without_mutation(
    tmp_path, monkeypatch
):
    path = tmp_path / "retry-write-failure.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="worker-1", now=NOW, lease_seconds=30)
    before_order = _order_row(path, "order-1")
    before_task = _raw_task(path, "order-1")
    real_write_transaction = repository.write_transaction

    @contextmanager
    def failing_write_transaction(database_path):
        with real_write_transaction(database_path) as connection:
            yield _FailingReconciliationUpdateConnection(connection)

    monkeypatch.setattr(repository, "write_transaction", failing_write_transaction)

    with pytest.raises(PaymentReconciliationRepositoryError):
        repository.resolve_retry_claim(
            path,
            order_id=claim.order_id,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            completed_at=NOW + timedelta(seconds=1),
            next_attempt_at=NOW + timedelta(seconds=2),
            query_completed=True,
        )

    assert _order_row(path, "order-1") == before_order
    assert _raw_task(path, "order-1") == before_task
    with connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 0
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_reschedule_preserves_omitted_history_and_can_explicitly_clear_codes(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    with connect(path) as connection:
        connection.execute(
            "UPDATE payment_reconciliations SET trusted_trade_state='NOTPAY', last_error_code='OLD_ERROR' WHERE order_id='order-1'"
        )
        connection.commit()
    first = claim_next_due(path, worker_id="w", now=NOW, lease_seconds=10)
    preserved = reschedule_claim(
        path, claim_token=first.claim_token, expected_state_version=first.state_version,
        completed_at=NOW + timedelta(seconds=1), next_attempt_at=NOW + timedelta(seconds=2),
    ).record
    assert (preserved.trusted_trade_state, preserved.last_error_code) == ("NOTPAY", "OLD_ERROR")
    second = claim_next_due(path, worker_id="w", now=NOW + timedelta(seconds=2), lease_seconds=10)
    cleared = reschedule_claim(
        path, claim_token=second.claim_token, expected_state_version=second.state_version,
        completed_at=NOW + timedelta(seconds=3), next_attempt_at=NOW + timedelta(seconds=4),
        trusted_trade_state=None, last_error_code=None,
    ).record
    assert (cleared.trusted_trade_state, cleared.last_error_code) == (None, None)


def test_locked_database_is_structured_and_retryable(tmp_path, monkeypatch):
    from license_server import db

    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    monkeypatch.setattr(db, "BUSY_TIMEOUT_MS", 1)
    blocker = connect(path)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(PaymentReconciliationRepositoryError) as exc_info:
            ensure_ready(path, "order-1", NOW, NOW)
    finally:
        blocker.rollback()
        blocker.close()
    assert exc_info.value.code == "PAYMENT_RECONCILIATION_DATABASE_BUSY"
    assert exc_info.value.retryable
    assert str(path) not in str(exc_info.value)


def test_read_open_failure_is_structured_and_does_not_expose_path(tmp_path):
    with pytest.raises(PaymentReconciliationRepositoryError) as exc_info:
        get(tmp_path, "order-1")

    assert exc_info.value.code == "PAYMENT_RECONCILIATION_DATABASE_ERROR"
    assert not exc_info.value.retryable
    assert str(tmp_path) not in str(exc_info.value)


@pytest.mark.parametrize("lease", (True, 0, -1, float("inf"), 3601, 0.1))
def test_claim_rejects_invalid_lease_values(tmp_path, lease):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    with pytest.raises(PaymentReconciliationRepositoryError) as exc_info:
        claim_next_due(path, worker_id="w", now=NOW, lease_seconds=lease)
    assert exc_info.value.code == "PAYMENT_RECONCILIATION_INPUT_INVALID"


def test_repository_rejects_overlong_worker_token_and_error_code(tmp_path):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    with pytest.raises(PaymentReconciliationRepositoryError):
        claim_next_due(path, worker_id="w" * 129, now=NOW, lease_seconds=10)
    claim = claim_next_due(path, worker_id="w", now=NOW, lease_seconds=10)
    with pytest.raises(PaymentReconciliationRepositoryError):
        begin_close_attempt(
            path, claim_token="t" * 129,
            expected_state_version=claim.state_version, now=NOW,
        )
    with pytest.raises(PaymentReconciliationRepositoryError):
        reschedule_claim(
            path, claim_token=claim.claim_token,
            expected_state_version=claim.state_version, completed_at=NOW,
            next_attempt_at=NOW + timedelta(seconds=1),
            last_error_code="E" * 129,
        )
    assert get(path, "order-1").state_version == claim.state_version


@pytest.mark.parametrize("trade,error,reason", (("INVALID", None, None), (None, "bad-code", None), (None, None, "")))
def test_completion_rejects_untrusted_values(tmp_path, trade, error, reason):
    path = tmp_path / "db.sqlite3"
    initialize_database(path)
    _insert_order(path, "order-1", "WAITING_PAYMENT")
    ensure_ready(path, "order-1", NOW, NOW)
    claim = claim_next_due(path, worker_id="w", now=NOW, lease_seconds=30)
    with pytest.raises(PaymentReconciliationRepositoryError) as exc_info:
        if reason is not None:
            terminate_claim(path, claim_token=claim.claim_token, expected_state_version=claim.state_version, terminal_at=NOW, terminal_reason=reason)
        else:
            reschedule_claim(path, claim_token=claim.claim_token, expected_state_version=claim.state_version, completed_at=NOW, next_attempt_at=NOW + timedelta(seconds=1), trusted_trade_state=trade, last_error_code=error)
    assert exc_info.value.code == "PAYMENT_RECONCILIATION_INPUT_INVALID"


def _insert_order(database_path, order_id, status):
    open_slot = "open" if status in {"CREATED", "WAITING_PAYMENT", "ABNORMAL"} else None
    paid_at = datetime_text(NOW) if status == "PAID" else None
    closed_at = datetime_text(NOW) if status == "CLOSED" else None
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at, paid_at, closed_at
            ) VALUES (?, ?, 'annual_v1', 990, 'CNY', 'wechat_native', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order_id,
                f"device-{order_id}",
                status,
                open_slot,
                datetime_text(NOW),
                datetime_text(NOW),
                datetime_text(NOW + timedelta(minutes=15)),
                paid_at,
                closed_at,
            ),
        )
        connection.commit()


def _order_row(database_path, order_id):
    with connect(database_path) as connection:
        return tuple(connection.execute(
            "SELECT * FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone())


def _raw_task(database_path, order_id):
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM payment_reconciliations WHERE order_id = ?", (order_id,)
        ).fetchone()
        return tuple(row) if row is not None else None


class _FailingReconciliationUpdateConnection:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, sql, parameters=()):
        if "UPDATE payment_reconciliations" in " ".join(sql.split()):
            raise sqlite3.OperationalError("database is locked")
        return self._connection.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._connection, name)
