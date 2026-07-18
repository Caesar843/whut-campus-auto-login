from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event, local
import sqlite3

import pytest

from license_server.db import connect, initialize_database
from license_server.payment import ANNUAL_V1, PRODUCTS
from license_server.payment_notification_repository import (
    IncomingPaymentNotification,
    NotificationUpdateResult,
    UpdateOutcome,
    claim_next_payment_notification,
    insert_received_notification,
)
from license_server.payment_notification_worker import (
    PaymentNotificationWorker,
    WorkerProcessOutcome,
)
from license_server.payment_reconciliation_repository import (
    claim_order,
    ensure_ready,
    get,
)
from license_server.payment_service import PaymentServiceError
from license_server.signer import datetime_text


NOW = datetime(2026, 7, 14, 8, 0, tzinfo=timezone.utc)
SUCCESS_AT = NOW - timedelta(minutes=1)
APP_ID = "wx-test-app"
MCH_ID = "1900000109"


@pytest.mark.parametrize("status", ("CREATED", "WAITING_PAYMENT"))
def test_worker_confirms_created_or_waiting_order_atomically(tmp_path, status):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path, status=status)
    _insert_notification(database_path, order_id=order_id)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.PROCESSED
    with connect(database_path) as connection:
        order = connection.execute(
            "SELECT status, open_slot, provider_transaction_id, paid_at "
            "FROM payment_orders WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        notification = connection.execute(
            "SELECT process_status, failure_code, processed_at, worker_id, "
            "claim_token, processing_started_at, lease_expires_at, next_attempt_at "
            "FROM payment_notifications"
        ).fetchone()
        grant = connection.execute("SELECT * FROM license_grants").fetchone()
        license_row = connection.execute(
            "SELECT * FROM licenses WHERE license_type = 'paid'"
        ).fetchone()
    assert tuple(order) == (
        "PAID",
        None,
        "transaction-1",
        datetime_text(SUCCESS_AT),
    )
    assert tuple(notification) == (
        "PROCESSED",
        None,
        datetime_text(NOW),
        None,
        None,
        None,
        None,
        None,
    )
    assert grant["license_id"] == license_row["id"]
    assert grant["new_expire_at"] == license_row["expires_at"]
    assert license_row["starts_at"] == datetime_text(NOW)
    assert license_row["expires_at"] == datetime_text(NOW + timedelta(days=365))


@pytest.mark.parametrize("reconcile_status", ("READY", "CLAIMED"))
def test_callback_worker_converges_ready_or_claimed_reconciliation(
    tmp_path, reconcile_status
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    ensure_ready(database_path, order_id, NOW, NOW)
    if reconcile_status == "CLAIMED":
        claim = claim_order(
            database_path,
            order_id=order_id,
            worker_id="reconciliation-worker",
            now=NOW,
            lease_seconds=60,
        ).claim
        assert claim is not None
    before = get(database_path, order_id)
    _insert_notification(database_path, order_id=order_id)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.PROCESSED
    record = get(database_path, order_id)
    assert record.reconcile_status == "TERMINAL"
    assert record.terminal_reason == "PAYMENT_CONFIRMED"
    assert record.next_attempt_at is None
    assert record.claim_token is None
    assert record.claimed_by is None
    assert record.claimed_at is None
    assert record.lease_expires_at is None
    assert record.state_version == before.state_version + 1
    with connect(database_path) as connection:
        assert tuple(connection.execute("SELECT status, open_slot FROM payment_orders").fetchone()) == (
            "PAID",
            None,
        )
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM licenses WHERE license_type='paid'").fetchone()[0] == 1


def test_worker_renews_from_existing_paid_expiry_not_notification_time(tmp_path):
    database_path = _database(tmp_path)
    future = NOW + timedelta(days=30)
    _insert_paid_license(database_path, expires_at=future)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.PROCESSED
    with connect(database_path) as connection:
        grant = connection.execute("SELECT * FROM license_grants").fetchone()
    assert grant["previous_expire_at"] == datetime_text(future)
    assert grant["new_expire_at"] == datetime_text(future + timedelta(days=365))


def test_worker_marks_unknown_order_orphan_without_business_writes(tmp_path):
    database_path = _database(tmp_path)
    _insert_notification(database_path, order_id="unknown-order")

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ORPHAN
    _assert_terminal(database_path, "ORPHAN", "PAYMENT_NOTIFICATION_ORDER_NOT_FOUND")
    _assert_no_payment_writes(database_path)


@pytest.mark.parametrize(
    ("notification_changes", "order_changes"),
    (
        ({"reported_amount_fen": 1}, {}),
        ({"reported_currency": "USD"}, {}),
        ({"reported_appid": "wrong-app"}, {}),
        ({"reported_mchid": "wrong-mch"}, {}),
        ({"reported_trade_type": "JSAPI"}, {}),
        ({"reported_trade_state": "NOTPAY"}, {}),
        ({"provider": "mock"}, {}),
        ({"event_type": "TRANSACTION.CLOSED"}, {}),
        ({}, {"provider": "mock"}),
        ({}, {"status": "CLOSED", "open_slot": None}),
        ({}, {"status": "ABNORMAL"}),
    ),
)
def test_worker_marks_deterministic_conflicts_abnormal(
    tmp_path, notification_changes, order_changes
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path, **order_changes)
    _insert_notification(database_path, order_id=order_id, **notification_changes)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_terminal(
        database_path,
        "ABNORMAL",
        "PAYMENT_NOTIFICATION_EVIDENCE_MISMATCH",
    )
    _assert_no_payment_writes(database_path)
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone()[0] != "PAID"


def test_worker_rejects_notification_order_binding_mismatch(tmp_path):
    database_path = _database(tmp_path)
    first = _insert_order(database_path, order_id="order-1")
    second = _insert_order(database_path, order_id="order-2", device_hash="device-2")
    _insert_notification(database_path, order_id=first)
    with connect(database_path) as connection:
        connection.execute(
            "UPDATE payment_notifications SET order_id = ?", (second,)
        )
        connection.commit()

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_no_payment_writes(database_path)


def test_worker_marks_same_paid_fact_duplicate_without_extending(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id, notification_id="notice-1")
    first = _worker(database_path).process_next(now=NOW)
    with connect(database_path) as connection:
        expires_at = connection.execute(
            "SELECT expires_at FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0]
    _insert_notification(database_path, order_id=order_id, notification_id="notice-2")

    second = _worker(database_path, worker_id="worker-b").process_next(
        now=NOW + timedelta(seconds=1)
    )

    assert first.outcome is WorkerProcessOutcome.PROCESSED
    assert second.outcome is WorkerProcessOutcome.DUPLICATE
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT expires_at FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == expires_at


def test_worker_marks_paid_order_with_conflicting_fact_abnormal(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id, notification_id="notice-1")
    assert _worker(database_path).process_next(now=NOW).outcome is WorkerProcessOutcome.PROCESSED
    _insert_notification(
        database_path,
        order_id=order_id,
        notification_id="notice-2",
        provider_transaction_id="transaction-2",
    )

    result = _worker(database_path, worker_id="worker-b").process_next(
        now=NOW + timedelta(seconds=1)
    )

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


@pytest.mark.parametrize(
    "mutation",
    (
        "UPDATE license_grants SET grant_days = 364",
        "UPDATE license_grants SET previous_expire_at = '2029-04-09T08:00:00Z'",
        "UPDATE license_grants SET new_expire_at = '2027-07-15T08:00:00Z'",
        "UPDATE license_grants SET granted_at = '2026-07-14T08:00:01Z'",
        "UPDATE license_grants SET issued_by = 'admin'",
        "UPDATE licenses SET starts_at = '2026-07-14T08:00:01Z' WHERE license_type = 'paid'",
        "UPDATE licenses SET expires_at = '2027-07-15T08:00:00Z' WHERE license_type = 'paid'",
        "UPDATE license_grants SET device_fingerprint_hash = 'device-2'",
        "UPDATE licenses SET device_id = (SELECT id FROM devices WHERE device_fingerprint_hash = 'device-2') WHERE license_type = 'paid'",
        "UPDATE license_grants SET source_order_id = 'other-order'",
        "UPDATE licenses SET order_id = 'other-order' WHERE license_type = 'paid'",
    ),
)
def test_worker_rejects_paid_order_with_inconsistent_grant(tmp_path, mutation):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id, notification_id="notice-1")
    assert _worker(database_path).process_next(now=NOW).outcome is WorkerProcessOutcome.PROCESSED
    with connect(database_path) as connection:
        connection.execute(mutation)
        connection.commit()
    damaged = _payment_chain_snapshot(database_path)
    _insert_notification(database_path, order_id=order_id, notification_id="notice-2")

    result = _worker(database_path, worker_id="worker-b").process_next(
        now=NOW + timedelta(seconds=1)
    )

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == 1
    assert _payment_chain_snapshot(database_path) == damaged


@pytest.mark.parametrize(
    ("order_changes", "notification_changes"),
    (
        ({"amount_fen": 1}, {"reported_amount_fen": 1}),
        ({"product_code": "unknown_product"}, {}),
    ),
)
def test_worker_marks_order_product_conflict_abnormal(
    tmp_path, order_changes, notification_changes
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path, **order_changes)
    _insert_notification(database_path, order_id=order_id, **notification_changes)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_terminal(
        database_path,
        "ABNORMAL",
        "PAYMENT_NOTIFICATION_EVIDENCE_MISMATCH",
    )
    _assert_no_payment_writes(database_path)
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone()[0] != "PAID"


def test_worker_marks_product_duration_conflict_abnormal(tmp_path, monkeypatch):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    monkeypatch.setitem(PRODUCTS, ANNUAL_V1.product_code, replace(ANNUAL_V1, duration_days=364))

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_no_payment_writes(database_path)


def test_worker_marks_product_currency_conflict_abnormal(tmp_path, monkeypatch):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    monkeypatch.setitem(PRODUCTS, ANNUAL_V1.product_code, replace(ANNUAL_V1, currency="USD"))

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_no_payment_writes(database_path)


def test_payment_service_error_rolls_back_savepoint_before_abnormal(
    tmp_path, monkeypatch
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)

    def fail_after_partial_write(connection, *_args, **_kwargs):
        device_id = connection.execute(
            "SELECT id FROM devices WHERE device_fingerprint_hash = 'device-1'"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO licenses (device_id, license_type, status, starts_at, "
            "expires_at, source, order_id, created_at) "
            "VALUES (?, 'paid', 'active', ?, ?, 'payment', ?, ?)",
            (
                device_id,
                datetime_text(NOW),
                datetime_text(NOW + timedelta(days=365)),
                order_id,
                datetime_text(NOW),
            ),
        )
        connection.execute(
            "UPDATE payment_orders SET status = 'ABNORMAL', open_slot = NULL "
            "WHERE order_id = ?",
            (order_id,),
        )
        raise PaymentServiceError("deterministic_conflict", commit=True)

    monkeypatch.setattr(
        "license_server.payment_notification_worker._confirm_paid_order_in_transaction",
        fail_after_partial_write,
    )

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_no_payment_writes(database_path)
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone()[0] == "WAITING_PAYMENT"


def test_worker_rejects_transaction_bound_to_another_order(tmp_path):
    database_path = _database(tmp_path)
    first = _insert_order(database_path, order_id="order-1")
    second = _insert_order(database_path, order_id="order-2", device_hash="device-2")
    with connect(database_path) as connection:
        connection.execute(
            "UPDATE payment_orders SET provider_transaction_id = ? WHERE order_id = ?",
            ("transaction-1", first),
        )
        connection.commit()
    _insert_notification(database_path, order_id=second)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_no_payment_writes(database_path)


def test_worker_returns_no_work_without_side_effects(tmp_path):
    database_path = _database(tmp_path)

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.NO_WORK


@pytest.mark.parametrize("process_offset", (60, 61))
def test_expired_claim_without_reclaim_cannot_modify_business_data(
    tmp_path, process_offset
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    claimed = _claim(database_path, worker_id="worker-a", lease_seconds=60)
    lease_before = _notification_lease_snapshot(database_path)

    result = _worker(database_path)._process_claimed(
        claimed,
        now=NOW + timedelta(seconds=process_offset),
    )

    assert result.outcome is WorkerProcessOutcome.LOST_CLAIM
    assert _notification_lease_snapshot(database_path) == lease_before
    _assert_no_payment_writes(database_path)
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone()[0] == "WAITING_PAYMENT"


def test_unexpired_claim_can_process_normally(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    claimed = _claim(database_path, worker_id="worker-a", lease_seconds=60)

    result = _worker(database_path)._process_claimed(
        claimed,
        now=NOW + timedelta(seconds=59),
    )

    assert result.outcome is WorkerProcessOutcome.PROCESSED
    _assert_single_grant(database_path)


def test_stale_claim_cannot_modify_order_or_new_lease(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    stale = claim_next_payment_notification(
        database_path,
        worker_id="worker-a",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=1),
        max_attempts=8,
    )
    current = claim_next_payment_notification(
        database_path,
        worker_id="worker-b",
        now=NOW + timedelta(seconds=1),
        lease_expires_at=NOW + timedelta(seconds=61),
        max_attempts=8,
    )
    assert stale is not None and current is not None
    result = _worker(database_path)._process_claimed(
        stale,
        now=NOW + timedelta(seconds=2),
    )

    assert result.outcome is WorkerProcessOutcome.LOST_CLAIM
    _assert_no_payment_writes(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT process_status, worker_id, claim_token FROM payment_notifications"
        ).fetchone()
    assert tuple(row) == ("PROCESSING", "worker-b", current.claim_token)

    completed = _worker(database_path, worker_id="worker-b")._process_claimed(
        current,
        now=NOW + timedelta(seconds=2),
    )
    assert completed.outcome is WorkerProcessOutcome.PROCESSED
    _assert_single_grant(database_path)


def test_final_notification_cas_failure_rolls_back_payment(tmp_path, monkeypatch):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    monkeypatch.setattr(
        "license_server.payment_notification_worker.mark_terminal_in_transaction",
        lambda *_args, **_kwargs: NotificationUpdateResult(
            UpdateOutcome.LOST_CLAIM,
            None,
        ),
    )

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.LOST_CLAIM
    _assert_no_payment_writes(database_path)
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone()[0] == "WAITING_PAYMENT"
        assert connection.execute(
            "SELECT process_status FROM payment_notifications"
        ).fetchone()[0] == "PROCESSING"


@pytest.mark.parametrize(
    ("timing", "table", "operation"),
    (
        ("BEFORE", "license_grants", "INSERT"),
        ("AFTER", "license_grants", "INSERT"),
        ("BEFORE", "licenses", "INSERT"),
        ("AFTER", "licenses", "INSERT"),
        ("BEFORE", "payment_orders", "UPDATE"),
        ("AFTER", "payment_orders", "UPDATE"),
        ("BEFORE", "payment_notifications", "UPDATE"),
        ("AFTER", "payment_notifications", "UPDATE"),
    ),
)
def test_integrity_failure_rolls_back_and_becomes_abnormal(
    tmp_path, timing, table, operation
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    condition = (
        " WHEN NEW.process_status = 'PROCESSED'"
        if table == "payment_notifications"
        else ""
    )
    with connect(database_path) as connection:
        connection.execute(
            f"CREATE TRIGGER fail_worker {timing} {operation} ON {table}{condition} "
            "BEGIN SELECT RAISE(ABORT, 'temporary storage failure'); END"
        )
        connection.commit()

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    with connect(database_path) as connection:
        order = connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?", (order_id,)
        ).fetchone()[0]
        notification = connection.execute(
            "SELECT process_status, attempt_count, next_attempt_at, failure_code "
            "FROM payment_notifications"
        ).fetchone()
        assert order == "WAITING_PAYMENT"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == 0
        assert tuple(notification) == (
            "ABNORMAL",
            1,
            None,
            "PAYMENT_NOTIFICATION_STORAGE_CONFLICT",
        )


@pytest.mark.parametrize(
    "trigger_body",
    (
        "INSERT INTO license_grants (source_order_id, device_fingerprint_hash, "
        "license_id, product_code, grant_days, previous_expire_at, new_expire_at, "
        "granted_at, issued_by) VALUES (NEW.source_order_id, NEW.device_fingerprint_hash, "
        "NEW.license_id, NEW.product_code, NEW.grant_days, NEW.previous_expire_at, "
        "NEW.new_expire_at, NEW.granted_at, NEW.issued_by);",
        "INSERT INTO license_grants (source_order_id, device_fingerprint_hash, "
        "license_id, product_code, grant_days, new_expire_at, granted_at, issued_by) "
        "VALUES ('constraint-probe', NEW.device_fingerprint_hash, NEW.license_id, "
        "NEW.product_code, 0, NEW.new_expire_at, NEW.granted_at, NEW.issued_by);",
        "INSERT INTO license_grants (source_order_id, device_fingerprint_hash, "
        "license_id, product_code, grant_days, new_expire_at, granted_at, issued_by) "
        "VALUES ('constraint-probe', NEW.device_fingerprint_hash, 999999, "
        "NEW.product_code, NEW.grant_days, NEW.new_expire_at, NEW.granted_at, NEW.issued_by);",
    ),
    ids=("unique", "check", "foreign_key"),
)
def test_constraint_integrity_error_is_abnormal(tmp_path, trigger_body):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    with connect(database_path) as connection:
        connection.execute(
            f"CREATE TRIGGER fail_worker BEFORE INSERT ON license_grants BEGIN "
            f"{trigger_body} END"
        )
        connection.commit()

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_terminal(
        database_path,
        "ABNORMAL",
        "PAYMENT_NOTIFICATION_STORAGE_CONFLICT",
    )
    _assert_no_payment_writes(database_path)


def test_integrity_reclassification_accepts_complete_paid_fact(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id, notification_id="notice-1")
    assert _worker(database_path).process_next(now=NOW).outcome is WorkerProcessOutcome.PROCESSED
    _insert_notification(database_path, order_id=order_id, notification_id="notice-2")
    claimed = _claim(database_path, worker_id="worker-b", lease_seconds=60)

    result = _worker(
        database_path,
        worker_id="worker-b",
    )._recover_integrity_error(claimed, now=NOW)

    assert result.outcome is WorkerProcessOutcome.DUPLICATE
    _assert_single_grant(database_path)


def test_database_busy_after_claim_schedules_retry(tmp_path, monkeypatch):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    claimed = _claim(database_path, worker_id="worker-a", lease_seconds=60)
    busy_observed = Event()
    release_busy = Event()

    @contextmanager
    def observed_transaction(path):
        connection = sqlite3.connect(path, timeout=0)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.row_factory = sqlite3.Row
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                assert exc.sqlite_errorcode & 0xFF in {
                    sqlite3.SQLITE_BUSY,
                    sqlite3.SQLITE_LOCKED,
                }
                busy_observed.set()
                assert release_busy.wait(timeout=5)
                raise
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    monkeypatch.setattr(
        "license_server.payment_notification_worker.write_transaction",
        observed_transaction,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker.finalize_expired_max_attempts",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker.claim_next_payment_notification",
        lambda *_args, **_kwargs: claimed,
    )

    blocker = connect(database_path)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_worker(database_path).process_next, now=NOW)
            assert busy_observed.wait(timeout=5)
            assert blocker.in_transaction
            assert not future.done()
            blocker.rollback()
            release_busy.set()
            result = future.result(timeout=5)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()

    assert result.outcome is WorkerProcessOutcome.RETRY_SCHEDULED
    with connect(database_path) as connection:
        assert tuple(
            connection.execute(
                "SELECT process_status, attempt_count, next_attempt_at "
                "FROM payment_notifications"
            ).fetchone()
        ) == ("RETRY", 1, datetime_text(NOW + timedelta(seconds=5)))

    monkeypatch.undo()
    result = _worker(database_path).process_next(now=NOW + timedelta(seconds=5))
    assert result.outcome is WorkerProcessOutcome.PROCESSED


def test_busy_at_max_attempts_becomes_abnormal(tmp_path, monkeypatch):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    claimed = _claim(database_path, worker_id="worker-a", lease_seconds=60, max_attempts=1)

    @contextmanager
    def busy_transaction(_database_path):
        error = sqlite3.OperationalError("database is locked")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        raise error
        yield

    monkeypatch.setattr(
        "license_server.payment_notification_worker.write_transaction",
        busy_transaction,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker.finalize_expired_max_attempts",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker.claim_next_payment_notification",
        lambda *_args, **_kwargs: claimed,
    )

    result = _worker(database_path, max_attempts=1).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_terminal(
        database_path,
        "ABNORMAL",
        "PAYMENT_NOTIFICATION_MAX_ATTEMPTS_EXCEEDED",
    )


def test_nonbusy_operational_error_does_not_retry(tmp_path, monkeypatch):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)

    @contextmanager
    def broken_transaction(_database_path):
        error = sqlite3.OperationalError("invalid database operation")
        error.sqlite_errorcode = sqlite3.SQLITE_ERROR
        raise error
        yield

    monkeypatch.setattr(
        "license_server.payment_notification_worker.write_transaction",
        broken_transaction,
    )

    result = _worker(database_path).process_next(now=NOW)

    assert result.outcome is WorkerProcessOutcome.ABNORMAL
    _assert_terminal(
        database_path,
        "ABNORMAL",
        "PAYMENT_NOTIFICATION_STORAGE_CONFLICT",
    )


def test_worker_emits_no_sensitive_payment_identifiers(tmp_path, caplog):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path, order_id="secret-order-reference")
    _insert_notification(
        database_path,
        order_id=order_id,
        notification_id="secret-notification-reference",
        provider_transaction_id="secret-transaction-reference",
        payload_digest_sha256="a" * 64,
    )

    _worker(database_path, worker_id="secret-worker-reference").process_next(now=NOW)

    assert "secret-order-reference" not in caplog.text
    assert "secret-notification-reference" not in caplog.text
    assert "secret-transaction-reference" not in caplog.text
    assert "secret-worker-reference" not in caplog.text
    assert APP_ID not in caplog.text
    assert MCH_ID not in caplog.text


def test_two_workers_competing_for_same_notification_issue_once(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    results = _run_workers(database_path, 2)

    assert sorted(result.outcome for result in results) == sorted(
        (WorkerProcessOutcome.NO_WORK, WorkerProcessOutcome.PROCESSED)
    )
    _assert_single_grant(database_path)


def test_two_notifications_for_same_order_compete_after_real_claim(
    tmp_path, monkeypatch
):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id, notification_id="notice-1")
    _insert_notification(database_path, order_id=order_id, notification_id="notice-2")
    results = _run_claimed_workers(database_path, monkeypatch)

    assert {result.outcome for result in results} == {
        WorkerProcessOutcome.PROCESSED,
        WorkerProcessOutcome.DUPLICATE,
    }
    _assert_single_grant(database_path)


def test_same_transaction_for_two_orders_competes_after_real_claim(
    tmp_path, monkeypatch
):
    database_path = _database(tmp_path)
    first = _insert_order(database_path, order_id="order-1")
    second = _insert_order(database_path, order_id="order-2", device_hash="device-2")
    _insert_notification(database_path, order_id=first, notification_id="notice-1")
    _insert_notification(database_path, order_id=second, notification_id="notice-2")
    results = _run_claimed_workers(database_path, monkeypatch)

    assert {result.outcome for result in results} == {
        WorkerProcessOutcome.PROCESSED,
        WorkerProcessOutcome.ABNORMAL,
    }
    _assert_single_grant(database_path)
    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM payment_orders WHERE status = 'PAID'"
        ).fetchone()[0] == 1


def _database(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_device(database_path, "device-1")
    _insert_device(database_path, "device-2")
    return database_path


def _insert_device(database_path, device_hash):
    with connect(database_path) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO devices (product_id, device_fingerprint_hash, "
            "first_seen_at, last_seen_at) VALUES ('whut-campus-auto-login', ?, ?, ?)",
            (device_hash, datetime_text(NOW), datetime_text(NOW)),
        )
        connection.commit()


def _insert_order(
    database_path,
    *,
    order_id="order-1",
    device_hash="device-1",
    status="WAITING_PAYMENT",
    open_slot="open",
    provider="wechat_native",
    product_code="annual_v1",
    amount_fen=990,
    currency="CNY",
):
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                order_id,
                device_hash,
                product_code,
                amount_fen,
                currency,
                provider,
                status,
                open_slot,
                datetime_text(NOW),
                datetime_text(NOW),
                datetime_text(NOW + timedelta(minutes=15)),
            ),
        )
        connection.commit()
    return order_id


def _insert_notification(
    database_path,
    *,
    order_id,
    notification_id="notice-1",
    provider_transaction_id="transaction-1",
    **overrides,
):
    values = {
        "provider_notification_id": notification_id,
        "provider": "wechat_native",
        "out_trade_no": order_id,
        "provider_transaction_id": provider_transaction_id,
        "event_type": "TRANSACTION.SUCCESS",
        "signature_key_id": "PUB_KEY_ID_1",
        "payload_digest_sha256": notification_id[-1] * 64,
        "reported_appid": APP_ID,
        "reported_mchid": MCH_ID,
        "reported_trade_type": "NATIVE",
        "reported_trade_state": "SUCCESS",
        "reported_amount_fen": 990,
        "reported_currency": "CNY",
        "reported_success_at": SUCCESS_AT,
        "provider_created_at": SUCCESS_AT,
        "received_at": NOW,
    }
    values.update(overrides)
    insert_received_notification(database_path, IncomingPaymentNotification(**values))


def _insert_paid_license(database_path, *, expires_at):
    with connect(database_path) as connection:
        device_id = connection.execute(
            "SELECT id FROM devices WHERE device_fingerprint_hash = 'device-1'"
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO licenses (
                device_id, license_type, status, starts_at, expires_at, source,
                order_id, created_at
            ) VALUES (?, 'paid', 'active', ?, ?, 'admin', NULL, ?)
            """,
            (
                device_id,
                datetime_text(NOW - timedelta(days=1)),
                datetime_text(expires_at),
                datetime_text(NOW - timedelta(days=1)),
            ),
        )
        connection.commit()


def _worker(database_path, *, worker_id="worker-a", max_attempts=8):
    return PaymentNotificationWorker(
        database_path=database_path,
        worker_id=worker_id,
        expected_appid=APP_ID,
        expected_mchid=MCH_ID,
        lease_seconds=60,
        max_attempts=max_attempts,
        retry_base_seconds=5,
        retry_max_seconds=300,
    )


def _assert_terminal(database_path, status, failure_code):
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT process_status, failure_code, processed_at, worker_id, "
            "claim_token, processing_started_at, lease_expires_at, next_attempt_at "
            "FROM payment_notifications ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert tuple(row) == (
        status,
        failure_code,
        datetime_text(NOW),
        None,
        None,
        None,
        None,
        None,
    )


def _assert_no_payment_writes(database_path):
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == 0


def _assert_single_grant(database_path):
    with connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type = 'paid'"
        ).fetchone()[0] == 1


def _claim(database_path, *, worker_id, lease_seconds, max_attempts=8):
    claimed = claim_next_payment_notification(
        database_path,
        worker_id=worker_id,
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=lease_seconds),
        max_attempts=max_attempts,
    )
    assert claimed is not None
    return claimed


def _notification_lease_snapshot(database_path):
    with connect(database_path) as connection:
        return tuple(
            connection.execute(
                "SELECT process_status, worker_id, claim_token, processing_started_at, "
                "lease_expires_at, attempt_count FROM payment_notifications"
            ).fetchone()
        )


def _payment_chain_snapshot(database_path):
    with connect(database_path) as connection:
        grant = connection.execute(
            "SELECT source_order_id, device_fingerprint_hash, license_id, product_code, "
            "grant_days, previous_expire_at, new_expire_at, granted_at, issued_by "
            "FROM license_grants"
        ).fetchone()
        license_row = connection.execute(
            "SELECT device_id, license_type, status, starts_at, expires_at, source, order_id "
            "FROM licenses WHERE license_type = 'paid'"
        ).fetchone()
    return tuple(grant) if grant else None, tuple(license_row) if license_row else None


def _run_workers(database_path, count):
    barrier = Barrier(count)

    def run(index):
        barrier.wait(timeout=5)
        return _worker(database_path, worker_id=f"worker-{index}").process_next(now=NOW)

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(run, index) for index in range(count)]
        return [future.result(timeout=10) for future in futures]


def _run_claimed_workers(database_path, monkeypatch):
    claims = [
        _claim(database_path, worker_id=f"worker-{index}", lease_seconds=60)
        for index in range(2)
    ]
    assert claims[0].id != claims[1].id
    assert claims[0].claim_token != claims[1].claim_token
    assert {claim.worker_id for claim in claims} == {"worker-0", "worker-1"}

    events = [Event(), Event()]
    state = local()

    class ObservedConnection:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, sql, parameters=()):
            if sql.strip().upper() == "BEGIN IMMEDIATE":
                state.event.set()
            return self._connection.execute(sql, parameters)

        def __getattr__(self, name):
            return getattr(self._connection, name)

    @contextmanager
    def observed_transaction(path):
        connection = connect(path)
        proxy = ObservedConnection(connection)
        try:
            proxy.execute("BEGIN IMMEDIATE")
            yield proxy
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    monkeypatch.setattr(
        "license_server.payment_notification_worker.write_transaction",
        observed_transaction,
    )

    blocker = connect(database_path)
    blocker.execute("BEGIN IMMEDIATE")

    def run(index):
        state.event = events[index]
        return _worker(
            database_path,
            worker_id=f"worker-{index}",
        )._process_claimed(claims[index], now=NOW)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run, index) for index in range(2)]
            assert all(event.wait(timeout=5) for event in events)
            assert blocker.in_transaction
            assert all(not future.done() for future in futures)
            blocker.rollback()
            return [future.result(timeout=10) for future in futures]
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
