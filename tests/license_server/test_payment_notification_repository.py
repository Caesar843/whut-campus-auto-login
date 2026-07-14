import sqlite3
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import fields
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event, local
from unittest.mock import patch

import pytest

import license_server.db as database_module
from license_server.db import connect, initialize_database
from license_server.payment_notification_repository import (
    DUPLICATE_FAILURE_CODE,
    MAX_ATTEMPTS_FAILURE_CODE,
    ORPHAN_FAILURE_CODE,
    IncomingPaymentNotification,
    InsertOutcome,
    PaymentNotificationRepositoryError,
    UpdateOutcome,
    claim_next_payment_notification,
    finalize_expired_max_attempts,
    insert_received_notification,
    mark_abnormal,
    mark_duplicate,
    mark_orphan,
    mark_processed,
    mark_retry,
    retry_delay_seconds,
)
from license_server.signer import datetime_text


NOW = datetime(2026, 7, 14, tzinfo=timezone.utc)


def test_insert_received_notification_binds_existing_order_and_stores_minimum(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    _insert_order(database_path, "order-1")

    result = insert_received_notification(database_path, _incoming())

    assert result.outcome is InsertOutcome.INSERTED
    with connect(database_path) as connection:
        row = connection.execute("SELECT * FROM payment_notifications").fetchone()
        assert row["order_id"] == "order-1"
        assert row["out_trade_no"] == "order-1"
        assert row["process_status"] == "RECEIVED"
        assert row["signature_valid"] == 1
        assert row["merchant_identity_valid"] == 1
        assert row["attempt_count"] == 0
        assert row["worker_id"] is None
        assert row["claim_token"] is None
        assert row["lease_expires_at"] is None


def test_insert_received_notification_keeps_unknown_order_unbound(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    insert_received_notification(database_path, _incoming())

    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT order_id FROM payment_notifications"
        ).fetchone()[0] is None


def test_duplicate_notification_reports_digest_match_or_conflict_without_overwrite(
    tmp_path,
):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    first = insert_received_notification(database_path, _incoming())
    same = insert_received_notification(database_path, _incoming())
    conflict = insert_received_notification(
        database_path,
        _incoming(payload_digest_sha256="b" * 64),
    )

    assert first.outcome is InsertOutcome.INSERTED
    assert same.outcome is InsertOutcome.DUPLICATE_SAME_DIGEST
    assert conflict.outcome is InsertOutcome.DUPLICATE_DIGEST_CONFLICT
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*), payload_digest_sha256 FROM payment_notifications"
        ).fetchone()
        assert tuple(row) == (1, "a" * 64)


def test_concurrent_duplicate_insert_creates_one_row(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)

    results = _run_concurrently_behind_write_lock(
        database_path,
        (
            lambda: insert_received_notification(database_path, _incoming()),
            lambda: insert_received_notification(database_path, _incoming()),
        ),
    )

    assert sorted(result.outcome.value for result in results) == [
        "duplicate_same_digest",
        "inserted",
    ]
    with connect(database_path) as connection:
        rows = connection.execute("SELECT * FROM payment_notifications").fetchall()
        assert len(rows) == 1
        assert _received_row_values(rows[0]) == _expected_received_values(_incoming())


def test_concurrent_digest_conflict_does_not_overwrite_first_insert(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    notifications = (
        _incoming(),
        _incoming(
            out_trade_no="order-2",
            provider="wechat_native_alternate",
            provider_transaction_id="transaction-2",
            event_type="TRANSACTION.SUCCESS.ALTERNATE",
            signature_key_id="PUB_KEY_ID_2",
            payload_digest_sha256="b" * 64,
            reported_appid="wx-app-2",
            reported_mchid="merchant-2",
            reported_trade_type="NATIVE_2",
            reported_trade_state="SUCCESS_2",
            reported_amount_fen=991,
            reported_currency="CNY_2",
            reported_success_at=NOW + timedelta(seconds=1),
            provider_created_at=NOW + timedelta(seconds=2),
            received_at=NOW + timedelta(seconds=3),
        ),
    )

    results = _run_concurrently_behind_write_lock(
        database_path,
        tuple(
            lambda notification=notification: insert_received_notification(
                database_path, notification
            )
            for notification in notifications
        ),
    )

    assert sorted(result.outcome.value for result in results) == [
        "duplicate_digest_conflict",
        "inserted",
    ]
    inserted_index = next(
        index
        for index, result in enumerate(results)
        if result.outcome is InsertOutcome.INSERTED
    )
    with connect(database_path) as connection:
        rows = connection.execute("SELECT * FROM payment_notifications").fetchall()
        assert len(rows) == 1
        assert _received_row_values(rows[0]) == _expected_received_values(
            notifications[inserted_index]
        )


def test_incoming_type_cannot_accept_forbidden_payload_fields():
    names = {field.name for field in fields(IncomingPaymentNotification)}

    assert names.isdisjoint(
        {
            "raw_body",
            "raw_payload",
            "decrypted_body",
            "openid",
            "bank_type",
            "signature",
            "api_v3_key",
        }
    )


def test_received_notification_can_be_claimed_once(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())

    claimed = claim_next_payment_notification(
        database_path,
        worker_id="worker-a",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=60),
        max_attempts=8,
    )

    assert claimed is not None
    assert claimed.worker_id == "worker-a"
    assert claimed.claim_token
    assert claimed.attempt_count == 1
    assert claimed.processing_started_at == NOW
    assert claimed.lease_expires_at == NOW + timedelta(seconds=60)
    assert claim_next_payment_notification(
        database_path,
        worker_id="worker-b",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=60),
        max_attempts=8,
    ) is None


def test_claim_rejects_lease_that_truncates_to_current_second(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    now = NOW + timedelta(microseconds=100_000)

    with pytest.raises(
        PaymentNotificationRepositoryError,
        match="PAYMENT_NOTIFICATION_CLAIM_CONFIG_INVALID",
    ):
        claim_next_payment_notification(
            database_path,
            worker_id="worker-a",
            now=now,
            lease_expires_at=now + timedelta(microseconds=100_000),
            max_attempts=8,
        )


def test_retry_is_claimable_only_when_due(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    claimed = _claim(database_path)
    retry_at = NOW + timedelta(seconds=10)
    result = mark_retry(
        database_path,
        notification_id=claimed.id,
        claim_token=claimed.claim_token,
        failure_code="TEMPORARY_DATABASE_ERROR",
        next_attempt_at=retry_at,
        processed_at=NOW,
        max_attempts=8,
    )

    assert result.outcome is UpdateOutcome.UPDATED
    assert result.process_status == "RETRY"
    with connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT worker_id, claim_token, processing_started_at,
                   lease_expires_at, processed_at, next_attempt_at,
                   attempt_count
            FROM payment_notifications
            """
        ).fetchone()
        assert tuple(row) == (
            None,
            None,
            None,
            None,
            None,
            "2026-07-14T00:00:10Z",
            1,
        )
    assert claim_next_payment_notification(
        database_path,
        worker_id="worker-b",
        now=retry_at - timedelta(seconds=1),
        lease_expires_at=retry_at + timedelta(seconds=60),
        max_attempts=8,
    ) is None
    reclaimed = claim_next_payment_notification(
        database_path,
        worker_id="worker-b",
        now=retry_at,
        lease_expires_at=retry_at + timedelta(seconds=60),
        max_attempts=8,
    )
    assert reclaimed is not None
    assert reclaimed.attempt_count == 2


def test_expired_processing_is_reclaimed_with_new_token(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    first = claim_next_payment_notification(
        database_path,
        worker_id="worker-a",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=1),
        max_attempts=8,
    )

    second = claim_next_payment_notification(
        database_path,
        worker_id="worker-b",
        now=NOW + timedelta(seconds=1),
        lease_expires_at=NOW + timedelta(seconds=61),
        max_attempts=8,
    )

    assert first is not None and second is not None
    assert second.claim_token != first.claim_token
    assert second.worker_id == "worker-b"
    assert second.attempt_count == 2


def test_two_workers_competing_claim_only_one_notification(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())

    def claim(worker_id):
        return claim_next_payment_notification(
            database_path,
            worker_id=worker_id,
            now=NOW,
            lease_expires_at=NOW + timedelta(seconds=60),
            max_attempts=8,
        )

    workers = ("worker-a", "worker-b")
    results = _run_concurrently_behind_write_lock(
        database_path,
        tuple(lambda worker=worker: claim(worker) for worker in workers),
    )

    assert sum(result is not None for result in results) == 1
    assert sum(result is None for result in results) == 1
    successful_index = next(
        index for index, result in enumerate(results) if result is not None
    )
    successful = results[successful_index]
    with connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*), process_status, attempt_count, worker_id, claim_token,
                   processing_started_at, lease_expires_at
            FROM payment_notifications
            """
        ).fetchone()
        assert tuple(row) == (
            1,
            "PROCESSING",
            1,
            workers[successful_index],
            successful.claim_token,
            datetime_text(successful.processing_started_at),
            datetime_text(successful.lease_expires_at),
        )


@pytest.mark.parametrize(
    "operation", ("processed", "retry", "duplicate", "abnormal", "orphan")
)
def test_stale_claim_token_cannot_overwrite_new_worker(tmp_path, operation):
    database_path = tmp_path / f"{operation}.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    first = claim_next_payment_notification(
        database_path,
        worker_id="worker-a",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=1),
        max_attempts=8,
    )
    second = claim_next_payment_notification(
        database_path,
        worker_id="worker-b",
        now=NOW + timedelta(seconds=1),
        lease_expires_at=NOW + timedelta(seconds=61),
        max_attempts=8,
    )
    assert first is not None and second is not None

    if operation == "processed":
        stale = mark_processed(database_path, first.id, first.claim_token, NOW)
    elif operation == "retry":
        stale = mark_retry(
            database_path,
            notification_id=first.id,
            claim_token=first.claim_token,
            failure_code="TEMPORARY_DATABASE_ERROR",
            next_attempt_at=NOW + timedelta(seconds=10),
            processed_at=NOW,
            max_attempts=8,
        )
    elif operation == "duplicate":
        stale = mark_duplicate(database_path, first.id, first.claim_token, NOW)
    elif operation == "abnormal":
        stale = mark_abnormal(
            database_path,
            first.id,
            first.claim_token,
            "PERMANENT_EVIDENCE_CONFLICT",
            NOW,
        )
    else:
        stale = mark_orphan(database_path, first.id, first.claim_token, NOW)

    assert stale.outcome is UpdateOutcome.LOST_CLAIM
    with connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT worker_id, claim_token, process_status, processing_started_at,
                   lease_expires_at, attempt_count
            FROM payment_notifications
            """
        ).fetchone()
        assert tuple(row) == (
            "worker-b",
            second.claim_token,
            "PROCESSING",
            "2026-07-14T00:00:01Z",
            "2026-07-14T00:01:01Z",
            2,
        )
    assert mark_processed(
        database_path, second.id, second.claim_token, NOW
    ).outcome is UpdateOutcome.UPDATED


@pytest.mark.parametrize(
    ("marker", "expected_status", "expected_code"),
    (
        (mark_processed, "PROCESSED", None),
        (mark_duplicate, "DUPLICATE", DUPLICATE_FAILURE_CODE),
        (mark_orphan, "ORPHAN", ORPHAN_FAILURE_CODE),
    ),
)
def test_terminal_markers_clear_claim(tmp_path, marker, expected_status, expected_code):
    database_path = tmp_path / f"{expected_status}.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    claimed = _claim(database_path)

    result = marker(database_path, claimed.id, claimed.claim_token, NOW)

    assert result.outcome is UpdateOutcome.UPDATED
    assert result.process_status == expected_status
    with connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT failure_code, processed_at, worker_id, claim_token,
                   processing_started_at, lease_expires_at, next_attempt_at
            FROM payment_notifications
            """
        ).fetchone()
        assert tuple(row) == (
            expected_code,
            "2026-07-14T00:00:00Z",
            None,
            None,
            None,
            None,
            None,
        )


def test_mark_retry_at_max_attempts_becomes_abnormal(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    claimed = _claim(database_path, max_attempts=1)

    result = mark_retry(
        database_path,
        notification_id=claimed.id,
        claim_token=claimed.claim_token,
        failure_code="TEMPORARY_DATABASE_ERROR",
        next_attempt_at=NOW + timedelta(seconds=5),
        processed_at=NOW,
        max_attempts=1,
    )

    assert result.outcome is UpdateOutcome.UPDATED
    assert result.process_status == "ABNORMAL"
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT failure_code, processed_at, next_attempt_at FROM payment_notifications"
        ).fetchone()
        assert tuple(row) == (
            MAX_ATTEMPTS_FAILURE_CODE,
            "2026-07-14T00:00:00Z",
            None,
        )


def test_finalize_expired_max_attempts_without_processing(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    insert_received_notification(database_path, _incoming())
    _claim(database_path, max_attempts=1, lease_seconds=1)

    count = finalize_expired_max_attempts(
        database_path,
        now=NOW + timedelta(seconds=1),
        max_attempts=1,
        limit=10,
    )

    assert count == 1
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT process_status, failure_code, processed_at FROM payment_notifications"
        ).fetchone()
        assert tuple(row) == (
            "ABNORMAL",
            MAX_ATTEMPTS_FAILURE_CODE,
            "2026-07-14T00:00:01Z",
        )


@pytest.mark.parametrize(
    ("attempt", "expected"),
    ((1, 5), (2, 10), (4, 40), (7, 300), (10_000, 300)),
)
def test_retry_delay(attempt, expected):
    assert retry_delay_seconds(attempt, 5, 300) == expected


@pytest.mark.parametrize(
    ("attempt", "base", "maximum"),
    ((0, 5, 300), (-1, 5, 300), (1, 0, 300), (1, 5, 4)),
)
def test_retry_delay_rejects_invalid_values(attempt, base, maximum):
    with pytest.raises(ValueError, match="PAYMENT_NOTIFICATION_RETRY_CONFIG_INVALID"):
        retry_delay_seconds(attempt, base, maximum)


def test_begin_immediate_proxy_signals_before_delegating_and_forwards_failures():
    attempted = Event()

    class UnderlyingConnection:
        closed = False

        def execute(self, sql, parameters=()):
            if sql == " \n BeGiN   ImMeDiAtE ; ":
                assert attempted.is_set()
                raise sqlite3.OperationalError("delegated failure")
            assert not attempted.is_set()
            return "ordinary-result"

        def close(self):
            self.closed = True

    underlying = UnderlyingConnection()
    connection = _BeginImmediateObservingConnection(underlying, attempted)

    for sql in (
        "SELECT 1",
        "BEGIN",
        "BEGIN EXCLUSIVE",
        "SELECT 'BEGIN IMMEDIATE'",
        "BEGIN IMMEDIATE; SELECT 1",
    ):
        assert connection.execute(sql) == "ordinary-result"
        assert not attempted.is_set()
    with pytest.raises(sqlite3.OperationalError, match="delegated failure"):
        connection.execute(" \n BeGiN   ImMeDiAtE ; ")
    connection.close()

    assert attempted.is_set()
    assert underlying.closed


def _incoming(**overrides) -> IncomingPaymentNotification:
    values = {
        "provider_notification_id": "notice-1",
        "provider": "wechat_native",
        "out_trade_no": "order-1",
        "provider_transaction_id": "transaction-1",
        "event_type": "TRANSACTION.SUCCESS",
        "signature_key_id": "PUB_KEY_ID_1",
        "payload_digest_sha256": "a" * 64,
        "reported_appid": "wx-app",
        "reported_mchid": "merchant-1",
        "reported_trade_type": "NATIVE",
        "reported_trade_state": "SUCCESS",
        "reported_amount_fen": 990,
        "reported_currency": "CNY",
        "reported_success_at": NOW,
        "provider_created_at": NOW,
        "received_at": NOW,
    }
    values.update(overrides)
    return IncomingPaymentNotification(**values)


def _insert_order(database_path, order_id):
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO payment_orders (
                order_id, device_fingerprint_hash, product_code, amount_fen,
                currency, provider, status, open_slot, created_at, updated_at,
                expires_at
            ) VALUES (?, 'device-1', 'annual_v1', 990, 'CNY', 'wechat_native',
                      'WAITING_PAYMENT', 'open', '2026-07-14T00:00:00Z',
                      '2026-07-14T00:00:00Z', '2026-07-14T00:15:00Z')
            """,
            (order_id,),
        )
        connection.commit()


def _claim(database_path, *, max_attempts=8, lease_seconds=60):
    claimed = claim_next_payment_notification(
        database_path,
        worker_id="worker-a",
        now=NOW,
        lease_expires_at=NOW + timedelta(seconds=lease_seconds),
        max_attempts=max_attempts,
    )
    assert claimed is not None
    return claimed


def _expected_received_values(notification):
    return {
        "provider_notification_id": notification.provider_notification_id,
        "order_id": None,
        "out_trade_no": notification.out_trade_no,
        "provider": notification.provider,
        "provider_transaction_id": notification.provider_transaction_id,
        "event_type": notification.event_type,
        "signature_key_id": notification.signature_key_id,
        "signature_valid": 1,
        "payload_digest_sha256": notification.payload_digest_sha256,
        "reported_trade_type": notification.reported_trade_type,
        "reported_trade_state": notification.reported_trade_state,
        "reported_amount_fen": notification.reported_amount_fen,
        "reported_currency": notification.reported_currency,
        "merchant_identity_valid": 1,
        "process_status": "RECEIVED",
        "security_error_code": None,
        "failure_code": None,
        "provider_created_at": datetime_text(notification.provider_created_at),
        "received_at": datetime_text(notification.received_at),
        "processing_started_at": None,
        "lease_expires_at": None,
        "worker_id": None,
        "processed_at": None,
        "attempt_count": 0,
        "next_attempt_at": None,
        "reported_appid": notification.reported_appid,
        "reported_mchid": notification.reported_mchid,
        "reported_success_at": datetime_text(notification.reported_success_at),
        "claim_token": None,
    }


def _received_row_values(row):
    values = dict(row)
    values.pop("id")
    return values


def _is_begin_immediate(sql):
    normalized = " ".join(sql.strip().removesuffix(";").split()).casefold()
    return normalized == "begin immediate"


class _BeginImmediateObservingConnection:
    def __init__(self, connection, attempted):
        self._connection = connection
        self._attempted = attempted

    def execute(self, sql, parameters=()):
        if _is_begin_immediate(sql):
            self._attempted.set()
        return self._connection.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def _run_concurrently_behind_write_lock(database_path, actions):
    barrier = Barrier(len(actions) + 1)
    begin_attempted = tuple(Event() for _action in actions)
    assert len({id(event) for event in begin_attempted}) == len(actions)
    worker_context = local()
    real_connect = database_module.connect
    blocker = sqlite3.connect(database_path)
    blocker.execute("BEGIN IMMEDIATE")

    def observing_connect(path):
        connection = real_connect(path)
        return _BeginImmediateObservingConnection(
            connection, worker_context.begin_attempted
        )

    def run(index, action):
        worker_context.begin_attempted = begin_attempted[index]
        barrier.wait(timeout=2)
        return action()

    try:
        with patch.object(database_module, "connect", observing_connect):
            with ThreadPoolExecutor(max_workers=len(actions)) as executor:
                futures = tuple(
                    executor.submit(run, index, action)
                    for index, action in enumerate(actions)
                )
                try:
                    barrier.wait(timeout=2)
                    assert all(event.wait(timeout=2) for event in begin_attempted)
                    assert blocker.in_transaction
                    for future in futures:
                        assert not future.done()
                        with pytest.raises(FutureTimeoutError):
                            future.result(timeout=0.05)
                finally:
                    blocker.rollback()
                return [future.result(timeout=10) for future in futures]
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
