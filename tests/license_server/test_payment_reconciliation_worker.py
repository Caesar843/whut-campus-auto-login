import importlib
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from license_server.db import connect, initialize_database
from license_server.payment import ANNUAL_V1, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_gateway import QueryOrderOutcome, QueryOrderResult
from license_server.payment_reconciliation_repository import (
    PaymentReconciliationRepositoryError,
    UpdateOutcome,
    claim_order,
    ensure_ready,
    get,
    reschedule_claim,
    terminate_claim,
)
from license_server.payment_reconciliation_service import (
    PaymentReconciliationPolicy,
    PaymentReconciliationService,
    ReconciliationOutcome,
    ReconciliationResult,
)
from license_server.payment_service import confirm_paid_order
from license_server.signer import datetime_text
from license_server.wechat_payment import WechatPaymentError


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)


def _worker_module():
    return importlib.import_module("license_server.payment_reconciliation_worker")


def test_worker_policy_defaults_are_bounded_and_immutable():
    module = _worker_module()

    policy = module.PaymentReconciliationWorkerPolicy()

    assert policy.scan_interval_seconds == 30
    assert policy.recent_order_window_seconds == 600
    assert 0 < policy.max_claims_per_cycle <= 100
    assert 0 < policy.lease_seconds <= 3600
    assert 0 < policy.idle_wait_seconds <= policy.scan_interval_seconds
    assert 0 < policy.max_orders_per_scan <= 1000
    with pytest.raises((AttributeError, TypeError)):
        policy.scan_interval_seconds = 1


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("scan_interval_seconds", 0),
        ("scan_interval_seconds", 3601),
        ("recent_order_window_seconds", -1),
        ("recent_order_window_seconds", 86401),
        ("max_claims_per_cycle", True),
        ("max_claims_per_cycle", 101),
        ("lease_seconds", 0),
        ("lease_seconds", 3601),
        ("idle_wait_seconds", 0),
        ("idle_wait_seconds", 31),
        ("max_orders_per_scan", 0),
        ("max_orders_per_scan", 1001),
        ("lease_seconds", 1.5),
        ("idle_wait_seconds", float("nan")),
        ("scan_interval_seconds", float("inf")),
    ),
)
def test_worker_policy_rejects_invalid_values(field, value):
    module = _worker_module()
    values = {
        "scan_interval_seconds": 30,
        "recent_order_window_seconds": 600,
        "max_claims_per_cycle": 10,
        "lease_seconds": 60,
        "idle_wait_seconds": 1,
        "max_orders_per_scan": 100,
    }
    values[field] = value

    with pytest.raises(ValueError, match="PAYMENT_RECONCILIATION_WORKER_POLICY_INVALID"):
        module.PaymentReconciliationWorkerPolicy(**values)


def test_schedule_recent_waiting_orders_uses_inclusive_created_at_window(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "recent", "WAITING_PAYMENT", NOW - timedelta(seconds=599))
    _insert_order(path, "boundary", "WAITING_PAYMENT", NOW - timedelta(seconds=600))
    _insert_order(path, "outside", "WAITING_PAYMENT", NOW - timedelta(seconds=601))
    _insert_order(path, "future", "WAITING_PAYMENT", NOW + timedelta(seconds=1))
    worker = _worker(path)

    scheduled = worker.schedule_recent_waiting_orders(now=NOW)

    assert scheduled == 2
    assert get(path, "recent") is not None
    assert get(path, "boundary") is not None
    assert get(path, "outside") is None
    assert get(path, "future") is None


@pytest.mark.parametrize("status", ("CREATED", "PAID", "CLOSED", "ABNORMAL"))
def test_schedule_recent_waiting_orders_ignores_other_statuses(tmp_path, status):
    path = _database(tmp_path)
    _insert_order(path, status.lower(), status, NOW)

    assert _worker(path).schedule_recent_waiting_orders(now=NOW) == 0
    assert get(path, status.lower()) is None


def test_schedule_is_idempotent_and_preserves_claimed_terminal_and_orders(tmp_path):
    path = _database(tmp_path)
    for order_id in ("ready", "claimed", "terminal"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
        ensure_ready(path, order_id, NOW, NOW)
    claimed = claim_order(
        path,
        order_id="claimed",
        worker_id="manual-worker",
        now=NOW,
        lease_seconds=60,
    ).claim
    terminal_claim = claim_order(
        path,
        order_id="terminal",
        worker_id="manual-worker",
        now=NOW,
        lease_seconds=60,
    ).claim
    terminate_claim(
        path,
        claim_token=terminal_claim.claim_token,
        expected_state_version=terminal_claim.state_version,
        terminal_at=NOW,
        terminal_reason="MANUAL_REVIEW_REQUIRED",
    )
    before_tasks = {order_id: _task_row(path, order_id) for order_id in ("ready", "claimed", "terminal")}
    before_orders = _order_rows(path)

    scheduled = _worker(path).schedule_recent_waiting_orders(now=NOW)

    assert scheduled == 0
    assert {order_id: _task_row(path, order_id) for order_id in before_tasks} == before_tasks
    assert _order_rows(path) == before_orders
    assert claimed is not None


def test_schedule_batch_prioritizes_unscheduled_orders_without_starvation(tmp_path):
    path = _database(tmp_path)
    for order_id in ("order-a", "order-b", "order-c"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
    worker = _worker(path, max_orders_per_scan=2)

    assert worker.schedule_recent_waiting_orders(now=NOW) == 2
    assert worker.schedule_recent_waiting_orders(now=NOW) == 1
    assert {order_id for order_id in ("order-a", "order-b", "order-c") if get(path, order_id)} == {
        "order-a",
        "order-b",
        "order-c",
    }


def test_run_once_reports_no_work_without_exposing_identifiers(tmp_path):
    path = _database(tmp_path)

    result = _worker(path).run_once(now=NOW)

    assert result.scheduled_count == 0
    assert result.claimed_count == 0
    assert result.processed_count == 0
    assert result.infrastructure_error_count == 0
    assert result.no_work is True
    result_text = repr(result)
    assert str(path) not in result_text
    assert "reconciliation-worker-test0001" not in result_text


def test_run_once_discovers_and_processes_at_most_cycle_limit(tmp_path):
    path = _database(tmp_path)
    for order_id in ("order-a", "order-b", "order-c"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
    service = _RecordingService()

    result = _worker(path, service=service, max_claims_per_cycle=2).run_once(now=NOW)

    assert result.scheduled_count == 3
    assert result.claimed_count == 2
    assert result.processed_count == 2
    assert result.infrastructure_error_count == 0
    assert result.no_work is False
    assert [claim.order_id for claim, _ in service.claims] == ["order-a", "order-b"]
    assert {processed_at for _, processed_at in service.claims} == {NOW}


def test_run_once_uses_fresh_clock_for_each_claim_in_same_cycle(tmp_path):
    path = _database(tmp_path)
    for order_id in ("order-1", "order-2"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
        ensure_ready(path, order_id, NOW, NOW)
    clock = _MutableClock(NOW)

    def process(_claim, _now):
        if clock.current == NOW:
            clock.set(NOW + timedelta(seconds=10))
        return ReconciliationResult(ReconciliationOutcome.RESCHEDULED)

    service = _RecordingService(process)
    worker = _worker(path, service=service, clock=clock, max_claims_per_cycle=2)

    result = worker.run_once(now=NOW)

    assert result.claimed_count == result.processed_count == 2
    first, second = (item[0] for item in service.claims)
    assert first.claimed_at == NOW
    assert second.claimed_at == NOW + timedelta(seconds=10)
    assert second.lease_expires_at == NOW + timedelta(seconds=70)
    assert second.query_attempt_count == second.state_version == 1
    assert result.infrastructure_error_count == 0
    assert result.no_work is False
    assert [claim.order_id for claim, _ in service.claims] == ["order-1", "order-2"]
    assert {processed_at for _, processed_at in service.claims} == {
        NOW,
        NOW + timedelta(seconds=10),
    }


def test_run_once_claims_persisted_due_task_outside_scan_window(tmp_path):
    path = _database(tmp_path)
    created_at = NOW - timedelta(days=1)
    _insert_order(path, "persisted", "WAITING_PAYMENT", created_at)
    ensure_ready(path, "persisted", created_at, NOW)
    service = _RecordingService()

    result = _worker(path, service=service).run_once(now=NOW)

    assert result.scheduled_count == 0
    assert result.claimed_count == 1
    assert result.processed_count == 1
    assert [claim.order_id for claim, _ in service.claims] == ["persisted"]


def test_run_once_scans_on_cadence_but_claims_on_every_cycle(tmp_path):
    path = _database(tmp_path)
    service = _RecordingService()
    worker = _worker(path, service=service, scan_interval_seconds=30)
    assert worker.run_once(now=NOW).no_work is True

    ten_seconds_later = NOW + timedelta(seconds=10)
    _insert_order(path, "new-order", "WAITING_PAYMENT", ten_seconds_later)
    before_scan = worker.run_once(now=ten_seconds_later)
    assert before_scan.scheduled_count == 0
    assert before_scan.no_work is True

    at_scan = worker.run_once(now=NOW + timedelta(seconds=30))
    assert at_scan.scheduled_count == 1
    assert at_scan.claimed_count == 1
    assert [claim.order_id for claim, _ in service.claims] == ["new-order"]


def test_default_worker_ids_are_unique_bounded_and_non_sensitive(tmp_path):
    module = _worker_module()
    path = _database(tmp_path)

    first = module.PaymentReconciliationWorker(path, _RecordingService())
    second = module.PaymentReconciliationWorker(path, _RecordingService())

    assert first.worker_id != second.worker_id
    for worker_id in (first.worker_id, second.worker_id):
        assert worker_id.startswith("reconciliation-worker-")
        assert len(worker_id) <= 128
        assert str(path) not in worker_id


@pytest.mark.parametrize("worker_id", ("", "   ", "x" * 129, 123))
def test_worker_rejects_invalid_explicit_worker_id(tmp_path, worker_id):
    module = _worker_module()

    with pytest.raises(ValueError, match="PAYMENT_RECONCILIATION_WORKER_ID_INVALID"):
        module.PaymentReconciliationWorker(
            _database(tmp_path),
            _RecordingService(),
            worker_id=worker_id,
        )


def test_worker_rejects_missing_service_contract(tmp_path):
    module = _worker_module()

    with pytest.raises(ValueError, match="PAYMENT_RECONCILIATION_WORKER_SERVICE_INVALID"):
        module.PaymentReconciliationWorker(_database(tmp_path), object())


def test_worker_rejects_naive_cycle_time(tmp_path):
    with pytest.raises(ValueError, match="PAYMENT_RECONCILIATION_WORKER_TIME_INVALID"):
        _worker(_database(tmp_path)).run_once(now=NOW.replace(tzinfo=None))


@pytest.mark.parametrize("error", (ConnectionError("offline"), TimeoutError("slow")))
def test_run_once_isolates_transient_service_infrastructure_errors(tmp_path, error):
    path = _database(tmp_path)
    for order_id in ("order-a", "order-b"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
    calls = 0

    def action(claim, now):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise error
        return ReconciliationResult(ReconciliationOutcome.RESCHEDULED)

    result = _worker(path, service=_RecordingService(action)).run_once(now=NOW)

    assert result.claimed_count == 2
    assert result.processed_count == 1
    assert result.infrastructure_error_count == 1
    assert result.no_work is False


@pytest.mark.parametrize(
    ("error_kind", "sqlite_error_code"),
    (
        ("sqlite", sqlite3.SQLITE_BUSY),
        ("sqlite", sqlite3.SQLITE_LOCKED),
        ("payment", None),
    ),
)
def test_run_once_isolates_known_retryable_storage_or_payment_errors(
    tmp_path,
    error_kind,
    sqlite_error_code,
):
    path = _database(tmp_path)
    for order_id in ("order-a", "order-b"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
    if error_kind == "sqlite":
        error = sqlite3.OperationalError("retryable storage failure")
        error.sqlite_errorcode = sqlite_error_code
    else:
        error = WechatPaymentError("PAYMENT_READ_TIMEOUT", retryable=True)
    calls = 0

    def action(claim, now):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise error
        return ReconciliationResult(ReconciliationOutcome.RESCHEDULED)

    result = _worker(path, service=_RecordingService(action)).run_once(now=NOW)

    assert result.claimed_count == 2
    assert result.processed_count == 1
    assert result.infrastructure_error_count == 1
    assert get(path, "order-a").reconcile_status == "CLAIMED"
    with connect(path) as connection:
        assert connection.execute(
            "SELECT status FROM payment_orders WHERE order_id='order-a'"
        ).fetchone()[0] == "WAITING_PAYMENT"


def test_run_once_isolates_retryable_repository_error_from_service(tmp_path):
    path = _database(tmp_path)
    for order_id in ("order-a", "order-b"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
    calls = 0

    def action(claim, now):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PaymentReconciliationRepositoryError("DATABASE_BUSY", retryable=True)
        return ReconciliationResult(ReconciliationOutcome.RESCHEDULED)

    result = _worker(path, service=_RecordingService(action)).run_once(now=NOW)

    assert result.claimed_count == 2
    assert result.processed_count == 1
    assert result.infrastructure_error_count == 1


def test_run_once_propagates_fatal_service_or_programming_errors(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "order-a", "WAITING_PAYMENT", NOW)

    def action(claim, now):
        raise PaymentReconciliationRepositoryError("SCHEMA_INVALID", retryable=False)

    with pytest.raises(PaymentReconciliationRepositoryError, match="SCHEMA_INVALID"):
        _worker(path, service=_RecordingService(action)).run_once(now=NOW)


@pytest.mark.parametrize(
    "error",
    (
        sqlite3.OperationalError("no such table: payment_reconciliations"),
        WechatPaymentError("PAYMENT_CONFIG_INVALID", retryable=False),
        LookupError("programming defect"),
    ),
)
def test_run_once_propagates_nonretryable_storage_payment_and_unknown_errors(
    tmp_path,
    error,
):
    path = _database(tmp_path)
    _insert_order(path, "order-a", "WAITING_PAYMENT", NOW)

    def action(claim, now):
        raise error

    with pytest.raises(type(error), match=str(error)):
        _worker(path, service=_RecordingService(action)).run_once(now=NOW)


def test_infrastructure_error_result_does_not_echo_sensitive_exception_text(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "sensitive-order", "WAITING_PAYMENT", NOW)
    sensitive = f"{path} SELECT * token-secret sensitive-order"

    def action(claim, now):
        raise ConnectionError(sensitive)

    result = _worker(path, service=_RecordingService(action)).run_once(now=NOW)

    assert result.infrastructure_error_count == 1
    assert str(path) not in repr(result)
    assert "token-secret" not in repr(result)
    assert "sensitive-order" not in repr(result)


def test_run_once_rejects_invalid_service_result(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "order-a", "WAITING_PAYMENT", NOW)

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_WORKER_RESULT_INVALID"):
        _worker(path, service=_RecordingService(lambda claim, now: object())).run_once(now=NOW)


def test_run_once_rejects_result_with_invalid_business_outcome(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "order-a", "WAITING_PAYMENT", NOW)
    malformed = ReconciliationResult("NOT_A_RECONCILIATION_OUTCOME")

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_WORKER_RESULT_INVALID"):
        _worker(
            path,
            service=_RecordingService(lambda claim, now: malformed),
        ).run_once(now=NOW)


@pytest.mark.parametrize("outcome", tuple(ReconciliationOutcome))
def test_worker_accepts_every_business_result_without_secondary_database_write(
    tmp_path,
    outcome,
):
    path = _database(tmp_path)
    _insert_order(path, "business-order", "WAITING_PAYMENT", NOW)
    order_before = _order_rows(path)
    service = _RecordingService(
        lambda claim, now: ReconciliationResult(outcome)
    )

    result = _worker(path, service=service).run_once(now=NOW)

    assert result.processed_count == 1
    assert len(service.claims) == 1
    assert get(path, "business-order").reconcile_status == "CLAIMED"
    assert _order_rows(path) == order_before


def test_retryable_claim_error_is_counted_without_busy_retry(tmp_path, monkeypatch):
    module = _worker_module()
    path = _database(tmp_path)
    calls = 0

    def fail_claim(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise PaymentReconciliationRepositoryError("DATABASE_BUSY", retryable=True)

    monkeypatch.setattr(module, "claim_next_due", fail_claim)

    result = _worker(path).run_once(now=NOW)

    assert calls == 1
    assert result.claimed_count == 0
    assert result.processed_count == 0
    assert result.infrastructure_error_count == 1


def test_retryable_scan_error_does_not_block_persisted_due_task(tmp_path, monkeypatch):
    module = _worker_module()
    path = _database(tmp_path)
    old = NOW - timedelta(days=1)
    _insert_order(path, "persisted", "WAITING_PAYMENT", old)
    ensure_ready(path, "persisted", old, NOW)
    _insert_order(path, "scan-candidate", "WAITING_PAYMENT", NOW)

    def fail_schedule(*args, **kwargs):
        raise PaymentReconciliationRepositoryError("DATABASE_BUSY", retryable=True)

    monkeypatch.setattr(module, "ensure_ready", fail_schedule)
    service = _RecordingService()

    result = _worker(path, service=service).run_once(now=NOW)

    assert result.scheduled_count == 0
    assert result.claimed_count == 1
    assert result.processed_count == 1
    assert result.infrastructure_error_count == 1
    assert [claim.order_id for claim, _ in service.claims] == ["persisted"]


class _RecordingStopEvent:
    def __init__(self, *, initially_set=False):
        self._set = initially_set
        self.waits = []

    def is_set(self):
        return self._set

    def set(self):
        self._set = True

    def wait(self, seconds):
        self.waits.append(seconds)
        self._set = True
        return True


def test_run_forever_returns_immediately_when_already_stopped(tmp_path, monkeypatch):
    worker = _worker(_database(tmp_path))
    calls = []
    monkeypatch.setattr(worker, "run_once", lambda **kwargs: calls.append(kwargs))

    worker.run_forever(_RecordingStopEvent(initially_set=True), now_fn=lambda: NOW)

    assert calls == []


def test_run_forever_waits_on_stop_event_without_busy_spinning(tmp_path):
    stop_event = _RecordingStopEvent()

    _worker(_database(tmp_path), idle_wait_seconds=3).run_forever(
        stop_event,
        now_fn=lambda: NOW,
    )

    assert stop_event.waits == [3]


def test_stop_requested_during_service_prevents_another_claim(tmp_path):
    path = _database(tmp_path)
    for order_id in ("order-a", "order-b"):
        _insert_order(path, order_id, "WAITING_PAYMENT", NOW)
    stop_event = threading.Event()

    def action(claim, now):
        stop_event.set()
        return ReconciliationResult(ReconciliationOutcome.RESCHEDULED)

    service = _RecordingService(action)
    _worker(path, service=service).run_forever(stop_event, now_fn=lambda: NOW)

    assert len(service.claims) == 1


def test_run_forever_propagates_fatal_error_without_retry_loop(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "order-a", "WAITING_PAYMENT", NOW)
    stop_event = _RecordingStopEvent()
    calls = 0

    def action(claim, now):
        nonlocal calls
        calls += 1
        raise LookupError("programming defect")

    with pytest.raises(LookupError, match="programming defect"):
        _worker(path, service=_RecordingService(action)).run_forever(
            stop_event,
            now_fn=lambda: NOW,
        )

    assert calls == 1
    assert stop_event.waits == []


def test_two_workers_compete_for_one_ready_task_with_one_service_call(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "shared-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "shared-order", NOW, NOW)
    barrier = threading.Barrier(2)

    def run(worker_id):
        service = _RecordingService()
        worker = _worker(path, service=service, worker_id=worker_id)
        barrier.wait(timeout=5)
        return worker.run_once(now=NOW), service

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run, f"worker-{index}") for index in range(2)]
        outcomes = [future.result(timeout=5) for future in futures]

    assert sum(result.claimed_count for result, _ in outcomes) == 1
    assert sum(result.processed_count for result, _ in outcomes) == 1
    assert sum(len(service.claims) for _, service in outcomes) == 1
    record = get(path, "shared-order")
    assert record.reconcile_status == "CLAIMED"
    assert record.claimed_by in {"worker-0", "worker-1"}


def test_two_workers_compete_to_reclaim_one_expired_lease(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "expired-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "expired-order", NOW, NOW)
    old_claim = claim_order(
        path,
        order_id="expired-order",
        worker_id="crashed-worker",
        now=NOW,
        lease_seconds=1,
    ).claim
    barrier = threading.Barrier(2)
    recovered_at = NOW + timedelta(seconds=1)

    def run(worker_id):
        service = _RecordingService()
        worker = _worker(path, service=service, worker_id=worker_id)
        barrier.wait(timeout=5)
        return worker.run_once(now=recovered_at), service

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run, f"worker-{index}") for index in range(2)]
        outcomes = [future.result(timeout=5) for future in futures]

    assert sum(result.claimed_count for result, _ in outcomes) == 1
    assert sum(len(service.claims) for _, service in outcomes) == 1
    record = get(path, "expired-order")
    assert record.reconcile_status == "CLAIMED"
    assert record.claim_token != old_claim.claim_token
    stale_update = reschedule_claim(
        path,
        claim_token=old_claim.claim_token,
        expected_state_version=old_claim.state_version,
        completed_at=recovered_at,
        next_attempt_at=recovered_at + timedelta(seconds=1),
    )
    assert stale_update.outcome is UpdateOutcome.LOST_CLAIM


def test_valid_lease_cannot_be_stolen_by_other_workers(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "leased-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "leased-order", NOW, NOW)
    active_claim = claim_order(
        path,
        order_id="leased-order",
        worker_id="active-worker",
        now=NOW,
        lease_seconds=60,
    ).claim
    barrier = threading.Barrier(2)

    def run(worker_id):
        service = _RecordingService()
        worker = _worker(path, service=service, worker_id=worker_id)
        barrier.wait(timeout=5)
        return worker.run_once(now=NOW + timedelta(seconds=59)), service

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run, f"waiting-worker-{index}") for index in range(2)]
        outcomes = [future.result(timeout=5) for future in futures]

    assert sum(result.claimed_count for result, _ in outcomes) == 0
    assert sum(len(service.claims) for _, service in outcomes) == 0
    record = get(path, "leased-order")
    assert record.claim_token == active_claim.claim_token
    assert record.claimed_by == "active-worker"


def test_crashed_worker_claim_is_recovered_exactly_at_lease_expiry(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "recoverable-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "recoverable-order", NOW, NOW)
    abandoned = claim_order(
        path,
        order_id="recoverable-order",
        worker_id="crashed-worker",
        now=NOW,
        lease_seconds=60,
    ).claim
    service = _RecordingService()
    recovery_worker = _worker(path, service=service, worker_id="recovery-worker")

    before_expiry = recovery_worker.run_once(now=NOW + timedelta(seconds=59))
    at_expiry = recovery_worker.run_once(now=NOW + timedelta(seconds=60))

    assert before_expiry.claimed_count == 0
    assert at_expiry.claimed_count == 1
    assert len(service.claims) == 1
    record = get(path, "recoverable-order")
    assert record.claimed_by == "recovery-worker"
    assert record.claim_token != abandoned.claim_token


def test_manual_refresh_and_worker_enter_service_and_gateway_only_once(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "refresh-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "refresh-order", NOW, NOW)
    background_gateway = _FakeGateway(_success("refresh-order"))
    manual_gateway = _FakeGateway(_success("refresh-order"))
    barrier = threading.Barrier(2)

    def run_background():
        barrier.wait(timeout=5)
        return _worker(
            path,
            service=_real_service(path, background_gateway),
            worker_id="background-worker",
        ).run_once(now=NOW)

    def run_manual_refresh():
        barrier.wait(timeout=5)
        result = claim_order(
            path,
            order_id="refresh-order",
            worker_id="manual-refresh",
            now=NOW,
            lease_seconds=60,
        )
        if result.claim is not None:
            _real_service(path, manual_gateway).reconcile_claim(result.claim, now=NOW)
        return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        background_future = executor.submit(run_background)
        manual_future = executor.submit(run_manual_refresh)
        background_result = background_future.result(timeout=5)
        manual_result = manual_future.result(timeout=5)

    service_entries = background_result.processed_count + int(manual_result.claim is not None)
    assert service_entries == 1
    assert len(background_gateway.queried) + len(manual_gateway.queried) == 1
    assert get(path, "refresh-order").query_attempt_count == 1
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "PAID"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_stale_http_result_cannot_overwrite_reclaimed_worker_result(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "http-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "http-order", NOW, NOW)
    entered = threading.Event()
    release = threading.Event()
    old_gateway = _BlockingGateway(_notpay("http-order"), entered, release)
    new_gateway = _FakeGateway(_notpay("http-order"))
    old_clock = _MutableClock(NOW)
    new_clock = _MutableClock(NOW + timedelta(seconds=1))
    old_worker = _worker(
        path,
        service=_real_service(path, old_gateway, clock=old_clock),
        worker_id="old-worker",
        clock=old_clock,
        lease_seconds=1,
    )
    new_worker = _worker(
        path,
        service=_real_service(path, new_gateway, clock=new_clock),
        worker_id="new-worker",
        clock=new_clock,
        lease_seconds=60,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        old_future = executor.submit(old_worker.run_once, now=NOW)
        assert entered.wait(timeout=5)
        new_future = executor.submit(
            new_worker.run_once,
            now=NOW + timedelta(seconds=1),
        )
        new_result = new_future.result(timeout=5)
        release.set()
        old_result = old_future.result(timeout=5)

    assert new_result.processed_count == old_result.processed_count == 1
    assert old_gateway.queried == new_gateway.queried == ["http-order"]
    record = get(path, "http-order")
    assert record.reconcile_status == "READY"
    assert record.query_attempt_count == 2
    assert record.next_attempt_at == NOW + timedelta(seconds=5)
    with connect(path) as connection:
        assert connection.execute("SELECT status FROM payment_orders").fetchone()[0] == "WAITING_PAYMENT"


def test_callback_during_worker_query_keeps_paid_order_and_one_grant(tmp_path):
    path = _database(tmp_path)
    _insert_order(path, "callback-order", "WAITING_PAYMENT", NOW)
    ensure_ready(path, "callback-order", NOW, NOW)
    entered = threading.Event()
    release = threading.Event()
    gateway = _BlockingGateway(_success("callback-order"), entered, release)
    worker = _worker(
        path,
        service=_real_service(path, gateway),
        worker_id="callback-worker",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        worker_future = executor.submit(worker.run_once, now=NOW)
        assert entered.wait(timeout=5)
        callback_future = executor.submit(
            confirm_paid_order,
            path,
            _callback_evidence("callback-order"),
            issued_by="wechat_callback",
            now=NOW,
        )
        callback_future.result(timeout=5)
        release.set()
        result = worker_future.result(timeout=5)

    assert result.processed_count == 1
    assert gateway.queried == ["callback-order"]
    with connect(path) as connection:
        order = connection.execute(
            "SELECT status FROM payment_orders WHERE order_id='callback-order'"
        ).fetchone()[0]
        grant_count = connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0]
        paid_license_count = connection.execute(
            "SELECT COUNT(*) FROM licenses WHERE license_type='paid'"
        ).fetchone()[0]
    assert order == "PAID"
    assert grant_count == paid_license_count == 1
    assert get(path, "callback-order").reconcile_status == "TERMINAL"


class _RecordingService:
    def __init__(self, action=None):
        self.action = action
        self.claims = []

    def reconcile_claim(self, claim, *, now):
        self.claims.append((claim, now))
        if self.action is not None:
            return self.action(claim, now)
        return ReconciliationResult(ReconciliationOutcome.RESCHEDULED)


def _worker(
    path,
    *,
    service=None,
    worker_id="reconciliation-worker-test0001",
    clock=None,
    **policy_overrides,
):
    module = _worker_module()
    policy_values = {
        "scan_interval_seconds": 30,
        "recent_order_window_seconds": 600,
        "max_claims_per_cycle": 10,
        "lease_seconds": 60,
        "idle_wait_seconds": 1,
        "max_orders_per_scan": 100,
    }
    policy_values.update(policy_overrides)
    return module.PaymentReconciliationWorker(
        database_path=path,
        reconciliation_service=service or _RecordingService(),
        worker_id=worker_id,
        policy=module.PaymentReconciliationWorkerPolicy(**policy_values),
        clock=clock or (lambda: NOW),
    )


def _database(tmp_path):
    path = tmp_path / "license.sqlite3"
    initialize_database(path)
    return path


def _insert_order(path, order_id, status, created_at, *, expires_at=None):
    open_slot = "open" if status in {"CREATED", "WAITING_PAYMENT", "ABNORMAL"} else None
    paid_at = NOW if status == "PAID" else None
    closed_at = NOW if status == "CLOSED" else None
    with connect(path) as connection:
        connection.execute(
            """INSERT OR IGNORE INTO devices (
                   product_id, device_fingerprint_hash, first_seen_at, last_seen_at
               ) VALUES ('whut-campus-auto-login', ?, ?, ?)""",
            (
                f"device-{order_id}",
                datetime_text(created_at),
                datetime_text(created_at),
            ),
        )
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
                datetime_text(created_at),
                datetime_text(created_at),
                datetime_text(expires_at or NOW + timedelta(minutes=15)),
                datetime_text(paid_at) if paid_at else None,
                datetime_text(closed_at) if closed_at else None,
            ),
        )
        connection.commit()


def _task_row(path, order_id):
    with connect(path) as connection:
        return tuple(
            connection.execute(
                "SELECT * FROM payment_reconciliations WHERE order_id=?",
                (order_id,),
            ).fetchone()
        )


def _order_rows(path):
    with connect(path) as connection:
        return [
            tuple(row)
            for row in connection.execute("SELECT * FROM payment_orders ORDER BY order_id")
        ]


SERVICE_POLICY = PaymentReconciliationPolicy(
    query_retry_base_seconds=2,
    query_retry_max_seconds=8,
    max_query_attempts=3,
    close_retry_base_seconds=3,
    close_retry_max_seconds=9,
    max_close_attempts=2,
)
APP_ID = "wx-test-app"
MCH_ID = "1900000109"


class _FakeGateway:
    def __init__(self, query_result):
        self.query_result = query_result
        self.queried = []

    def query_order(self, order_id):
        self.queried.append(order_id)
        return self.query_result

    def close_order(self, order_id):
        raise AssertionError("close is outside this worker race")


class _BlockingGateway(_FakeGateway):
    def __init__(self, query_result, entered, release):
        super().__init__(query_result)
        self.entered = entered
        self.release = release

    def query_order(self, order_id):
        self.queried.append(order_id)
        self.entered.set()
        assert self.release.wait(timeout=5)
        return self.query_result


def _real_service(path, gateway, *, clock=None):
    return PaymentReconciliationService(
        database_path=path,
        gateway=gateway,
        expected_appid=APP_ID,
        expected_mchid=MCH_ID,
        policy=SERVICE_POLICY,
        clock=clock or (lambda: NOW),
    )


class _MutableClock:
    def __init__(self, current):
        self.current = current

    def __call__(self):
        return self.current

    def set(self, value):
        self.current = value


def _notpay(order_id):
    return QueryOrderResult(
        outcome=QueryOrderOutcome.NOTPAY,
        out_trade_no=order_id,
        trade_state="NOTPAY",
    )


def _success(order_id):
    return QueryOrderResult(
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
