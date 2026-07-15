from __future__ import annotations

import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from license_server.db import connect
from license_server.payment_reconciliation_repository import (
    EnsureReadyOutcome,
    PaymentReconciliationRepositoryError,
    claim_next_due,
    ensure_ready,
)
from license_server.payment_reconciliation_service import (
    ReconciliationOutcome,
    ReconciliationResult,
)
from license_server.signer import datetime_text
from license_server.wechat_payment import WechatPaymentError


@dataclass(frozen=True)
class PaymentReconciliationWorkerPolicy:
    scan_interval_seconds: int = 30
    recent_order_window_seconds: int = 600
    max_claims_per_cycle: int = 10
    lease_seconds: int = 60
    idle_wait_seconds: int = 1
    max_orders_per_scan: int = 100

    def __post_init__(self) -> None:
        limits = {
            "scan_interval_seconds": 3600,
            "recent_order_window_seconds": 86_400,
            "max_claims_per_cycle": 100,
            "lease_seconds": 3600,
            "idle_wait_seconds": 60,
            "max_orders_per_scan": 1000,
        }
        if any(
            type(getattr(self, name)) is not int
            or getattr(self, name) <= 0
            or getattr(self, name) > limit
            for name, limit in limits.items()
        ) or self.idle_wait_seconds > self.scan_interval_seconds:
            raise ValueError("PAYMENT_RECONCILIATION_WORKER_POLICY_INVALID")


@dataclass(frozen=True)
class WorkerCycleResult:
    scheduled_count: int
    claimed_count: int
    processed_count: int
    infrastructure_error_count: int
    no_work: bool


@dataclass
class PaymentReconciliationWorker:
    database_path: Path
    reconciliation_service: object
    worker_id: str | None = None
    policy: PaymentReconciliationWorkerPolicy = field(
        default_factory=PaymentReconciliationWorkerPolicy
    )
    _next_scan_at: datetime | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        self.database_path = Path(self.database_path)
        if not callable(getattr(self.reconciliation_service, "reconcile_claim", None)):
            raise ValueError("PAYMENT_RECONCILIATION_WORKER_SERVICE_INVALID")
        if self.worker_id is None:
            self.worker_id = f"reconciliation-worker-{secrets.token_hex(4)}"
        if not isinstance(self.worker_id, str):
            raise ValueError("PAYMENT_RECONCILIATION_WORKER_ID_INVALID")
        self.worker_id = self.worker_id.strip()
        if not self.worker_id or len(self.worker_id) > 128:
            raise ValueError("PAYMENT_RECONCILIATION_WORKER_ID_INVALID")

    def schedule_recent_waiting_orders(self, *, now: datetime) -> int:
        now = _utc_datetime(now)
        window_start = now - timedelta(seconds=self.policy.recent_order_window_seconds)
        with connect(self.database_path) as connection:
            order_ids = [
                str(row["order_id"])
                for row in connection.execute(
                    """
                    SELECT o.order_id
                    FROM payment_orders AS o
                    LEFT JOIN payment_reconciliations AS r ON r.order_id = o.order_id
                    WHERE o.status = 'WAITING_PAYMENT'
                      AND o.created_at >= ?
                      AND o.created_at <= ?
                    ORDER BY CASE WHEN r.order_id IS NULL THEN 0 ELSE 1 END,
                             o.created_at,
                             o.order_id
                    LIMIT ?
                    """,
                    (
                        datetime_text(window_start),
                        datetime_text(now),
                        self.policy.max_orders_per_scan,
                    ),
                )
            ]

        return sum(
            ensure_ready(
                self.database_path,
                order_id,
                now,
                now,
            ).outcome
            is EnsureReadyOutcome.CREATED
            for order_id in order_ids
        )

    def run_once(self, *, now: datetime, stop_event: object | None = None) -> WorkerCycleResult:
        now = _utc_datetime(now)
        scheduled_count = 0
        infrastructure_error_count = 0
        if self._next_scan_at is None or now >= self._next_scan_at:
            self._next_scan_at = now + timedelta(
                seconds=self.policy.scan_interval_seconds
            )
            try:
                scheduled_count = self.schedule_recent_waiting_orders(now=now)
            except (
                ConnectionError,
                TimeoutError,
                PaymentReconciliationRepositoryError,
                sqlite3.OperationalError,
            ) as exc:
                if not _is_retryable_infrastructure_error(exc):
                    raise
                infrastructure_error_count += 1

        claimed_count = 0
        processed_count = 0
        for _ in range(self.policy.max_claims_per_cycle):
            if stop_event is not None and stop_event.is_set():
                break
            try:
                claim = claim_next_due(
                    self.database_path,
                    worker_id=self.worker_id,
                    now=now,
                    lease_seconds=self.policy.lease_seconds,
                )
            except (
                ConnectionError,
                TimeoutError,
                PaymentReconciliationRepositoryError,
                sqlite3.OperationalError,
            ) as exc:
                if not _is_retryable_infrastructure_error(exc):
                    raise
                infrastructure_error_count += 1
                break
            if claim is None:
                break
            claimed_count += 1
            try:
                result = self.reconciliation_service.reconcile_claim(claim, now=now)
            except (
                ConnectionError,
                TimeoutError,
                PaymentReconciliationRepositoryError,
                sqlite3.OperationalError,
                WechatPaymentError,
            ) as exc:
                if not _is_retryable_infrastructure_error(exc):
                    raise
                infrastructure_error_count += 1
                continue
            if not isinstance(result, ReconciliationResult) or not isinstance(
                result.outcome,
                ReconciliationOutcome,
            ):
                raise RuntimeError("PAYMENT_RECONCILIATION_WORKER_RESULT_INVALID")
            processed_count += 1

        return WorkerCycleResult(
            scheduled_count=scheduled_count,
            claimed_count=claimed_count,
            processed_count=processed_count,
            infrastructure_error_count=infrastructure_error_count,
            no_work=claimed_count == 0,
        )

    def run_forever(self, stop_event: object, *, now_fn=None) -> None:
        clock = now_fn or (lambda: datetime.now(timezone.utc))
        while not stop_event.is_set():
            self.run_once(now=clock(), stop_event=stop_event)
            if stop_event.is_set():
                break
            stop_event.wait(self.policy.idle_wait_seconds)


def _utc_datetime(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("PAYMENT_RECONCILIATION_WORKER_TIME_INVALID")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _is_retryable_infrastructure_error(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    if isinstance(
        exc,
        (PaymentReconciliationRepositoryError, WechatPaymentError),
    ):
        return exc.retryable
    if isinstance(exc, sqlite3.OperationalError):
        code = getattr(exc, "sqlite_errorcode", None)
        return isinstance(code, int) and code & 0xFF in {
            sqlite3.SQLITE_BUSY,
            sqlite3.SQLITE_LOCKED,
        }
    return False
