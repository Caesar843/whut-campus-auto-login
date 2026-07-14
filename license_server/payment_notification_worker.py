from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

from license_server.db import write_transaction
from license_server.payment import OrderStatus, PaymentEvidence, PaymentEvidenceSource
from license_server.payment_notification_repository import (
    DUPLICATE_FAILURE_CODE,
    EVIDENCE_MISMATCH_FAILURE_CODE,
    ORPHAN_FAILURE_CODE,
    ClaimedPaymentNotification,
    UpdateOutcome,
    claim_next_payment_notification,
    finalize_expired_max_attempts,
    load_claimed_notification_in_transaction,
    mark_abnormal,
    mark_retry,
    mark_terminal_in_transaction,
    retry_delay_seconds,
)
from license_server.payment_service import (
    PaymentServiceError,
    _committed_payment_chain_is_valid_in_transaction,
    _confirm_paid_order_in_transaction,
    _order_product_error,
)
from license_server.signer import datetime_text


_RETRY_FAILURE_CODE = "PAYMENT_NOTIFICATION_STORAGE_RETRY"


class _LostClaimError(RuntimeError):
    pass


class WorkerProcessOutcome(str, Enum):
    NO_WORK = "NO_WORK"
    PROCESSED = "PROCESSED"
    DUPLICATE = "DUPLICATE"
    ORPHAN = "ORPHAN"
    ABNORMAL = "ABNORMAL"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    LOST_CLAIM = "LOST_CLAIM"


@dataclass(frozen=True)
class WorkerProcessResult:
    outcome: WorkerProcessOutcome
    notification_id: int | None = None


@dataclass(frozen=True)
class PaymentNotificationWorker:
    database_path: Path
    worker_id: str
    expected_appid: str
    expected_mchid: str
    lease_seconds: int = 60
    max_attempts: int = 8
    retry_base_seconds: int = 5
    retry_max_seconds: int = 300
    finalize_limit: int = 100

    def __post_init__(self) -> None:
        object.__setattr__(self, "database_path", Path(self.database_path))
        for name in ("worker_id", "expected_appid", "expected_mchid"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError("PAYMENT_NOTIFICATION_WORKER_CONFIG_INVALID")
        for name in ("lease_seconds", "max_attempts", "finalize_limit"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError("PAYMENT_NOTIFICATION_WORKER_CONFIG_INVALID")
        retry_delay_seconds(
            1,
            self.retry_base_seconds,
            self.retry_max_seconds,
        )

    def process_next(self, *, now: datetime) -> WorkerProcessResult:
        now = _utc(now)
        finalize_expired_max_attempts(
            self.database_path,
            now=now,
            max_attempts=self.max_attempts,
            limit=self.finalize_limit,
        )
        claimed = claim_next_payment_notification(
            self.database_path,
            worker_id=self.worker_id,
            now=now,
            lease_expires_at=now + timedelta(seconds=self.lease_seconds),
            max_attempts=self.max_attempts,
        )
        if claimed is None:
            return WorkerProcessResult(WorkerProcessOutcome.NO_WORK)
        try:
            return self._process_claimed(claimed, now=now)
        except _LostClaimError:
            return WorkerProcessResult(WorkerProcessOutcome.LOST_CLAIM, claimed.id)
        except sqlite3.IntegrityError:
            return self._recover_integrity_error(claimed, now=now)
        except sqlite3.OperationalError as exc:
            if _is_retryable_sqlite_error(exc):
                return self._schedule_retry(claimed, now=now)
            return self._mark_storage_conflict(claimed, now=now)
        except sqlite3.Error:
            return self._mark_storage_conflict(claimed, now=now)

    def _process_claimed(
        self,
        claimed: ClaimedPaymentNotification,
        *,
        now: datetime,
    ) -> WorkerProcessResult:
        with write_transaction(self.database_path) as connection:
            notification = load_claimed_notification_in_transaction(
                connection,
                notification_id=claimed.id,
                claim_token=claimed.claim_token,
                worker_id=self.worker_id,
                now=now,
            )
            if notification is None:
                return WorkerProcessResult(
                    WorkerProcessOutcome.LOST_CLAIM,
                    claimed.id,
                )
            if not _valid_persisted_evidence(
                notification,
                expected_appid=self.expected_appid,
                expected_mchid=self.expected_mchid,
            ):
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.ABNORMAL,
                    EVIDENCE_MISMATCH_FAILURE_CODE,
                    now,
                )

            order = connection.execute(
                "SELECT * FROM payment_orders WHERE order_id = ?",
                (str(notification["out_trade_no"]),),
            ).fetchone()
            if order is None:
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.ORPHAN,
                    ORPHAN_FAILURE_CODE,
                    now,
                )
            if _order_evidence_conflicts(connection, notification, order, now=now):
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.ABNORMAL,
                    EVIDENCE_MISMATCH_FAILURE_CODE,
                    now,
                )
            if _order_product_error(order) is not None:
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.ABNORMAL,
                    EVIDENCE_MISMATCH_FAILURE_CODE,
                    now,
                )

            status = str(order["status"])
            if status == OrderStatus.PAID.value:
                if not _paid_fact_is_consistent(connection, notification, order):
                    return _finish(
                        connection,
                        claimed,
                        WorkerProcessOutcome.ABNORMAL,
                        EVIDENCE_MISMATCH_FAILURE_CODE,
                        now,
                    )
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.DUPLICATE,
                    DUPLICATE_FAILURE_CODE,
                    now,
                )
            if status not in {
                OrderStatus.CREATED.value,
                OrderStatus.WAITING_PAYMENT.value,
            }:
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.ABNORMAL,
                    EVIDENCE_MISMATCH_FAILURE_CODE,
                    now,
                )

            evidence = PaymentEvidence(
                source=PaymentEvidenceSource.WECHAT_CALLBACK,
                out_trade_no=str(notification["out_trade_no"]),
                provider_transaction_id=str(
                    notification["provider_transaction_id"]
                ),
                trade_type=str(notification["reported_trade_type"]),
                trade_state=str(notification["reported_trade_state"]),
                amount_fen=int(notification["reported_amount_fen"]),
                currency=str(notification["reported_currency"]),
                paid_at=_parse_utc(str(notification["reported_success_at"])),
                appid=str(notification["reported_appid"]),
                mchid=str(notification["reported_mchid"]),
                provider_notification_id=str(
                    notification["provider_notification_id"]
                ),
            )
            connection.execute("SAVEPOINT payment_confirmation")
            try:
                confirmation = _confirm_paid_order_in_transaction(
                    connection,
                    evidence,
                    notification_id=None,
                    issued_by="wechat_callback",
                    now=now,
                )
            except PaymentServiceError:
                connection.execute("ROLLBACK TO payment_confirmation")
                connection.execute("RELEASE payment_confirmation")
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.ABNORMAL,
                    EVIDENCE_MISMATCH_FAILURE_CODE,
                    now,
                )
            connection.execute("RELEASE payment_confirmation")
            if confirmation.idempotent:
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.DUPLICATE,
                    DUPLICATE_FAILURE_CODE,
                    now,
                )
            return _finish(
                connection,
                claimed,
                WorkerProcessOutcome.PROCESSED,
                None,
                now,
            )

    def _recover_integrity_error(
        self,
        claimed: ClaimedPaymentNotification,
        *,
        now: datetime,
    ) -> WorkerProcessResult:
        with write_transaction(self.database_path) as connection:
            notification = load_claimed_notification_in_transaction(
                connection,
                notification_id=claimed.id,
                claim_token=claimed.claim_token,
                worker_id=self.worker_id,
                now=now,
            )
            if notification is None:
                return WorkerProcessResult(
                    WorkerProcessOutcome.LOST_CLAIM,
                    claimed.id,
                )
            order = connection.execute(
                "SELECT * FROM payment_orders WHERE order_id = ?",
                (str(notification["out_trade_no"]),),
            ).fetchone()
            if (
                _valid_persisted_evidence(
                    notification,
                    expected_appid=self.expected_appid,
                    expected_mchid=self.expected_mchid,
                )
                and order is not None
                and not _order_evidence_conflicts(
                    connection,
                    notification,
                    order,
                    now=now,
                )
                and _order_product_error(order) is None
                and str(order["status"]) == OrderStatus.PAID.value
                and _paid_fact_is_consistent(connection, notification, order)
            ):
                return _finish(
                    connection,
                    claimed,
                    WorkerProcessOutcome.DUPLICATE,
                    DUPLICATE_FAILURE_CODE,
                    now,
                )
            return _finish(
                connection,
                claimed,
                WorkerProcessOutcome.ABNORMAL,
                "PAYMENT_NOTIFICATION_STORAGE_CONFLICT",
                now,
            )

    def _mark_storage_conflict(
        self,
        claimed: ClaimedPaymentNotification,
        *,
        now: datetime,
    ) -> WorkerProcessResult:
        update = mark_abnormal(
            self.database_path,
            notification_id=claimed.id,
            claim_token=claimed.claim_token,
            failure_code="PAYMENT_NOTIFICATION_STORAGE_CONFLICT",
            processed_at=now,
        )
        if update.outcome is UpdateOutcome.LOST_CLAIM:
            return WorkerProcessResult(WorkerProcessOutcome.LOST_CLAIM, claimed.id)
        return WorkerProcessResult(WorkerProcessOutcome.ABNORMAL, claimed.id)

    def _schedule_retry(
        self,
        claimed: ClaimedPaymentNotification,
        *,
        now: datetime,
    ) -> WorkerProcessResult:
        delay = retry_delay_seconds(
            claimed.attempt_count,
            self.retry_base_seconds,
            self.retry_max_seconds,
        )
        update = mark_retry(
            self.database_path,
            notification_id=claimed.id,
            claim_token=claimed.claim_token,
            failure_code=_RETRY_FAILURE_CODE,
            next_attempt_at=now + timedelta(seconds=delay),
            processed_at=now,
            max_attempts=self.max_attempts,
        )
        if update.outcome is UpdateOutcome.LOST_CLAIM:
            return WorkerProcessResult(WorkerProcessOutcome.LOST_CLAIM, claimed.id)
        outcome = (
            WorkerProcessOutcome.ABNORMAL
            if update.process_status == "ABNORMAL"
            else WorkerProcessOutcome.RETRY_SCHEDULED
        )
        return WorkerProcessResult(outcome, claimed.id)


def _finish(
    connection: sqlite3.Connection,
    claimed: ClaimedPaymentNotification,
    outcome: WorkerProcessOutcome,
    failure_code: str | None,
    now: datetime,
) -> WorkerProcessResult:
    update = mark_terminal_in_transaction(
        connection,
        notification_id=claimed.id,
        claim_token=claimed.claim_token,
        status=outcome.value,
        failure_code=failure_code,
        processed_at=now,
    )
    if update.outcome is UpdateOutcome.LOST_CLAIM:
        raise _LostClaimError
    return WorkerProcessResult(outcome, claimed.id)


def _valid_persisted_evidence(
    notification: sqlite3.Row,
    *,
    expected_appid: str,
    expected_mchid: str,
) -> bool:
    required_text = (
        "out_trade_no",
        "provider_transaction_id",
        "reported_appid",
        "reported_mchid",
        "reported_success_at",
    )
    if any(not str(notification[name] or "").strip() for name in required_text):
        return False
    if (
        int(notification["signature_valid"]) != 1
        or int(notification["merchant_identity_valid"]) != 1
        or str(notification["provider"]) != "wechat_native"
        or str(notification["event_type"]) != "TRANSACTION.SUCCESS"
        or str(notification["reported_trade_type"]) != "NATIVE"
        or str(notification["reported_trade_state"]) != "SUCCESS"
        or type(notification["reported_amount_fen"]) is not int
        or int(notification["reported_amount_fen"]) <= 0
        or str(notification["reported_currency"]) != "CNY"
        or str(notification["reported_appid"]) != expected_appid
        or str(notification["reported_mchid"]) != expected_mchid
    ):
        return False
    return _try_parse_utc(str(notification["reported_success_at"])) is not None


def _order_evidence_conflicts(connection, notification, order, *, now: datetime) -> bool:
    notification_order_id = notification["order_id"]
    if notification_order_id is not None and str(notification_order_id) != str(
        order["order_id"]
    ):
        return True
    if (
        str(notification["out_trade_no"]) != str(order["order_id"])
        or int(notification["reported_amount_fen"]) != int(order["amount_fen"])
        or str(notification["reported_currency"]) != str(order["currency"])
        or str(notification["provider"]) != str(order["provider"])
        or str(order["provider"]) != "wechat_native"
    ):
        return True
    transaction_id = str(notification["provider_transaction_id"])
    existing_transaction_id = str(order["provider_transaction_id"] or "")
    if existing_transaction_id and existing_transaction_id != transaction_id:
        return True
    other_order = connection.execute(
        "SELECT 1 FROM payment_orders "
        "WHERE provider_transaction_id = ? AND order_id <> ?",
        (transaction_id, str(order["order_id"])),
    ).fetchone()
    if other_order is not None:
        return True
    if order["paid_at"] is not None and not _same_time(
        str(order["paid_at"]),
        str(notification["reported_success_at"]),
    ):
        return True
    if str(order["status"]) == OrderStatus.PAID.value and order["paid_at"] is None:
        return True
    if str(order["status"]) in {
        OrderStatus.CREATED.value,
        OrderStatus.WAITING_PAYMENT.value,
    }:
        expires_at = _try_parse_utc(str(order["expires_at"] or ""))
        if expires_at is None or expires_at <= now:
            return True
    device = connection.execute(
        "SELECT 1 FROM devices WHERE device_fingerprint_hash = ?",
        (str(order["device_fingerprint_hash"]),),
    ).fetchone()
    return device is None


def _paid_fact_is_consistent(connection, notification, order) -> bool:
    if str(order["provider_transaction_id"] or "") != str(
        notification["provider_transaction_id"]
    ):
        return False
    if str(order["provider_trade_state"] or "") != "SUCCESS":
        return False
    return _committed_payment_chain_is_valid_in_transaction(
        connection,
        order,
        expected_issued_by="wechat_callback",
    )


def _is_retryable_sqlite_error(exc: sqlite3.OperationalError) -> bool:
    code = getattr(exc, "sqlite_errorcode", None)
    return isinstance(code, int) and code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }


def _same_time(first: str, second: str) -> bool:
    first_time = _try_parse_utc(first)
    second_time = _try_parse_utc(second)
    return first_time is not None and first_time == second_time


def _parse_utc(value: str) -> datetime:
    parsed = _try_parse_utc(value)
    if parsed is None:
        raise ValueError("PAYMENT_NOTIFICATION_TIME_INVALID")
    return parsed


def _try_parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("PAYMENT_NOTIFICATION_WORKER_TIME_INVALID")
    return value.astimezone(timezone.utc)
