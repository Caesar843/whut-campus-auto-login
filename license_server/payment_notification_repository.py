from __future__ import annotations

import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, TypeVar

from license_server.db import write_transaction
from license_server.signer import datetime_text


MAX_ATTEMPTS_FAILURE_CODE = "PAYMENT_NOTIFICATION_MAX_ATTEMPTS_EXCEEDED"
DUPLICATE_FAILURE_CODE = "PAYMENT_NOTIFICATION_DUPLICATE"
ORPHAN_FAILURE_CODE = "PAYMENT_NOTIFICATION_ORDER_NOT_FOUND"

_ACTIVE_STATUSES = ("RECEIVED", "RETRY", "PROCESSING")
_FAILURE_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_T = TypeVar("_T")


class InsertOutcome(str, Enum):
    INSERTED = "inserted"
    DUPLICATE_SAME_DIGEST = "duplicate_same_digest"
    DUPLICATE_DIGEST_CONFLICT = "duplicate_digest_conflict"


class UpdateOutcome(str, Enum):
    UPDATED = "updated"
    LOST_CLAIM = "lost_claim"


class PaymentNotificationRepositoryError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class IncomingPaymentNotification:
    provider_notification_id: str
    provider: str
    out_trade_no: str
    provider_transaction_id: str
    event_type: str
    signature_key_id: str
    payload_digest_sha256: str
    reported_appid: str
    reported_mchid: str
    reported_trade_type: str
    reported_trade_state: str
    reported_amount_fen: int
    reported_currency: str
    reported_success_at: datetime
    provider_created_at: datetime
    received_at: datetime

    def __post_init__(self) -> None:
        for field_name in (
            "provider_notification_id",
            "provider",
            "out_trade_no",
            "provider_transaction_id",
            "event_type",
            "signature_key_id",
            "reported_appid",
            "reported_mchid",
            "reported_trade_type",
            "reported_trade_state",
            "reported_currency",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise PaymentNotificationRepositoryError(
                    "PAYMENT_NOTIFICATION_INPUT_INVALID"
                )
        if not _SHA256.fullmatch(self.payload_digest_sha256):
            raise PaymentNotificationRepositoryError(
                "PAYMENT_NOTIFICATION_INPUT_INVALID"
            )
        if (
            type(self.reported_amount_fen) is not int
            or self.reported_amount_fen <= 0
        ):
            raise PaymentNotificationRepositoryError(
                "PAYMENT_NOTIFICATION_INPUT_INVALID"
            )
        for field_name in (
            "reported_success_at",
            "provider_created_at",
            "received_at",
        ):
            _require_aware_datetime(getattr(self, field_name))


@dataclass(frozen=True)
class NotificationInsertResult:
    outcome: InsertOutcome
    notification_id: int


@dataclass(frozen=True)
class ClaimedPaymentNotification:
    id: int
    provider_notification_id: str
    order_id: str | None
    out_trade_no: str
    provider: str
    provider_transaction_id: str
    event_type: str
    signature_key_id: str
    payload_digest_sha256: str
    reported_appid: str
    reported_mchid: str
    reported_trade_type: str
    reported_trade_state: str
    reported_amount_fen: int
    reported_currency: str
    reported_success_at: datetime
    provider_created_at: datetime
    received_at: datetime
    worker_id: str
    claim_token: str
    processing_started_at: datetime
    lease_expires_at: datetime
    attempt_count: int


@dataclass(frozen=True)
class NotificationUpdateResult:
    outcome: UpdateOutcome
    process_status: str | None


def insert_received_notification(
    database_path: Path,
    notification: IncomingPaymentNotification,
) -> NotificationInsertResult:
    def insert(connection: sqlite3.Connection) -> NotificationInsertResult:
        orders = connection.execute(
            "SELECT order_id FROM payment_orders WHERE order_id = ? LIMIT 2",
            (notification.out_trade_no,),
        ).fetchall()
        if len(orders) > 1:
            raise PaymentNotificationRepositoryError(
                "PAYMENT_NOTIFICATION_SCHEMA_INVALID"
            )
        order_id = str(orders[0]["order_id"]) if orders else None
        cursor = connection.execute(
            """
            INSERT INTO payment_notifications (
                provider_notification_id, order_id, out_trade_no, provider,
                provider_transaction_id, event_type, signature_key_id,
                signature_valid, payload_digest_sha256, reported_trade_type,
                reported_trade_state, reported_amount_fen, reported_currency,
                merchant_identity_valid, process_status, provider_created_at,
                received_at, attempt_count, reported_appid, reported_mchid,
                reported_success_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 1, 'RECEIVED',
                      ?, ?, 0, ?, ?, ?)
            ON CONFLICT(provider_notification_id) DO NOTHING
            """,
            (
                notification.provider_notification_id,
                order_id,
                notification.out_trade_no,
                notification.provider,
                notification.provider_transaction_id,
                notification.event_type,
                notification.signature_key_id,
                notification.payload_digest_sha256,
                notification.reported_trade_type,
                notification.reported_trade_state,
                notification.reported_amount_fen,
                notification.reported_currency,
                datetime_text(notification.provider_created_at),
                datetime_text(notification.received_at),
                notification.reported_appid,
                notification.reported_mchid,
                datetime_text(notification.reported_success_at),
            ),
        )
        if cursor.rowcount == 1:
            return NotificationInsertResult(
                InsertOutcome.INSERTED,
                int(cursor.lastrowid),
            )
        existing = connection.execute(
            """
            SELECT id, payload_digest_sha256
            FROM payment_notifications
            WHERE provider_notification_id = ?
            """,
            (notification.provider_notification_id,),
        ).fetchone()
        if existing is None:
            raise PaymentNotificationRepositoryError(
                "PAYMENT_NOTIFICATION_SCHEMA_INVALID"
            )
        outcome = (
            InsertOutcome.DUPLICATE_SAME_DIGEST
            if str(existing["payload_digest_sha256"])
            == notification.payload_digest_sha256
            else InsertOutcome.DUPLICATE_DIGEST_CONFLICT
        )
        return NotificationInsertResult(outcome, int(existing["id"]))

    return _run_write(database_path, insert)


def claim_next_payment_notification(
    database_path: Path,
    *,
    worker_id: str,
    now: datetime,
    lease_expires_at: datetime,
    max_attempts: int,
) -> ClaimedPaymentNotification | None:
    worker_id = _required_text(worker_id)
    now_text = _datetime_text(now)
    lease_text = _datetime_text(lease_expires_at)
    if lease_text <= now_text or type(max_attempts) is not int or max_attempts <= 0:
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_CLAIM_CONFIG_INVALID"
        )
    claim_token = secrets.token_urlsafe(32)

    def claim(connection: sqlite3.Connection) -> ClaimedPaymentNotification | None:
        row = connection.execute(
            """
            SELECT id
            FROM payment_notifications
            WHERE attempt_count < ?
              AND (
                    process_status = 'RECEIVED'
                 OR (process_status = 'RETRY' AND next_attempt_at <= ?)
                 OR (process_status = 'PROCESSING' AND lease_expires_at <= ?)
              )
            ORDER BY received_at, id
            LIMIT 1
            """,
            (max_attempts, now_text, now_text),
        ).fetchone()
        if row is None:
            return None
        cursor = connection.execute(
            """
            UPDATE payment_notifications
            SET process_status = 'PROCESSING',
                worker_id = ?,
                claim_token = ?,
                processing_started_at = ?,
                lease_expires_at = ?,
                next_attempt_at = NULL,
                failure_code = NULL,
                attempt_count = attempt_count + 1
            WHERE id = ?
              AND attempt_count < ?
              AND (
                    process_status = 'RECEIVED'
                 OR (process_status = 'RETRY' AND next_attempt_at <= ?)
                 OR (process_status = 'PROCESSING' AND lease_expires_at <= ?)
              )
            """,
            (
                worker_id,
                claim_token,
                now_text,
                lease_text,
                int(row["id"]),
                max_attempts,
                now_text,
                now_text,
            ),
        )
        if cursor.rowcount != 1:
            return None
        claimed = connection.execute(
            "SELECT * FROM payment_notifications WHERE id = ? AND claim_token = ?",
            (int(row["id"]), claim_token),
        ).fetchone()
        if claimed is None:
            raise PaymentNotificationRepositoryError(
                "PAYMENT_NOTIFICATION_CLAIM_LOST"
            )
        return _claimed_notification(claimed)

    return _run_write(database_path, claim)


def mark_retry(
    database_path: Path,
    *,
    notification_id: int,
    claim_token: str,
    failure_code: str,
    next_attempt_at: datetime,
    processed_at: datetime,
    max_attempts: int,
) -> NotificationUpdateResult:
    claim_token = _required_text(claim_token)
    failure_code = _required_failure_code(failure_code)
    next_attempt_text = _datetime_text(next_attempt_at)
    processed_text = _datetime_text(processed_at)
    if type(max_attempts) is not int or max_attempts <= 0:
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_RETRY_CONFIG_INVALID"
        )

    def update(connection: sqlite3.Connection) -> NotificationUpdateResult:
        row = connection.execute(
            """
            SELECT attempt_count FROM payment_notifications
            WHERE id = ? AND process_status = 'PROCESSING' AND claim_token = ?
            """,
            (notification_id, claim_token),
        ).fetchone()
        if row is None:
            return NotificationUpdateResult(UpdateOutcome.LOST_CLAIM, None)
        if int(row["attempt_count"]) >= max_attempts:
            status = "ABNORMAL"
            code = MAX_ATTEMPTS_FAILURE_CODE
            next_value = None
            terminal_time = processed_text
        else:
            status = "RETRY"
            code = failure_code
            next_value = next_attempt_text
            terminal_time = None
        cursor = connection.execute(
            """
            UPDATE payment_notifications
            SET process_status = ?, failure_code = ?, next_attempt_at = ?,
                processed_at = ?, worker_id = NULL, claim_token = NULL,
                processing_started_at = NULL, lease_expires_at = NULL
            WHERE id = ? AND process_status = 'PROCESSING' AND claim_token = ?
            """,
            (
                status,
                code,
                next_value,
                terminal_time,
                notification_id,
                claim_token,
            ),
        )
        if cursor.rowcount != 1:
            return NotificationUpdateResult(UpdateOutcome.LOST_CLAIM, None)
        return NotificationUpdateResult(UpdateOutcome.UPDATED, status)

    return _run_write(database_path, update)


def mark_processed(
    database_path: Path,
    notification_id: int,
    claim_token: str,
    processed_at: datetime,
) -> NotificationUpdateResult:
    return _mark_terminal(
        database_path,
        notification_id,
        claim_token,
        status="PROCESSED",
        failure_code=None,
        processed_at=processed_at,
    )


def mark_duplicate(
    database_path: Path,
    notification_id: int,
    claim_token: str,
    processed_at: datetime,
) -> NotificationUpdateResult:
    return _mark_terminal(
        database_path,
        notification_id,
        claim_token,
        status="DUPLICATE",
        failure_code=DUPLICATE_FAILURE_CODE,
        processed_at=processed_at,
    )


def mark_abnormal(
    database_path: Path,
    notification_id: int,
    claim_token: str,
    failure_code: str,
    processed_at: datetime,
) -> NotificationUpdateResult:
    return _mark_terminal(
        database_path,
        notification_id,
        claim_token,
        status="ABNORMAL",
        failure_code=_required_failure_code(failure_code),
        processed_at=processed_at,
    )


def mark_orphan(
    database_path: Path,
    notification_id: int,
    claim_token: str,
    processed_at: datetime,
) -> NotificationUpdateResult:
    return _mark_terminal(
        database_path,
        notification_id,
        claim_token,
        status="ORPHAN",
        failure_code=ORPHAN_FAILURE_CODE,
        processed_at=processed_at,
    )


def finalize_expired_max_attempts(
    database_path: Path,
    *,
    now: datetime,
    max_attempts: int,
    limit: int,
) -> int:
    now_text = _datetime_text(now)
    if (
        type(max_attempts) is not int
        or max_attempts <= 0
        or type(limit) is not int
        or limit <= 0
    ):
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_CLAIM_CONFIG_INVALID"
        )

    def finalize(connection: sqlite3.Connection) -> int:
        cursor = connection.execute(
            """
            UPDATE payment_notifications
            SET process_status = 'ABNORMAL',
                failure_code = ?,
                processed_at = ?,
                worker_id = NULL,
                claim_token = NULL,
                processing_started_at = NULL,
                lease_expires_at = NULL,
                next_attempt_at = NULL
            WHERE id IN (
                SELECT id FROM payment_notifications
                WHERE process_status = 'PROCESSING'
                  AND lease_expires_at <= ?
                  AND attempt_count >= ?
                ORDER BY lease_expires_at, id
                LIMIT ?
            )
              AND process_status = 'PROCESSING'
              AND lease_expires_at <= ?
              AND attempt_count >= ?
            """,
            (
                MAX_ATTEMPTS_FAILURE_CODE,
                now_text,
                now_text,
                max_attempts,
                limit,
                now_text,
                max_attempts,
            ),
        )
        return cursor.rowcount

    return _run_write(database_path, finalize)


def retry_delay_seconds(
    attempt_count: int,
    retry_base_seconds: int,
    retry_max_seconds: int,
) -> int:
    if (
        type(attempt_count) is not int
        or attempt_count < 1
        or type(retry_base_seconds) is not int
        or retry_base_seconds <= 0
        or type(retry_max_seconds) is not int
        or retry_max_seconds < retry_base_seconds
    ):
        raise ValueError("PAYMENT_NOTIFICATION_RETRY_CONFIG_INVALID")
    shift = attempt_count - 1
    if shift >= retry_max_seconds.bit_length():
        return retry_max_seconds
    return min(retry_max_seconds, retry_base_seconds << shift)


def _mark_terminal(
    database_path: Path,
    notification_id: int,
    claim_token: str,
    *,
    status: str,
    failure_code: str | None,
    processed_at: datetime,
) -> NotificationUpdateResult:
    claim_token = _required_text(claim_token)
    processed_text = _datetime_text(processed_at)

    def update(connection: sqlite3.Connection) -> NotificationUpdateResult:
        cursor = connection.execute(
            """
            UPDATE payment_notifications
            SET process_status = ?, failure_code = ?, processed_at = ?,
                worker_id = NULL, claim_token = NULL,
                processing_started_at = NULL, lease_expires_at = NULL,
                next_attempt_at = NULL
            WHERE id = ? AND process_status = 'PROCESSING' AND claim_token = ?
            """,
            (
                status,
                failure_code,
                processed_text,
                notification_id,
                claim_token,
            ),
        )
        if cursor.rowcount != 1:
            return NotificationUpdateResult(UpdateOutcome.LOST_CLAIM, None)
        return NotificationUpdateResult(UpdateOutcome.UPDATED, status)

    return _run_write(database_path, update)


def _claimed_notification(row: sqlite3.Row) -> ClaimedPaymentNotification:
    return ClaimedPaymentNotification(
        id=int(row["id"]),
        provider_notification_id=str(row["provider_notification_id"]),
        order_id=str(row["order_id"]) if row["order_id"] is not None else None,
        out_trade_no=str(row["out_trade_no"]),
        provider=str(row["provider"]),
        provider_transaction_id=str(row["provider_transaction_id"]),
        event_type=str(row["event_type"]),
        signature_key_id=str(row["signature_key_id"]),
        payload_digest_sha256=str(row["payload_digest_sha256"]),
        reported_appid=str(row["reported_appid"]),
        reported_mchid=str(row["reported_mchid"]),
        reported_trade_type=str(row["reported_trade_type"]),
        reported_trade_state=str(row["reported_trade_state"]),
        reported_amount_fen=int(row["reported_amount_fen"]),
        reported_currency=str(row["reported_currency"]),
        reported_success_at=_parse_datetime(str(row["reported_success_at"])),
        provider_created_at=_parse_datetime(str(row["provider_created_at"])),
        received_at=_parse_datetime(str(row["received_at"])),
        worker_id=str(row["worker_id"]),
        claim_token=str(row["claim_token"]),
        processing_started_at=_parse_datetime(str(row["processing_started_at"])),
        lease_expires_at=_parse_datetime(str(row["lease_expires_at"])),
        attempt_count=int(row["attempt_count"]),
    )


def _run_write(database_path: Path, action: Callable[[sqlite3.Connection], _T]) -> _T:
    try:
        with write_transaction(database_path) as connection:
            return action(connection)
    except PaymentNotificationRepositoryError:
        raise
    except sqlite3.IntegrityError:
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_INVALID_STATE"
        ) from None
    except sqlite3.OperationalError as exc:
        code = getattr(exc, "sqlite_errorcode", None)
        if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            raise PaymentNotificationRepositoryError(
                "PAYMENT_NOTIFICATION_DATABASE_BUSY"
            ) from None
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_DATABASE_ERROR"
        ) from None


def _required_text(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_INPUT_INVALID"
        )
    return value.strip()


def _required_failure_code(value: str) -> str:
    if not isinstance(value, str) or not _FAILURE_CODE.fullmatch(value):
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_FAILURE_CODE_INVALID"
        )
    return value


def _require_aware_datetime(value: datetime) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_INPUT_INVALID"
        )


def _datetime_text(value: datetime) -> str:
    _require_aware_datetime(value)
    return datetime_text(value)


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PaymentNotificationRepositoryError(
            "PAYMENT_NOTIFICATION_SCHEMA_INVALID"
        ) from None
    _require_aware_datetime(parsed)
    return parsed
