from __future__ import annotations

import sqlite3
import math
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, TypeVar

from license_server.db import connect, write_transaction
from license_server.signer import datetime_text


_T = TypeVar("_T")
_MAX_TEXT_LENGTH = 128
_MAX_LEASE_SECONDS = 3600
_SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_TRADE_STATES = frozenset(
    {"SUCCESS", "NOTPAY", "CLOSED", "REFUND", "REVOKED", "USERPAYING", "PAYERROR", "UNKNOWN"}
)
_UNSET = object()


class EnsureReadyOutcome(str, Enum):
    CREATED = "created"
    EXISTING = "existing"
    NOT_FOUND = "not_found"
    NOT_ELIGIBLE = "not_eligible"


class ClaimOrderOutcome(str, Enum):
    CLAIMED = "claimed"
    NOT_FOUND = "not_found"
    NOT_ELIGIBLE = "not_eligible"
    NOT_DUE = "not_due"
    IN_PROGRESS = "in_progress"
    TERMINAL = "terminal"


class UpdateOutcome(str, Enum):
    UPDATED = "updated"
    LOST_CLAIM = "lost_claim"


class PaymentReconciliationRepositoryError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False):
        self.code = code
        self.retryable = retryable
        super().__init__(code)


@dataclass(frozen=True)
class ReconciliationRecord:
    order_id: str
    reconcile_status: str
    last_query_at: datetime | None
    next_attempt_at: datetime | None
    query_attempt_count: int
    last_close_at: datetime | None
    close_attempt_count: int
    trusted_trade_state: str | None
    last_error_code: str | None
    terminal_reason: str | None
    terminal_at: datetime | None
    claim_token: str | None
    claimed_by: str | None
    claimed_at: datetime | None
    lease_expires_at: datetime | None
    updated_at: datetime
    state_version: int


@dataclass(frozen=True)
class EnsureReadyResult:
    outcome: EnsureReadyOutcome
    record: ReconciliationRecord | None


@dataclass(frozen=True)
class ReconciliationClaim:
    order_id: str
    claim_token: str
    claimed_by: str
    claimed_at: datetime
    lease_expires_at: datetime
    state_version: int
    query_attempt_count: int
    close_attempt_count: int


@dataclass(frozen=True)
class ClaimOrderResult:
    outcome: ClaimOrderOutcome
    claim: ReconciliationClaim | None


@dataclass(frozen=True)
class ClaimUpdateResult:
    outcome: UpdateOutcome
    claim: ReconciliationClaim | None


@dataclass(frozen=True)
class RecordUpdateResult:
    outcome: UpdateOutcome
    record: ReconciliationRecord | None


def get(database_path: Path, order_id: str) -> ReconciliationRecord | None:
    order_id = _required_text(order_id)

    def read(connection: sqlite3.Connection) -> ReconciliationRecord | None:
        row = connection.execute(
            "SELECT * FROM payment_reconciliations WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        return _record(row) if row is not None else None

    return _run_read(database_path, read)


def ensure_ready(
    database_path: Path,
    order_id: str,
    now: datetime,
    next_attempt_at: datetime,
) -> EnsureReadyResult:
    order_id = _required_text(order_id)
    now_text = _datetime_text(now)
    next_attempt_text = _datetime_text(next_attempt_at)

    def ensure(connection: sqlite3.Connection) -> EnsureReadyResult:
        order = connection.execute(
            "SELECT status FROM payment_orders WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        if order is None:
            return EnsureReadyResult(EnsureReadyOutcome.NOT_FOUND, None)
        if str(order["status"]) != "WAITING_PAYMENT":
            return EnsureReadyResult(EnsureReadyOutcome.NOT_ELIGIBLE, None)
        cursor = connection.execute(
            """
            INSERT INTO payment_reconciliations (
                order_id, reconcile_status, next_attempt_at, updated_at
            ) VALUES (?, 'READY', ?, ?)
            ON CONFLICT(order_id) DO NOTHING
            """,
            (order_id, next_attempt_text, now_text),
        )
        row = connection.execute(
            "SELECT * FROM payment_reconciliations WHERE order_id = ?",
            (order_id,),
        ).fetchone()
        if row is None:
            raise PaymentReconciliationRepositoryError(
                "PAYMENT_RECONCILIATION_SCHEMA_INVALID"
            )
        outcome = (
            EnsureReadyOutcome.CREATED
            if cursor.rowcount == 1
            else EnsureReadyOutcome.EXISTING
        )
        return EnsureReadyResult(outcome, _record(row))

    return _run_write(database_path, ensure)


def claim_next_due(
    database_path: Path, *, worker_id: str, now: datetime, lease_seconds: float,
    clock: Callable[[], datetime] | None = None,
) -> ReconciliationClaim | None:
    worker_id = _required_text(worker_id)
    _lease_times(now, lease_seconds)

    def claim(connection: sqlite3.Connection) -> ReconciliationClaim | None:
        now_text, lease_text = _lease_times(_operation_time(now, clock), lease_seconds)
        row = connection.execute(
            f"""SELECT r.order_id FROM payment_reconciliations r
                JOIN payment_orders o ON o.order_id = r.order_id
                WHERE o.status = 'WAITING_PAYMENT' AND ({_DUE_SQL})
                ORDER BY CASE WHEN r.reconcile_status = 'READY'
                              THEN r.next_attempt_at ELSE r.lease_expires_at END,
                         r.order_id LIMIT 1""",
            (now_text, now_text),
        ).fetchone()
        return _claim(connection, str(row["order_id"]), worker_id, now_text, lease_text) if row else None

    return _run_write(database_path, claim)


def claim_order(
    database_path: Path, *, order_id: str, worker_id: str,
    now: datetime, lease_seconds: float,
    clock: Callable[[], datetime] | None = None,
) -> ClaimOrderResult:
    order_id = _required_text(order_id)
    worker_id = _required_text(worker_id)
    _lease_times(now, lease_seconds)

    def claim(connection: sqlite3.Connection) -> ClaimOrderResult:
        now_text, lease_text = _lease_times(_operation_time(now, clock), lease_seconds)
        row = connection.execute(
            """SELECT r.*, o.status AS order_status
               FROM payment_reconciliations r JOIN payment_orders o ON o.order_id=r.order_id
               WHERE r.order_id=?""",
            (order_id,),
        ).fetchone()
        if row is None:
            return ClaimOrderResult(ClaimOrderOutcome.NOT_FOUND, None)
        if row["order_status"] != "WAITING_PAYMENT":
            return ClaimOrderResult(ClaimOrderOutcome.NOT_ELIGIBLE, None)
        if row["reconcile_status"] == "TERMINAL":
            return ClaimOrderResult(ClaimOrderOutcome.TERMINAL, None)
        if row["reconcile_status"] == "READY" and row["next_attempt_at"] > now_text:
            return ClaimOrderResult(ClaimOrderOutcome.NOT_DUE, None)
        if row["reconcile_status"] == "CLAIMED" and row["lease_expires_at"] > now_text:
            return ClaimOrderResult(ClaimOrderOutcome.IN_PROGRESS, None)
        result = _claim(connection, order_id, worker_id, now_text, lease_text)
        if result is None:
            raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INVALID_STATE")
        return ClaimOrderResult(ClaimOrderOutcome.CLAIMED, result)

    return _run_write(database_path, claim)


def begin_close_attempt(
    database_path: Path, *, claim_token: str, expected_state_version: int, now: datetime,
    clock: Callable[[], datetime] | None = None,
) -> ClaimUpdateResult:
    token = _required_text(claim_token)
    version = _version(expected_state_version)
    _datetime_text(now)

    def update(connection: sqlite3.Connection) -> ClaimUpdateResult:
        now_text = _datetime_text(_operation_time(now, clock))
        cursor = connection.execute(
            """UPDATE payment_reconciliations
               SET close_attempt_count=close_attempt_count+1,
                   state_version=state_version+1, updated_at=?
               WHERE reconcile_status='CLAIMED' AND claim_token=?
                 AND state_version=? AND lease_expires_at>?""",
            (now_text, token, version, now_text),
        )
        if cursor.rowcount != 1:
            return ClaimUpdateResult(UpdateOutcome.LOST_CLAIM, None)
        row = connection.execute(
            "SELECT * FROM payment_reconciliations WHERE claim_token=?", (token,)
        ).fetchone()
        return ClaimUpdateResult(UpdateOutcome.UPDATED, _claim_record(row))

    return _run_write(database_path, update)


def reschedule_claim(
    database_path: Path, *, claim_token: str, expected_state_version: int,
    completed_at: datetime, next_attempt_at: datetime,
    trusted_trade_state: str | None | object = _UNSET,
    last_error_code: str | None | object = _UNSET,
    query_completed: bool = False, close_completed: bool = False,
    clock: Callable[[], datetime] | None = None,
) -> RecordUpdateResult:
    completed = _normalized_datetime(completed_at)
    next_attempt = _normalized_datetime(next_attempt_at)
    if next_attempt <= completed:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    return _finish_claim(
        database_path, claim_token, expected_state_version, completed,
        retry_delay=next_attempt - completed, terminal_reason=None,
        trusted_trade_state=trusted_trade_state, last_error_code=last_error_code,
        query_completed=query_completed, close_completed=close_completed,
        clock=clock,
    )


def terminate_claim(
    database_path: Path, *, claim_token: str, expected_state_version: int,
    terminal_at: datetime, terminal_reason: str,
    trusted_trade_state: str | None | object = _UNSET,
    last_error_code: str | None | object = _UNSET,
    query_completed: bool = False, close_completed: bool = False,
    clock: Callable[[], datetime] | None = None,
) -> RecordUpdateResult:
    reason = _safe_code(terminal_reason)
    return _finish_claim(
        database_path, claim_token, expected_state_version,
        _normalized_datetime(terminal_at), retry_delay=None, terminal_reason=reason,
        trusted_trade_state=trusted_trade_state, last_error_code=last_error_code,
        query_completed=query_completed, close_completed=close_completed,
        clock=clock,
    )


def reconciliation_claim_is_current_in_transaction(
    connection: sqlite3.Connection,
    *,
    order_id: str,
    claim_token: str,
    expected_state_version: int,
    operation_time: datetime,
) -> bool:
    return connection.execute(
        """SELECT 1 FROM payment_reconciliations
           WHERE order_id=? AND reconcile_status='CLAIMED'
             AND claim_token=? AND state_version=? AND lease_expires_at>?""",
        (
            _required_text(order_id),
            _required_text(claim_token),
            _version(expected_state_version),
            _datetime_text(operation_time),
        ),
    ).fetchone() is not None


def terminate_claim_in_transaction(
    connection: sqlite3.Connection,
    *,
    claim_token: str,
    expected_state_version: int,
    terminal_at: datetime,
    terminal_reason: str,
    trusted_trade_state: str | None | object = _UNSET,
    last_error_code: str | None | object = _UNSET,
    query_completed: bool = False,
    close_completed: bool = False,
) -> RecordUpdateResult:
    return _finish_claim_in_transaction(
        connection,
        token=_required_text(claim_token),
        version=_version(expected_state_version),
        completed_text=_datetime_text(terminal_at),
        next_text=None,
        terminal_reason=_safe_code(terminal_reason),
        trade=_optional_trade_state(trusted_trade_state),
        error=_optional_safe_code(last_error_code),
        query_completed=query_completed,
        close_completed=close_completed,
    )


_DUE_SQL = """(r.reconcile_status='READY' AND r.next_attempt_at<=?) OR
                (r.reconcile_status='CLAIMED' AND r.lease_expires_at<=?)"""


def _claim(connection, order_id, worker_id, now_text, lease_text):
    token = secrets.token_urlsafe(32)
    cursor = connection.execute(
        f"""UPDATE payment_reconciliations AS r
            SET reconcile_status='CLAIMED', next_attempt_at=NULL,
                claim_token=?, claimed_by=?, claimed_at=?, lease_expires_at=?,
                terminal_reason=NULL, terminal_at=NULL,
                query_attempt_count=query_attempt_count+1,
                state_version=state_version+1, updated_at=?
            WHERE order_id=? AND ({_DUE_SQL})""",
        (token, worker_id, now_text, lease_text, now_text, order_id, now_text, now_text),
    )
    if cursor.rowcount != 1:
        return None
    row = connection.execute("SELECT * FROM payment_reconciliations WHERE order_id=?", (order_id,)).fetchone()
    return _claim_record(row)


def _claim_record(row):
    if row is None:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_SCHEMA_INVALID")
    return ReconciliationClaim(
        order_id=str(row["order_id"]), claim_token=str(row["claim_token"]),
        claimed_by=str(row["claimed_by"]), claimed_at=_parse_datetime(row["claimed_at"]),
        lease_expires_at=_parse_datetime(row["lease_expires_at"]),
        state_version=int(row["state_version"]), query_attempt_count=int(row["query_attempt_count"]),
        close_attempt_count=int(row["close_attempt_count"]),
    )


def _finish_claim(
    database_path, claim_token, expected_state_version, completed_at, *, retry_delay,
    terminal_reason, trusted_trade_state, last_error_code, query_completed, close_completed,
    clock,
):
    token = _required_text(claim_token)
    version = _version(expected_state_version)
    trade = _optional_trade_state(trusted_trade_state)
    error = _optional_safe_code(last_error_code)
    if not isinstance(query_completed, bool) or not isinstance(close_completed, bool):
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")

    def update(connection):
        operation_time = _operation_time(completed_at, clock)
        next_text = (
            _datetime_text(operation_time + retry_delay)
            if retry_delay is not None
            else None
        )
        return _finish_claim_in_transaction(
            connection,
            token=token,
            version=version,
            completed_text=_datetime_text(operation_time),
            next_text=next_text,
            terminal_reason=terminal_reason,
            trade=trade,
            error=error,
            query_completed=query_completed,
            close_completed=close_completed,
        )

    return _run_write(database_path, update)


def _finish_claim_in_transaction(
    connection, *, token, version, completed_text, next_text, terminal_reason,
    trade, error, query_completed, close_completed,
):
    if not isinstance(query_completed, bool) or not isinstance(close_completed, bool):
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    current = connection.execute(
        "SELECT order_id FROM payment_reconciliations WHERE claim_token=?",
        (token,),
    ).fetchone()
    assignments = [
        "reconcile_status=?", "next_attempt_at=?", "claim_token=NULL", "claimed_by=NULL",
        "claimed_at=NULL", "lease_expires_at=NULL", "terminal_reason=?", "terminal_at=?",
        "state_version=state_version+1", "updated_at=?",
    ]
    values = ["TERMINAL" if terminal_reason else "READY", next_text, terminal_reason,
              completed_text if terminal_reason else None, completed_text]
    if query_completed:
        assignments.append("last_query_at=?"); values.append(completed_text)
    if close_completed:
        assignments.append("last_close_at=?"); values.append(completed_text)
    if trade is not _UNSET:
        assignments.append("trusted_trade_state=?"); values.append(trade)
    if error is not _UNSET:
        assignments.append("last_error_code=?"); values.append(error)
    values.extend((token, version, completed_text))
    cursor = connection.execute(
        f"UPDATE payment_reconciliations SET {', '.join(assignments)} "
        "WHERE reconcile_status='CLAIMED' AND claim_token=? AND state_version=? AND lease_expires_at>?",
        values,
    )
    if cursor.rowcount != 1:
        return RecordUpdateResult(UpdateOutcome.LOST_CLAIM, None)
    if current is None:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_SCHEMA_INVALID")
    row = connection.execute(
        "SELECT * FROM payment_reconciliations WHERE order_id=?",
        (current["order_id"],),
    ).fetchone()
    return RecordUpdateResult(UpdateOutcome.UPDATED, _record(row))


def _lease_times(now: datetime, lease_seconds: float) -> tuple[str, str]:
    if (
        isinstance(lease_seconds, bool)
        or not isinstance(lease_seconds, (int, float))
        or not math.isfinite(lease_seconds)
        or lease_seconds <= 0
        or lease_seconds > _MAX_LEASE_SECONDS
    ):
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    now_text = _datetime_text(now)
    lease_text = _datetime_text(now + timedelta(seconds=lease_seconds))
    if lease_text <= now_text:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    return now_text, lease_text


def _version(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    return value


def _safe_code(value: str) -> str:
    if not isinstance(value, str) or _SAFE_CODE.fullmatch(value) is None:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    return value


def _optional_safe_code(value):
    if value is _UNSET or value is None:
        return value
    return _safe_code(value)


def _optional_trade_state(value):
    if value is _UNSET or value is None:
        return value
    if not isinstance(value, str) or value not in _TRADE_STATES:
        raise PaymentReconciliationRepositoryError("PAYMENT_RECONCILIATION_INPUT_INVALID")
    return value


def _record(row: sqlite3.Row) -> ReconciliationRecord:
    return ReconciliationRecord(
        order_id=str(row["order_id"]),
        reconcile_status=str(row["reconcile_status"]),
        last_query_at=_optional_datetime(row["last_query_at"]),
        next_attempt_at=_optional_datetime(row["next_attempt_at"]),
        query_attempt_count=int(row["query_attempt_count"]),
        last_close_at=_optional_datetime(row["last_close_at"]),
        close_attempt_count=int(row["close_attempt_count"]),
        trusted_trade_state=(
            str(row["trusted_trade_state"])
            if row["trusted_trade_state"] is not None
            else None
        ),
        last_error_code=(
            str(row["last_error_code"])
            if row["last_error_code"] is not None
            else None
        ),
        terminal_reason=(
            str(row["terminal_reason"])
            if row["terminal_reason"] is not None
            else None
        ),
        terminal_at=_optional_datetime(row["terminal_at"]),
        claim_token=(
            str(row["claim_token"]) if row["claim_token"] is not None else None
        ),
        claimed_by=(
            str(row["claimed_by"]) if row["claimed_by"] is not None else None
        ),
        claimed_at=_optional_datetime(row["claimed_at"]),
        lease_expires_at=_optional_datetime(row["lease_expires_at"]),
        updated_at=_parse_datetime(str(row["updated_at"])),
        state_version=int(row["state_version"]),
    )


def _run_read(database_path: Path, action: Callable[[sqlite3.Connection], _T]) -> _T:
    connection: sqlite3.Connection | None = None
    try:
        connection = connect(database_path)
        return action(connection)
    except PaymentReconciliationRepositoryError:
        raise
    except sqlite3.OperationalError as exc:
        raise _database_error(exc) from None
    except sqlite3.DatabaseError:
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_DATABASE_ERROR"
        ) from None
    finally:
        if connection is not None:
            connection.close()


def _run_write(database_path: Path, action: Callable[[sqlite3.Connection], _T]) -> _T:
    try:
        with write_transaction(database_path) as connection:
            return action(connection)
    except PaymentReconciliationRepositoryError:
        raise
    except sqlite3.IntegrityError:
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_INVALID_STATE"
        ) from None
    except sqlite3.OperationalError as exc:
        raise _database_error(exc) from None
    except sqlite3.DatabaseError:
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_DATABASE_ERROR"
        ) from None


def _database_error(exc: sqlite3.OperationalError) -> PaymentReconciliationRepositoryError:
    code = getattr(exc, "sqlite_errorcode", None)
    base_code = code & 0xFF if isinstance(code, int) else None
    if base_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_DATABASE_BUSY",
            retryable=True,
        )
    return PaymentReconciliationRepositoryError(
        "PAYMENT_RECONCILIATION_DATABASE_ERROR"
    )


def _required_text(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > _MAX_TEXT_LENGTH
    ):
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_INPUT_INVALID"
        )
    return value.strip()


def _datetime_text(value: datetime) -> str:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_INPUT_INVALID"
        )
    return datetime_text(value)


def _normalized_datetime(value: datetime) -> datetime:
    _datetime_text(value)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _operation_time(
    fallback: datetime,
    clock: Callable[[], datetime] | None,
) -> datetime:
    return _normalized_datetime(clock() if clock is not None else fallback)


def _optional_datetime(value: object) -> datetime | None:
    return _parse_datetime(str(value)) if value is not None else None


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_SCHEMA_INVALID"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PaymentReconciliationRepositoryError(
            "PAYMENT_RECONCILIATION_SCHEMA_INVALID"
        )
    return parsed
