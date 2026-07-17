from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Callable

from license_server.payment import ANNUAL_V1
from license_server.payment_gateway import (
    CloseOrderOutcome,
    PaymentGateway,
    QueryOrderOutcome,
    QueryOrderResult,
)
from license_server.payment_reconciliation_repository import (
    ReconciliationClaim,
    UpdateOutcome,
    begin_close_attempt,
    reschedule_claim,
    terminate_claim,
)
from license_server.payment_service import (
    PaymentServiceError,
    TrustedOrderUpdateOutcome,
    confirm_paid_order_from_query,
    load_reconciliation_order,
    mark_open_order_abnormal_and_terminate_reconciliation,
    mark_open_order_closed_from_trusted_provider,
)
from license_server.wechat_payment import WechatPaymentError


_MAX_DELAY_SECONDS = 86_400
_MAX_ATTEMPTS = 100


def _server_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReconciliationOutcome(str, Enum):
    PAID = "PAID"
    ALREADY_PAID = "ALREADY_PAID"
    RESCHEDULED = "RESCHEDULED"
    CLOSED = "CLOSED"
    ALREADY_CLOSED = "ALREADY_CLOSED"
    TERMINAL_ABNORMAL = "TERMINAL_ABNORMAL"
    LOST_CLAIM = "LOST_CLAIM"
    LOST_CLAIM_AFTER_PAYMENT = "LOST_CLAIM_AFTER_PAYMENT"


@dataclass(frozen=True)
class ReconciliationResult:
    outcome: ReconciliationOutcome


@dataclass(frozen=True)
class PaymentReconciliationPolicy:
    query_retry_base_seconds: int
    query_retry_max_seconds: int
    max_query_attempts: int
    close_retry_base_seconds: int
    close_retry_max_seconds: int
    max_close_attempts: int

    def __post_init__(self) -> None:
        delays = (
            self.query_retry_base_seconds,
            self.query_retry_max_seconds,
            self.close_retry_base_seconds,
            self.close_retry_max_seconds,
        )
        attempts = (self.max_query_attempts, self.max_close_attempts)
        if (
            any(type(value) is not int or value <= 0 or value > _MAX_DELAY_SECONDS for value in delays)
            or any(type(value) is not int or value <= 0 or value > _MAX_ATTEMPTS for value in attempts)
            or self.query_retry_base_seconds > self.query_retry_max_seconds
            or self.close_retry_base_seconds > self.close_retry_max_seconds
        ):
            raise ValueError("PAYMENT_RECONCILIATION_POLICY_INVALID")


@dataclass(frozen=True)
class PaymentReconciliationService:
    database_path: Path
    gateway: PaymentGateway
    expected_appid: str
    expected_mchid: str
    policy: PaymentReconciliationPolicy
    clock: Callable[[], datetime] = field(
        default=_server_utc_now,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "database_path", Path(self.database_path))
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (self.expected_appid, self.expected_mchid)
        ):
            raise ValueError("PAYMENT_RECONCILIATION_SERVICE_CONFIG_INVALID")
        if not callable(self.clock):
            raise ValueError("PAYMENT_RECONCILIATION_SERVICE_CONFIG_INVALID")

    def reconcile_claim(
        self,
        claim: ReconciliationClaim,
        *,
        now: datetime,
    ) -> ReconciliationResult:
        _utc(now)
        try:
            query = self.gateway.query_order(claim.order_id)
        except WechatPaymentError as exc:
            if exc.retryable:
                return self._retry_query(
                    claim,
                    error="QUERY_GATEWAY_RETRYABLE",
                )
            return self._terminate_and_mark_abnormal(
                claim,
                reason="QUERY_GATEWAY_REJECTED",
                error="QUERY_GATEWAY_NON_RETRYABLE",
            )
        except (ConnectionError, TimeoutError):
            return self._retry_query(
                claim,
                error="QUERY_GATEWAY_RETRYABLE",
            )
        if query.out_trade_no != claim.order_id:
            return self._terminate_and_mark_abnormal(
                claim,
                reason="QUERY_RESULT_INVALID",
                error="QUERY_RESULT_INVALID",
            )
        if query.outcome is QueryOrderOutcome.SUCCESS:
            return self._success(claim, query=query)
        if query.outcome is QueryOrderOutcome.NOTPAY:
            return self._notpay(claim)
        if query.outcome is QueryOrderOutcome.CLOSED:
            return self._closed(claim, query=query)
        if query.outcome is QueryOrderOutcome.USERPAYING:
            return self._retry_query(claim, trade_state="USERPAYING")
        abnormal_reasons = {
            QueryOrderOutcome.REFUND: "REFUND_REVIEW_REQUIRED",
            QueryOrderOutcome.REVOKED: "REVOKED_REVIEW_REQUIRED",
            QueryOrderOutcome.PAYERROR: "PAYERROR_REVIEW_REQUIRED",
            QueryOrderOutcome.UNKNOWN: "UNKNOWN_REVIEW_REQUIRED",
        }
        if query.outcome in abnormal_reasons:
            return self._terminate_and_mark_abnormal(
                claim,
                reason=abnormal_reasons[query.outcome],
                trade_state=query.outcome.value,
                error=abnormal_reasons[query.outcome],
            )
        return self._terminate(
            claim,
            reason="QUERY_RESULT_UNSUPPORTED",
            error="QUERY_RESULT_UNSUPPORTED",
        )

    def _success(
        self,
        claim: ReconciliationClaim,
        *,
        query: QueryOrderResult,
    ) -> ReconciliationResult:
        try:
            confirmation_time = self._now()
            confirmation = confirm_paid_order_from_query(
                self.database_path,
                query,
                expected_appid=self.expected_appid,
                expected_mchid=self.expected_mchid,
                now=confirmation_time,
            )
        except PaymentServiceError:
            return self._terminate_and_mark_abnormal(
                claim,
                reason="PAYMENT_QUERY_MISMATCH",
                trade_state="SUCCESS",
                error="PAYMENT_QUERY_MISMATCH",
            )
        update = terminate_claim(
            self.database_path,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            terminal_at=self._now(),
            terminal_reason=(
                "ORDER_ALREADY_PAID" if confirmation.idempotent else "PAYMENT_CONFIRMED"
            ),
            trusted_trade_state="SUCCESS",
            last_error_code=None,
            query_completed=True,
            clock=self.clock,
        )
        if update.outcome is UpdateOutcome.LOST_CLAIM:
            return ReconciliationResult(ReconciliationOutcome.LOST_CLAIM_AFTER_PAYMENT)
        return ReconciliationResult(
            ReconciliationOutcome.ALREADY_PAID
            if confirmation.idempotent
            else ReconciliationOutcome.PAID
        )

    def _terminate_and_mark_abnormal(
        self,
        claim: ReconciliationClaim,
        *,
        reason: str,
        trade_state: str | None = None,
        error: str,
    ) -> ReconciliationResult:
        outcome = mark_open_order_abnormal_and_terminate_reconciliation(
            self.database_path,
            order_id=claim.order_id,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            terminal_reason=reason,
            trusted_trade_state=trade_state,
            code=error,
            now=self._now(),
            clock=self.clock,
        )
        if outcome is TrustedOrderUpdateOutcome.LOST_CLAIM:
            return ReconciliationResult(ReconciliationOutcome.LOST_CLAIM)
        return ReconciliationResult(ReconciliationOutcome.TERMINAL_ABNORMAL)

    def _closed(
        self,
        claim: ReconciliationClaim,
        *,
        query: QueryOrderResult,
    ) -> ReconciliationResult:
        order = load_reconciliation_order(self.database_path, claim.order_id)
        if order is None:
            return self._terminate(
                claim,
                reason="ORDER_NOT_FOUND",
                error="ORDER_NOT_FOUND",
            )
        if order.status == "PAID":
            return self._terminate_paid_race(claim)
        if (
            query.trade_state != "CLOSED"
            or query.trade_type != "NATIVE"
            or query.amount_total != order.amount_fen
            or query.currency != order.currency
            or query.appid != self.expected_appid
            or query.mchid != self.expected_mchid
            or order.product_code != ANNUAL_V1.product_code
            or order.provider != "wechat_native"
        ):
            return self._terminate_and_mark_abnormal(
                claim,
                reason="CLOSED_QUERY_MISMATCH",
                error="CLOSED_QUERY_MISMATCH",
            )
        local = mark_open_order_closed_from_trusted_provider(
            self.database_path,
            order_id=claim.order_id,
            provider_trade_state="CLOSED",
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            now=self._now(),
            clock=self.clock,
        )
        return self._finish_closed(
            claim,
            local=local,
            close_completed=False,
        )

    def _notpay(
        self,
        claim: ReconciliationClaim,
    ) -> ReconciliationResult:
        order = load_reconciliation_order(self.database_path, claim.order_id)
        if order is None:
            return self._terminate(
                claim,
                reason="ORDER_NOT_FOUND",
                trade_state="NOTPAY",
                error="ORDER_NOT_FOUND",
            )
        if order.status == "PAID":
            return self._terminate_paid_race(claim)
        if self._now() < order.expires_at:
            return self._retry_query(claim, trade_state="NOTPAY")
        close_claim = begin_close_attempt(
            self.database_path,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            now=self._now(),
            clock=self.clock,
        )
        if close_claim.outcome is UpdateOutcome.LOST_CLAIM:
            return ReconciliationResult(ReconciliationOutcome.LOST_CLAIM)
        assert close_claim.claim is not None
        try:
            closed = self.gateway.close_order(claim.order_id)
        except WechatPaymentError as exc:
            return self._retry_close(
                close_claim.claim,
                error=(
                    "CLOSE_GATEWAY_RETRYABLE"
                    if exc.retryable
                    else "CLOSE_GATEWAY_NON_RETRYABLE"
                ),
            )
        except (ConnectionError, TimeoutError):
            return self._retry_close(
                close_claim.claim,
                error="CLOSE_GATEWAY_RETRYABLE",
            )
        if closed.outcome is not CloseOrderOutcome.CLOSED:
            return self._retry_close(close_claim.claim)
        local = mark_open_order_closed_from_trusted_provider(
            self.database_path,
            order_id=claim.order_id,
            provider_trade_state="CLOSED",
            claim_token=close_claim.claim.claim_token,
            expected_state_version=close_claim.claim.state_version,
            now=self._now(),
            clock=self.clock,
        )
        return self._finish_closed(
            close_claim.claim,
            local=local,
            close_completed=True,
        )

    def _finish_closed(
        self,
        claim: ReconciliationClaim,
        *,
        local: TrustedOrderUpdateOutcome,
        close_completed: bool,
    ) -> ReconciliationResult:
        if local is TrustedOrderUpdateOutcome.LOST_CLAIM:
            return ReconciliationResult(ReconciliationOutcome.LOST_CLAIM)
        if local is TrustedOrderUpdateOutcome.ALREADY_PAID:
            return self._terminate_paid_race(claim)
        if local is TrustedOrderUpdateOutcome.ALREADY_CLOSED:
            outcome = ReconciliationOutcome.ALREADY_CLOSED
        elif local is TrustedOrderUpdateOutcome.UPDATED:
            outcome = ReconciliationOutcome.CLOSED
        else:
            return self._terminate(
                claim,
                reason="LOCAL_CLOSE_REVIEW",
                trade_state="CLOSED",
                error="LOCAL_CLOSE_REVIEW",
                query_completed=True,
                close_completed=close_completed,
            )
        update = terminate_claim(
            self.database_path,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            terminal_at=self._now(),
            terminal_reason="PROVIDER_CLOSED",
            trusted_trade_state="CLOSED",
            last_error_code=None,
            query_completed=True,
            close_completed=close_completed,
            clock=self.clock,
        )
        if update.outcome is UpdateOutcome.LOST_CLAIM:
            return ReconciliationResult(ReconciliationOutcome.LOST_CLAIM)
        return ReconciliationResult(outcome)

    def _retry_query(
        self,
        claim: ReconciliationClaim,
        *,
        trade_state: str | None = None,
        error: str | None = None,
    ) -> ReconciliationResult:
        order = load_reconciliation_order(self.database_path, claim.order_id)
        if order is not None and order.status == "PAID":
            return self._terminate_paid_race(claim)
        if claim.query_attempt_count >= self.policy.max_query_attempts:
            return self._terminate(
                claim,
                reason="QUERY_RETRY_EXHAUSTED",
                trade_state=trade_state,
                error=error,
            )
        operation_time = self._now()
        values = dict(
            database_path=self.database_path,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            completed_at=operation_time,
            next_attempt_at=operation_time + timedelta(
                seconds=_retry_delay(
                    claim.query_attempt_count,
                    self.policy.query_retry_base_seconds,
                    self.policy.query_retry_max_seconds,
                )
            ),
            last_error_code=error,
            query_completed=True,
            clock=self.clock,
        )
        if trade_state is not None:
            values["trusted_trade_state"] = trade_state
        update = reschedule_claim(
            **values,
        )
        return ReconciliationResult(
            ReconciliationOutcome.RESCHEDULED
            if update.outcome is UpdateOutcome.UPDATED
            else ReconciliationOutcome.LOST_CLAIM
        )

    def _retry_close(
        self,
        claim: ReconciliationClaim,
        *,
        error: str = "CLOSE_RESULT_UNKNOWN",
    ) -> ReconciliationResult:
        order = load_reconciliation_order(self.database_path, claim.order_id)
        if order is not None and order.status == "PAID":
            return self._terminate_paid_race(claim)
        if claim.close_attempt_count >= self.policy.max_close_attempts:
            return self._terminate(
                claim,
                reason="CLOSE_RETRY_EXHAUSTED",
                trade_state="NOTPAY",
                error=error,
                query_completed=True,
                close_completed=True,
            )
        operation_time = self._now()
        update = reschedule_claim(
            self.database_path,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            completed_at=operation_time,
            next_attempt_at=operation_time + timedelta(
                seconds=_retry_delay(
                    claim.close_attempt_count,
                    self.policy.close_retry_base_seconds,
                    self.policy.close_retry_max_seconds,
                )
            ),
            trusted_trade_state="NOTPAY",
            last_error_code=error,
            query_completed=True,
            close_completed=True,
            clock=self.clock,
        )
        return ReconciliationResult(
            ReconciliationOutcome.RESCHEDULED
            if update.outcome is UpdateOutcome.UPDATED
            else ReconciliationOutcome.LOST_CLAIM
        )

    def _terminate_paid_race(
        self,
        claim: ReconciliationClaim,
    ) -> ReconciliationResult:
        result = self._terminate(
            claim,
            reason="ORDER_ALREADY_PAID",
            query_completed=True,
        )
        return (
            ReconciliationResult(ReconciliationOutcome.ALREADY_PAID)
            if result.outcome is not ReconciliationOutcome.LOST_CLAIM
            else result
        )

    def _terminate(
        self,
        claim: ReconciliationClaim,
        *,
        reason: str,
        trade_state: str | None = None,
        error: str | None = None,
        query_completed: bool = True,
        close_completed: bool = False,
    ) -> ReconciliationResult:
        values = dict(
            database_path=self.database_path,
            claim_token=claim.claim_token,
            expected_state_version=claim.state_version,
            terminal_at=self._now(),
            terminal_reason=reason,
            last_error_code=error,
            query_completed=query_completed,
            close_completed=close_completed,
            clock=self.clock,
        )
        if trade_state is not None:
            values["trusted_trade_state"] = trade_state
        update = terminate_claim(**values)
        return ReconciliationResult(
            ReconciliationOutcome.TERMINAL_ABNORMAL
            if update.outcome is UpdateOutcome.UPDATED
            else ReconciliationOutcome.LOST_CLAIM
        )

    def _now(self) -> datetime:
        return _utc(self.clock())


def _retry_delay(attempt_count: int, base_seconds: int, max_seconds: int) -> int:
    return min(max_seconds, base_seconds * (1 << min(attempt_count - 1, 30)))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("PAYMENT_RECONCILIATION_TIME_INVALID")
    return value.astimezone(timezone.utc).replace(microsecond=0)
