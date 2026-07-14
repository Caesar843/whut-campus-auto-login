from __future__ import annotations

import argparse
import json
import logging
import secrets
import signal
from datetime import datetime, timezone
from threading import Event, Lock
from typing import Callable, Sequence

from license_server.config import LicenseServerConfig, load_config
from license_server.db import initialize_database
from license_server.payment_notification_worker import (
    PaymentNotificationWorker,
    WorkerProcessOutcome,
)


EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_CONFIG_ERROR = 2

_LOGGER = logging.getLogger("license_server.payment_notification_worker")


class _ClaimAdmission:
    def __init__(self) -> None:
        self._lock = Lock()
        self._active = False

    def try_admit(self, stop_event: Event) -> bool:
        if stop_event.is_set():
            return False
        with self._lock:
            if self._active:
                raise RuntimeError("PAYMENT_NOTIFICATION_WORKER_ADMISSION_INVALID")
            self._active = True
            if stop_event.is_set():
                self._active = False
                return False
            return True

    def finish(self) -> None:
        with self._lock:
            if not self._active:
                raise RuntimeError("PAYMENT_NOTIFICATION_WORKER_ADMISSION_INVALID")
            self._active = False


def create_worker_id() -> str:
    return f"payment-worker-{secrets.token_hex(4)}"


def build_worker(
    config: LicenseServerConfig,
    *,
    worker_id: str | None = None,
) -> PaymentNotificationWorker:
    if config.payment_provider != "wechat_native" or config.wechat_pay is None:
        raise ValueError("PAYMENT_NOTIFICATION_WORKER_PROVIDER_INVALID")
    return PaymentNotificationWorker(
        database_path=config.database_path,
        worker_id=worker_id or create_worker_id(),
        expected_appid=config.wechat_pay.app_id,
        expected_mchid=config.wechat_pay.mch_id,
        lease_seconds=config.payment_notification_lease_seconds,
        max_attempts=config.payment_notification_max_attempts,
        retry_base_seconds=config.payment_notification_retry_base_seconds,
        retry_max_seconds=config.payment_notification_retry_max_seconds,
    )


def run_worker(
    worker: PaymentNotificationWorker,
    *,
    poll_seconds: float,
    stop_event: Event,
    once: bool = False,
    now_fn: Callable[[], datetime] | None = None,
) -> int:
    clock = now_fn or _utc_now
    admission = _ClaimAdmission()
    while admission.try_admit(stop_event):
        try:
            result = worker.process_next(now=clock())
            outcome = _validated_outcome(result)
        finally:
            admission.finish()
        if once:
            return EXIT_OK
        if outcome is WorkerProcessOutcome.NO_WORK:
            stop_event.wait(poll_seconds)
    return EXIT_OK


def _validated_outcome(result: object) -> WorkerProcessOutcome:
    outcome = getattr(result, "outcome", None)
    if not isinstance(outcome, WorkerProcessOutcome):
        raise RuntimeError("PAYMENT_NOTIFICATION_WORKER_OUTCOME_INVALID")
    return outcome


def install_signal_handlers(stop_event: Event) -> dict[int, signal.Handlers]:
    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    previous = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, request_stop)
    return previous


def main(argv: Sequence[str] | None = None) -> int:
    _configure_logging()
    args = _parser().parse_args(argv)
    try:
        config = load_config()
        if not config.payment_notification_worker_enabled:
            _log_event(logging.INFO, "payment_notification_worker_disabled")
            return EXIT_OK
        worker = build_worker(config)
    except (RuntimeError, ValueError):
        _log_event(
            logging.ERROR,
            "payment_notification_worker_config_invalid",
            failure_code="PAYMENT_NOTIFICATION_WORKER_CONFIG_INVALID",
        )
        return EXIT_CONFIG_ERROR

    stop_event = Event()
    previous_handlers = install_signal_handlers(stop_event)
    started = False
    exit_code = EXIT_RUNTIME_ERROR
    try:
        initialize_database(config.database_path)
        _log_event(
            logging.INFO,
            "payment_notification_worker_started",
            environment=config.environment,
            worker_ref=worker.worker_id.rsplit("-", 1)[-1],
        )
        started = True
        exit_code = run_worker(
            worker,
            poll_seconds=config.payment_notification_worker_poll_seconds,
            stop_event=stop_event,
            once=args.once,
        )
    except Exception as exc:
        _log_event(
            logging.ERROR,
            "payment_notification_worker_failed",
            failure_code="PAYMENT_NOTIFICATION_WORKER_RUNTIME_FAILED",
            error_type=type(exc).__name__,
        )
        exit_code = EXIT_RUNTIME_ERROR
    finally:
        _restore_signal_handlers(previous_handlers)
        if started:
            _log_event(
                logging.INFO,
                "payment_notification_worker_stopped",
                exit_code=exit_code,
            )
    return exit_code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Process WeChat payment notifications.")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one available notification, then exit.",
    )
    return parser


def _restore_signal_handlers(previous: dict[int, signal.Handlers]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


def _log_event(level: int, event: str, **fields: object) -> None:
    payload = {"event": event, **fields}
    _LOGGER.log(
        level,
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
    )


if __name__ == "__main__":
    raise SystemExit(main())
