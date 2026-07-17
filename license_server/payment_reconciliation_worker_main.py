from __future__ import annotations

import logging
import os
import signal
import sqlite3
from contextlib import closing
from pathlib import Path
from threading import Event

from license_server.config import LicenseServerConfig, _boolean_from_env, load_config
from license_server.db import (
    _assert_no_foreign_key_violations,
    _require_exact_versioned_schema,
    _schema_version,
)
from license_server.payment_reconciliation_service import (
    PaymentReconciliationService,
)
from license_server.payment_reconciliation_worker import PaymentReconciliationWorker
from license_server.wechat_payment import WeChatNativePaymentGateway


EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_CONFIG_ERROR = 2
_REQUIRED_SCHEMA_VERSION = 5

_LOGGER = logging.getLogger(__name__)


def validate_schema_v5(database_path: Path) -> None:
    path = Path(database_path)
    if not path.is_absolute() or not path.is_file():
        raise RuntimeError("PAYMENT_RECONCILIATION_SCHEMA_INVALID")
    try:
        uri = path.resolve(strict=True).as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA query_only = ON")
            if _schema_version(connection) != _REQUIRED_SCHEMA_VERSION:
                raise RuntimeError("PAYMENT_RECONCILIATION_SCHEMA_INVALID")
            _require_exact_versioned_schema(connection, _REQUIRED_SCHEMA_VERSION)
            _assert_no_foreign_key_violations(connection)
    except Exception as exc:
        raise RuntimeError("PAYMENT_RECONCILIATION_SCHEMA_INVALID") from exc


def build_worker(
    config: LicenseServerConfig,
    *,
    gateway_factory=WeChatNativePaymentGateway,
    service_factory=PaymentReconciliationService,
    worker_factory=PaymentReconciliationWorker,
):
    if config.payment_provider != "wechat_native" or config.wechat_pay is None:
        raise RuntimeError("PAYMENT_RECONCILIATION_WORKER_PROVIDER_UNAVAILABLE")
    gateway = gateway_factory(config.wechat_pay)
    service = service_factory(
        database_path=config.database_path,
        gateway=gateway,
        expected_appid=config.wechat_pay.app_id,
        expected_mchid=config.wechat_pay.mch_id,
        policy=config.payment_reconciliation_policy,
    )
    return worker_factory(
        database_path=config.database_path,
        reconciliation_service=service,
        policy=config.payment_reconciliation_worker_policy,
    )


def install_signal_handlers(stop_event: Event) -> dict[signal.Signals, object]:
    def request_stop(_signum, _frame) -> None:
        stop_event.set()

    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, request_stop)
    except Exception:
        _restore_signal_handlers(previous)
        raise
    return previous


def _restore_signal_handlers(previous: dict[signal.Signals, object]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def main() -> int:
    try:
        if not _worker_enabled():
            _log("payment_reconciliation_worker_disabled")
            return EXIT_OK
        config = load_config()
    except Exception:
        _log("payment_reconciliation_worker_config_invalid")
        return EXIT_CONFIG_ERROR

    if not config.payment_reconciliation_worker_enabled:
        _log("payment_reconciliation_worker_disabled")
        return EXIT_OK
    if config.payment_provider != "wechat_native" or config.wechat_pay is None:
        _log("payment_reconciliation_worker_provider_unavailable")
        return EXIT_CONFIG_ERROR

    try:
        validate_schema_v5(config.database_path)
    except Exception:
        _log("payment_reconciliation_worker_schema_invalid")
        return EXIT_RUNTIME_ERROR

    try:
        worker = build_worker(config)
    except Exception:
        _log("payment_reconciliation_worker_config_invalid")
        return EXIT_CONFIG_ERROR

    stop_event = Event()
    previous = {}
    try:
        previous = install_signal_handlers(stop_event)
        _log("payment_reconciliation_worker_started")
        worker.run_forever(stop_event)
        _log("payment_reconciliation_worker_stopped")
        return EXIT_OK
    except Exception:
        _log("payment_reconciliation_worker_runtime_failed")
        return EXIT_RUNTIME_ERROR
    finally:
        _restore_signal_handlers(previous)


def _log(event: str) -> None:
    _LOGGER.info('{"event":"%s"}', event)


def _worker_enabled() -> bool:
    return _boolean_from_env(
        os.environ,
        "PAYMENT_RECONCILIATION_WORKER_ENABLED",
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    raise SystemExit(main())
