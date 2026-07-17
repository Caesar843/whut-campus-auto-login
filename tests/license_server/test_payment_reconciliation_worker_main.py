from __future__ import annotations

import logging
import os
import re
import signal
import sqlite3
import subprocess
import sys
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

import license_server.payment_reconciliation_worker_main as worker_main
from license_server import db
from license_server.db import initialize_database
from license_server.payment_reconciliation_service import PaymentReconciliationPolicy
from license_server.payment_reconciliation_worker import PaymentReconciliationWorkerPolicy
from license_server.payment_reconciliation_worker_main import (
    EXIT_CONFIG_ERROR,
    EXIT_OK,
    EXIT_RUNTIME_ERROR,
    build_worker,
    install_signal_handlers,
    main,
    validate_schema_v5,
)
from tests.license_server.test_license_server import _production_env
from tests.license_server.test_payment_config import _wechat_env


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_validate_schema_v5_accepts_exact_schema_without_modifying_database(tmp_path):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    before = (
        database_path.read_bytes(),
        database_path.stat().st_mtime_ns,
        sorted(path.name for path in tmp_path.iterdir()),
    )

    validate_schema_v5(database_path)

    assert (
        database_path.read_bytes(),
        database_path.stat().st_mtime_ns,
        sorted(path.name for path in tmp_path.iterdir()),
    ) == before


def test_validate_schema_v5_stays_pinned_when_supported_version_changes(
    monkeypatch, tmp_path
):
    database_path = tmp_path / "license.sqlite3"
    initialize_database(database_path)
    monkeypatch.setattr(
        worker_main,
        "SUPPORTED_SCHEMA_VERSION",
        6,
        raising=False,
    )

    validate_schema_v5(database_path)


def test_validate_schema_v5_rejects_missing_database_without_creating_it(tmp_path):
    database_path = tmp_path / "missing" / "license.sqlite3"

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_SCHEMA_INVALID"):
        validate_schema_v5(database_path)

    assert not database_path.exists()
    assert not database_path.parent.exists()


@pytest.mark.parametrize(
    "schema_state",
    (
        "v4",
        "missing-table",
        "tampered-column",
        "tampered-index",
        "v6",
        "invalid-meta",
        "not-sqlite",
    ),
)
def test_validate_schema_v5_rejects_every_non_exact_schema_read_only(
    tmp_path, schema_state
):
    database_path = tmp_path / f"{schema_state}.sqlite3"
    if schema_state == "v4":
        _create_v4_database(database_path)
    elif schema_state == "not-sqlite":
        database_path.write_bytes(b"not a sqlite database")
    else:
        initialize_database(database_path)
        with sqlite3.connect(database_path) as connection:
            if schema_state == "missing-table":
                connection.execute("DROP TABLE payment_reconciliations")
            elif schema_state == "tampered-column":
                connection.execute(
                    "ALTER TABLE payment_reconciliations ADD COLUMN unexpected TEXT"
                )
            elif schema_state == "tampered-index":
                connection.execute(
                    "DROP INDEX idx_payment_reconciliations_candidate"
                )
            elif schema_state == "v6":
                connection.execute(
                    "UPDATE schema_meta SET value = '6' WHERE key = 'schema_version'"
                )
            else:
                connection.execute("DROP TABLE schema_meta")
    before = database_path.read_bytes()

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_SCHEMA_INVALID"):
        validate_schema_v5(database_path)

    assert database_path.read_bytes() == before


def test_validate_schema_v5_rejects_nonfile_database_path(tmp_path):
    database_path = tmp_path / "database-directory"
    database_path.mkdir()

    with pytest.raises(RuntimeError, match="PAYMENT_RECONCILIATION_SCHEMA_INVALID"):
        validate_schema_v5(database_path)


def test_build_worker_constructs_gateway_service_and_worker_once(tmp_path):
    config = _runtime_config(tmp_path)
    calls = []
    gateway = object()
    service = SimpleNamespace(reconcile_claim=lambda *_args, **_kwargs: None)
    worker = object()

    def gateway_factory(wechat_pay):
        calls.append(("gateway", wechat_pay))
        return gateway

    def service_factory(**kwargs):
        calls.append(("service", kwargs))
        return service

    def worker_factory(**kwargs):
        calls.append(("worker", kwargs))
        return worker

    assert build_worker(
        config,
        gateway_factory=gateway_factory,
        service_factory=service_factory,
        worker_factory=worker_factory,
    ) is worker
    assert calls == [
        ("gateway", config.wechat_pay),
        (
            "service",
            {
                "database_path": config.database_path,
                "gateway": gateway,
                "expected_appid": config.wechat_pay.app_id,
                "expected_mchid": config.wechat_pay.mch_id,
                "policy": config.payment_reconciliation_policy,
            },
        ),
        (
            "worker",
            {
                "database_path": config.database_path,
                "reconciliation_service": service,
                "policy": config.payment_reconciliation_worker_policy,
            },
        ),
    ]


def test_build_worker_uses_real_service_and_worker_without_gateway_network(tmp_path):
    config = _runtime_config(tmp_path)

    class Gateway:
        def __init__(self):
            self.calls = []

        def query_order(self, order_id):
            self.calls.append(("query", order_id))

        def close_order(self, order_id):
            self.calls.append(("close", order_id))

    gateway = Gateway()

    worker = build_worker(config, gateway_factory=lambda _wechat_pay: gateway)

    assert worker.database_path == config.database_path
    assert worker.policy is config.payment_reconciliation_worker_policy
    assert worker.reconciliation_service.policy is config.payment_reconciliation_policy
    assert worker.reconciliation_service.gateway is gateway
    assert gateway.calls == []
    assert re.fullmatch(r"reconciliation-worker-[0-9a-f]{8}", worker.worker_id)
    assert worker.worker_id == worker.worker_id
    for sensitive in (
        str(config.database_path),
        config.wechat_pay.app_id,
        config.wechat_pay.mch_id,
    ):
        assert sensitive not in worker.worker_id


def test_main_disabled_exits_without_schema_gateway_worker_or_signals(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("PAYMENT_RECONCILIATION_WORKER_ENABLED", "false")
    config = _runtime_config(tmp_path, enabled=False)
    calls = []
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.validate_schema_v5",
        lambda _path: calls.append("schema"),
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.build_worker",
        lambda _config: calls.append("worker"),
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.install_signal_handlers",
        lambda _event: calls.append("signals"),
    )

    assert main() == EXIT_OK
    assert calls == []


@pytest.mark.parametrize("provider", (None, "mock"))
def test_main_enabled_rejects_non_wechat_provider_before_schema(
    monkeypatch, tmp_path, provider
):
    monkeypatch.setenv("PAYMENT_RECONCILIATION_WORKER_ENABLED", "true")
    config = _runtime_config(tmp_path)
    config.payment_provider = provider
    calls = []
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.validate_schema_v5",
        lambda _path: calls.append("schema"),
    )

    assert main() == EXIT_CONFIG_ERROR
    assert calls == []


def test_main_validates_schema_before_constructing_and_running_worker(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("PAYMENT_RECONCILIATION_WORKER_ENABLED", "true")
    config = _runtime_config(tmp_path)
    calls = []

    class Worker:
        def run_forever(self, stop_event):
            calls.append(("run", stop_event))

    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.validate_schema_v5",
        lambda path: calls.append(("schema", path)),
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.build_worker",
        lambda loaded: calls.append(("build", loaded)) or Worker(),
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.install_signal_handlers",
        lambda event: calls.append(("signals", event)) or {},
    )

    assert main() == EXIT_OK
    assert [item[0] for item in calls] == ["schema", "build", "signals", "run"]
    assert calls[0][1] == config.database_path
    assert calls[1][1] is config
    assert calls[2][1] is calls[3][1]


@pytest.mark.parametrize("signum", (signal.SIGTERM, signal.SIGINT))
def test_signal_handlers_only_set_stop_event(monkeypatch, signum):
    installed = {}
    stop_event = Event()

    def capture(captured_signum, handler):
        installed[captured_signum] = handler
        return signal.SIG_DFL

    monkeypatch.setattr(signal, "signal", capture)

    previous = install_signal_handlers(stop_event)
    installed[signum](signum, None)

    assert stop_event.is_set()
    assert previous[signal.SIGTERM] == signal.SIG_DFL
    assert previous[signal.SIGINT] == signal.SIG_DFL


@pytest.mark.parametrize("phase", ("config", "schema", "build", "run"))
def test_main_returns_fixed_nonzero_codes_without_leaking_secrets(
    monkeypatch, caplog, tmp_path, phase
):
    monkeypatch.setenv("PAYMENT_RECONCILIATION_WORKER_ENABLED", "true")
    caplog.set_level(logging.INFO)
    secret = "secret-path-order-token-appid-mchid"
    config = _runtime_config(tmp_path)

    class Worker:
        def run_forever(self, _stop_event):
            if phase == "run":
                raise RuntimeError(secret)

    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.load_config",
        lambda: (_ for _ in ()).throw(RuntimeError(secret))
        if phase == "config"
        else config,
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.validate_schema_v5",
        lambda _path: (_ for _ in ()).throw(RuntimeError(secret))
        if phase == "schema"
        else None,
    )
    monkeypatch.setattr(
        "license_server.payment_reconciliation_worker_main.build_worker",
        lambda _config: (_ for _ in ()).throw(RuntimeError(secret))
        if phase == "build"
        else Worker(),
    )

    expected = EXIT_CONFIG_ERROR if phase in {"config", "build"} else EXIT_RUNTIME_ERROR
    assert main() == expected
    assert secret not in caplog.text
    assert str(config.database_path) not in caplog.text
    assert config.wechat_pay.app_id not in caplog.text
    assert config.wechat_pay.mch_id not in caplog.text
    assert config.wechat_pay.api_v3_key.decode() not in caplog.text


def test_module_subprocess_disabled_and_invalid_schema_are_safe(tmp_path):
    disabled = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    disabled["PAYMENT_RECONCILIATION_WORKER_ENABLED"] = "false"

    disabled_result = _run_module(disabled)

    assert disabled_result.returncode == EXIT_OK
    assert not Path(disabled["DATABASE_URL"].removeprefix("sqlite:///")).exists()
    assert disabled["DATABASE_URL"] not in disabled_result.stdout + disabled_result.stderr

    enabled = _wechat_env(tmp_path)
    enabled["PAYMENT_RECONCILIATION_WORKER_ENABLED"] = "true"
    database_path = Path(enabled["DATABASE_URL"].removeprefix("sqlite:///"))

    invalid_schema_result = _run_module(enabled)

    assert invalid_schema_result.returncode == EXIT_RUNTIME_ERROR
    assert not database_path.exists()
    output = invalid_schema_result.stdout + invalid_schema_result.stderr
    assert enabled["DATABASE_URL"] not in output
    assert enabled["WECHAT_PAY_API_V3_KEY"] not in output
    assert "uvicorn" not in output.lower()


def test_module_subprocess_disabled_does_not_validate_wechat_secrets(tmp_path):
    disabled = _production_env(
        tmp_path,
        PAYMENT_PROVIDER="wechat_native",
        PAYMENT_RECONCILIATION_WORKER_ENABLED="false",
    )

    result = _run_module(disabled)

    assert result.returncode == EXIT_OK
    output = result.stdout + result.stderr
    assert "WECHAT_PAY_" not in output
    assert disabled["DATABASE_URL"] not in output


def test_worker_systemd_unit_is_separate_default_safe_and_secret_free():
    unit = Path(
        "deploy/systemd/whut-payment-reconciliation-worker.service.example"
    ).read_text(encoding="utf-8")

    for required in (
        "User=whutlogin",
        "Group=whutlogin",
        "WorkingDirectory=/opt/whut-campus-auto-login",
        "EnvironmentFile=/etc/whut-campus-auto-login/license-server.env",
        "After=network-online.target whut-license-server.service",
        "Requires=whut-license-server.service",
        "ExecStart=/opt/whut-campus-auto-login/.venv/bin/python -m license_server.payment_reconciliation_worker_main",
        "Restart=on-failure",
        "RestartPreventExitStatus=2",
        "KillSignal=SIGTERM",
        "TimeoutStopSec=30",
        "WantedBy=multi-user.target",
    ):
        assert required in unit
    for forbidden in (
        "User=root",
        "uvicorn",
        "bash -c",
        "WECHAT_PAY_API_V3_KEY=",
        "PAYMENT_RECONCILIATION_WORKER_ENABLED=true",
        "ExecStartPre=",
        "sqlite3",
        "mock",
    ):
        assert forbidden not in unit


def test_environment_example_has_explicit_safe_reconciliation_defaults():
    example = Path("license_server/.env.example").read_text(encoding="utf-8")

    for required in (
        "PAYMENT_RECONCILIATION_WORKER_ENABLED=false",
        "PAYMENT_RECONCILIATION_WORKER_SCAN_INTERVAL_SECONDS=30",
        "PAYMENT_RECONCILIATION_WORKER_RECENT_ORDER_WINDOW_SECONDS=600",
        "PAYMENT_RECONCILIATION_WORKER_MAX_CLAIMS_PER_CYCLE=10",
        "PAYMENT_RECONCILIATION_WORKER_LEASE_SECONDS=60",
        "PAYMENT_RECONCILIATION_WORKER_IDLE_WAIT_SECONDS=1",
        "PAYMENT_RECONCILIATION_WORKER_MAX_ORDERS_PER_SCAN=100",
        "PAYMENT_RECONCILIATION_QUERY_RETRY_BASE_SECONDS=5",
        "PAYMENT_RECONCILIATION_QUERY_RETRY_MAX_SECONDS=300",
        "PAYMENT_RECONCILIATION_MAX_QUERY_ATTEMPTS=8",
        "PAYMENT_RECONCILIATION_CLOSE_RETRY_BASE_SECONDS=5",
        "PAYMENT_RECONCILIATION_CLOSE_RETRY_MAX_SECONDS=300",
        "PAYMENT_RECONCILIATION_MAX_CLOSE_ATTEMPTS=8",
    ):
        assert required in example
    lines = set(example.splitlines())
    for forbidden in (
        "PAYMENT_RECONCILIATION_WORKER_ENABLED=true",
        "PAYMENT_PROVIDER=mock",
        "PAYMENT_AMOUNT=",
        "ADMIN_ACCESS_TOKEN=",
    ):
        assert forbidden not in lines
    assert "WECHAT_PAY_APP_ID=\n" in example
    assert "WECHAT_PAY_MCH_ID=\n" in example
    assert "WECHAT_PAY_API_V3_KEY=\n" in example


def test_deployment_document_covers_default_disabled_operations_and_rollback():
    document = Path("docs/license_deploy_tencent_cloud.md").read_text(encoding="utf-8")

    for required in (
        "支付对账补偿 Worker",
        "独立进程",
        "默认关闭",
        "PAYMENT_RECONCILIATION_WORKER_ENABLED=false",
        "Schema V5",
        "不会执行迁移",
        "whut-payment-reconciliation-worker.service",
        "systemctl daemon-reload",
        "systemctl is-enabled whut-payment-reconciliation-worker.service",
        "systemctl is-active whut-payment-reconciliation-worker.service",
        "systemctl stop whut-payment-reconciliation-worker.service",
        "systemctl disable whut-payment-reconciliation-worker.service",
        "手动刷新",
        "回调缺失",
        "真实微信商户",
        "本轮不启用",
        "不得与 Notification Worker 混用入口或 unit",
        "启动日志不得出现 Secret",
    ):
        assert required in document
    assert "systemctl enable --now whut-payment-reconciliation-worker.service" not in document


def test_notification_worker_unit_remains_separate():
    unit = Path(
        "deploy/systemd/whut-license-payment-worker.service.example"
    ).read_text(encoding="utf-8")

    assert "license_server.payment_notification_worker_main" in unit
    assert "payment_reconciliation_worker_main" not in unit


def _runtime_config(tmp_path, *, enabled=True):
    return SimpleNamespace(
        database_path=tmp_path / "license.sqlite3",
        payment_provider="wechat_native",
        wechat_pay=SimpleNamespace(
            app_id="wx-test-app",
            mch_id="1900000109",
            api_v3_key=b"0123456789abcdef0123456789abcdef",
        ),
        payment_reconciliation_worker_enabled=enabled,
        payment_reconciliation_worker_policy=PaymentReconciliationWorkerPolicy(),
        payment_reconciliation_policy=PaymentReconciliationPolicy(
            query_retry_base_seconds=5,
            query_retry_max_seconds=300,
            max_query_attempts=8,
            close_retry_base_seconds=5,
            close_retry_max_seconds=300,
            max_close_attempts=8,
        ),
    )


def _create_v4_database(database_path):
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            "\n".join(
                (
                    db.CORE_SCHEMA,
                    db.PAYMENT_ORDER_SCHEMA,
                    db.PAYMENT_NOTIFICATION_SCHEMA,
                    db.LICENSE_GRANT_SCHEMA,
                    db.ADMIN_AUDIT_SCHEMA,
                    db.SCHEMA_META_SQL,
                )
            )
        )
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '4')"
        )


def _run_module(values):
    env = os.environ.copy()
    env.update(values)
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, "-m", "license_server.payment_reconciliation_worker_main"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
