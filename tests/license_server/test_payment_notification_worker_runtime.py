from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import sys
from datetime import timedelta
from enum import Enum
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from license_server.db import connect
from license_server.payment_notification_repository import (
    claim_next_payment_notification,
)
from license_server.payment_notification_worker import (
    PaymentNotificationWorker,
    WorkerProcessOutcome,
    WorkerProcessResult,
)
from license_server.payment_notification_worker_main import (
    EXIT_CONFIG_ERROR,
    EXIT_OK,
    EXIT_RUNTIME_ERROR,
    build_worker,
    create_worker_id,
    install_signal_handlers,
    main,
    run_worker,
)
from tests.license_server.test_license_server import _production_env
from tests.license_server.test_payment_config import _wechat_env
from tests.license_server.test_payment_notification_worker import (
    APP_ID,
    MCH_ID,
    NOW,
    _database,
    _insert_notification,
    _insert_order,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class _RecordingEvent(Event):
    def __init__(self) -> None:
        super().__init__()
        self.waits: list[float | None] = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        self.set()
        return True


class _ResultWorker:
    def __init__(self, outcomes, stop_event: Event | None = None) -> None:
        self._outcomes = iter(outcomes)
        self._stop_event = stop_event
        self.calls = 0
        self.worker_id = "payment-worker-fake0000"

    def process_next(self, *, now):
        self.calls += 1
        outcome = next(self._outcomes)
        if self._stop_event is not None:
            self._stop_event.set()
        return WorkerProcessResult(outcome)


def test_create_worker_id_is_short_stable_format_and_unique():
    first = create_worker_id()
    second = create_worker_id()

    assert re.fullmatch(r"payment-worker-[0-9a-f]{8}", first)
    assert first != second


def test_build_worker_passes_authoritative_runtime_configuration(tmp_path):
    config = _runtime_config(tmp_path)

    worker = build_worker(config, worker_id="payment-worker-deadbeef")

    assert isinstance(worker, PaymentNotificationWorker)
    assert worker.database_path == config.database_path
    assert worker.expected_appid == APP_ID
    assert worker.expected_mchid == MCH_ID
    assert worker.max_attempts == 17
    assert worker.lease_seconds == 60
    assert worker.retry_base_seconds == 5
    assert worker.retry_max_seconds == 300
    assert worker.worker_id == "payment-worker-deadbeef"


def test_build_worker_generates_one_nonsensitive_id_per_instance(tmp_path):
    config = _runtime_config(tmp_path)

    first = build_worker(config)
    second = build_worker(config)

    assert first.worker_id != second.worker_id
    for sensitive in (str(config.database_path), APP_ID, MCH_ID):
        assert sensitive not in first.worker_id
        assert sensitive not in second.worker_id


def test_no_work_uses_interruptible_configured_wait():
    stop_event = _RecordingEvent()
    worker = _ResultWorker([WorkerProcessOutcome.NO_WORK])

    result = run_worker(worker, poll_seconds=2.5, stop_event=stop_event)

    assert result == EXIT_OK
    assert worker.calls == 1
    assert stop_event.waits == [2.5]


@pytest.mark.parametrize(
    "outcome",
    (
        WorkerProcessOutcome.PROCESSED,
        WorkerProcessOutcome.DUPLICATE,
        WorkerProcessOutcome.ORPHAN,
        WorkerProcessOutcome.ABNORMAL,
        WorkerProcessOutcome.RETRY_SCHEDULED,
        WorkerProcessOutcome.LOST_CLAIM,
    ),
)
def test_terminal_and_recovery_outcomes_continue_without_sleep(outcome):
    stop_event = _RecordingEvent()
    worker = _ResultWorker([outcome, WorkerProcessOutcome.NO_WORK])

    assert run_worker(worker, poll_seconds=1.25, stop_event=stop_event) == EXIT_OK
    assert worker.calls == 2
    assert stop_event.waits == [1.25]


@pytest.mark.parametrize("outcome", tuple(WorkerProcessOutcome))
def test_once_mode_validates_and_processes_each_outcome_once_without_wait(outcome):
    stop_event = _RecordingEvent()
    worker = _ResultWorker(
        [outcome, WorkerProcessOutcome.PROCESSED]
    )

    assert run_worker(
        worker,
        poll_seconds=1,
        stop_event=stop_event,
        once=True,
    ) == EXIT_OK
    assert worker.calls == 1
    assert stop_event.waits == []


def test_stop_requested_during_processing_prevents_next_claim():
    stop_event = Event()
    worker = _ResultWorker(
        [WorkerProcessOutcome.PROCESSED, WorkerProcessOutcome.PROCESSED],
        stop_event,
    )

    assert run_worker(worker, poll_seconds=1, stop_event=stop_event) == EXIT_OK
    assert worker.calls == 1


def test_stop_requested_after_early_check_prevents_admission():
    class StaleCheckEvent(Event):
        def __init__(self):
            super().__init__()
            self.check_read = Event()
            self.release_check = Event()
            self._first_check = True

        def is_set(self):
            if not self._first_check:
                return super().is_set()
            self._first_check = False
            value = super().is_set()
            self.check_read.set()
            assert self.release_check.wait(2)
            return value

    stop_event = StaleCheckEvent()
    worker = _ResultWorker([WorkerProcessOutcome.PROCESSED])
    result = []
    thread = Thread(
        target=lambda: result.append(
            run_worker(
                worker,
                poll_seconds=1,
                stop_event=stop_event,
                once=True,
            )
        )
    )

    thread.start()
    assert stop_event.check_read.wait(2)
    stop_event.set()
    stop_event.release_check.set()
    thread.join(2)

    assert not thread.is_alive()
    assert result == [EXIT_OK]
    assert worker.calls == 0


def test_stop_requested_after_admission_allows_only_current_iteration():
    entered = Event()
    release = Event()
    stop_event = Event()
    result = []

    class BlockingWorker:
        def __init__(self):
            self.calls = 0

        def process_next(self, *, now):
            self.calls += 1
            entered.set()
            assert release.wait(2)
            return WorkerProcessResult(WorkerProcessOutcome.PROCESSED)

    worker = BlockingWorker()
    thread = Thread(
        target=lambda: result.append(
            run_worker(worker, poll_seconds=1, stop_event=stop_event)
        )
    )

    thread.start()
    assert entered.wait(2)
    stop_event.set()
    release.set()
    thread.join(2)

    assert not thread.is_alive()
    assert result == [EXIT_OK]
    assert worker.calls == 1


def test_once_mode_does_not_process_when_stop_is_already_requested():
    stop_event = Event()
    stop_event.set()
    worker = _ResultWorker([WorkerProcessOutcome.PROCESSED])

    assert run_worker(
        worker,
        poll_seconds=1,
        stop_event=stop_event,
        once=True,
    ) == EXIT_OK
    assert worker.calls == 0


@pytest.mark.parametrize("signum", (signal.SIGTERM, signal.SIGINT))
def test_signal_handlers_only_set_stop_event(monkeypatch, signum):
    installed = {}
    stop_event = Event()

    def capture(signum, handler):
        installed[signum] = handler
        return signal.SIG_DFL

    monkeypatch.setattr(signal, "signal", capture)

    previous = install_signal_handlers(stop_event)
    installed[signum](signum, None)

    assert stop_event.is_set()
    assert previous[signal.SIGTERM] == signal.SIG_DFL
    assert signal.SIGINT in installed


class _ForeignOutcome(Enum):
    UNKNOWN = "FOREIGN_OUTCOME_SECRET"


@pytest.mark.parametrize("once", (False, True))
@pytest.mark.parametrize(
    "invalid_result",
    (
        None,
        SimpleNamespace(outcome=None),
        SimpleNamespace(outcome="UNKNOWN_OUTCOME_SECRET"),
        SimpleNamespace(outcome=7),
        SimpleNamespace(outcome=_ForeignOutcome.UNKNOWN),
        SimpleNamespace(outcome=object()),
    ),
    ids=("none-result", "none", "string", "integer", "foreign-enum", "object"),
)
def test_invalid_process_outcome_fails_closed_after_one_call(once, invalid_result):
    class InvalidWorker:
        def __init__(self):
            self.calls = 0

        def process_next(self, *, now):
            self.calls += 1
            return invalid_result

    worker = InvalidWorker()

    with pytest.raises(RuntimeError, match="PAYMENT_NOTIFICATION_WORKER_OUTCOME_INVALID"):
        run_worker(worker, poll_seconds=1, stop_event=Event(), once=once)

    assert worker.calls == 1


@pytest.mark.parametrize("once", (False, True))
def test_process_exception_fails_after_one_call(once):
    class FailingWorker:
        def __init__(self):
            self.calls = 0

        def process_next(self, *, now):
            self.calls += 1
            raise LookupError("UNKNOWN_RUNTIME_SECRET")

    worker = FailingWorker()

    with pytest.raises(LookupError, match="UNKNOWN_RUNTIME_SECRET"):
        run_worker(worker, poll_seconds=1, stop_event=Event(), once=once)

    assert worker.calls == 1


def test_main_disabled_exits_without_database_or_worker(monkeypatch, tmp_path):
    config = _runtime_config(tmp_path, enabled=False)
    calls = []
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.initialize_database",
        lambda _path: calls.append("database"),
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.build_worker",
        lambda _config: calls.append("worker"),
    )

    assert main([]) == EXIT_OK
    assert calls == []


def test_main_runs_schema_gate_before_loop(monkeypatch, tmp_path):
    config = _runtime_config(tmp_path)
    calls = []
    worker = _ResultWorker([WorkerProcessOutcome.NO_WORK])
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.build_worker",
        lambda _config: worker,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.initialize_database",
        lambda path: calls.append(("database", path)),
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.run_worker",
        lambda *_args, **_kwargs: calls.append(("loop", None)) or EXIT_OK,
    )

    assert main(["--once"]) == EXIT_OK
    assert calls == [("database", config.database_path), ("loop", None)]


def test_main_returns_fixed_nonzero_codes_without_leaking_exception(
    monkeypatch, caplog, tmp_path
):
    secret = "secret-database-path-or-order"
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.load_config",
        lambda: (_ for _ in ()).throw(RuntimeError(secret)),
    )
    assert main([]) == EXIT_CONFIG_ERROR
    assert secret not in caplog.text

    config = _runtime_config(tmp_path)
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.initialize_database",
        lambda _path: (_ for _ in ()).throw(RuntimeError(secret)),
    )
    assert main([]) == EXIT_RUNTIME_ERROR
    assert secret not in caplog.text


@pytest.mark.parametrize("once", (False, True))
def test_main_invalid_outcome_returns_runtime_error_without_leaking_value(
    monkeypatch, caplog, tmp_path, once
):
    secret = "UNKNOWN_OUTCOME_SECRET"
    config = _runtime_config(tmp_path)

    class InvalidWorker:
        worker_id = "payment-worker-deadbeef"

        def __init__(self):
            self.calls = 0

        def process_next(self, *, now):
            self.calls += 1
            return SimpleNamespace(outcome=secret)

    worker = InvalidWorker()
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.build_worker",
        lambda _config: worker,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.initialize_database",
        lambda _path: None,
    )

    assert main(["--once"] if once else []) == EXIT_RUNTIME_ERROR
    assert worker.calls == 1
    assert secret not in caplog.text


@pytest.mark.parametrize("once", (False, True))
def test_main_process_exception_returns_runtime_error_without_leaking_value(
    monkeypatch, caplog, tmp_path, once
):
    secret = "UNKNOWN_RUNTIME_SECRET"
    config = _runtime_config(tmp_path)

    class FailingWorker:
        worker_id = "payment-worker-deadbeef"

        def __init__(self):
            self.calls = 0

        def process_next(self, *, now):
            self.calls += 1
            raise LookupError(secret)

    worker = FailingWorker()
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.build_worker",
        lambda _config: worker,
    )
    monkeypatch.setattr(
        "license_server.payment_notification_worker_main.initialize_database",
        lambda _path: None,
    )

    assert main(["--once"] if once else []) == EXIT_RUNTIME_ERROR
    assert worker.calls == 1
    assert secret not in caplog.text


def test_real_received_notification_is_processed_through_runtime(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    config = _runtime_config(tmp_path, database_path=database_path)

    assert run_worker(
        build_worker(config, worker_id="payment-worker-deadbeef"),
        poll_seconds=1,
        stop_event=Event(),
        once=True,
        now_fn=lambda: NOW,
    ) == EXIT_OK

    with connect(database_path) as connection:
        assert connection.execute(
            "SELECT process_status FROM payment_notifications"
        ).fetchone()[0] == "PROCESSED"
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_real_expired_processing_notification_is_recovered_through_runtime(tmp_path):
    database_path = _database(tmp_path)
    order_id = _insert_order(database_path)
    _insert_notification(database_path, order_id=order_id)
    claimed = claim_next_payment_notification(
        database_path,
        worker_id="payment-worker-old00000",
        now=NOW - timedelta(minutes=2),
        lease_expires_at=NOW - timedelta(minutes=1),
        max_attempts=8,
    )
    assert claimed is not None
    config = _runtime_config(tmp_path, database_path=database_path)

    assert run_worker(
        build_worker(config, worker_id="payment-worker-new00000"),
        poll_seconds=1,
        stop_event=Event(),
        once=True,
        now_fn=lambda: NOW,
    ) == EXIT_OK

    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT process_status, attempt_count FROM payment_notifications"
        ).fetchone()
        assert tuple(row) == ("PROCESSED", 2)
        assert connection.execute("SELECT COUNT(*) FROM license_grants").fetchone()[0] == 1


def test_module_subprocess_disabled_and_invalid_configuration_are_safe(tmp_path):
    secret = "do-not-log-this-private-key"
    disabled = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    disabled["LICENSE_PRIVATE_KEY"] = secret
    disabled["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "false"
    disabled_result = _run_module(REPO_ROOT, disabled)

    assert disabled_result.returncode == EXIT_CONFIG_ERROR
    assert secret not in disabled_result.stdout + disabled_result.stderr

    valid_disabled = _production_env(tmp_path, PAYMENT_PROVIDER="disabled")
    valid_disabled["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "false"
    valid_result = _run_module(REPO_ROOT, valid_disabled)
    assert valid_result.returncode == EXIT_OK
    assert str(valid_disabled["DATABASE_URL"]) not in valid_result.stdout + valid_result.stderr

    invalid = dict(valid_disabled)
    invalid["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    invalid_result = _run_module(REPO_ROOT, invalid)
    assert invalid_result.returncode == EXIT_CONFIG_ERROR


def test_module_subprocess_once_uses_real_configuration_without_fastapi(tmp_path):
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"

    result = _run_module(REPO_ROOT, env, "--once")

    assert result.returncode == EXIT_OK
    output = result.stdout + result.stderr
    assert env["WECHAT_PAY_API_V3_KEY"] not in output
    assert env["DATABASE_URL"] not in output
    assert "uvicorn" not in output.lower()


def test_module_subprocess_rejects_relative_worker_database_from_project_root(tmp_path):
    outside_cwd = tmp_path / "outside"
    outside_cwd.mkdir()
    relative_path = f"relative-worker-{tmp_path.name}.sqlite3"
    env = _wechat_env(tmp_path)
    env.update(
        LICENSE_SERVER_ENV="test",
        DATABASE_URL=f"sqlite:///{relative_path}",
        PAYMENT_NOTIFICATION_WORKER_ENABLED="true",
    )

    result = _run_module(REPO_ROOT, env, "--once")

    assert result.returncode == EXIT_CONFIG_ERROR
    assert not (REPO_ROOT / relative_path).exists()
    assert not (outside_cwd / relative_path).exists()
    output = result.stdout + result.stderr
    assert relative_path not in output
    assert env["WECHAT_PAY_API_V3_KEY"] not in output


def test_module_subprocess_accepts_absolute_worker_database_from_project_root(tmp_path):
    env = _wechat_env(tmp_path)
    env.update(
        LICENSE_SERVER_ENV="test",
        PAYMENT_NOTIFICATION_WORKER_ENABLED="true",
    )
    database_path = Path(env["DATABASE_URL"].removeprefix("sqlite:///"))

    result = _run_module(REPO_ROOT, env, "--once")

    assert result.returncode == EXIT_OK
    assert database_path.exists()
    assert env["DATABASE_URL"] not in result.stdout + result.stderr


def test_module_subprocess_outside_repo_without_pythonpath_cannot_import(tmp_path):
    outside_cwd = tmp_path / "outside"
    outside_cwd.mkdir()
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    database_path = Path(env["DATABASE_URL"].removeprefix("sqlite:///"))

    result = _run_module(outside_cwd, env, "--once")

    assert result.returncode != EXIT_OK
    assert not database_path.exists()
    output = result.stdout + result.stderr
    assert env["WECHAT_PAY_API_V3_KEY"] not in output
    assert env["DATABASE_URL"] not in output


@pytest.mark.skipif(os.name == "nt", reason="POSIX process signals are required")
@pytest.mark.parametrize("signum", (signal.SIGTERM, signal.SIGINT))
def test_module_subprocess_signal_interrupts_idle_wait(tmp_path, signum):
    env = _wechat_env(tmp_path)
    env["PAYMENT_NOTIFICATION_WORKER_ENABLED"] = "true"
    env["PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS"] = "300"
    process = _start_module(REPO_ROOT, env)
    try:
        ready, _, _ = select.select([process.stderr], [], [], 10)
        assert ready
        assert "payment_notification_worker_started" in process.stderr.readline()

        process.send_signal(signum)
        stdout, stderr = process.communicate(timeout=5)

        assert process.returncode == EXIT_OK
        assert env["WECHAT_PAY_API_V3_KEY"] not in stdout + stderr
        assert env["DATABASE_URL"] not in stdout + stderr
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def test_worker_systemd_unit_is_standalone_nonroot_and_secret_free():
    unit = Path(
        "deploy/systemd/whut-license-payment-worker.service.example"
    ).read_text(encoding="utf-8")

    assert "User=whutlogin" in unit
    assert "Group=whutlogin" in unit
    assert "WorkingDirectory=/opt/whut-campus-auto-login" in unit
    assert "EnvironmentFile=/etc/whut-campus-auto-login/license-server.env" in unit
    assert (
        "ExecStart=/opt/whut-campus-auto-login/.venv/bin/python -m "
        "license_server.payment_notification_worker_main"
    ) in unit
    assert "Restart=on-failure" in unit
    assert "RestartPreventExitStatus=2" in unit
    assert "KillSignal=SIGTERM" in unit
    assert "TimeoutStopSec=30" in unit
    assert "WantedBy=multi-user.target" in unit
    assert "uvicorn" not in unit
    assert "User=root" not in unit
    assert "bash -c" not in unit
    assert "&" not in unit
    assert "WECHAT_PAY_API_V3_KEY=" not in unit
    assert "ListenStream=" not in unit


def test_environment_example_uses_safe_disabled_worker_defaults():
    example = Path("license_server/.env.example").read_text(encoding="utf-8")

    assert "PAYMENT_NOTIFICATION_WORKER_ENABLED=false" in example
    assert "PAYMENT_NOTIFICATION_WORKER_POLL_SECONDS=1" in example
    assert "PAYMENT_NOTIFICATION_MAX_ATTEMPTS=8" in example


def test_worker_deployment_document_covers_safe_operations_and_rollback():
    document = Path("docs/deploy/PAYMENT_NOTIFICATION_WORKER.md").read_text(
        encoding="utf-8"
    )

    for required in (
        "Schema V4",
        "PAYMENT_NOTIFICATION_WORKER_ENABLED=false",
        "--once",
        "systemctl daemon-reload",
        "systemctl enable --now whut-license-payment-worker.service",
        "systemctl stop whut-license-payment-worker.service",
        "journalctl -u whut-license-payment-worker.service",
        "完整数据库备份",
        "Web 服务",
        "SQLite",
        "RETRY",
        "ABNORMAL",
        "PROCESSING",
        "回滚",
    ):
        assert required in document
    for unsafe in ("直接修改数据库", "删除 notification", "关闭唯一约束"):
        assert unsafe not in document
    assert document.count("cd /opt/whut-campus-auto-login") == 2
    assert "PYTHONPATH" not in document


def _runtime_config(tmp_path, *, enabled=True, database_path=None):
    return SimpleNamespace(
        database_path=database_path or tmp_path / "license.sqlite3",
        payment_provider="wechat_native",
        wechat_pay=SimpleNamespace(app_id=APP_ID, mch_id=MCH_ID),
        payment_notification_worker_enabled=enabled,
        payment_notification_worker_poll_seconds=1.0,
        payment_notification_max_attempts=17,
        payment_notification_lease_seconds=60,
        payment_notification_retry_base_seconds=5,
        payment_notification_retry_max_seconds=300,
        environment="test",
    )


def _run_module(tmp_path, values, *arguments):
    return subprocess.run(
        _module_command(*arguments),
        cwd=tmp_path,
        env=_module_env(values),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _start_module(tmp_path, values, *arguments):
    return subprocess.Popen(
        _module_command(*arguments),
        cwd=tmp_path,
        env=_module_env(values),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _module_command(*arguments):
    return [
        sys.executable,
        "-m",
        "license_server.payment_notification_worker_main",
        *arguments,
    ]


def _module_env(values):
    env = os.environ.copy()
    env.update(values)
    env.pop("PYTHONPATH", None)
    return env
