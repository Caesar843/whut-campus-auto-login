import json
from datetime import datetime, timedelta
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from desktop_app.runtime_logs import (
    DIAGNOSTIC_LOG_LIMIT,
    MAX_LOG_ENTRIES,
    RuntimeLogStore,
    UI_LOG_DISPLAY_LIMIT,
    default_log_dir,
    mask_account,
    safe_exception_message,
    sanitize_text,
)


FAKE_ACCOUNT = "2024" + "00001234"
SHORT_ACCOUNT = "360" + "869"
FAKE_PASSWORD = "secret-" + "password"
RAW_TOKEN = "raw-" + "token"
RAW_SIGNED_TOKEN = "raw-signed-" + "token"
RAW_COOKIE = "raw-" + "cookie"
RAW_SESSION = "raw-" + "session"
RAW_AUTH_CODE = "raw-auth-" + "code"
RAW_BEARER = "raw-" + "bearer"


def _clock(start: datetime):
    current = {"value": start}

    def now():
        value = current["value"]
        current["value"] = value + timedelta(seconds=1)
        return value

    return now


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_default_log_dir_uses_appdata_whut_campus_auto_login_logs(monkeypatch, tmp_path):
    appdata = tmp_path / "Roaming"
    monkeypatch.setenv("APPDATA", str(appdata))
    local_appdata_key = "LOCAL" + "APPDATA"
    old_app_name = "WHUT" + "CampusLogin"
    monkeypatch.setenv(local_appdata_key, str(tmp_path / "Local"))

    path = default_log_dir()

    assert path == appdata / "WHUTCampusAutoLogin" / "logs"
    assert old_app_name not in str(path)
    assert local_appdata_key not in str(path)


def test_mask_account_keeps_two_prefix_and_suffix_digits():
    assert mask_account("360869") == "36****69"
    assert mask_account(FAKE_ACCOUNT) == "20****34"
    assert mask_account("123") == "****"
    assert mask_account("") == ""
    assert mask_account(None) == ""


def test_write_creates_jsonl_file_with_sanitized_allowlist_fields(tmp_path):
    store = RuntimeLogStore(
        log_dir=tmp_path / "logs",
        now_func=_clock(datetime(2026, 6, 5, 18, 21, 3)),
    )

    assert store.write(
        event="manual_login_failed",
        action="test_login",
        status="failed",
        safe_message=f"password={FAKE_PASSWORD} token={RAW_TOKEN} signed_token={RAW_SIGNED_TOKEN} account={FAKE_ACCOUNT}",
        failed_stage="account_login",
        failure_reason="invalid_credentials",
        retry_count=2,
        response_msg=f"cookie={RAW_COOKIE} session={RAW_SESSION} authCode={RAW_AUTH_CODE}",
        password=FAKE_PASSWORD,
        token=RAW_TOKEN,
        signed_license_token=RAW_SIGNED_TOKEN,
        cookie=RAW_COOKIE,
        session=RAW_SESSION,
    )

    log_file = tmp_path / "logs" / "2026-06-05.jsonl"
    rows = _read_jsonl(log_file)
    assert len(rows) == 1
    assert rows[0]["timestamp"] == "2026-06-05T18:21:03"
    assert rows[0]["event"] == "manual_login_failed"
    assert rows[0]["action"] == "test_login"
    assert rows[0]["status"] == "failed"
    assert rows[0]["failed_stage"] == "account_login"
    assert rows[0]["failure_reason"] == "invalid_credentials"
    assert rows[0]["retry_count"] == 2
    assert "response_msg" in rows[0]
    assert set(rows[0]) <= {
        "timestamp",
        "event",
        "action",
        "status",
        "failed_stage",
        "failure_reason",
        "retry_count",
        "safe_message",
        "http_status",
        "response_code",
        "response_msg",
    }
    serialized = json.dumps(rows[0], ensure_ascii=False)
    for forbidden in (
        FAKE_PASSWORD,
        RAW_TOKEN,
        RAW_SIGNED_TOKEN,
        RAW_COOKIE,
        RAW_SESSION,
        RAW_AUTH_CODE,
        FAKE_ACCOUNT,
    ):
        assert forbidden not in serialized


def test_sanitizer_filters_sensitive_keys_values_and_full_accounts():
    text = (
        f"password={FAKE_PASSWORD}; token=abc.def; signed_license_token=signed-value; "
        "LICENSE_PRIVATE_KEY=private-value; admin_access_token=admin-value; "
        f"cookie=session-cookie; session={RAW_SESSION}; authCode=raw-auth; "
        f"authorization=Bearer {RAW_BEARER}; user={FAKE_ACCOUNT}"
    )

    sanitized = sanitize_text(text)

    for forbidden in (
        FAKE_PASSWORD,
        "abc.def",
        "signed-value",
        "private-value",
        "admin-value",
        "session-cookie",
        RAW_SESSION,
        "raw-auth",
        RAW_BEARER,
        FAKE_ACCOUNT,
    ):
        assert forbidden not in sanitized
    assert "20****34" in sanitized


def test_exception_message_is_sanitized_before_truncation():
    exc = RuntimeError(
        f"password={FAKE_PASSWORD} token={RAW_TOKEN} signed_token={RAW_SIGNED_TOKEN} "
        f"cookie={RAW_COOKIE} session={RAW_SESSION} account={FAKE_ACCOUNT} " + "x" * 500
    )

    message = safe_exception_message(exc, max_length=120)

    assert len(message) == 120
    for forbidden in (
        FAKE_PASSWORD,
        RAW_TOKEN,
        RAW_SIGNED_TOKEN,
        RAW_COOKIE,
        RAW_SESSION,
        FAKE_ACCOUNT,
    ):
        assert forbidden not in message


def test_response_msg_is_sanitized_before_truncation(tmp_path):
    store = RuntimeLogStore(
        log_dir=tmp_path / "logs",
        now_func=_clock(datetime(2026, 6, 5, 18, 21, 3)),
        max_text_length=80,
    )

    store.write(
        event="campus_login_failed_stage",
        action="startup_auto_login",
        status="failed",
        response_msg=f"password={FAKE_PASSWORD} " + "x" * 200,
    )

    row = _read_jsonl(tmp_path / "logs" / "2026-06-05.jsonl")[0]
    assert len(row["response_msg"]) == 80
    assert FAKE_PASSWORD not in row["response_msg"]


def test_read_recent_returns_latest_80_entries(tmp_path):
    store = RuntimeLogStore(
        log_dir=tmp_path / "logs",
        now_func=_clock(datetime(2026, 6, 5, 18, 0, 0)),
    )
    for index in range(UI_LOG_DISPLAY_LIMIT + 5):
        store.write(
            event="app_start",
            action="tray_start",
            status="ok",
            safe_message=f"record {index}",
        )

    rows = store.read_recent()

    assert len(rows) == UI_LOG_DISPLAY_LIMIT
    assert rows[0]["safe_message"] == "record 5"
    assert rows[-1]["safe_message"] == "record 84"


def test_build_diagnostic_text_uses_latest_30_safe_entries(tmp_path):
    store = RuntimeLogStore(
        log_dir=tmp_path / "logs",
        now_func=_clock(datetime(2026, 6, 5, 18, 0, 0)),
    )
    for index in range(DIAGNOSTIC_LOG_LIMIT + 2):
        store.write(
            event="manual_login_failed",
            action="test_login",
            status="failed",
            safe_message=f"failed {index} password={FAKE_PASSWORD} account={SHORT_ACCOUNT}",
        )

    text = store.build_diagnostic_text()

    assert "武汉理工校园网助手诊断信息" in text
    assert "运行日志仅保存在本机" in text
    assert "最近 30 条" in text
    assert "message=failed 0 " not in text
    assert "message=failed 1 " not in text
    assert "message=failed 2 " in text
    assert FAKE_PASSWORD not in text
    assert SHORT_ACCOUNT not in text


def test_cleanup_keeps_latest_200_entries_and_removes_old_files(tmp_path):
    log_dir = tmp_path / "logs"
    store = RuntimeLogStore(
        log_dir=log_dir,
        now_func=_clock(datetime(2026, 6, 5, 18, 0, 0)),
    )
    old_file = log_dir / "2026-05-20.jsonl"
    old_file.parent.mkdir(parents=True)
    old_file.write_text(
        json.dumps(
            {
                "timestamp": "2026-05-20T12:00:00",
                "event": "app_start",
                "action": "tray_start",
                "status": "ok",
                "safe_message": "old",
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    for index in range(MAX_LOG_ENTRIES + 3):
        store.write(
            event="app_start",
            action="tray_start",
            status="ok",
            safe_message=f"record {index}",
        )

    assert store.cleanup(now=datetime(2026, 6, 5, 18, 30, 0))
    rows = store.read_recent(limit=MAX_LOG_ENTRIES + 10)

    assert old_file.exists() is False
    assert len(rows) == MAX_LOG_ENTRIES
    assert rows[0]["safe_message"] == "record 3"
    assert rows[-1]["safe_message"] == "record 202"


def test_clear_removes_only_jsonl_log_files(tmp_path):
    log_dir = tmp_path / "logs"
    store = RuntimeLogStore(
        log_dir=log_dir,
        now_func=_clock(datetime(2026, 6, 5, 18, 0, 0)),
    )
    store.write(event="app_start", action="tray_start", status="ok")
    keep_file = log_dir / "keep.txt"
    keep_file.write_text("keep", encoding="utf-8")

    assert store.clear()

    assert list(log_dir.glob("*.jsonl")) == []
    assert keep_file.read_text(encoding="utf-8") == "keep"
