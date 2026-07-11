from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


LOG_RETENTION_DAYS = 7
MAX_LOG_ENTRIES = 200
UI_LOG_DISPLAY_LIMIT = 80
DIAGNOSTIC_LOG_LIMIT = 30
MAX_TEXT_LENGTH = 240
LOG_FILE_SUFFIX = ".jsonl"
APP_DIR_NAME = "WHUTCampusAutoLogin"

_ALLOWED_FIELDS = (
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
)

_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "token",
    "signed_token",
    "signed_license_token",
    "license_private_key",
    "cookie",
    "session",
    "authcode",
    "authorization",
    "payment_key",
    "pay_key",
    "private_key",
    "secret",
)

_SENSITIVE_PAIR_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|token|signed_token|signed_license_token|LICENSE_PRIVATE_KEY|"
    r"cookie|session|authCode|authorization|payment_key|pay_key|"
    r"private_key|secret"
    r")\b\s*[:=]\s*([^\s;&,]+)"
)
_AUTHORIZATION_RE = re.compile(r"(?i)\bauthorization\b\s*[:=]\s*Bearer\s+[^\s;&,]+")
_ACCOUNT_RE = re.compile(r"(?<!\d)(\d{6,18})(?!\d)")
_SENSITIVE_WORD_RE = re.compile(
    r"(?i)\b\S*(password|passwd|token|cookie|session|authcode|authorization)\S*\b"
)
_PRIVATE_KEY_WORD_RE = re.compile(r"(?i)private\s+key")


def default_log_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / APP_DIR_NAME / "logs"
    return Path.home() / "AppData" / "Roaming" / APP_DIR_NAME / "logs"


def mask_account(account: Optional[Any]) -> str:
    if account is None:
        return ""
    value = str(account).strip()
    if not value:
        return ""
    if len(value) < 4:
        return "****"
    return value[:2] + "****" + value[-2:]


def sanitize_text(
    value: Optional[Any],
    *,
    sensitive_values: Iterable[Any] = (),
    max_length: Optional[int] = None,
) -> str:
    if value is None:
        text = ""
    else:
        text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    for item in sensitive_values:
        item_text = str(item or "")
        if item_text:
            text = text.replace(item_text, "[REDACTED]")
    text = _AUTHORIZATION_RE.sub("authorization=[REDACTED]", text)
    text = _SENSITIVE_PAIR_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _PRIVATE_KEY_WORD_RE.sub("[REDACTED]", text)
    text = _SENSITIVE_WORD_RE.sub("[REDACTED]", text)
    text = _ACCOUNT_RE.sub(lambda match: mask_account(match.group(1)), text)
    if max_length is not None:
        return text[:max_length]
    return text


def safe_exception_message(exc: Exception, *, max_length: int = MAX_TEXT_LENGTH) -> str:
    sanitized = sanitize_text(str(exc) or exc.__class__.__name__, max_length=max_length)
    return sanitized or exc.__class__.__name__


class RuntimeLogStore:
    def __init__(
        self,
        *,
        log_dir: Optional[Path] = None,
        now_func: Optional[Callable[[], datetime]] = None,
        max_text_length: int = MAX_TEXT_LENGTH,
        enabled: bool = True,
    ):
        self.log_dir = Path(log_dir) if log_dir is not None else default_log_dir()
        self._now_func = now_func or datetime.now
        self._max_text_length = int(max_text_length)
        self.enabled = bool(enabled)

    def write(
        self,
        *,
        event: str,
        action: Optional[str] = None,
        status: Optional[str] = None,
        failed_stage: Optional[str] = None,
        failure_reason: Optional[str] = None,
        retry_count: Optional[int] = None,
        safe_message: Optional[Any] = None,
        http_status: Optional[int] = None,
        response_code: Optional[Any] = None,
        response_msg: Optional[Any] = None,
        **extra: Any,
    ) -> bool:
        if not self.enabled:
            return False
        now = self._now_func()
        sensitive_values = _sensitive_values(extra)
        row = {
            "timestamp": now.isoformat(timespec="seconds"),
            "event": _clean_identifier(event),
            "action": _optional_clean_identifier(action),
            "status": _optional_clean_identifier(status),
            "failed_stage": _optional_clean_identifier(failed_stage),
            "failure_reason": _optional_clean_identifier(failure_reason),
            "retry_count": _clean_retry_count(retry_count),
            "safe_message": sanitize_text(
                safe_message,
                sensitive_values=sensitive_values,
                max_length=self._max_text_length,
            ),
            "http_status": http_status,
            "response_code": response_code,
            "response_msg": sanitize_text(
                response_msg,
                sensitive_values=sensitive_values,
                max_length=self._max_text_length,
            )
            if response_msg is not None
            else None,
        }
        row = {field: row[field] for field in _ALLOWED_FIELDS if row.get(field) is not None}
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            path = self.log_dir / f"{now.date().isoformat()}{LOG_FILE_SUFFIX}"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            return True
        except OSError:
            return False

    def read_recent(self, limit: int = UI_LOG_DISPLAY_LIMIT) -> list[dict]:
        if limit <= 0:
            return []
        return self._read_all()[-limit:]

    def build_diagnostic_text(self, *, limit: int = DIAGNOSTIC_LOG_LIMIT) -> str:
        rows = self.read_recent(limit=limit)
        lines = [
            "武汉理工校园网助手诊断信息",
            "运行日志仅保存在本机，未上传服务器。",
            f"日志范围：最近 {min(limit, len(rows))} 条",
            "",
            "最近记录：",
        ]
        lines.extend(format_log_entry(row) for row in rows)
        return "\n".join(lines)

    def cleanup(self, *, now: Optional[datetime] = None) -> bool:
        cleanup_now = now or self._now_func()
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            cutoff = cleanup_now.date() - timedelta(days=LOG_RETENTION_DAYS)
            for path in self._iter_log_files():
                log_date = _date_from_log_file(path)
                if log_date is not None and log_date < cutoff:
                    path.unlink(missing_ok=True)
            self._trim_to_max_entries()
            return True
        except OSError:
            return False

    def clear(self) -> bool:
        try:
            if not self.log_dir.exists():
                return True
            for path in self._iter_log_files():
                path.unlink(missing_ok=True)
            return True
        except OSError:
            return False

    def _read_all(self) -> list[dict]:
        rows: list[dict] = []
        for path in self._iter_log_files():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict):
                    rows.append(_normalize_row(row))
        return rows

    def _iter_log_files(self) -> list[Path]:
        if not self.log_dir.exists():
            return []
        return sorted(self.log_dir.glob(f"*{LOG_FILE_SUFFIX}"))

    def _trim_to_max_entries(self) -> None:
        rows = self._read_all()
        if len(rows) <= MAX_LOG_ENTRIES:
            return
        kept = rows[-MAX_LOG_ENTRIES:]
        for path in self._iter_log_files():
            path.unlink(missing_ok=True)
        grouped: dict[str, list[dict]] = defaultdict(list)
        for row in kept:
            date_key = str(row.get("timestamp") or "")[:10] or self._now_func().date().isoformat()
            grouped[date_key].append(_normalize_row(row))
        for date_key, items in grouped.items():
            path = self.log_dir / f"{date_key}{LOG_FILE_SUFFIX}"
            with path.open("w", encoding="utf-8") as handle:
                for row in items:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def format_log_entry(row: dict) -> str:
    parts = [
        f"[{row.get('timestamp') or ''}]",
        f"event={row.get('event') or ''}",
    ]
    for field in ("action", "status", "failed_stage", "failure_reason", "retry_count"):
        if row.get(field) not in (None, ""):
            parts.append(f"{field}={row.get(field)}")
    if row.get("safe_message"):
        parts.append(f"message={row.get('safe_message')}")
    if row.get("response_code") is not None or row.get("response_msg"):
        summary = []
        if row.get("response_code") is not None:
            summary.append(f"code={row.get('response_code')}")
        if row.get("response_msg"):
            summary.append(f"msg={row.get('response_msg')}")
        parts.append("response=" + ", ".join(summary))
    return "；".join(parts)


def format_log_entry_block(row: dict) -> str:
    lines = [
        f"[{row.get('timestamp') or ''}]",
        f"事件：{row.get('event') or ''}",
    ]
    for label, field in (
        ("动作", "action"),
        ("状态", "status"),
        ("失败阶段", "failed_stage"),
        ("失败原因", "failure_reason"),
        ("重试次数", "retry_count"),
    ):
        if row.get(field) not in (None, ""):
            lines.append(f"{label}：{row.get(field)}")
    if row.get("safe_message"):
        lines.append(f"说明：{row.get('safe_message')}")
    if row.get("response_code") is not None or row.get("response_msg"):
        summary = []
        if row.get("response_code") is not None:
            summary.append(f"code={row.get('response_code')}")
        if row.get("response_msg"):
            summary.append(f"msg={row.get('response_msg')}")
        lines.append("响应摘要：" + ", ".join(summary))
    return "\n".join(lines)


def get_default_log_store() -> RuntimeLogStore:
    return RuntimeLogStore()


def write_runtime_log(**kwargs: Any) -> bool:
    return get_default_log_store().write(**kwargs)


def _normalize_row(row: dict) -> dict:
    return {field: row.get(field) for field in _ALLOWED_FIELDS if row.get(field) is not None}


def _clean_identifier(value: Any) -> str:
    return sanitize_text(value, max_length=80).strip().replace(" ", "_")


def _optional_clean_identifier(value: Any) -> Optional[str]:
    if value is None:
        return None
    return _clean_identifier(value)


def _clean_retry_count(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _sensitive_values(extra: dict[str, Any]) -> list[str]:
    values = []
    for key, value in extra.items():
        if value is None:
            continue
        if _is_sensitive_key(str(key)):
            text = str(value)
            if text:
                values.append(text)
    return values


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(item.replace("_", "") in normalized for item in _SENSITIVE_KEYS)


def _date_from_log_file(path: Path):
    try:
        return datetime.strptime(path.stem, "%Y-%m-%d").date()
    except ValueError:
        return None
