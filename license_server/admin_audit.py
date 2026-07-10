from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from license_server.db import write_transaction
from license_server.signer import datetime_text


MAX_ACTOR_LENGTH = 128
MAX_SOURCE_IP_LENGTH = 128
MAX_REQUEST_ID_LENGTH = 128
MAX_ACTION_LENGTH = 64
MAX_TARGET_TYPE_LENGTH = 64
MAX_TARGET_ID_LENGTH = 256
MAX_REASON_LENGTH = 500
MAX_FAILURE_CODE_LENGTH = 64
MAX_AUDIT_SNAPSHOT_STRING_LENGTH = 1024
MAX_AUDIT_SNAPSHOT_JSON_BYTES = 8192
STRUCTURED_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]+\Z")
SAFE_SNAPSHOT_FIELDS = frozenset(
    {
        "order_id",
        "out_trade_no",
        "device_id_hash",
        "plan_code",
        "channel",
        "status",
        "amount_fen",
        "currency",
        "provider_transaction_id",
        "provider_trade_state",
        "notification_id",
        "process_status",
        "signature_valid",
        "merchant_identity_valid",
        "license_id",
        "license_status",
        "license_expire_at",
        "grant_id",
        "source_order_id",
        "grant_days",
        "previous_expire_at",
        "new_expire_at",
        "issued_by",
        "failure_code",
        "created_at",
        "updated_at",
        "paid_at",
        "closed_at",
    }
)
FORBIDDEN_SNAPSHOT_FIELDS = frozenset(
    {
        "provider_code_url",
        "raw_payload",
        "body_raw",
        "body_decrypted",
        "openid",
        "bank_type",
        "authorization",
        "Authorization",
        "bearer",
        "token",
        "signed_token",
        "admin_token",
        "admin_access_token_sha256",
        "password",
        "campus_account",
        "campus_password",
        "private_key",
        "api_v3_key",
        "wechatpay_signature",
    }
)


class AuditResult(str, Enum):
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


@dataclass(frozen=True)
class AdminAuditEntry:
    actor: str
    source_ip: str
    request_id: str
    action: str
    target_type: str
    target_id: str
    result: AuditResult
    before_state: Mapping[str, object] | None
    after_state: Mapping[str, object] | None
    reason: str
    failure_code: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "actor", _text(self.actor, "actor", MAX_ACTOR_LENGTH))
        object.__setattr__(
            self,
            "source_ip",
            _text(self.source_ip, "source_ip", MAX_SOURCE_IP_LENGTH),
        )
        object.__setattr__(
            self,
            "request_id",
            _structured(self.request_id, "request_id", MAX_REQUEST_ID_LENGTH),
        )
        object.__setattr__(self, "action", _structured(self.action, "action", MAX_ACTION_LENGTH))
        object.__setattr__(
            self,
            "target_type",
            _structured(self.target_type, "target_type", MAX_TARGET_TYPE_LENGTH),
        )
        object.__setattr__(self, "target_id", _text(self.target_id, "target_id", MAX_TARGET_ID_LENGTH))
        try:
            result = AuditResult(self.result)
        except ValueError as exc:
            raise ValueError("admin_audit_result_invalid") from exc
        object.__setattr__(self, "result", result)
        object.__setattr__(self, "before_state", _snapshot(self.before_state))
        object.__setattr__(self, "after_state", _snapshot(self.after_state))
        object.__setattr__(self, "reason", _text(self.reason, "reason", MAX_REASON_LENGTH))
        if self.failure_code is not None:
            object.__setattr__(
                self,
                "failure_code",
                _structured(self.failure_code, "failure_code", MAX_FAILURE_CODE_LENGTH),
            )
        _datetime(self.created_at)


def serialize_audit_snapshot(snapshot: Mapping[str, object] | None) -> str | None:
    normalized = _snapshot(snapshot)
    if normalized is None:
        return None
    serialized = json.dumps(dict(normalized), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(serialized.encode("utf-8")) > MAX_AUDIT_SNAPSHOT_JSON_BYTES:
        raise ValueError("admin_audit_snapshot_json_too_large")
    return serialized


def insert_admin_audit(connection: sqlite3.Connection, entry: AdminAuditEntry) -> str:
    cursor = connection.execute(
        """
        INSERT INTO admin_audit_logs (
            actor, source_ip, request_id, action, target_type, target_id, result,
            before_state_json, after_state_json, reason, failure_code, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.actor,
            entry.source_ip,
            entry.request_id,
            entry.action,
            entry.target_type,
            entry.target_id,
            entry.result.value,
            serialize_audit_snapshot(entry.before_state),
            serialize_audit_snapshot(entry.after_state),
            entry.reason,
            entry.failure_code,
            datetime_text(entry.created_at),
        ),
    )
    return str(cursor.lastrowid)


def record_admin_audit(database_path: Path | str, entry: AdminAuditEntry) -> str:
    with write_transaction(Path(database_path)) as connection:
        return insert_admin_audit(connection, entry)


def _text(value: object, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"admin_audit_{field}_invalid")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or _has_control_characters(normalized):
        raise ValueError(f"admin_audit_{field}_invalid")
    return normalized


def _structured(value: object, field: str, maximum: int) -> str:
    normalized = _text(value, field, maximum)
    if STRUCTURED_IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(f"admin_audit_{field}_invalid")
    return normalized


def _snapshot(snapshot: Mapping[str, object] | None) -> Mapping[str, object] | None:
    if snapshot is None:
        return None
    if not isinstance(snapshot, Mapping):
        raise ValueError("admin_audit_snapshot_invalid")
    normalized: dict[str, object] = {}
    for key, value in snapshot.items():
        if not isinstance(key, str):
            raise ValueError("admin_audit_snapshot_unknown_field")
        if key in FORBIDDEN_SNAPSHOT_FIELDS:
            raise ValueError("admin_audit_snapshot_forbidden_field")
        if key not in SAFE_SNAPSHOT_FIELDS:
            raise ValueError("admin_audit_snapshot_unknown_field")
        normalized[key] = _snapshot_value(value)
    return MappingProxyType(normalized)


def _snapshot_value(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if len(value) > MAX_AUDIT_SNAPSHOT_STRING_LENGTH:
            raise ValueError("admin_audit_snapshot_value_invalid")
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, datetime):
        return datetime_text(_datetime(value))
    raise ValueError("admin_audit_snapshot_value_invalid")


def _datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("admin_audit_created_at_invalid")
    return value


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)
