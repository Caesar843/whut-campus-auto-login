from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import unicodedata
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict

from license_server.admin_audit import AdminAuditEntry, AuditResult, insert_admin_audit
from license_server.db import connect, write_transaction
from license_server.signer import datetime_text


SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
}
LICENSE_STATUSES = {"active", "revoked"}
AUDIT_RESULTS = {item.value for item in AuditResult}
SENSITIVE_TEXT_PATTERNS = (
    "token",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "privatekey",
    "apikey",
    "apiv3key",
    "codeurl",
    "wechatpaysignature",
    "weixinwxpay",
    "密码",
    "私钥",
    "二维码",
    "rawpayload",
    "bodyraw",
    "bodydecrypted",
    "callbackbody",
    "回调正文",
)
DEVICE_DETAIL_FIELDS = (
    "device_id_hash",
    "product_id",
    "first_seen_at",
    "last_seen_at",
)
DEVICE_LICENSE_FIELDS = (
    "license_id",
    "license_type",
    "status",
    "starts_at",
    "expires_at",
    "source",
    "created_at",
    "revoked_at",
)


class AdminNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str


def create_admin_router(
    *,
    database_path: Path,
    operator_name: str,
    access_token_sha256: str,
) -> APIRouter:
    expected_digest = access_token_sha256.lower()

    def require_admin(
        response: Response,
        authorization: str = Header(default=""),
    ) -> str:
        _secure(response)
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise _admin_error(401, "ADMIN_AUTH_REQUIRED")
        raw_token = authorization[len(prefix):].strip()
        if not raw_token:
            raise _admin_error(401, "ADMIN_AUTH_REQUIRED")
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, expected_digest):
            raise _admin_error(401, "ADMIN_AUTH_INVALID")
        return operator_name

    router = APIRouter(prefix="/internal/admin", include_in_schema=False)
    admin_dependency = [Depends(require_admin)]

    @router.get("/", response_class=HTMLResponse)
    def admin_page():
        return HTMLResponse(_ADMIN_HTML, headers=SECURITY_HEADERS)

    @router.get("/assets/admin.js")
    def admin_script():
        return Response(_ADMIN_JS, media_type="application/javascript", headers=SECURITY_HEADERS)

    @router.get("/api/summary", dependencies=admin_dependency)
    def summary():
        try:
            with _connection(database_path) as connection:
                now_text = datetime_text(datetime.now(timezone.utc))
                return {
                    "devices_total": _count(connection, "devices"),
                    "devices_active_24h": _count_devices_seen_since(
                        connection,
                        now_text,
                        hours=24,
                    ),
                    "devices_active_7d": _count_devices_seen_since(
                        connection,
                        now_text,
                        hours=24 * 7,
                    ),
                    "devices_active_30d": _count_devices_seen_since(
                        connection,
                        now_text,
                        hours=24 * 30,
                    ),
                    "licenses_by_type": _count_by(connection, "licenses", "license_type"),
                    "licenses_by_status": _count_by(connection, "licenses", "status"),
                    "licenses_active_unexpired": int(
                        connection.execute(
                            """
                            SELECT COUNT(*)
                            FROM licenses
                            WHERE status = 'active'
                              AND datetime(expires_at) > datetime(?)
                            """,
                            (now_text,),
                        ).fetchone()[0]
                    ),
                }
        except sqlite3.Error as exc:
            raise _admin_error(500, "ADMIN_INTERNAL_ERROR") from exc

    @router.get("/api/devices", dependencies=admin_dependency)
    def devices(
        device_id_hash: str | None = None,
        product_id: str | None = None,
        seen_from: str | None = None,
        seen_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        limit, offset = _page(limit, offset)
        clauses: list[str] = []
        params: list[object] = []
        _eq(clauses, params, "devices.device_fingerprint_hash", device_id_hash)
        _eq(clauses, params, "devices.product_id", product_id)
        _range(clauses, params, "devices.last_seen_at", seen_from, seen_to)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT
                devices.id,
                devices.device_fingerprint_hash,
                devices.product_id,
                devices.first_seen_at,
                devices.last_seen_at,
                licenses.id AS license_id,
                licenses.license_type,
                licenses.status AS license_status,
                licenses.expires_at AS license_expires_at
            FROM devices
            LEFT JOIN licenses ON licenses.id = (
                SELECT latest.id
                FROM licenses AS latest
                WHERE latest.device_id = devices.id
                ORDER BY (latest.status = 'active') DESC,
                         latest.expires_at DESC,
                         latest.id DESC
                LIMIT 1
            )
            {where}
            ORDER BY devices.last_seen_at DESC, devices.id DESC
            LIMIT ? OFFSET ?
        """
        rows = _select(database_path, sql, (*params, limit, offset))
        return {"items": [_device(row) for row in rows], "limit": limit, "offset": offset}

    @router.get("/api/devices/{device_fingerprint_hash}", dependencies=admin_dependency)
    def device_detail(device_fingerprint_hash: str):
        device = _one(
            database_path,
            """
            SELECT id, device_fingerprint_hash, product_id, first_seen_at, last_seen_at
            FROM devices
            WHERE device_fingerprint_hash = ?
            """,
            (device_fingerprint_hash,),
        )
        if device is None:
            raise _admin_error(404, "ADMIN_RESOURCE_NOT_FOUND")
        license_rows = _select(
            database_path,
            """
            SELECT id, license_type, status, starts_at, expires_at, source,
                   created_at, revoked_at
            FROM licenses
            WHERE device_id = ?
            ORDER BY expires_at DESC, id DESC
            """,
            (device["id"],),
        )
        return {
            "device_id_hash": str(device["device_fingerprint_hash"]),
            "product_id": str(device["product_id"]),
            "first_seen_at": str(device["first_seen_at"]),
            "last_seen_at": str(device["last_seen_at"]),
            "licenses": [_license(row) for row in license_rows],
        }

    @router.get("/api/audit-logs", dependencies=admin_dependency)
    def audit_logs(
        target_type: str | None = None,
        target_id: str | None = None,
        action: str | None = None,
        result: str | None = None,
        request_id: str | None = None,
        created_from: str | None = None,
        created_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        limit, offset = _page(limit, offset)
        result = _enum(result, AUDIT_RESULTS)
        clauses: list[str] = []
        params: list[object] = []
        _eq(clauses, params, "target_type", target_type)
        _eq(clauses, params, "target_id", target_id)
        _eq(clauses, params, "action", action)
        _eq(clauses, params, "result", result)
        _eq(clauses, params, "request_id", request_id)
        _range(clauses, params, "created_at", created_from, created_to)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = _select(
            database_path,
            f"""
            SELECT id, actor, source_ip, request_id, action, target_type,
                   target_id, result, before_state_json, after_state_json,
                   reason, failure_code, created_at
            FROM admin_audit_logs
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        )
        return {"items": [_audit(row) for row in rows], "limit": limit, "offset": offset}

    @router.get("/api/audit-logs/{audit_id}", dependencies=admin_dependency)
    def audit_log_detail(audit_id: str):
        row = _one(
            database_path,
            """
            SELECT id, actor, source_ip, request_id, action, target_type,
                   target_id, result, before_state_json, after_state_json,
                   reason, failure_code, created_at
            FROM admin_audit_logs
            WHERE id = ?
            """,
            (audit_id,),
        )
        if row is None:
            raise _admin_error(404, "ADMIN_RESOURCE_NOT_FOUND")
        return _audit(row)

    @router.post("/api/devices/{device_fingerprint_hash}/notes", status_code=201)
    def add_device_note(
        device_fingerprint_hash: str,
        body: AdminNoteRequest,
        request: Request,
        operator: str = Depends(require_admin),
    ):
        if not operator.strip():
            raise _admin_error(503, "ADMIN_OPERATOR_REQUIRED")
        note = _note(body.note)
        source_ip = request.client.host if request.client else ""
        if not source_ip:
            raise _admin_error(500, "ADMIN_INTERNAL_ERROR")
        try:
            with write_transaction(database_path) as connection:
                device = connection.execute(
                    """
                    SELECT device_fingerprint_hash
                    FROM devices
                    WHERE device_fingerprint_hash = ?
                    """,
                    (device_fingerprint_hash,),
                ).fetchone()
                if device is None:
                    raise _admin_error(404, "ADMIN_RESOURCE_NOT_FOUND")
                audit_id = insert_admin_audit(
                    connection,
                    AdminAuditEntry(
                        actor=operator,
                        source_ip=source_ip,
                        request_id=str(uuid4()),
                        action="DEVICE_NOTE_ADDED",
                        target_type="DEVICE",
                        target_id=str(device["device_fingerprint_hash"]),
                        result=AuditResult.SUCCESS,
                        before_state=None,
                        after_state=None,
                        reason=note,
                        failure_code=None,
                        created_at=datetime.now(timezone.utc),
                    ),
                )
                row = connection.execute(
                    """
                    SELECT id, actor, source_ip, request_id, action, target_type,
                           target_id, result, before_state_json, after_state_json,
                           reason, failure_code, created_at
                    FROM admin_audit_logs
                    WHERE id = ?
                    """,
                    (audit_id,),
                ).fetchone()
        except HTTPException:
            raise
        except (sqlite3.Error, RuntimeError, ValueError) as exc:
            raise _admin_error(500, "ADMIN_INTERNAL_ERROR") from exc
        return _audit(row)

    @router.get("/api/licenses", dependencies=admin_dependency)
    def licenses(
        device_id_hash: str | None = None,
        status: str | None = None,
        expires_from: str | None = None,
        expires_to: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        limit, offset = _page(limit, offset)
        status = _enum(status, LICENSE_STATUSES)
        clauses: list[str] = []
        params: list[object] = []
        _eq(clauses, params, "devices.device_fingerprint_hash", device_id_hash)
        _eq(clauses, params, "licenses.status", status)
        _range(clauses, params, "licenses.expires_at", expires_from, expires_to)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"""
            SELECT
                licenses.id,
                devices.device_fingerprint_hash,
                licenses.license_type,
                licenses.status,
                licenses.starts_at,
                licenses.expires_at,
                licenses.source,
                licenses.created_at,
                licenses.revoked_at
            FROM licenses
            JOIN devices ON devices.id = licenses.device_id
            {where}
            ORDER BY licenses.expires_at DESC
            LIMIT ? OFFSET ?
        """
        rows = _select(database_path, sql, (*params, limit, offset))
        return {"items": [_license(row) for row in rows], "limit": limit, "offset": offset}

    @router.post("/api/licenses/{license_id}/notes", status_code=201)
    def add_license_note(
        license_id: str,
        body: AdminNoteRequest,
        request: Request,
        operator: str = Depends(require_admin),
    ):
        if not operator.strip():
            raise _admin_error(503, "ADMIN_OPERATOR_REQUIRED")
        note = _note(body.note)
        source_ip = request.client.host if request.client else ""
        if not source_ip:
            raise _admin_error(500, "ADMIN_INTERNAL_ERROR")
        try:
            with write_transaction(database_path) as connection:
                license_row = connection.execute(
                    "SELECT id FROM licenses WHERE id = ?",
                    (license_id,),
                ).fetchone()
                if license_row is None:
                    raise _admin_error(404, "ADMIN_RESOURCE_NOT_FOUND")
                audit_id = insert_admin_audit(
                    connection,
                    AdminAuditEntry(
                        actor=operator,
                        source_ip=source_ip,
                        request_id=str(uuid4()),
                        action="LICENSE_NOTE_ADDED",
                        target_type="LICENSE",
                        target_id=str(license_row["id"]),
                        result=AuditResult.SUCCESS,
                        before_state=None,
                        after_state=None,
                        reason=note,
                        failure_code=None,
                        created_at=datetime.now(timezone.utc),
                    ),
                )
                row = connection.execute(
                    """
                    SELECT id, actor, source_ip, request_id, action, target_type,
                           target_id, result, before_state_json, after_state_json,
                           reason, failure_code, created_at
                    FROM admin_audit_logs
                    WHERE id = ?
                    """,
                    (audit_id,),
                ).fetchone()
        except HTTPException:
            raise
        except (sqlite3.Error, RuntimeError, ValueError) as exc:
            raise _admin_error(500, "ADMIN_INTERNAL_ERROR") from exc
        return _audit(row)

    return router


def _secure(response: Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value


def _admin_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail, headers=SECURITY_HEADERS)


def _page(limit: int, offset: int) -> tuple[int, int]:
    if limit < 1 or offset < 0:
        raise _admin_error(400, "ADMIN_QUERY_INVALID")
    return min(limit, 100), offset


def _enum(value: str | None, allowed: set[str]) -> str | None:
    if value is None:
        return None
    if value not in allowed:
        raise _admin_error(400, "ADMIN_QUERY_INVALID")
    return value


def _note(value: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 500
        or any(unicodedata.category(character) in {"Cc", "Zl", "Zp"} for character in normalized)
    ):
        raise _admin_error(400, "ADMIN_NOTE_INVALID")
    if _is_sensitive_text(normalized):
        raise _admin_error(400, "ADMIN_NOTE_SENSITIVE")
    return normalized


def _is_sensitive_text(value: str) -> bool:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    compact = "".join(
        character
        for character in normalized
        if unicodedata.category(character)[0] not in {"C", "P", "Z"}
    )
    return (
        any(pattern in compact for pattern in SENSITIVE_TEXT_PATTERNS)
        or "weixin://wxpay/" in normalized
        or (normalized.startswith("{") and normalized.endswith("}"))
    )


def _time(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _admin_error(400, "ADMIN_QUERY_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _admin_error(400, "ADMIN_QUERY_INVALID")
    return datetime_text(parsed)


def _eq(clauses: list[str], params: list[object], column: str, value: object | None) -> None:
    if value is not None:
        clauses.append(f"{column} = ?")
        params.append(value)


def _range(
    clauses: list[str],
    params: list[object],
    column: str,
    start: str | None,
    end: str | None,
) -> None:
    start_text = _time(start)
    end_text = _time(end)
    if start_text:
        clauses.append(f"{column} >= ?")
        params.append(start_text)
    if end_text:
        clauses.append(f"{column} <= ?")
        params.append(end_text)


def _one(database_path: Path, sql: str, params: tuple[object, ...]):
    rows = _select(database_path, sql, params)
    return rows[0] if rows else None


def _select(database_path: Path, sql: str, params: tuple[object, ...] = ()):
    try:
        with closing(connect(database_path)) as connection:
            return connection.execute(sql, params).fetchall()
    except sqlite3.Error as exc:
        raise _admin_error(500, "ADMIN_INTERNAL_ERROR") from exc


def _connection(database_path: Path):
    try:
        return closing(connect(database_path))
    except sqlite3.Error as exc:
        raise _admin_error(500, "ADMIN_INTERNAL_ERROR") from exc


def _count(connection, table: str) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _count_by(connection, table: str, column: str) -> dict[str, int]:
    return {
        str(row[column]): int(row["count"])
        for row in connection.execute(
            f"SELECT {column}, COUNT(*) AS count FROM {table} GROUP BY {column}"
        ).fetchall()
    }


def _count_devices_seen_since(connection, now_text: str, *, hours: int) -> int:
    return int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM devices
            WHERE datetime(last_seen_at) >= datetime(?, ?)
              AND datetime(last_seen_at) <= datetime(?)
            """,
            (now_text, f"-{hours} hours", now_text),
        ).fetchone()[0]
    )


def _device(row) -> dict[str, object]:
    return {
        "device_id_hash": str(row["device_fingerprint_hash"]),
        "product_id": str(row["product_id"]),
        "first_seen_at": str(row["first_seen_at"]),
        "last_seen_at": str(row["last_seen_at"]),
        "license_id": int(row["license_id"]) if row["license_id"] is not None else None,
        "license_type": row["license_type"],
        "license_status": row["license_status"],
        "license_expires_at": row["license_expires_at"],
    }


def _license(row) -> dict[str, object]:
    return {
        "license_id": int(row["id"]),
        "license_type": str(row["license_type"]),
        "status": str(row["status"]),
        "starts_at": str(row["starts_at"]),
        "expires_at": str(row["expires_at"]),
        "source": str(row["source"]),
        "created_at": str(row["created_at"]),
        "revoked_at": row["revoked_at"],
    }


def _audit(row) -> dict[str, object]:
    reason = str(row["reason"])
    return {
        "id": str(row["id"]),
        "actor": str(row["actor"]),
        "source_ip": str(row["source_ip"]),
        "request_id": str(row["request_id"]),
        "action": str(row["action"]),
        "target_type": str(row["target_type"]),
        "target_id": str(row["target_id"]),
        "result": str(row["result"]),
        "before_state": _json(row["before_state_json"]),
        "after_state": _json(row["after_state_json"]),
        "reason": "[REDACTED]" if _is_sensitive_text(reason) else reason,
        "failure_code": row["failure_code"],
        "created_at": str(row["created_at"]),
    }


def _json(value: str | None):
    return json.loads(value) if value is not None else None


_ADMIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>管理后台</title>
  <script src="/internal/admin/assets/admin.js" defer></script>
</head>
<body>
  <main>
    <h1>管理后台</h1>
    <p>只读后台。页面不含业务数据；管理员令牌仅保存在本次浏览器会话的 sessionStorage 中。</p>

    <section aria-labelledby="access-title">
      <h2 id="access-title">访问令牌</h2>
      <label for="admin-secret">管理员令牌</label>
      <input id="admin-secret" type="password" autocomplete="off">
      <button id="save-secret" type="button">保存本次会话</button>
      <button id="clear-secret" type="button">清除令牌</button>
      <p id="access-status" role="status">未加载数据。</p>
    </section>

    <section aria-labelledby="summary-title">
      <h2 id="summary-title">使用统计</h2>
      <button id="load-summary" type="button">加载统计</button>
      <div id="summary-output"></div>
    </section>

    <section aria-labelledby="devices-title">
      <h2 id="devices-title">设备</h2>
      <label for="devices-device-id">device_id_hash</label>
      <input id="devices-device-id" autocomplete="off">
      <label for="devices-product-id">product_id</label>
      <input id="devices-product-id" autocomplete="off">
      <label for="devices-limit">limit</label>
      <input id="devices-limit" type="number" min="1" max="100" value="50">
      <label for="devices-offset">offset</label>
      <input id="devices-offset" type="number" min="0" value="0">
      <button id="devices-load" type="button">加载设备</button>
      <button id="devices-prev" type="button">上一页</button>
      <button id="devices-next" type="button">下一页</button>
      <p id="devices-page">offset 0</p>
      <div id="devices-output"></div>
      <h3>设备详情</h3>
      <label for="device-detail-hash">device_id_hash</label>
      <input id="device-detail-hash" autocomplete="off">
      <button id="device-detail-load" type="button">加载详情</button>
      <div id="device-detail-output"></div>
      <h3>追加设备备注</h3>
      <label for="device-note-device-id">device_id_hash</label>
      <input id="device-note-device-id" autocomplete="off">
      <label for="device-note-text">备注</label>
      <textarea id="device-note-text" maxlength="500"></textarea>
      <button id="device-note-submit" type="button">追加备注</button>
      <p id="device-note-status" role="status"></p>
    </section>

    <section aria-labelledby="audit-title">
      <h2 id="audit-title">审计记录</h2>
      <label for="audit-target-type">target_type</label>
      <input id="audit-target-type" autocomplete="off">
      <label for="audit-target-id">target_id</label>
      <input id="audit-target-id" autocomplete="off">
      <label for="audit-action">action</label>
      <input id="audit-action" autocomplete="off">
      <label for="audit-result">result</label>
      <input id="audit-result" autocomplete="off">
      <label for="audit-request-id">request_id</label>
      <input id="audit-request-id" autocomplete="off">
      <label for="audit-created-from">created_from</label>
      <input id="audit-created-from" autocomplete="off">
      <label for="audit-created-to">created_to</label>
      <input id="audit-created-to" autocomplete="off">
      <label for="audit-limit">limit</label>
      <input id="audit-limit" type="number" min="1" max="100" value="50">
      <label for="audit-offset">offset</label>
      <input id="audit-offset" type="number" min="0" value="0">
      <button id="audit-load" type="button">加载审计记录</button>
      <button id="audit-prev" type="button">上一页</button>
      <button id="audit-next" type="button">下一页</button>
      <p id="audit-page">offset 0</p>
      <div id="audit-output"></div>
      <h3>审计详情</h3>
      <div id="audit-detail-output"></div>
    </section>

    <section aria-labelledby="licenses-title">
      <h2 id="licenses-title">当前授权</h2>
      <label for="licenses-device-id">device_id_hash</label>
      <input id="licenses-device-id" autocomplete="off">
      <label for="licenses-status">status</label>
      <input id="licenses-status" autocomplete="off">
      <label for="licenses-limit">limit</label>
      <input id="licenses-limit" type="number" min="1" max="100" value="50">
      <label for="licenses-offset">offset</label>
      <input id="licenses-offset" type="number" min="0" value="0">
      <button id="licenses-load" type="button">加载当前授权</button>
      <button id="licenses-prev" type="button">上一页</button>
      <button id="licenses-next" type="button">下一页</button>
      <p id="licenses-page">offset 0</p>
      <div id="licenses-output"></div>
      <h3>追加授权备注</h3>
      <label for="license-note-license-id">license_id</label>
      <input id="license-note-license-id" autocomplete="off">
      <label for="license-note-text">备注</label>
      <textarea id="license-note-text" maxlength="500"></textarea>
      <button id="license-note-submit" type="button">追加备注</button>
      <p id="license-note-status" role="status"></p>
    </section>
  </main>
</body>
</html>
"""


_ADMIN_JS = """
(() => {
  "use strict";

  const KEY = "whut-admin-secret";
  const API_BASE = "/internal/admin/api/";
  const state = {
    devices: { offset: 0, lastCount: null },
    audit: { offset: 0, lastCount: null },
    licenses: { offset: 0, lastCount: null },
    deviceNoteSubmitting: false,
    licenseNoteSubmitting: false,
  };
  const config = {
    devices: {
      path: "devices",
      output: "devices-output",
      page: "devices-page",
      fields: [
        "device_id_hash",
        "product_id",
        "first_seen_at",
        "last_seen_at",
        "license_id",
        "license_type",
        "license_status",
        "license_expires_at",
      ],
      filters: [
        ["devices-device-id", "device_id_hash"],
        ["devices-product-id", "product_id"],
      ],
    },
    audit: {
      path: "audit-logs",
      output: "audit-output",
      page: "audit-page",
      detailOutput: "audit-detail-output",
      detail: true,
      fields: [
        "id",
        "actor",
        "source_ip",
        "request_id",
        "action",
        "target_type",
        "target_id",
        "result",
        "reason",
        "failure_code",
        "created_at",
      ],
      filters: [
        ["audit-target-type", "target_type"],
        ["audit-target-id", "target_id"],
        ["audit-action", "action"],
        ["audit-result", "result"],
        ["audit-request-id", "request_id"],
        ["audit-created-from", "created_from"],
        ["audit-created-to", "created_to"],
      ],
    },
    licenses: {
      path: "licenses",
      output: "licenses-output",
      page: "licenses-page",
      fields: [
        "license_id",
        "device_id_hash",
        "license_type",
        "status",
        "starts_at",
        "expires_at",
        "source",
        "created_at",
        "revoked_at",
      ],
      filters: [
        ["licenses-device-id", "device_id_hash"],
        ["licenses-status", "status"],
      ],
    },
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function setStatus(message) {
    byId("access-status").textContent = message;
  }

  function saveSecret() {
    const value = byId("admin-secret").value;
    sessionStorage.setItem(KEY, value);
    byId("admin-secret").value = "";
    setStatus("管理员令牌已保存到本次会话。");
  }

  function clearSecret() {
    sessionStorage.removeItem(KEY);
    byId("admin-secret").value = "";
    setStatus("管理员令牌已清除。");
  }

  function getSecret() {
    return (sessionStorage.getItem(KEY) || "").trim();
  }

  async function adminFetch(path, options = {}) {
    if (!path.startsWith(API_BASE)) {
      throw new Error("blocked");
    }
    const secret = getSecret();
    if (!secret) {
      throw new Error("empty-secret");
    }
    const request = {
      method: options.method || "GET",
      cache: "no-store",
      credentials: "omit",
      headers: { Authorization: "Bearer " + secret },
    };
    if (options.body !== undefined) {
      request.headers["Content-Type"] = "application/json";
      request.body = options.body;
    }
    const response = await fetch(path, request);
    if (response.status === 401) {
      throw new Error("unauthorized");
    }
    if (response.status === 400 || response.status === 422) {
      throw new Error("invalid-request");
    }
    if (response.status === 404) {
      throw new Error("not-found");
    }
    if (!response.ok) {
      throw new Error("request-failed");
    }
    return response.json();
  }

  function handleError(error) {
    if (error.message === "unauthorized") {
      setStatus("管理员令牌无效或已失效。");
      return;
    }
    if (error.message === "empty-secret") {
      setStatus("请输入管理员令牌。");
      return;
    }
    if (error.message === "invalid-request") {
      setStatus("请求参数无效。");
      return;
    }
    if (error.message === "not-found") {
      setStatus("资源不存在。");
      return;
    }
    setStatus("请求失败，请检查筛选条件或稍后重试。");
  }

  function readNumber(id, fallback, minValue, maxValue) {
    const parsed = Number.parseInt(byId(id).value, 10);
    const value = Number.isFinite(parsed) ? parsed : fallback;
    return Math.min(Math.max(value, minValue), maxValue);
  }

  function addParam(params, inputId, name) {
    const value = byId(inputId).value.trim();
    if (value) {
      params.set(name, value);
    }
  }

  function buildListPath(kind, direction) {
    const item = config[kind];
    const limit = readNumber(kind + "-limit", 50, 1, 100);
    const typedOffset = readNumber(kind + "-offset", state[kind].offset, 0, 1000000);
    let offset = Math.max(0, typedOffset + direction * limit);
    if (direction > 0 && state[kind].lastCount === 0) {
      offset = state[kind].offset;
    }
    state[kind].offset = offset;
    byId(kind + "-offset").value = String(offset);
    const params = new URLSearchParams();
    params.set("limit", String(limit));
    params.set("offset", String(offset));
    for (const pair of item.filters) {
      addParam(params, pair[0], pair[1]);
    }
    return API_BASE + item.path + "?" + params.toString();
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function formatValue(value) {
    if (value === null || value === undefined) {
      return "";
    }
    if (typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  }

  function clearAuditDetail() {
    clearNode(byId("audit-detail-output"));
  }

  function resetListOffset(kind) {
    state[kind].offset = 0;
    state[kind].lastCount = null;
    byId(kind + "-offset").value = "0";
    byId(kind + "-page").textContent = "offset 0";
  }

  function renderSummary(data) {
    const output = byId("summary-output");
    clearNode(output);
    const list = document.createElement("dl");
    for (const name of Object.keys(data)) {
      const term = document.createElement("dt");
      const detail = document.createElement("dd");
      term.textContent = name;
      detail.textContent = JSON.stringify(data[name]);
      list.appendChild(term);
      list.appendChild(detail);
    }
    output.appendChild(list);
  }

  function renderRows(kind, rows) {
    const item = config[kind];
    const output = byId(item.output);
    clearNode(output);
    if (rows.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "无数据。";
      output.appendChild(empty);
      return;
    }
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    if (item.detail) {
      const detailHead = document.createElement("th");
      detailHead.textContent = "detail";
      headRow.appendChild(detailHead);
    }
    for (const field of item.fields) {
      const th = document.createElement("th");
      th.textContent = field;
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    for (const row of rows) {
      const tr = document.createElement("tr");
      if (item.detail) {
        const td = document.createElement("td");
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = "查看";
        button.addEventListener("click", () => loadAuditDetail(String(row.id || "")));
        td.appendChild(button);
        tr.appendChild(td);
      }
      for (const field of item.fields) {
        const td = document.createElement("td");
        td.textContent = formatValue(row[field]);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    output.appendChild(table);
  }

  function renderAuditDetail(data) {
    const output = byId("audit-detail-output");
    clearAuditDetail();
    const list = document.createElement("dl");
    for (const field of config.audit.fields.concat(["before_state", "after_state"])) {
      const term = document.createElement("dt");
      const detail = document.createElement("dd");
      term.textContent = field;
      detail.textContent = formatValue(data[field]);
      list.appendChild(term);
      list.appendChild(detail);
    }
    output.appendChild(list);
  }

  async function loadAuditDetail(auditId) {
    clearAuditDetail();
    if (!auditId) {
      setStatus("资源不存在。");
      return;
    }
    try {
      const data = await adminFetch(API_BASE + "audit-logs/" + encodeURIComponent(auditId));
      renderAuditDetail(data);
      setStatus("审计详情已加载。");
    } catch (error) {
      handleError(error);
    }
  }

  async function loadDeviceDetail() {
    const output = byId("device-detail-output");
    clearNode(output);
    const deviceHash = byId("device-detail-hash").value.trim();
    if (!deviceHash) {
      setStatus("请求参数无效。");
      return;
    }
    try {
      const data = await adminFetch(API_BASE + "devices/" + encodeURIComponent(deviceHash));
      const list = document.createElement("dl");
      for (const field of ["device_id_hash", "product_id", "first_seen_at", "last_seen_at"]) {
        const term = document.createElement("dt");
        const detail = document.createElement("dd");
        term.textContent = field;
        detail.textContent = formatValue(data[field]);
        list.appendChild(term);
        list.appendChild(detail);
      }
      output.appendChild(list);
      const rows = Array.isArray(data.licenses) ? data.licenses : [];
      if (rows.length === 0) {
        const empty = document.createElement("p");
        empty.textContent = "无授权记录。";
        output.appendChild(empty);
      } else {
        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const headRow = document.createElement("tr");
        for (const field of DEVICE_LICENSE_FIELDS) {
          const th = document.createElement("th");
          th.textContent = field;
          headRow.appendChild(th);
        }
        thead.appendChild(headRow);
        table.appendChild(thead);
        const tbody = document.createElement("tbody");
        for (const row of rows) {
          const tr = document.createElement("tr");
          for (const field of DEVICE_LICENSE_FIELDS) {
            const td = document.createElement("td");
            td.textContent = formatValue(row[field]);
            tr.appendChild(td);
          }
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        output.appendChild(table);
      }
      setStatus("设备详情已加载。");
    } catch (error) {
      handleError(error);
    }
  }

  async function submitDeviceNote() {
    if (state.deviceNoteSubmitting) {
      return;
    }
    const deviceHash = byId("device-note-device-id").value.trim();
    const note = byId("device-note-text").value.trim();
    if (!deviceHash || note.length < 1 || note.length > 500) {
      byId("device-note-status").textContent = "备注要求 1-500 字符。";
      setStatus("请求参数无效。");
      return;
    }
    state.deviceNoteSubmitting = true;
    byId("device-note-submit").disabled = true;
    try {
      const data = await adminFetch(API_BASE + "devices/" + encodeURIComponent(deviceHash) + "/notes", {
        method: "POST",
        body: JSON.stringify({ note: note }),
      });
      byId("device-note-text").value = "";
      renderAuditDetail(data);
      await loadList("audit", 0);
      byId("device-note-status").textContent = "备注已追加。";
      setStatus("备注已追加。");
    } catch (error) {
      byId("device-note-status").textContent = "备注提交失败。";
      handleError(error);
    } finally {
      state.deviceNoteSubmitting = false;
      byId("device-note-submit").disabled = false;
    }
  }

  async function submitLicenseNote() {
    if (state.licenseNoteSubmitting) {
      return;
    }
    const licenseId = byId("license-note-license-id").value.trim();
    const note = byId("license-note-text").value.trim();
    if (!licenseId || note.length < 1 || note.length > 500) {
      byId("license-note-status").textContent = "备注要求 1-500 字符。";
      setStatus("请求参数无效。");
      return;
    }
    state.licenseNoteSubmitting = true;
    byId("license-note-submit").disabled = true;
    try {
      const data = await adminFetch(API_BASE + "licenses/" + encodeURIComponent(licenseId) + "/notes", {
        method: "POST",
        body: JSON.stringify({ note: note }),
      });
      byId("license-note-text").value = "";
      renderAuditDetail(data);
      await loadList("audit", 0);
      byId("license-note-status").textContent = "备注已追加。";
      setStatus("备注已追加。");
    } catch (error) {
      byId("license-note-status").textContent = "备注提交失败。";
      handleError(error);
    } finally {
      state.licenseNoteSubmitting = false;
      byId("license-note-submit").disabled = false;
    }
  }

  async function loadSummary() {
    try {
      const data = await adminFetch(API_BASE + "summary");
      renderSummary(data);
      setStatus("统计已加载。");
    } catch (error) {
      handleError(error);
    }
  }

  async function loadList(kind, direction) {
    const previous = state[kind].offset;
    try {
      const data = await adminFetch(buildListPath(kind, direction));
      const rows = Array.isArray(data.items) ? data.items : [];
      if (rows.length === 0 && direction > 0) {
        state[kind].offset = previous;
        byId(kind + "-offset").value = String(previous);
      }
      state[kind].lastCount = rows.length;
      byId(config[kind].page).textContent = "offset " + state[kind].offset;
      renderRows(kind, rows);
      setStatus("数据已加载。");
    } catch (error) {
      state[kind].offset = previous;
      byId(kind + "-offset").value = String(previous);
      handleError(error);
    }
  }

  function bindList(kind) {
    byId(kind + "-load").addEventListener("click", () => loadList(kind, 0));
    byId(kind + "-prev").addEventListener("click", () => loadList(kind, -1));
    byId(kind + "-next").addEventListener("click", () => loadList(kind, 1));
  }

  function bindFilterReset(kind) {
    for (const pair of config[kind].filters.concat([[kind + "-limit", "limit"]])) {
      byId(pair[0]).addEventListener("change", () => resetListOffset(kind));
    }
  }

  function init() {
    byId("save-secret").addEventListener("click", saveSecret);
    byId("clear-secret").addEventListener("click", clearSecret);
    byId("load-summary").addEventListener("click", loadSummary);
    byId("device-detail-load").addEventListener("click", loadDeviceDetail);
    byId("device-note-submit").addEventListener("click", submitDeviceNote);
    byId("license-note-submit").addEventListener("click", submitLicenseNote);
    bindList("devices");
    bindList("audit");
    bindFilterReset("audit");
    bindList("licenses");
    if (getSecret()) {
      setStatus("管理员令牌已在本次会话中。");
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
"""
