"""免费版后台 UI 测试。

页面与脚本适配免费版后台：订单、支付通知、授权发放区块已移除，只保留摘要、
设备列表/详情、授权列表、审计日志查询与设备、授权备注表单。脚本仍只以
同源 API_BASE 路径 + Bearer 令牌取数，使用 textContent 渲染，不使用任何
localStorage / cookie / innerHTML。

断言以 `license_server/admin_routes.py` 内置页面与脚本的真实内容为准。
"""

from tests.license_server.test_admin_readonly import (
    ADMIN_PAGE,
    ADMIN_PAGE_TITLE,
    ADMIN_SCRIPT,
    _admin_client,
    _assert_security_headers,
)


def _script(tmp_path, monkeypatch) -> str:
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    response = client.get(ADMIN_SCRIPT)
    assert response.status_code == 200
    return response.text


def _page(tmp_path, monkeypatch) -> str:
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    response = client.get(ADMIN_PAGE)
    assert response.status_code == 200
    return response.text


def _function_body(script: str, name: str) -> str:
    """按花括号配对截取单个函数体，避免被函数体内的 const/document 调用截断。"""
    start = script.index("function " + name)
    opening = script.index("{", start)
    depth = 0
    for index in range(opening, len(script)):
        character = script[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return script[start : index + 1]
    return script[start:]


PAGE_CONTROL_IDS = (
    "admin-secret",
    "save-secret",
    "clear-secret",
    "load-summary",
    "summary-output",
    "devices-device-id",
    "devices-product-id",
    "devices-limit",
    "devices-offset",
    "devices-load",
    "devices-prev",
    "devices-next",
    "devices-page",
    "devices-output",
    "device-detail-hash",
    "device-detail-load",
    "device-detail-output",
    "licenses-device-id",
    "licenses-status",
    "licenses-limit",
    "licenses-offset",
    "licenses-load",
    "licenses-prev",
    "licenses-next",
    "licenses-page",
    "licenses-output",
    "audit-target-type",
    "audit-target-id",
    "audit-action",
    "audit-result",
    "audit-request-id",
    "audit-created-from",
    "audit-created-to",
    "audit-limit",
    "audit-offset",
    "audit-load",
    "audit-prev",
    "audit-next",
    "audit-page",
    "audit-output",
    "audit-detail-output",
    "device-note-device-id",
    "device-note-text",
    "device-note-submit",
    "device-note-status",
    "license-note-license-id",
    "license-note-text",
    "license-note-submit",
    "license-note-status",
)
REMOVED_PAGE_ID_PREFIXES = (
    "orders-",
    "notifications-",
    "grants-",
    "order-note-",
    "payment-",
    "trial-",
)


def test_admin_page_exposes_free_version_controls_only(tmp_path, monkeypatch):
    page = _page(tmp_path, monkeypatch)

    assert ADMIN_PAGE_TITLE in page
    assert ADMIN_SCRIPT in page
    assert "sessionStorage" in page
    for element_id in PAGE_CONTROL_IDS:
        assert f'id="{element_id}"' in page
    for removed_prefix in REMOVED_PAGE_ID_PREFIXES:
        assert f'id="{removed_prefix}' not in page
    for removed_text in ("订单", "支付", "激活码", "试用期"):
        assert removed_text not in page


def test_admin_page_and_script_have_security_headers(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    page = client.get(ADMIN_PAGE)
    script = client.get(ADMIN_SCRIPT)

    assert page.status_code == 200
    assert script.status_code == 200
    _assert_security_headers(page)
    _assert_security_headers(script)
    for response in (page, script):
        assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_admin_script_uses_safe_audit_and_note_api_patterns(tmp_path, monkeypatch):
    script = _script(tmp_path, monkeypatch)

    assert 'const API_BASE = "/internal/admin/api/"' in script
    assert "path.startsWith(API_BASE)" in script
    assert 'const KEY = "whut-admin-secret"' in script
    assert "sessionStorage.setItem" in script
    assert "sessionStorage.getItem" in script
    assert "sessionStorage.removeItem" in script
    assert "localStorage" not in script
    assert "document.cookie" not in script
    assert "X-Forwarded-For" not in script
    assert "window.location" not in script
    assert 'adminFetch(API_BASE + "audit-logs/" + encodeURIComponent(auditId))' in script
    assert (
        'adminFetch(API_BASE + "devices/" + encodeURIComponent(deviceHash) + "/notes",'
        in script
    )
    assert (
        'adminFetch(API_BASE + "licenses/" + encodeURIComponent(licenseId) + "/notes",'
        in script
    )
    assert 'method: "POST"' in script
    assert "JSON.stringify({ note: note })" in script
    assert 'Authorization: "Bearer " + secret' in script
    assert 'credentials: "omit"' in script
    assert "管理员令牌无效或已失效。" in script


def test_admin_script_has_no_removed_payment_helpers(tmp_path, monkeypatch):
    script = _script(tmp_path, monkeypatch)

    for forbidden in (
        "订单",
        "支付",
        "微信",
        "内购",
        "续费",
        "激活码",
        "orders",
        "notifications",
        "grants",
        "confirm_paid_order",
        '"DELETE"',
        '"PUT"',
        '"PATCH"',
    ):
        assert forbidden not in script


def test_admin_ui_renders_api_data_without_unsafe_dom_or_external_resources(
    tmp_path,
    monkeypatch,
):
    page = _page(tmp_path, monkeypatch)
    script = _script(tmp_path, monkeypatch)
    combined = page + script

    for forbidden in (
        "innerHTML",
        "insertAdjacentHTML",
        "document.write",
        "http://",
        "https://",
        "console.log",
        "response.text",
        "response.body",
    ):
        assert forbidden not in combined
    assert "document.createElement" in script
    assert "textContent" in script
    assert "removeChild" in script
    assert "[REDACTED]" not in script


def test_admin_ui_has_safe_status_handling_and_no_extra_write_actions(
    tmp_path,
    monkeypatch,
):
    script = _script(tmp_path, monkeypatch)

    assert "response.status === 401" in script
    assert "response.status === 400 || response.status === 422" in script
    assert "response.status === 404" in script
    assert 'method: options.method || "GET"' in script
    assert 'throw new Error("blocked")' in script
    assert 'throw new Error("empty-secret")' in script
    assert "function handleError(error)" in script
    assert "function setStatus(message)" in script
    assert "function clearNode(node)" in script


def _assert_note_submit_guard(script: str, *, kind: str) -> None:
    body = _function_body(script, f"submit{kind.capitalize()}Note")
    flag = f"state.{kind}NoteSubmitting"
    submit_id = f'{kind}-note-submit'
    text_id = f'{kind}-note-text'

    guard_index = body.index(f"if ({flag}) {{")
    lock_index = body.index(f"{flag} = true;")
    disabled_index = body.index(f'byId("{submit_id}").disabled = true;')
    fetch_index = body.index("await adminFetch(")
    finally_index = body.index("finally {")

    assert guard_index < lock_index < disabled_index < fetch_index < finally_index
    assert body.count("await adminFetch(") == 1
    assert f'byId("{text_id}").value = "";' in body
    assert "renderAuditDetail(data);" in body
    assert f"{flag} = false;" in body[finally_index:]
    assert f'byId("{submit_id}").disabled = false;' in body[finally_index:]
    assert "handleError(error);" in body


def test_device_note_submit_has_in_flight_guard_and_finally_restore(
    tmp_path,
    monkeypatch,
):
    script = _script(tmp_path, monkeypatch)

    _assert_note_submit_guard(script, kind="device")


def test_license_note_submit_has_in_flight_guard_and_finally_restore(
    tmp_path,
    monkeypatch,
):
    script = _script(tmp_path, monkeypatch)

    _assert_note_submit_guard(script, kind="license")


def test_note_submit_refreshes_audit_list_and_starts_unlocked(tmp_path, monkeypatch):
    script = _script(tmp_path, monkeypatch)

    assert "deviceNoteSubmitting: false" in script
    assert "licenseNoteSubmitting: false" in script
    device_body = _function_body(script, "submitDeviceNote")
    assert 'await loadList("audit", 0);' in device_body
    assert 'byId("device-note-text").value.trim()' in device_body
    for forbidden in ('method: "DELETE"', 'method: "PUT"'):
        assert forbidden not in script


def test_audit_filter_changes_reset_offset_without_breaking_pagination(
    tmp_path,
    monkeypatch,
):
    page = _page(tmp_path, monkeypatch)
    script = _script(tmp_path, monkeypatch)

    assert "function resetListOffset(kind)" in script
    assert "function bindFilterReset(kind)" in script
    assert 'config[kind].filters.concat([[kind + "-limit", "limit"]])' in script
    assert 'byId(kind + "-offset").value = "0";' in script
    assert 'byId(config[kind].page).textContent = "offset " + state[kind].offset;' in script
    assert 'byId(kind + "-prev").addEventListener("click", () => loadList(kind, -1));' in script
    assert 'byId(kind + "-next").addEventListener("click", () => loadList(kind, 1));' in script
    assert 'addEventListener("change", () => resetListOffset(kind))' in script
    assert "rows.length === 0 && direction > 0" in script
    for field_id in (
        "audit-target-type",
        "audit-target-id",
        "audit-action",
        "audit-result",
        "audit-request-id",
        "audit-created-from",
        "audit-created-to",
        "audit-limit",
    ):
        assert f'id="{field_id}"' in page

    bind_list_body = _function_body(script, "bindList")
    assert "resetListOffset" not in bind_list_body


def test_audit_detail_clears_before_request_and_stays_clear_on_failure(
    tmp_path,
    monkeypatch,
):
    script = _script(tmp_path, monkeypatch)
    body = _function_body(script, "loadAuditDetail")

    assert "function clearAuditDetail()" in script
    assert 'clearNode(byId("audit-detail-output"));' in script
    assert body.index("clearAuditDetail();") < body.index("if (!auditId)")
    assert body.index("if (!auditId)") < body.index("await adminFetch(")
    assert "renderAuditDetail(data);" in body
    catch_index = body.index("catch (error)")
    assert "renderAuditDetail" not in body[catch_index:]
    assert "handleError(error);" in body[catch_index:]


def test_device_detail_view_clears_output_and_renders_whitelisted_fields(
    tmp_path,
    monkeypatch,
):
    script = _script(tmp_path, monkeypatch)
    body = _function_body(script, "loadDeviceDetail")

    assert 'clearNode(output);' in body
    assert body.index("clearNode(output);") < body.index("await adminFetch(")
    for field in ("device_id_hash", "product_id", "first_seen_at", "last_seen_at"):
        assert f'"{field}"' in body
    for forbidden in ("campus_account", "campus_password", "order_id", "signed_token"):
        assert forbidden not in body