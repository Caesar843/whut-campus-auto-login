from tests.license_server.test_admin_readonly import _admin_client, _assert_security_headers


def test_admin_page_exposes_audit_and_order_note_controls(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)

    page = client.get("/internal/admin/")
    script = client.get("/internal/admin/assets/admin.js")

    assert page.status_code == 200
    assert script.status_code == 200
    _assert_security_headers(page)
    _assert_security_headers(script)
    assert "/internal/admin/assets/admin.js" in page.text
    assert "sessionStorage" in page.text
    for expected in (
        'id="audit-target-type"',
        'id="audit-target-id"',
        'id="audit-action"',
        'id="audit-result"',
        'id="audit-created-from"',
        'id="audit-created-to"',
        'id="audit-limit"',
        'id="audit-offset"',
        'id="audit-load"',
        'id="audit-prev"',
        'id="audit-next"',
        'id="audit-output"',
        'id="audit-detail-output"',
        'id="order-note-order-id"',
        'id="order-note-text"',
        'id="order-note-submit"',
        'id="order-note-status"',
    ):
        assert expected in page.text


def test_admin_script_uses_safe_audit_and_note_api_patterns(tmp_path, monkeypatch):
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    script = client.get("/internal/admin/assets/admin.js").text

    assert 'const API_BASE = "/internal/admin/api/"' in script
    assert "path.startsWith(API_BASE)" in script
    assert "sessionStorage.setItem" in script
    assert "sessionStorage.getItem" in script
    assert "localStorage" not in script
    assert "document.cookie" not in script
    assert "X-Forwarded-For" not in script
    assert 'path: "audit-logs"' in script
    assert 'bindList("audit")' in script
    assert 'adminFetch(API_BASE + "audit-logs/" + encodeURIComponent(auditId))' in script
    assert (
        'adminFetch(API_BASE + "orders/" + encodeURIComponent(orderId) + "/notes",'
        in script
    )
    assert 'method: "POST"' in script
    assert "JSON.stringify({ note: note })" in script
    assert 'Authorization: "Bearer " + secret' in script


def test_admin_ui_renders_api_data_without_unsafe_dom_or_external_resources(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    page = client.get("/internal/admin/").text
    script = client.get("/internal/admin/assets/admin.js").text
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
    assert "[REDACTED]" not in script


def test_admin_ui_has_safe_status_handling_and_no_extra_write_actions(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    page = client.get("/internal/admin/").text
    script = client.get("/internal/admin/assets/admin.js").text
    combined = page + script

    assert "response.status === 401" in script
    assert "response.status === 400 || response.status === 422" in script
    assert "response.status === 404" in script
    assert 'setStatus("备注已追加。")' in script
    assert 'setStatus("审计详情已加载。")' in script
    for forbidden in (
        "\u8865\u53d1",
        "\u5173\u5355",
        "\u51bb\u7ed3",
        "confirm_paid_order",
    ):
        assert forbidden not in combined


def test_order_note_submit_has_in_flight_guard_and_finally_restore(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    script = client.get("/internal/admin/assets/admin.js").text
    submit_start = script.index("async function submitOrderNote()")
    summary_start = script.index("async function loadSummary()")
    submit_body = script[submit_start:summary_start]

    assert "noteSubmitting: false" in script
    guard_index = submit_body.index("if (state.noteSubmitting) {\n      return;\n    }")
    lock_index = submit_body.index("state.noteSubmitting = true;")
    fetch_index = submit_body.index("await adminFetch(")
    finally_index = submit_body.index("finally {")
    assert guard_index < lock_index < fetch_index < finally_index
    assert submit_body.count("await adminFetch(") == 1
    assert 'byId("order-note-submit").disabled = true;' in submit_body
    assert "state.noteSubmitting = false;" in submit_body[finally_index:]
    assert 'byId("order-note-submit").disabled = false;' in submit_body[finally_index:]
    assert 'byId("order-note-text").value = "";' in submit_body
    assert 'await loadList("audit", 0);' in submit_body


def test_audit_filter_changes_reset_offset_without_breaking_pagination(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    page = client.get("/internal/admin/").text
    script = client.get("/internal/admin/assets/admin.js").text

    assert "function resetListOffset(kind)" in script
    assert "function bindFilterReset(kind)" in script
    assert 'bindFilterReset("audit")' in script
    assert 'byId(kind + "-offset").value = "0";' in script
    assert 'byId(kind + "-page").textContent = "offset 0";' in script
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
        assert field_id in page
    assert 'config[kind].filters.concat([[kind + "-limit", "limit"]])' in script
    assert 'addEventListener("change", () => resetListOffset(kind))' in script
    bind_list_start = script.index("function bindList(kind)")
    bind_filter_start = script.index("function bindFilterReset(kind)")
    bind_list_body = script[bind_list_start:bind_filter_start]
    assert "resetListOffset" not in bind_list_body
    assert 'byId(kind + "-prev").addEventListener("click", () => loadList(kind, -1));' in script
    assert 'byId(kind + "-next").addEventListener("click", () => loadList(kind, 1));' in script


def test_audit_detail_clears_before_request_and_stays_clear_on_failure(
    tmp_path,
    monkeypatch,
):
    client, _database_path = _admin_client(tmp_path, monkeypatch)
    script = client.get("/internal/admin/assets/admin.js").text
    load_start = script.index("async function loadAuditDetail(auditId)")
    submit_start = script.index("async function submitOrderNote()")
    load_body = script[load_start:submit_start]

    assert "function clearAuditDetail()" in script
    assert 'clearNode(byId("audit-detail-output"));' in script
    assert "async function loadAuditDetail(auditId)" in load_body
    assert load_body.index("clearAuditDetail();") < load_body.index("await adminFetch(")
    assert "clearAuditDetail();\n    if (!auditId)" in load_body
    assert "renderAuditDetail(data);" in load_body
    catch_index = load_body.index("catch (error)")
    assert "renderAuditDetail" not in load_body[catch_index:]
    assert "catch (error) {\n      handleError(error);\n    }" in load_body
