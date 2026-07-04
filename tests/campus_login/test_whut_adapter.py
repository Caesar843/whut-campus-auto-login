import json

import requests

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.status import LoginStatus


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text="", url=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.url = url or "http://172.30.21.100/tpl/whut/login.html?nasId=14"
        self.headers = headers or {}
        self.cookies = {}

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text)


class FakeSession:
    def __init__(self, get_queue=None, post_queue=None):
        self.get_queue = list(get_queue or [])
        self.post_queue = list(post_queue or [])
        self.get_calls = []
        self.post_calls = []
        self.trust_env = True

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        item = self.get_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        item = self.post_queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_adapter(session, sleeps=None):
    return WhutCampusLoginAdapter(
        session=session,
        timeout=0.1,
        retry_delay=0,
        sleeper=(lambda seconds: sleeps.append(seconds)) if sleeps is not None else None,
    )


def bootstrap_probe(nas_id="14", host="172.30.21.100", extra_query=""):
    suffix = f"&{extra_query}" if extra_query else ""
    return FakeResponse(
        url=f"http://{host}/tpl/whut/login.html?nasId={nas_id}{suffix}",
    )


def login_page(text="<html></html>", nas_id="14", host="172.30.21.100"):
    return FakeResponse(
        text=text,
        url=f"http://{host}/tpl/whut/login.html?nasId={nas_id}",
    )


def test_login_page_js_get_url_param_does_not_override_default_nas_id():
    session = FakeSession(
        get_queue=[
            FakeResponse(url="http://172.30.21.100/tpl/whut/login.html"),
            login_page(text='const nasId = getUrlParam("nasId");'),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[FakeResponse(json_data={"code": 0, "msg": "ok"})],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert result.nas_id == "52"
    assert result.nas_id_source == "default_fallback"
    assert session.post_calls[0][1]["data"]["nasId"] == "52"
    assert "getUrlParam" not in session.post_calls[0][1]["data"]["nasId"]
    assert "secret-password" not in str(result)


def test_html_variable_nas_id_one_does_not_override_fallback_52():
    session = FakeSession(
        get_queue=[
            FakeResponse(url="http://172.30.21.100/tpl/whut/login.html"),
            login_page(text='window.nasId = "1";'),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[FakeResponse(json_data={"code": 0, "msg": "ok"})],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert result.nas_id == "52"
    assert result.nas_id_source == "default_fallback"
    assert session.post_calls[0][1]["data"]["nasId"] == "52"


def test_nas_id_from_url_query_takes_priority_and_records_source():
    session = FakeSession(
        get_queue=[
            FakeResponse(url="http://172.30.21.100/xxx?nas_id=14"),
            login_page(text='nasId = "88";'),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 0, "msg": "online", "token": "raw-token"}),
        ]
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.ALREADY_ONLINE
    assert result.nas_id == "14"
    assert result.nas_id_source == "url_query"
    assert session.post_calls == []
    assert "raw-token" not in str(result.response_summary)


def test_nas_id_from_hidden_input_overrides_fallback_and_records_source():
    session = FakeSession(
        get_queue=[
            FakeResponse(url="http://172.30.21.100/tpl/whut/login.html"),
            login_page(text='<input type="hidden" name="nasId" value="52">'),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[FakeResponse(json_data={"code": 0, "msg": "ok"})],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert result.nas_id == "52"
    assert result.nas_id_source == "hidden_input"
    assert session.post_calls[0][1]["data"]["nasId"] == "52"


def test_account_login_matches_browser_form_request_and_safe_summary():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(nas_id="52"),
            login_page(nas_id="52"),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[
            FakeResponse(
                json_data={
                    "code": 0,
                    "msg": "认证成功",
                    "authCode": "ok:radius",
                    "token": "raw-token",
                    "SessionId": "raw-session",
                    "online": {
                        "Username": "202400001234",
                        "Name": "张三",
                        "UserMac": "aa:bb:cc:dd:ee:ff",
                    },
                }
            )
        ],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert result.message == "校园网认证成功"
    assert session.post_calls[0][0] == "http://172.30.21.100/api/account/login"
    headers = session.post_calls[0][1]["headers"]
    assert headers["Content-Type"] == "application/x-www-form-urlencoded; charset=UTF-8"
    assert headers["X-Requested-With"] == "XMLHttpRequest"
    assert headers["Accept"] == "*/*"
    assert headers["Origin"] == "http://172.30.21.100"
    assert headers["Referer"] == "http://172.30.21.100/tpl/whut/login.html?nasId=52"
    assert set(session.post_calls[0][1]["data"]) == {"username", "password", "nasId"}
    assert "nas_id" not in session.post_calls[0][1]["data"]
    assert result.request_summary["method"] == "POST"
    assert result.request_summary["content_type"] == (
        "application/x-www-form-urlencoded; charset=UTF-8"
    )
    assert result.request_summary["login_payload_keys"] == ["username", "password", "nasId"]
    assert result.request_summary["login_payload_sanitized"] == {
        "username": "20****34",
        "password": "<PASSWORD>",
        "nasId": "52",
    }
    assert result.request_summary["cookie_present"] is False
    assert result.request_summary["reused_same_session"] is True
    safe_result = str(result)
    assert "secret-password" not in safe_result
    assert "202400001234" not in safe_result
    assert "raw-token" not in str(result.response_summary)
    assert "raw-session" not in str(result.response_summary)
    assert "aa:bb:cc:dd:ee:ff" not in str(result.response_summary)
    assert "张三" not in str(result.response_summary)


def test_maps_invalid_parameter_response_to_invalid_portal_parameter():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[FakeResponse(json_data={"code": 1, "msg": "参数无效"})],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.INVALID_PORTAL_PARAMETER
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "INVALID_PORTAL_PARAMETER"
    assert result.failed_stage == "account_login"
    assert result.response_summary == {"code": 1, "msg": "参数无效"}
    assert "secret-password" not in str(result)
    assert "202400001234" not in str(result)


def test_maps_auth_failed_response_without_unknown_error():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(nas_id="52"),
            login_page(nas_id="52"),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[FakeResponse(json_data={"code": 1, "msg": "认证失败"})],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.AUTH_FAILED
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "AUTH_FAILED"
    assert result.failed_stage == "account_login"
    assert result.response_summary == {"code": 1, "msg": "认证失败"}


def test_success_detection_uses_json_msg_and_auth_code():
    for payload in (
        {"code": 1, "msg": "认证成功"},
        {"code": 1, "msg": "ok", "authCode": "ok:radius"},
    ):
        session = FakeSession(
            get_queue=[
                bootstrap_probe(nas_id="52"),
                login_page(nas_id="52"),
                FakeResponse(status_code=404, text="not found"),
                FakeResponse(json_data={"csrf_token": "csrf-123"}),
                FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
            ],
            post_queue=[FakeResponse(json_data=payload)],
        )

        result = make_adapter(session).login("202400001234", "secret-password")

        assert result.status == LoginStatus.SUCCESS
        assert result.message == "校园网认证成功"


def test_bootstrap_happens_before_login_and_reuses_portal_context():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(
                nas_id="88",
                extra_query="userIpv4=10.0.0.2&ac_id=7",
            ),
            login_page(text='window.host_url = "/portal-api";', nas_id="88"),
            FakeResponse(text='window.host_url = "/portal-api";'),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-456"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[
            FakeResponse(
                json_data={"code": 0, "msg": "ok", "online": {"Username": "202400001234"}}
            )
        ],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert session.get_calls[0][0] == "http://www.msftconnecttest.com/connecttest.txt"
    assert session.get_calls[1][0] == "http://172.30.21.100/tpl/whut/login.html?nasId=88"
    assert session.get_calls[-1][0] == "http://172.30.21.100/portal-api/account/status?token=null"
    assert session.post_calls[0][0] == "http://172.30.21.100/portal-api/account/login"
    headers = session.post_calls[0][1]["headers"]
    assert headers["Referer"] == "http://172.30.21.100/tpl/whut/login.html?nasId=88"
    assert headers["Origin"] == "http://172.30.21.100"
    assert headers["X-Csrf-Token"] == "csrf-456"
    data = session.post_calls[0][1]["data"]
    assert data["username"] == "202400001234"
    assert data["password"] == "secret-password"
    assert data["nasId"] == "88"
    assert set(data) == {"username", "password", "nasId"}
    assert "secret-password" not in result.message
    assert "secret-password" not in str(result.response_summary)


def test_already_online_after_bootstrap_does_not_submit_password():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(
                json_data={
                    "code": 0,
                    "msg": "在线",
                    "token": "raw-token",
                    "cookie": "raw-cookie",
                    "online": {
                        "Username": "202400001234",
                        "Name": "张三",
                        "UserMac": "aa:bb:cc:dd:ee:ff",
                        "UserIpv4": "10.0.0.2",
                    },
                }
            ),
        ]
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.ALREADY_ONLINE
    assert result.portal_host == "172.30.21.100"
    assert result.nas_id == "14"
    assert session.post_calls == []
    assert result.response_summary == {"code": 0, "msg": "在线"}
    summary = str(result.response_summary)
    assert "secret-password" not in str(result)
    assert "raw-token" not in summary
    assert "raw-cookie" not in summary
    assert "aa:bb:cc:dd:ee:ff" not in summary
    assert "202400001234" not in summary
    assert "张三" not in summary


def test_maps_clear_credential_failure_to_invalid_credentials_after_bootstrap():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[FakeResponse(json_data={"code": 1, "msg": "账号或密码错误"})],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.INVALID_CREDENTIALS
    assert result.message == "Invalid username or password."
    assert result.response_summary == {"code": 1, "msg": "账号或密码错误"}
    assert "secret-password" not in str(result)


def test_ip_not_online_rebootstraps_waits_and_retries_once_successfully():
    sleeps = []
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-1"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-2"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[
            FakeResponse(json_data={"code": 1, "msg": "您的设备IP不在线，请断开网网络重新连接后再次登陆。"}),
            FakeResponse(json_data={"code": 0, "msg": "ok"}),
        ],
    )

    result = make_adapter(session, sleeps=sleeps).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    assert sleeps == [0]
    assert len(session.post_calls) == 2
    assert session.get_calls[0][0] == "http://www.msftconnecttest.com/connecttest.txt"
    assert session.get_calls[5][0] == "http://www.msftconnecttest.com/connecttest.txt"
    assert session.post_calls[0][1]["headers"]["X-Csrf-Token"] == "csrf-1"
    assert session.post_calls[1][1]["headers"]["X-Csrf-Token"] == "csrf-2"
    assert "secret-password" not in str(result)


def test_ip_not_online_after_retry_returns_clear_error():
    sleeps = []
    message = "您的设备IP不在线，请断开网网络重新连接后再次登陆。"
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-1"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-2"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[
            FakeResponse(json_data={"code": 1, "msg": message}),
            FakeResponse(json_data={"code": 1, "msg": message}),
        ],
    )

    result = make_adapter(session, sleeps=sleeps).login("202400001234", "secret-password")

    assert result.status == LoginStatus.IP_NOT_ONLINE
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.status != LoginStatus.INVALID_CREDENTIALS
    assert result.error_code == "IP_NOT_ONLINE"
    assert result.failed_stage == "portal_context_or_ip_online_check"
    assert result.message == "校园网门户尚未识别当前设备 IP，请确认已连接 WHUT 校园网 Wi-Fi，并稍后重试。"
    assert result.response_summary == {"code": 1, "msg": message}
    assert sleeps == [0]
    assert len(session.post_calls) == 2
    assert "secret-password" not in str(result)
    assert "202400001234" not in str(result)


def test_bootstrap_falls_back_to_default_context_when_probe_has_no_portal():
    session = FakeSession(
        get_queue=[
            FakeResponse(url="http://www.msftconnecttest.com/connecttest.txt"),
            FakeResponse(url="http://neverssl.com/"),
            FakeResponse(url="http://connectivitycheck.gstatic.com/generate_204"),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 0, "msg": "在线", "token": "raw-token"}),
        ]
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.ALREADY_ONLINE
    assert result.portal_host == "172.30.21.100"
    assert result.nas_id == "52"
    assert session.get_calls[3][0] == "http://172.30.21.100/tpl/whut/login.html?nasId=52"
    assert session.post_calls == []
    assert "raw-token" not in str(result.response_summary)


def test_maps_account_status_timeout_to_stage_specific_timeout_after_bootstrap():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            requests.Timeout("status timed out"),
        ]
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.TIMEOUT
    assert result.failed_stage == "account_status"
    assert result.attempted_url == "http://172.30.21.100/api/account/status?token=redacted"
    assert result.portal_host == "172.30.21.100"
    assert result.nas_id == "14"
    assert "secret-password" not in str(result)


def test_maps_account_login_timeout_to_stage_specific_timeout_after_bootstrap():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[requests.Timeout("login timed out")],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.TIMEOUT
    assert result.failed_stage == "account_login"
    assert result.attempted_url == "http://172.30.21.100/api/account/login"
    assert result.portal_host == "172.30.21.100"
    assert result.nas_id == "14"
    assert "secret-password" not in str(result)


def test_maps_login_page_404_to_auth_service_unavailable_after_bootstrap_probe():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            FakeResponse(status_code=404, text="not found"),
        ]
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.AUTH_SERVICE_UNAVAILABLE
    assert result.message == "Portal detected but endpoint returned 404."
    assert result.http_status == 404
    assert result.failed_stage == "login_page"
    assert result.attempted_url == "http://172.30.21.100/tpl/whut/login.html?nasId=14"
    assert "secret-password" not in str(result)


def test_response_summary_excludes_sensitive_online_identity_fields_after_login():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "offline", "online": None}),
        ],
        post_queue=[
            FakeResponse(
                json_data={
                    "code": 0,
                    "msg": "ok",
                    "token": "raw-token",
                    "cookie": "raw-cookie",
                    "online": {
                        "Username": "202400001234",
                        "Name": "张三",
                        "UserMac": "aa:bb:cc:dd:ee:ff",
                        "UserIpv4": "10.0.0.2",
                    },
                }
            )
        ],
    )

    result = make_adapter(session).login("202400001234", "secret-password")

    assert result.status == LoginStatus.SUCCESS
    summary = str(result.response_summary)
    assert "raw-token" not in summary
    assert "raw-cookie" not in summary
    assert "aa:bb:cc:dd:ee:ff" not in summary
    assert "202400001234" not in summary
    assert "张三" not in summary
