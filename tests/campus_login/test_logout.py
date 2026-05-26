import json

import requests

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.status import LoginStatus


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text="", url=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.url = url or "http://172.30.21.100/tpl/whut/login.html?nasId=52"
        self.headers = headers or {}
        self.cookies = {}

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text)


class FakeCookieJar:
    def __init__(self, count=0):
        self.count = count

    def __len__(self):
        return self.count


class FakeSession:
    def __init__(self, get_queue=None, post_queue=None, cookie_count=0):
        self.get_queue = list(get_queue or [])
        self.post_queue = list(post_queue or [])
        self.get_calls = []
        self.post_calls = []
        self.cookies = FakeCookieJar(cookie_count)
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


def make_adapter(session):
    return WhutCampusLoginAdapter(session=session, timeout=0.1, retry_delay=0)


def bootstrap_probe(nas_id="52", host="172.30.21.100"):
    return FakeResponse(url=f"http://{host}/tpl/whut/login.html?nasId={nas_id}")


def login_page(text="<html></html>", nas_id="52", host="172.30.21.100"):
    return FakeResponse(
        text=text,
        url=f"http://{host}/tpl/whut/login.html?nasId={nas_id}",
    )


def online_status(token="raw-token"):
    return FakeResponse(
        json_data={
            "code": 0,
            "msg": "在线",
            "token": token,
            "SessionId": "raw-session",
            "online": {
                "Username": "202400001234",
                "Name": "张三",
                "UserMac": "aa:bb:cc:dd:ee:ff",
            },
        }
    )


def logout_session(logout_payload, *, token="raw-token", cookie_count=1):
    return FakeSession(
        cookie_count=cookie_count,
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            online_status(token),
            FakeResponse(json_data=logout_payload),
        ],
    )


def test_logout_matches_browser_get_request_and_safe_summary():
    session = FakeSession(
        cookie_count=1,
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            online_status("raw-token"),
            FakeResponse(json_data={"code": 0, "msg": "注销成功", "token": "new-token"}),
            FakeResponse(json_data={"code": 1, "msg": "用户不在线"}),
        ],
    )

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_SUCCESS
    assert result.message == "校园网注销成功"
    assert session.post_calls == []
    assert session.get_calls[-2][0] == "http://172.30.21.100/api/account/logout?token=raw-token"
    assert session.get_calls[-1][0] == "http://172.30.21.100/api/account/status?token=null"
    headers = session.get_calls[-2][1]["headers"]
    assert headers["Accept"] == "*/*"
    assert headers["X-Requested-With"] == "XMLHttpRequest"
    assert headers["Referer"] == "http://172.30.21.100/tpl/whut/success.html"
    assert "Content-Type" not in headers
    assert "data" not in session.get_calls[-2][1]
    assert result.attempted_url == "http://172.30.21.100/api/account/logout?token=redacted"
    assert result.http_status == 200
    assert result.request_summary == {
        "method": "GET",
        "logout_payload": None,
        "cookie_present": True,
        "reused_same_session": True,
        "token_present": True,
    }
    assert result.response_summary == {
        "logout": {"code": 0, "msg": "注销成功"},
        "status": {"code": 1, "msg": "用户不在线"},
    }
    safe_result = str(result)
    assert "raw-token" not in safe_result
    assert "new-token" not in safe_result
    assert "raw-session" not in safe_result
    assert "aa:bb:cc:dd:ee:ff" not in safe_result
    assert "202400001234" not in safe_result
    assert "张三" not in safe_result


def test_logout_endpoint_acceptance_is_not_success_until_status_is_offline():
    session = FakeSession(
        cookie_count=1,
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            online_status("raw-token"),
            FakeResponse(json_data={"code": 0, "msg": "正在登出，请稍后刷新页面"}),
            FakeResponse(json_data={"code": 0, "msg": "在线", "token": "still-token"}),
        ],
    )

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_FAILED
    assert result.status != LoginStatus.LOGOUT_SUCCESS
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "LOGOUT_STILL_ONLINE"
    assert result.failed_stage == "post_logout_status"
    assert result.response_summary == {
        "logout": {"code": 0, "msg": "正在登出，请稍后刷新页面"},
        "status": {"code": 0, "msg": "在线"},
    }
    assert "raw-token" not in str(result)
    assert "still-token" not in str(result)


def test_logout_reuses_configured_api_base_and_session_status_token():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(nas_id="88"),
            login_page(text='window.host_url = "/portal-api";', nas_id="88"),
            FakeResponse(text='window.host_url = "/portal-api";'),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-456"}),
            online_status("status-token"),
            FakeResponse(json_data={"code": 0, "msg": "退出成功"}),
            FakeResponse(json_data={"code": 1, "msg": "用户不在线"}),
        ],
    )

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_SUCCESS
    assert session.get_calls[-3][0] == (
        "http://172.30.21.100/portal-api/account/status?token=null"
    )
    assert session.get_calls[-2][0] == (
        "http://172.30.21.100/portal-api/account/logout?token=status-token"
    )
    assert session.get_calls[-1][0] == (
        "http://172.30.21.100/portal-api/account/status?token=null"
    )
    assert session.get_calls[-2][1]["headers"]["Referer"] == (
        "http://172.30.21.100/tpl/whut/success.html"
    )


def test_logout_status_not_online_is_clear_not_unknown():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 1, "msg": "用户不在线"}),
        ],
    )

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_NOT_ONLINE
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "LOGOUT_NOT_ONLINE"
    assert result.failed_stage == "account_status"
    assert session.get_calls[-1][0] == "http://172.30.21.100/api/account/status?token=null"


def test_logout_invalid_session_is_clear_not_unknown():
    session = logout_session({"code": 1, "msg": "token无效，请重新登录"})

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_INVALID_SESSION
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "LOGOUT_INVALID_SESSION"
    assert result.failed_stage == "account_logout"


def test_logout_failed_is_clear_not_unknown():
    session = logout_session({"code": 1, "msg": "注销失败"})

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_FAILED
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "LOGOUT_FAILED"
    assert result.failed_stage == "account_logout"


def test_logout_unknown_response_is_specific_not_generic_unknown():
    session = logout_session({"code": 7, "msg": "稍后再试"})

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_UNKNOWN_RESPONSE
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.error_code == "LOGOUT_UNKNOWN_RESPONSE"
    assert result.failed_stage == "account_logout"


def test_logout_portal_unreachable_is_clear_not_unknown():
    session = FakeSession(
        get_queue=[
            requests.Timeout("probe timed out"),
            requests.Timeout("probe timed out"),
            requests.Timeout("probe timed out"),
            requests.Timeout("login page timed out"),
        ]
    )

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_PORTAL_UNREACHABLE
    assert result.status != LoginStatus.UNKNOWN_ERROR
    assert result.failed_stage == "login_page"


def test_logout_without_status_token_reports_invalid_session_safely():
    session = FakeSession(
        get_queue=[
            bootstrap_probe(),
            login_page(),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse(json_data={"csrf_token": "csrf-123"}),
            FakeResponse(json_data={"code": 0, "msg": "在线"}),
        ],
    )

    result = make_adapter(session).logout()

    assert result.status == LoginStatus.LOGOUT_INVALID_SESSION
    assert result.error_code == "LOGOUT_INVALID_SESSION"
    assert result.request_summary["token_present"] is False
    assert "token" not in str(result.response_summary).lower()
