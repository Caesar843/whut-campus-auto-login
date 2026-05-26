import importlib.util
from pathlib import Path

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus


def load_logout_script():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "dev" / "logout.py"
    spec = importlib.util.spec_from_file_location("dev_logout", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_logout_script_prints_safe_summary_without_sensitive_values(capsys):
    module = load_logout_script()

    class FakeAdapter:
        def logout(self):
            return LoginResult(
                status=LoginStatus.LOGOUT_SUCCESS,
                message="校园网注销成功",
                http_status=200,
                portal_host="172.30.21.100",
                attempted_url="http://172.30.21.100/api/account/logout?token=raw-token",
                request_summary={
                    "method": "GET",
                    "logout_payload": None,
                    "cookie_present": True,
                    "reused_same_session": True,
                    "token_present": True,
                    "Cookie": "raw-cookie",
                    "SessionId": "raw-session",
                    "UserMac": "aa:bb:cc:dd:ee:ff",
                    "Name": "张三",
                },
                response_summary={
                    "code": 0,
                    "msg": "注销成功",
                    "token": "new-token",
                    "SessionId": "raw-session",
                    "online": {
                        "Username": "202400001234",
                        "Name": "张三",
                        "UserMac": "aa:bb:cc:dd:ee:ff",
                    },
                },
            )

    exit_code = module.main(
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "status: logout_success" in output
    assert "message: 校园网注销成功" in output
    assert "portal_host: 172.30.21.100" in output
    assert "attempted_url: http://172.30.21.100/api/account/logout?token=redacted" in output
    assert "http_status: 200" in output
    assert "response_summary: code=0, msg=注销成功" in output
    assert "request_summary: " in output
    assert "method=GET" in output
    assert "logout_payload=None" in output
    assert "cookie_present=True" in output
    assert "token_present=True" in output
    assert "raw-token" not in output
    assert "new-token" not in output
    assert "raw-cookie" not in output
    assert "raw-session" not in output
    assert "aa:bb:cc:dd:ee:ff" not in output
    assert "202400001234" not in output
    assert "张三" not in output


def test_logout_script_returns_failure_for_not_online(capsys):
    module = load_logout_script()

    class FakeAdapter:
        def logout(self):
            return LoginResult(
                status=LoginStatus.LOGOUT_NOT_ONLINE,
                message="当前设备不在线，无需注销。",
                portal_host="172.30.21.100",
                failed_stage="account_status",
                error_code="LOGOUT_NOT_ONLINE",
                response_summary={"code": 1, "msg": "用户不在线"},
            )

    exit_code = module.main(
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "status: logout_not_online" in output
    assert "failed_stage: account_status" in output
    assert "error_code: LOGOUT_NOT_ONLINE" in output


def test_logout_script_prints_nested_post_logout_status_safely(capsys):
    module = load_logout_script()

    class FakeAdapter:
        def logout(self):
            return LoginResult(
                status=LoginStatus.LOGOUT_FAILED,
                message="校园网注销请求已受理，但复查状态仍为在线。",
                http_status=200,
                portal_host="172.30.21.100",
                failed_stage="post_logout_status",
                error_code="LOGOUT_STILL_ONLINE",
                attempted_url="http://172.30.21.100/api/account/logout?token=raw-token",
                response_summary={
                    "logout": {"code": 0, "msg": "正在登出，请稍后刷新页面"},
                    "status": {
                        "code": 0,
                        "msg": "在线",
                        "token": "still-token",
                        "online": {
                            "Username": "202400001234",
                            "Name": "张三",
                            "UserMac": "aa:bb:cc:dd:ee:ff",
                        },
                    },
                },
            )

    exit_code = module.main(
        adapter_factory=lambda timeout: FakeAdapter(),
        argv=["--timeout", "0.1"],
    )

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "status: logout_failed" in output
    assert "error_code: LOGOUT_STILL_ONLINE" in output
    assert "failed_stage: post_logout_status" in output
    assert "response_summary: logout={code=0, msg=正在登出，请稍后刷新页面}; status={code=0, msg=在线}" in output
    assert "raw-token" not in output
    assert "still-token" not in output
    assert "202400001234" not in output
    assert "aa:bb:cc:dd:ee:ff" not in output
    assert "张三" not in output
