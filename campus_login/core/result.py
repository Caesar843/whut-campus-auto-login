from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from campus_login.core.status import LoginStatus


_SENSITIVE_URL_KEY_PARTS = (
    "account",
    "captcha",
    "cookie",
    "csrf",
    "passwd",
    "password",
    "pwd",
    "session",
    "token",
    "user",
    "username",
)


def mask_account(account: Optional[str]) -> str:
    if not account:
        return ""
    value = str(account)
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 8:
        return value[:1] + "****" + value[-1:]
    return value[:2] + "****" + value[-2:]


def sanitize_url(
    url: Optional[str],
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    if not url:
        return ""

    value = str(url)
    try:
        parsed = urlsplit(value)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if query:
            query = [
                (key, "redacted") if _is_sensitive_url_key(key) else (key, item_value)
                for key, item_value in query
            ]
            value = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode(query),
                    parsed.fragment,
                )
            )
    except ValueError:
        pass

    if password:
        value = value.replace(password, "[redacted-password]")
    if username:
        value = value.replace(username, mask_account(username))
    return value[:500]


def _is_sensitive_url_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_URL_KEY_PARTS)


@dataclass(frozen=True)
class LoginResult:
    status: LoginStatus
    message: str
    http_status: Optional[int] = None
    portal_host: Optional[str] = None
    nas_id: Optional[str] = None
    nas_id_source: Optional[str] = None
    failed_stage: Optional[str] = None
    attempted_url: Optional[str] = None
    error_code: Optional[str] = None
    request_summary: Dict[str, Any] = field(default_factory=dict)
    response_summary: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in {
            LoginStatus.SUCCESS,
            LoginStatus.ALREADY_ONLINE,
            LoginStatus.LOGOUT_SUCCESS,
        }
