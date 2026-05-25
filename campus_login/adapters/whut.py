import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse, urlsplit, urlunsplit

import requests

from campus_login.core.result import LoginResult, mask_account, sanitize_url
from campus_login.core.status import LoginStatus


_API_BASE_RE = re.compile(r"host_url\s*=\s*['\"]([^'\"]+)['\"]")
_PORTAL_QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?P<key>nasId|nas_id|nasid|userIpv4|client_ip|clientIp|ac_id|acId|ac)\s*[:=]\s*(?P<quote>['\"])(?P<value>[^'\"]{1,128})(?P=quote)",
    re.IGNORECASE,
)
_PORTAL_NUMERIC_ASSIGNMENT_RE = re.compile(
    r"(?P<key>nasId|nas_id|nasid)\s*[:=]\s*(?P<value>[0-9]{1,32})(?:\b|[,;}])",
    re.IGNORECASE,
)
_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_INPUT_ATTR_RE = re.compile(
    r"(?P<name>[a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?P<quote>['\"])(?P<value>.*?)(?P=quote)",
    re.IGNORECASE,
)
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")
_NAS_ID_SOURCE_PRIORITY = {
    "default_fallback": 0,
    "html_variable": 1,
    "hidden_input": 2,
    "url_query": 3,
}
_IP_NOT_ONLINE_CODE = "IP_NOT_ONLINE"
_INVALID_PORTAL_CONTEXT_CODE = "INVALID_PORTAL_CONTEXT"
_INVALID_PORTAL_PARAMETER_CODE = "INVALID_PORTAL_PARAMETER"
_AUTH_FAILED_CODE = "AUTH_FAILED"
_IP_NOT_ONLINE_PATTERNS = (
    "设备ip不在线",
    "ip不在线",
)
_INVALID_PORTAL_PARAMETER_PATTERNS = (
    "参数无效",
    "invalid parameter",
    "invalid param",
)
_AUTH_FAILED_PATTERNS = (
    "认证失败",
    "auth failed",
    "authentication failed",
)
_BAD_CREDENTIAL_PATTERNS = (
    "账号或密码",
    "用户不存在",
    "密码错误",
    "用户名或密码",
    "invalid password",
    "wrong password",
    "invalid username",
    "invalid credential",
    "authentication failed",
)


@dataclass
class _PortalContext:
    host: str
    nas_id: str
    nas_id_source: str = "default_fallback"
    api_base_url: Optional[str] = None
    portal_detected: bool = False
    login_page_url: Optional[str] = None
    client_ip: Optional[str] = None
    ac_id: Optional[str] = None
    bootstrap_url: Optional[str] = None


@dataclass
class _ApiBaseDiscovery:
    base_url: str
    csrf_token: Optional[str] = None
    status_payload: Optional[Dict[str, Any]] = None


class _PortalUnavailable(Exception):
    def __init__(
        self,
        message: str,
        http_status: Optional[int] = None,
        stage: Optional[str] = None,
        attempted_url: Optional[str] = None,
    ):
        super().__init__(message)
        self.http_status = http_status
        self.stage = stage
        self.attempted_url = attempted_url


class _StageTimeout(Exception):
    def __init__(self, stage: str, attempted_url: Optional[str] = None):
        super().__init__(stage)
        self.stage = stage
        self.attempted_url = attempted_url


class WhutCampusLoginAdapter:
    DEFAULT_HOST = "172.30.21.100"
    DEFAULT_WHUT_NAS_ID = "52"
    DEFAULT_NAS_ID = DEFAULT_WHUT_NAS_ID
    DEFAULT_API_BASE = "/api"
    PROBE_URLS = (
        "http://www.msftconnecttest.com/connecttest.txt",
        "http://neverssl.com/",
        "http://connectivitycheck.gstatic.com/generate_204",
    )

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: float = 5.0,
        retry_delay: float = 2.0,
        sleeper: Optional[Callable[[float], None]] = None,
    ):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.retry_delay = retry_delay
        self._sleeper = sleeper or time.sleep
        if hasattr(self.session, "trust_env"):
            self.session.trust_env = False

    def login(self, username: str, password: str) -> LoginResult:
        context = _PortalContext(self.DEFAULT_HOST, self.DEFAULT_NAS_ID)
        try:
            context = self.bootstrap_portal_context()
            config_api_base = self._load_config_api_base(context)
            api_base = self._discover_api_base(context, config_api_base)
            return self._complete_login_with_api_base(
                context,
                api_base,
                username,
                password,
                retry_ip_not_online=True,
            )
        except _StageTimeout as exc:
            return self._result(
                LoginStatus.TIMEOUT,
                "Network request timed out.",
                portal=context,
                failed_stage=exc.stage,
                attempted_url=exc.attempted_url,
            )
        except requests.RequestException as exc:
            if not context.portal_detected:
                return self._missing_portal_result(context, None)
            return self._result(
                LoginStatus.AUTH_SERVICE_UNAVAILABLE,
                "Campus authentication service is unavailable.",
                portal=context,
                response_summary={"error": self._sanitize_text(str(exc), username, password)},
            )
        except _PortalUnavailable as exc:
            status = (
                LoginStatus.AUTH_SERVICE_UNAVAILABLE
                if context.portal_detected or exc.http_status is not None
                else LoginStatus.NOT_CAMPUS_NETWORK
            )
            message = self._portal_unavailable_message(exc, status)
            return self._result(
                status,
                message,
                http_status=exc.http_status,
                portal=context,
                failed_stage=exc.stage,
                attempted_url=exc.attempted_url,
            )
        except Exception as exc:
            return self._result(
                LoginStatus.UNKNOWN_ERROR,
                "Unknown campus login error.",
                portal=context,
                response_summary={"error": self._sanitize_text(str(exc), username, password)},
            )

    def bootstrap_portal_context(self) -> _PortalContext:
        context = self._discover_portal()
        response = self._load_login_page(context)
        context.portal_detected = True
        context.login_page_url = self._login_page_url(context)
        self._update_context_from_text(context, response.text or "")
        return context

    def _try_default_api_base(
        self,
        portal: _PortalContext,
    ) -> Tuple[Optional[_ApiBaseDiscovery], Optional[_PortalUnavailable]]:
        try:
            api_base = self._discover_api_base(portal, None)
        except _PortalUnavailable as exc:
            return None, exc
        portal.portal_detected = True
        return api_base, None

    def _complete_login_with_api_base(
        self,
        portal: _PortalContext,
        api_base: _ApiBaseDiscovery,
        username: str,
        password: str,
        retry_ip_not_online: bool = False,
    ) -> LoginResult:
        if api_base.status_payload and self._is_online_payload(api_base.status_payload):
            return self._result(
                LoginStatus.ALREADY_ONLINE,
                "Already online.",
                portal=portal,
                response_summary=self._summarize_payload(
                    api_base.status_payload,
                    username,
                    password,
                ),
            )

        csrf_token = api_base.csrf_token or self._fetch_csrf_token(portal)
        status_payload = api_base.status_payload or self._fetch_account_status(
            portal,
            csrf_token,
        )
        if self._is_online_payload(status_payload):
            return self._result(
                LoginStatus.ALREADY_ONLINE,
                "Already online.",
                portal=portal,
                response_summary=self._summarize_payload(
                    status_payload,
                    username,
                    password,
                ),
            )

        result = self._submit_login(portal, csrf_token, username, password)
        if result.error_code == _IP_NOT_ONLINE_CODE and retry_ip_not_online:
            refreshed_portal = self.bootstrap_portal_context()
            self._sleeper(self.retry_delay)
            config_api_base = self._load_config_api_base(refreshed_portal)
            refreshed_api_base = self._discover_api_base(refreshed_portal, config_api_base)
            return self._complete_login_with_api_base(
                refreshed_portal,
                refreshed_api_base,
                username,
                password,
                retry_ip_not_online=False,
            )
        return result

    def _missing_portal_result(
        self,
        portal: _PortalContext,
        default_failure: Optional[_PortalUnavailable],
    ) -> LoginResult:
        if default_failure and default_failure.http_status is not None:
            return self._result(
                LoginStatus.AUTH_SERVICE_UNAVAILABLE,
                self._portal_unavailable_message(
                    default_failure,
                    LoginStatus.AUTH_SERVICE_UNAVAILABLE,
                ),
                http_status=default_failure.http_status,
                portal=portal,
                failed_stage=default_failure.stage,
                attempted_url=default_failure.attempted_url,
            )
        if default_failure and self._is_timeout_failure(default_failure):
            return self._result(
                LoginStatus.TIMEOUT,
                "Network request timed out.",
                portal=portal,
                failed_stage=default_failure.stage,
                attempted_url=default_failure.attempted_url,
            )
        return self._result(
            LoginStatus.NOT_CAMPUS_NETWORK,
            "Campus network portal was not detected.",
            portal=portal,
        )

    def _discover_portal(self) -> _PortalContext:
        context = _PortalContext(self.DEFAULT_HOST, self.DEFAULT_NAS_ID)
        for probe_url in self.PROBE_URLS:
            try:
                response = self._get(
                    "portal_probe",
                    probe_url,
                    allow_redirects=True,
                    timeout=self.timeout,
                )
            except (_StageTimeout, requests.RequestException):
                continue
            candidates = [
                response.url or "",
                response.headers.get("Location", ""),
            ]
            for candidate in candidates:
                if self._update_context_from_url(context, candidate, probe_url):
                    return context
            if self._update_context_from_text(context, response.text or ""):
                context.bootstrap_url = sanitize_url(probe_url)
                return context
        return context

    def _load_login_page(self, portal: _PortalContext):
        url = self._login_page_url(portal)
        response = self._get(
            "login_page",
            url,
            headers=self._browser_headers(portal),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise _PortalUnavailable(
                "Login page is unavailable.",
                response.status_code,
                "login_page",
                sanitize_url(url),
            )
        portal.login_page_url = url
        return response

    def _update_context_from_url(
        self,
        portal: _PortalContext,
        value: str,
        probe_url: Optional[str] = None,
    ) -> bool:
        if not value:
            return False
        parsed = urlparse(value)
        query = parse_qs(parsed.query)
        found = False

        if parsed.netloc and (
            parsed.netloc == self.DEFAULT_HOST
            or "nasId" in query
            or "/tpl/whut/" in parsed.path
        ):
            portal.host = parsed.netloc
            found = True

        nas_id = self._first_query_value(query, "nas_id", "nasid", "nasId")
        if self._set_nas_id(portal, nas_id, "url_query"):
            found = True

        client_ip = self._first_query_value(
            query,
            "userIpv4",
            "client_ip",
            "clientIp",
            "wlanuserip",
            "userip",
            "ip",
        )
        if client_ip:
            portal.client_ip = client_ip
            found = True

        ac_id = self._first_query_value(query, "ac_id", "acId", "ac", "wlanacname")
        if ac_id:
            portal.ac_id = ac_id
            found = True

        if found:
            portal.portal_detected = True
            portal.bootstrap_url = sanitize_url(value or probe_url or "")
        return found

    def _update_context_from_text(self, portal: _PortalContext, text: str) -> bool:
        found = False
        for match in self._iter_portal_assignment_matches(text or ""):
            key = match.group("key").lower()
            value = match.group("value")
            if key in {"nasid", "nas_id"}:
                if self._set_nas_id(portal, value, "html_variable"):
                    found = True
            elif key in {"useripv4", "client_ip", "clientip"}:
                if self._is_safe_portal_value(value):
                    portal.client_ip = value
                    found = True
            elif key in {"ac_id", "acid", "ac"}:
                if self._is_safe_portal_value(value):
                    portal.ac_id = value
                    found = True
        for name, value in self._iter_hidden_input_values(text or ""):
            key = name.lower()
            if key in {"nasid", "nas_id"}:
                if self._set_nas_id(portal, value, "hidden_input"):
                    found = True
            elif key in {"useripv4", "client_ip", "clientip", "wlanuserip", "userip"}:
                if self._is_safe_portal_value(value):
                    portal.client_ip = value
                    found = True
            elif key in {"ac_id", "acid", "ac", "wlanacname"}:
                if self._is_safe_portal_value(value):
                    portal.ac_id = value
                    found = True
        return found

    def _iter_portal_assignment_matches(self, text: str):
        yield from _PORTAL_QUOTED_ASSIGNMENT_RE.finditer(text)
        yield from _PORTAL_NUMERIC_ASSIGNMENT_RE.finditer(text)

    def _iter_hidden_input_values(self, text: str):
        for tag_match in _INPUT_TAG_RE.finditer(text):
            attrs = {
                attr_match.group("name").lower(): attr_match.group("value")
                for attr_match in _INPUT_ATTR_RE.finditer(tag_match.group(0))
            }
            input_name = attrs.get("name")
            if input_name and "value" in attrs:
                yield input_name, attrs["value"]

    def _set_nas_id(
        self,
        portal: _PortalContext,
        value: Optional[str],
        source: str,
    ) -> bool:
        if not self._is_valid_nas_id(value):
            return False
        if source == "html_variable" and str(value).strip() in {"0", "1"}:
            return False
        current_priority = _NAS_ID_SOURCE_PRIORITY.get(portal.nas_id_source, 0)
        next_priority = _NAS_ID_SOURCE_PRIORITY.get(source, 0)
        if next_priority < current_priority:
            return False
        portal.nas_id = str(value).strip()
        portal.nas_id_source = source
        return True

    def _first_query_value(
        self,
        query: Dict[str, List[str]],
        *keys: str,
    ) -> Optional[str]:
        lowered = {key.lower(): values for key, values in query.items()}
        for key in keys:
            values = lowered.get(key.lower())
            if values:
                return values[0]
        return None

    def _is_valid_portal_context(self, portal: _PortalContext) -> bool:
        return self._is_valid_portal_host(portal.host) and self._is_valid_nas_id(
            portal.nas_id
        )

    def _is_valid_portal_host(self, value: Optional[str]) -> bool:
        if not value:
            return False
        host = str(value).strip()
        if not host or any(char in host for char in "/\\ \t\r\n"):
            return False
        return bool(_HOST_RE.fullmatch(host))

    def _is_valid_nas_id(self, value: Optional[str]) -> bool:
        if value is None:
            return False
        nas_id = str(value).strip()
        if not nas_id:
            return False
        if not self._is_safe_portal_value(nas_id):
            return False
        return bool(re.fullmatch(r"[0-9]+", nas_id))

    def _is_safe_portal_value(self, value: Optional[str]) -> bool:
        if value is None:
            return False
        text = str(value).strip()
        if not text:
            return False
        lowered = text.lower()
        if lowered in {"null", "undefined", "function"}:
            return False
        if "geturlparam" in lowered:
            return False
        if any(char in text for char in "(){};"):
            return False
        if any(char.isspace() for char in text):
            return False
        return len(text) <= 128

    def _load_config_api_base(self, portal: _PortalContext) -> Optional[str]:
        url = f"http://{portal.host}/tpl/whut/static/js/config.js"
        try:
            response = self._get(
                "config_js",
                url,
                headers=self._browser_headers(portal),
                timeout=self.timeout,
            )
        except (_StageTimeout, requests.RequestException):
            return None
        if response.status_code != 200:
            return None
        match = _API_BASE_RE.search(response.text or "")
        if match:
            return match.group(1).strip()
        return None

    def _discover_api_base(
        self,
        portal: _PortalContext,
        config_api_base: Optional[str],
    ) -> _ApiBaseDiscovery:
        last_failure: Optional[_PortalUnavailable] = None
        status_only: Optional[_ApiBaseDiscovery] = None

        for base_url in self._api_base_candidates(portal, config_api_base):
            csrf_token, failure = self._probe_csrf_token(portal, base_url)
            if csrf_token:
                portal.api_base_url = base_url
                return _ApiBaseDiscovery(base_url=base_url, csrf_token=csrf_token)
            last_failure = failure or last_failure

            status_payload, failure = self._probe_account_status(portal, base_url)
            if status_payload:
                discovery = _ApiBaseDiscovery(
                    base_url=base_url,
                    status_payload=status_payload,
                )
                if self._is_online_payload(status_payload):
                    portal.api_base_url = base_url
                    return discovery
                status_only = status_only or discovery
            last_failure = failure or last_failure

        if status_only:
            portal.api_base_url = status_only.base_url
            return status_only

        if last_failure:
            raise last_failure
        raise _PortalUnavailable(
            "No usable API base candidate was found.",
            stage="api_base_probe",
        )

    def _api_base_candidates(
        self,
        portal: _PortalContext,
        config_api_base: Optional[str],
    ) -> List[str]:
        values: List[str] = [
            f"http://{portal.host}{self.DEFAULT_API_BASE}",
        ]
        if portal.host != self.DEFAULT_HOST:
            values.append(f"http://{self.DEFAULT_HOST}{self.DEFAULT_API_BASE}")

        if config_api_base:
            normalized = self._normalize_api_base(portal, config_api_base)
            if normalized:
                if urlparse(config_api_base).scheme:
                    values.append(normalized)
                else:
                    values.insert(1, normalized)

        return self._dedupe(values)

    def _normalize_api_base(
        self,
        portal: _PortalContext,
        value: str,
    ) -> Optional[str]:
        raw = (value or "").strip()
        if not raw:
            return None
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            return self._strip_url_query_and_trailing_slash(raw)
        if raw.startswith("/"):
            return self._strip_url_query_and_trailing_slash(f"http://{portal.host}{raw}")
        return self._strip_url_query_and_trailing_slash(f"http://{portal.host}/{raw}")

    def _strip_url_query_and_trailing_slash(self, value: str) -> str:
        parsed = urlsplit(value)
        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path.rstrip("/"),
                "",
                "",
            )
        )

    def _dedupe(self, values: Iterable[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _probe_csrf_token(
        self,
        portal: _PortalContext,
        base_url: str,
    ) -> Tuple[Optional[str], Optional[_PortalUnavailable]]:
        url = self._api_url(base_url, "csrf-token")
        try:
            response = self._get(
                "api_base_probe",
                url,
                headers=self._xhr_headers(portal, api_base_url=base_url),
                timeout=self.timeout,
            )
        except _StageTimeout as exc:
            return None, _PortalUnavailable(
                "API base CSRF probe timed out.",
                stage="api_base_probe",
                attempted_url=exc.attempted_url,
            )
        except requests.RequestException as exc:
            return None, _PortalUnavailable(
                self._sanitize_text(str(exc), "", ""),
                stage="api_base_probe",
                attempted_url=sanitize_url(url),
            )

        if response.status_code != 200:
            return None, _PortalUnavailable(
                "API base CSRF probe returned non-200 response.",
                response.status_code,
                "api_base_probe",
                sanitize_url(url),
            )
        try:
            payload = response.json()
        except ValueError:
            return None, _PortalUnavailable(
                "API base CSRF probe returned non-JSON response.",
                response.status_code,
                "api_base_probe",
                sanitize_url(url),
            )
        token = payload.get("csrf_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            return None, _PortalUnavailable(
                "API base CSRF probe response is missing csrf_token.",
                response.status_code,
                "api_base_probe",
                sanitize_url(url),
            )
        return token, None

    def _probe_account_status(
        self,
        portal: _PortalContext,
        base_url: str,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[_PortalUnavailable]]:
        url = self._api_url(base_url, "account/status?token=null")
        try:
            response = self._get(
                "api_base_probe",
                url,
                headers=self._xhr_headers(portal, api_base_url=base_url),
                timeout=self.timeout,
            )
        except _StageTimeout as exc:
            return None, _PortalUnavailable(
                "API base status probe timed out.",
                stage="api_base_probe",
                attempted_url=exc.attempted_url,
            )
        except requests.RequestException as exc:
            return None, _PortalUnavailable(
                self._sanitize_text(str(exc), "", ""),
                stage="api_base_probe",
                attempted_url=sanitize_url(url),
            )

        if response.status_code != 200:
            return None, _PortalUnavailable(
                "API base status probe returned non-200 response.",
                response.status_code,
                "api_base_probe",
                sanitize_url(url),
            )
        try:
            payload = response.json()
        except ValueError:
            return None, _PortalUnavailable(
                "API base status probe returned non-JSON response.",
                response.status_code,
                "api_base_probe",
                sanitize_url(url),
            )
        if not self._looks_like_status_payload(payload):
            return None, _PortalUnavailable(
                "API base status probe response is missing code or msg.",
                response.status_code,
                "api_base_probe",
                sanitize_url(url),
            )
        return payload, None

    def _fetch_csrf_token(self, portal: _PortalContext) -> str:
        url = self._api_url(self._selected_api_base_url(portal), "csrf-token")
        response = self._get(
            "csrf_token",
            url,
            headers=self._xhr_headers(portal, api_base_url=portal.api_base_url),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise _PortalUnavailable(
                "CSRF endpoint is unavailable.",
                response.status_code,
                "csrf_token",
                sanitize_url(url),
            )
        try:
            payload = response.json()
        except ValueError:
            raise _PortalUnavailable(
                "CSRF endpoint returned non-JSON response.",
                response.status_code,
                "csrf_token",
                sanitize_url(url),
            )
        token = payload.get("csrf_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise _PortalUnavailable(
                "CSRF token is missing.",
                response.status_code,
                "csrf_token",
                sanitize_url(url),
            )
        return token

    def _fetch_account_status(
        self,
        portal: _PortalContext,
        csrf_token: str,
    ) -> Dict[str, Any]:
        url = self._api_url(
            self._selected_api_base_url(portal),
            "account/status?token=null",
        )
        response = self._get(
            "account_status",
            url,
            headers=self._xhr_headers(
                portal,
                csrf_token,
                api_base_url=portal.api_base_url,
            ),
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise _PortalUnavailable(
                "Status endpoint is unavailable.",
                response.status_code,
                "account_status",
                sanitize_url(url),
            )
        try:
            payload = response.json()
        except ValueError:
            raise _PortalUnavailable(
                "Status endpoint returned non-JSON response.",
                response.status_code,
                "account_status",
                sanitize_url(url),
            )
        if not self._looks_like_status_payload(payload):
            raise _PortalUnavailable(
                "Status endpoint response is missing code or msg.",
                response.status_code,
                "account_status",
                sanitize_url(url),
            )
        return payload

    def _submit_login(
        self,
        portal: _PortalContext,
        csrf_token: str,
        username: str,
        password: str,
    ) -> LoginResult:
        if not self._is_valid_portal_context(portal):
            return self._result(
                LoginStatus.INVALID_PORTAL_PARAMETER,
                "校园网门户参数解析失败，nas_id 非法",
                portal=portal,
                failed_stage="portal_context_validation",
                error_code=_INVALID_PORTAL_CONTEXT_CODE,
            )

        url = self._api_url(self._selected_api_base_url(portal), "account/login")
        headers = self._login_headers(portal, csrf_token)
        data = {
            "username": username,
            "password": password,
            "nasId": portal.nas_id,
        }
        request_summary = self._build_login_request_summary(
            portal,
            headers,
            data,
            username,
        )
        response = self._post(
            "account_login",
            url,
            headers=headers,
            data=data,
            timeout=self.timeout,
        )
        if response.status_code != 200:
            return self._result(
                LoginStatus.AUTH_SERVICE_UNAVAILABLE,
                "Campus authentication service is unavailable.",
                http_status=response.status_code,
                portal=portal,
                failed_stage="account_login",
                attempted_url=sanitize_url(url, username, password),
                request_summary=request_summary,
            )

        try:
            payload = response.json()
        except ValueError:
            return self._result(
                LoginStatus.UNKNOWN_ERROR,
                "Login endpoint returned non-JSON response.",
                http_status=response.status_code,
                portal=portal,
                failed_stage="account_login",
                attempted_url=sanitize_url(url, username, password),
                request_summary=request_summary,
            )

        summary = self._summarize_payload(payload, username, password)
        if self._looks_like_login_success(payload):
            return self._result(
                LoginStatus.SUCCESS,
                "校园网认证成功",
                http_status=response.status_code,
                portal=portal,
                response_summary=summary,
                request_summary=request_summary,
            )

        msg = str(payload.get("msg") or payload.get("message") or "")
        if self._looks_like_invalid_portal_parameter(msg):
            return self._result(
                LoginStatus.INVALID_PORTAL_PARAMETER,
                "校园网门户参数无效，可能是门户上下文解析失败。",
                http_status=response.status_code,
                portal=portal,
                response_summary=summary,
                failed_stage="account_login",
                attempted_url=sanitize_url(url, username, password),
                error_code=_INVALID_PORTAL_PARAMETER_CODE,
                request_summary=request_summary,
            )

        if self._looks_like_ip_not_online(msg):
            return self._result(
                LoginStatus.IP_NOT_ONLINE,
                "校园网门户尚未识别当前设备 IP，请确认已连接 WHUT 校园网 Wi-Fi，并稍后重试。",
                http_status=response.status_code,
                portal=portal,
                response_summary=summary,
                failed_stage="portal_context_or_ip_online_check",
                attempted_url=sanitize_url(url, username, password),
                error_code=_IP_NOT_ONLINE_CODE,
                request_summary=request_summary,
            )

        if self._looks_like_bad_credentials(msg):
            return self._result(
                LoginStatus.INVALID_CREDENTIALS,
                "Invalid username or password.",
                http_status=response.status_code,
                portal=portal,
                response_summary=summary,
                request_summary=request_summary,
            )

        if self._looks_like_auth_failed(msg):
            return self._result(
                LoginStatus.AUTH_FAILED,
                "校园网认证失败。",
                http_status=response.status_code,
                portal=portal,
                response_summary=summary,
                failed_stage="account_login",
                attempted_url=sanitize_url(url, username, password),
                error_code=_AUTH_FAILED_CODE,
                request_summary=request_summary,
            )

        return self._result(
            LoginStatus.UNKNOWN_ERROR,
            "Login failed with an unknown campus portal response.",
            http_status=response.status_code,
            portal=portal,
            response_summary=summary,
            failed_stage="account_login",
            attempted_url=sanitize_url(url, username, password),
            request_summary=request_summary,
        )

    def _login_page_url(self, portal: _PortalContext) -> str:
        return f"http://{portal.host}/tpl/whut/login.html?nasId={portal.nas_id}"

    def _selected_api_base_url(self, portal: _PortalContext) -> str:
        return portal.api_base_url or f"http://{portal.host}{self.DEFAULT_API_BASE}"

    def _api_url(self, base_url: str, endpoint: str) -> str:
        return base_url.rstrip("/") + "/" + endpoint.lstrip("/")

    def _build_login_request_summary(
        self,
        portal: _PortalContext,
        headers: Dict[str, str],
        data: Dict[str, str],
        username: str,
    ) -> Dict[str, Any]:
        return {
            "method": "POST",
            "content_type": headers.get("Content-Type", ""),
            "login_payload_keys": list(data.keys()),
            "login_payload_sanitized": {
                "username": mask_account(username),
                "password": "<PASSWORD>",
                "nasId": data.get("nasId", ""),
            },
            "cookie_present": self._has_session_cookies(),
            "reused_same_session": True,
        }

    def _has_session_cookies(self) -> bool:
        cookies = getattr(self.session, "cookies", None)
        if not cookies:
            return False
        try:
            return len(cookies) > 0
        except TypeError:
            return bool(cookies)

    def _browser_headers(self, portal: _PortalContext) -> Dict[str, str]:
        return {
            "Host": portal.host,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": f"http://{portal.host}/",
            "User-Agent": self._user_agent(),
        }

    def _xhr_headers(
        self,
        portal: _PortalContext,
        csrf_token: Optional[str] = None,
        api_base_url: Optional[str] = None,
    ) -> Dict[str, str]:
        host = urlparse(api_base_url).netloc if api_base_url else portal.host
        headers = {
            "Host": host or portal.host,
            "Accept": "*/*",
            "Referer": self._login_page_url(portal),
            "User-Agent": self._user_agent(),
            "X-Requested-With": "XMLHttpRequest",
        }
        if csrf_token:
            headers["X-Csrf-Token"] = csrf_token
        return headers

    def _login_headers(self, portal: _PortalContext, csrf_token: str) -> Dict[str, str]:
        headers = self._xhr_headers(
            portal,
            csrf_token,
            api_base_url=portal.api_base_url,
        )
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        parsed = urlparse(self._selected_api_base_url(portal))
        headers["Origin"] = f"{parsed.scheme}://{parsed.netloc}"
        return headers

    def _user_agent(self) -> str:
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        )

    def _get(self, stage: str, url: str, **kwargs):
        try:
            return self.session.get(url, **kwargs)
        except requests.Timeout as exc:
            raise _StageTimeout(stage, sanitize_url(url)) from exc

    def _post(self, stage: str, url: str, **kwargs):
        try:
            return self.session.post(url, **kwargs)
        except requests.Timeout as exc:
            raise _StageTimeout(stage, sanitize_url(url)) from exc

    def _looks_like_bad_credentials(self, message: str) -> bool:
        normalized = message.lower()
        return any(pattern in normalized for pattern in _BAD_CREDENTIAL_PATTERNS)

    def _looks_like_ip_not_online(self, message: str) -> bool:
        normalized = message.lower().replace(" ", "")
        return any(pattern in normalized for pattern in _IP_NOT_ONLINE_PATTERNS)

    def _looks_like_invalid_portal_parameter(self, message: str) -> bool:
        normalized = message.lower().replace(" ", "")
        return any(pattern in normalized for pattern in _INVALID_PORTAL_PARAMETER_PATTERNS)

    def _looks_like_auth_failed(self, message: str) -> bool:
        normalized = message.lower()
        return any(pattern in normalized for pattern in _AUTH_FAILED_PATTERNS)

    def _looks_like_login_success(self, payload: Dict[str, Any]) -> bool:
        if payload.get("code") == 0:
            return True
        msg = str(payload.get("msg") or payload.get("message") or "")
        if "认证成功" in msg:
            return True
        return payload.get("authCode") == "ok:radius"

    def _looks_like_status_payload(self, payload: Any) -> bool:
        return isinstance(payload, dict) and "code" in payload and "msg" in payload

    def _is_online_payload(self, payload: Dict[str, Any]) -> bool:
        return payload.get("code") == 0

    def _summarize_payload(
        self,
        payload: Dict[str, Any],
        username: str,
        password: str,
    ) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        for key in ("code", "msg", "message", "error"):
            if key in payload:
                value = payload[key]
                if isinstance(value, str):
                    summary[key] = self._sanitize_text(value, username, password)
                else:
                    summary[key] = value
        return summary

    def _sanitize_text(self, value: str, username: str, password: str) -> str:
        sanitized = value
        if password:
            sanitized = sanitized.replace(password, "[redacted-password]")
        if username:
            sanitized = sanitized.replace(username, mask_account(username))
        return sanitized[:240]

    def _is_timeout_failure(self, exc: _PortalUnavailable) -> bool:
        return "timed out" in str(exc).lower()

    def _portal_unavailable_message(
        self,
        exc: _PortalUnavailable,
        status: LoginStatus,
    ) -> str:
        if status == LoginStatus.NOT_CAMPUS_NETWORK:
            return "Campus network portal was not detected."
        if exc.http_status is not None and exc.http_status != 200:
            return f"Portal detected but endpoint returned {exc.http_status}."
        return str(exc) or "Campus authentication service is unavailable."

    def _result(
        self,
        status: LoginStatus,
        message: str,
        http_status: Optional[int] = None,
        portal: Optional[_PortalContext] = None,
        response_summary: Optional[Dict[str, Any]] = None,
        failed_stage: Optional[str] = None,
        attempted_url: Optional[str] = None,
        error_code: Optional[str] = None,
        request_summary: Optional[Dict[str, Any]] = None,
    ) -> LoginResult:
        return LoginResult(
            status=status,
            message=message,
            http_status=http_status,
            portal_host=portal.host if portal else None,
            nas_id=portal.nas_id if portal else None,
            nas_id_source=portal.nas_id_source if portal else None,
            failed_stage=failed_stage,
            attempted_url=attempted_url,
            error_code=error_code,
            request_summary=request_summary or {},
            response_summary=response_summary or {},
        )
