import argparse
import os
import sys
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.adapters.whut import WhutCampusLoginAdapter  # noqa: E402
from campus_login.core.client import login_with_adapter  # noqa: E402
from campus_login.core.result import LoginResult, mask_account, sanitize_url  # noqa: E402
from campus_login.saved_login import (  # noqa: E402
    load_saved_login_credentials,
    login_with_saved_config,
)
from license_client.license_guard import (  # noqa: E402
    LicenseCheckFunc,
    check_license_before_login,
    license_blocked_result,
)


AdapterFactory = Callable[[float], WhutCampusLoginAdapter]
ConfigLoader = Callable[[], object]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Test WHUT campus network login with environment credentials."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout in seconds for each portal request.",
    )
    parser.add_argument(
        "--use-saved-config",
        action="store_true",
        help="Read username and password from the local secure config store.",
    )
    return parser


def _safe_text(value: object, username: str, password: str) -> str:
    text = str(value)
    if password:
        text = text.replace(password, "[redacted-password]")
    if username:
        text = text.replace(username, mask_account(username))
    return text


def _format_response_summary(
    result: LoginResult, username: str, password: str
) -> Optional[str]:
    if not result.response_summary:
        return None
    parts = []
    for key in sorted(result.response_summary):
        value = _safe_text(result.response_summary[key], username, password)
        parts.append(f"{key}={value}")
    return ", ".join(parts)


def _format_request_summary(
    result: LoginResult, username: str, password: str
) -> Optional[str]:
    if not result.request_summary:
        return None

    parts = []
    for key in (
        "method",
        "content_type",
        "login_payload_keys",
        "login_payload_sanitized",
        "cookie_present",
        "reused_same_session",
    ):
        if key not in result.request_summary:
            continue
        value = result.request_summary[key]
        if key == "login_payload_keys" and isinstance(value, (list, tuple)):
            rendered = ",".join(_safe_text(item, username, password) for item in value)
        elif key == "login_payload_sanitized" and isinstance(value, Mapping):
            rendered = "{" + ",".join(
                f"{item_key}={_safe_text(value[item_key], username, password)}"
                for item_key in ("username", "password", "nasId")
                if item_key in value
            ) + "}"
        else:
            rendered = _safe_text(value, username, password)
        parts.append(f"{key}={rendered}")
    return ", ".join(parts) if parts else None


def print_result(result: LoginResult, username: str, password: str) -> None:
    print(f"status: {result.status.value}")
    print(f"message: {_safe_text(result.message, username, password)}")
    print(f"account: {mask_account(username)}")
    if result.portal_host:
        print(f"portal_host: {result.portal_host}")
    if result.nas_id:
        print(f"nas_id: {result.nas_id}")
    if result.nas_id_source:
        print(f"nas_id_source: {_safe_text(result.nas_id_source, username, password)}")
    if result.failed_stage:
        print(f"failed_stage: {result.failed_stage}")
    if result.attempted_url:
        print(f"attempted_url: {sanitize_url(result.attempted_url, username, password)}")
    if result.error_code:
        print(f"error_code: {result.error_code}")
    if result.http_status is not None:
        print(f"http_status: {result.http_status}")
    request_summary = _format_request_summary(result, username, password)
    if request_summary:
        print(f"request_summary: {request_summary}")
    summary = _format_response_summary(result, username, password)
    if summary:
        print(f"response_summary: {summary}")


def main(
    env: Optional[Mapping[str, str]] = None,
    adapter_factory: Optional[AdapterFactory] = None,
    argv: Optional[Sequence[str]] = None,
    config_loader: Optional[ConfigLoader] = None,
    license_check_func: Optional[LicenseCheckFunc] = None,
) -> int:
    args = _build_parser().parse_args([] if argv is None else list(argv))
    source_env = os.environ if env is None else env
    if args.use_saved_config:
        credentials = load_saved_login_credentials(config_loader)
        username = credentials.username
        password = credentials.password
        config = credentials.config
        if not username or not password:
            print("Saved login config is incomplete.")
            print(
                f"config_exists: {_bool_text(bool(getattr(config, 'config_exists', False)))}"
            )
            print(
                f"password_saved: {_bool_text(bool(getattr(config, 'credential_exists', False)))}"
            )
            return 2
    else:
        username = source_env.get("WHUT_NET_USERNAME", "").strip()
        password = source_env.get("WHUT_NET_PASSWORD", "")

    if not username or not password:
        print("Missing environment variables: WHUT_NET_USERNAME and WHUT_NET_PASSWORD")
        return 2

    license_checker = license_check_func or check_license_before_login
    license_decision = license_checker()
    if not license_decision.allowed:
        result = license_blocked_result(license_decision)
        print_result(result, username, password)
        return 1

    factory = adapter_factory or (lambda timeout: WhutCampusLoginAdapter(timeout=timeout))
    if args.use_saved_config:
        result = login_with_saved_config(
            timeout=args.timeout,
            adapter_factory=factory,
            config_loader=lambda: config,
        )
    else:
        result = login_with_adapter(factory(args.timeout), username, password)
    print_result(result, username, password)
    return 0 if result.ok else 1


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


if __name__ == "__main__":
    raise SystemExit(main(argv=sys.argv[1:]))
