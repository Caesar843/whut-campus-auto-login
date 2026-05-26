import argparse
import sys
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.adapters.whut import WhutCampusLoginAdapter  # noqa: E402
from campus_login.core.client import logout_with_adapter  # noqa: E402
from campus_login.core.result import LoginResult, sanitize_url  # noqa: E402
from campus_login.core.status import LoginStatus  # noqa: E402


AdapterFactory = Callable[[float], WhutCampusLoginAdapter]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Logout from the WHUT campus network portal for development testing."
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP timeout in seconds for each portal request.",
    )
    return parser


def _safe_text(value: object) -> str:
    return str(value)[:240]


def _format_summary(summary: Mapping[str, object], keys: Sequence[str]) -> Optional[str]:
    if not summary:
        return None
    parts = []
    for key in keys:
        if key in summary:
            parts.append(f"{key}={_safe_text(summary[key])}")
    return ", ".join(parts) if parts else None


def _format_response_summary(summary: Mapping[str, object]) -> Optional[str]:
    if not summary:
        return None
    sections = []
    for section_key in ("logout", "status"):
        section = summary.get(section_key)
        if isinstance(section, Mapping):
            rendered = _format_summary(section, ("code", "msg", "message", "error"))
            if rendered:
                sections.append(f"{section_key}={{{rendered}}}")
    if sections:
        return "; ".join(sections)
    return _format_summary(summary, ("code", "msg", "message", "error"))


def print_result(result: LoginResult) -> None:
    print(f"status: {result.status.value}")
    print(f"message: {_safe_text(result.message)}")
    if result.portal_host:
        print(f"portal_host: {result.portal_host}")
    if result.failed_stage:
        print(f"failed_stage: {result.failed_stage}")
    if result.attempted_url:
        print(f"attempted_url: {sanitize_url(result.attempted_url)}")
    if result.error_code:
        print(f"error_code: {result.error_code}")
    if result.http_status is not None:
        print(f"http_status: {result.http_status}")
    request_summary = _format_summary(
        result.request_summary,
        (
            "method",
            "logout_payload",
            "cookie_present",
            "reused_same_session",
            "token_present",
        ),
    )
    if request_summary:
        print(f"request_summary: {request_summary}")
    response_summary = _format_response_summary(result.response_summary)
    if response_summary:
        print(f"response_summary: {response_summary}")


def main(
    adapter_factory: Optional[AdapterFactory] = None,
    argv: Optional[Sequence[str]] = None,
) -> int:
    args = _build_parser().parse_args([] if argv is None else list(argv))
    factory = adapter_factory or (lambda timeout: WhutCampusLoginAdapter(timeout=timeout))
    result = logout_with_adapter(factory(args.timeout))
    print_result(result)
    return 0 if result.status == LoginStatus.LOGOUT_SUCCESS else 1


if __name__ == "__main__":
    raise SystemExit(main(argv=sys.argv[1:]))
