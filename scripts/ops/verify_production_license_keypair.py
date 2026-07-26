from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from license_server.license_key_preflight import (  # noqa: E402
    EXIT_UNEXPECTED,
    PreflightError,
    verify_configured_keypair,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify the configured production Ed25519 license key pair."
    )
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--show-public-key", action="store_true")
    return parser


def _print_success(report, *, show_public_key: bool) -> None:
    print("environment_file=pass")
    print(f"environment={report.environment}")
    print("configured_private_key=pass")
    print("configured_public_key=pass")
    print("configured_keypair_match=pass")
    print("configured_sign_verify=pass")
    print(f"public_key_sha256={report.public_key_sha256}")
    if show_public_key:
        print(f"public_key_base64={report.public_key_base64}")
    print("running_service_keypair=not_verified")
    print("result=PASS")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = verify_configured_keypair(args.env_file)
    except PreflightError as exc:
        print(f"error={exc.category}", file=sys.stderr)
        print("result=FAIL")
        return exc.exit_code
    except Exception as exc:
        print(
            f"error=unexpected_failure:{type(exc).__name__}",
            file=sys.stderr,
        )
        print("result=FAIL")
        return EXIT_UNEXPECTED
    _print_success(report, show_public_key=args.show_public_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
