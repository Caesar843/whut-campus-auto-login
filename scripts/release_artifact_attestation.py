"""Command-line entry point for offline Windows artifact attestation."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from scripts.release_attestation import attest_release


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create redacted offline release-attestation evidence.")
    parser.add_argument("--onedir", required=True)
    parser.add_argument("--staging-dir", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--app-version", required=True)
    parser.add_argument("--build-environment", required=True)
    parser.add_argument("--approved-license-server-url", required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--pyinstaller-version", required=True)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = attest_release(
            onedir=Path(args.onedir),
            staging_dir=Path(args.staging_dir),
            source_commit=args.source_commit,
            app_version=args.app_version,
            build_environment=args.build_environment,
            approved_license_server_url=args.approved_license_server_url,
            expected_public_key_sha256=args.expected_public_key_sha256,
            python_version=args.python_version,
            pyinstaller_version=args.pyinstaller_version,
        )
    except Exception:
        print("result=FAIL")
        print("category=attestation_failed")
        return 1
    print("result=PASS")
    print(f"public_key_sha256={result['public_key_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
