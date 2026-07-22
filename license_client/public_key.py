from __future__ import annotations

import argparse
import base64
import importlib
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Callable, Mapping, Optional
from urllib.parse import urlsplit


EMBEDDED_CONFIG_MODULE_NAME = "_license_client_embedded_build_config"
EMBEDDED_CONFIG_FILENAME = f"{EMBEDDED_CONFIG_MODULE_NAME}.py"
VALID_BUILD_ENVIRONMENTS = {"development", "preproduction", "production"}
RELEASE_BUILD_ENVIRONMENTS = {"preproduction", "production"}
EmbeddedConfig = Optional[tuple[str, str, str]]


def resolve_license_public_key(
    explicit_public_key: Optional[str] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
    embedded_config_loader: Optional[Callable[[], EmbeddedConfig]] = None,
) -> str:
    explicit = str(explicit_public_key or "").strip()
    if explicit:
        return explicit
    loader = embedded_config_loader or _load_embedded_build_config
    embedded_config = loader()
    build_environment = _resolve_build_environment_from_config(embedded_config)
    if not build_environment:
        return ""
    if build_environment in {"preproduction", "production"}:
        return _embedded_public_key(embedded_config)
    values = os.environ if env is None else env
    configured = str(values.get("LICENSE_PUBLIC_KEY", "") or "").strip()
    if configured:
        return configured
    return _embedded_public_key(embedded_config)


def resolve_build_environment(
    *,
    embedded_config_loader: Optional[Callable[[], EmbeddedConfig]] = None,
) -> str:
    loader = embedded_config_loader or _load_embedded_build_config
    return _resolve_build_environment_from_config(loader())


def write_embedded_build_config(
    *,
    public_key_b64: str,
    build_environment: str,
    license_server_url: str,
    build_session_id: str,
    output_path: Path,
) -> None:
    clean_key = str(public_key_b64 or "").strip()
    validate_public_key_b64(clean_key)
    clean_environment = _normalize_build_environment(build_environment)
    if not clean_environment:
        raise ValueError(
            "Build environment must be one of: development, preproduction, production."
        )
    raw_url = str(license_server_url or "")
    if clean_environment in RELEASE_BUILD_ENVIRONMENTS:
        clean_url = validate_release_server_url(raw_url)
    else:
        clean_url = raw_url.strip().rstrip("/")
    clean_session_id = str(build_session_id or "").strip()
    if not clean_session_id:
        raise ValueError("Build session ID is required.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        f"BUILD_ENVIRONMENT = {json.dumps(clean_environment)}\n"
        f"LICENSE_PUBLIC_KEY_B64 = {json.dumps(clean_key)}\n"
        f"LICENSE_SERVER_URL = {json.dumps(clean_url, ensure_ascii=False)}\n"
        f"BUILD_SESSION_ID = {json.dumps(clean_session_id)}\n",
        encoding="utf-8",
    )


def validate_public_key_b64(public_key_b64: str) -> None:
    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("LICENSE_PUBLIC_KEY must be base64-encoded Ed25519 public key bytes.") from exc
    if len(raw) != 32:
        raise ValueError("LICENSE_PUBLIC_KEY must decode to 32 Ed25519 public key bytes.")


def validate_release_server_url(license_server_url: str) -> str:
    raw_url = str(license_server_url or "")
    clean_url = raw_url.rstrip("/")
    message = (
        "Embedded license server URL must be an absolute non-loopback HTTPS URL "
        "without user info or fragment."
    )
    try:
        parsed = urlsplit(clean_url)
        host = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError(message) from exc
    if (
        not clean_url
        or raw_url != raw_url.strip()
        or any(character.isspace() for character in clean_url)
        or any(ord(character) < 32 or ord(character) == 127 for character in clean_url)
        or parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.fragment)
        or host.casefold().rstrip(".") == "localhost"
        or _is_loopback_host(host)
    ):
        raise ValueError(message)
    return clean_url


def resolve_embedded_license_server_url(
    *,
    embedded_config_loader: Optional[Callable[[], EmbeddedConfig]] = None,
) -> str:
    loader = embedded_config_loader or _load_embedded_build_config
    embedded_config = loader()
    if embedded_config is None:
        return ""
    try:
        return str(embedded_config[2] or "")
    except (IndexError, TypeError):
        return ""


def _load_embedded_build_config() -> EmbeddedConfig:
    try:
        module = importlib.import_module(EMBEDDED_CONFIG_MODULE_NAME)
    except ModuleNotFoundError:
        return None
    except Exception:
        return ("", "", "")
    return (
        str(getattr(module, "BUILD_ENVIRONMENT", "") or ""),
        str(getattr(module, "LICENSE_PUBLIC_KEY_B64", "") or ""),
        str(getattr(module, "LICENSE_SERVER_URL", "") or ""),
    )


def _resolve_build_environment_from_config(embedded_config: EmbeddedConfig) -> str:
    if embedded_config is None:
        if getattr(sys, "frozen", False):
            return ""
        return "development"
    return _normalize_build_environment(embedded_config[0])


def _embedded_public_key(embedded_config: EmbeddedConfig) -> str:
    if embedded_config is None:
        return ""
    return str(embedded_config[1] or "").strip()


def _is_loopback_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.is_loopback:
        return True
    return bool(
        isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped
        and address.ipv4_mapped.is_loopback
    )


def _normalize_build_environment(build_environment: str) -> str:
    clean_environment = str(build_environment or "").strip().lower()
    if not clean_environment:
        return ""
    if clean_environment not in VALID_BUILD_ENVIRONMENTS:
        return ""
    return clean_environment


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Write embedded client license build config.")
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--build-environment", required=True, choices=sorted(VALID_BUILD_ENVIRONMENTS))
    parser.add_argument("--license-server-url", default="")
    parser.add_argument("--build-session-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    write_embedded_build_config(
        public_key_b64=args.public_key,
        build_environment=args.build_environment,
        license_server_url=args.license_server_url,
        build_session_id=args.build_session_id,
        output_path=Path(args.output),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
