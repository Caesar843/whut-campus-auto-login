from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from license_client.constants import default_license_token_path


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TokenLoadResult:
    status: str
    signed_license_token: Optional[str] = None
    path: Optional[Path] = None
    error: Optional[str] = None


def load_signed_license_token(*, token_path: Optional[Path] = None) -> TokenLoadResult:
    path = Path(token_path) if token_path is not None else default_license_token_path()
    if not path.exists():
        return TokenLoadResult(status="missing", path=path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("Local license token file is unreadable: %s", exc.__class__.__name__)
        return TokenLoadResult(status="corrupt", path=path, error=exc.__class__.__name__)
    if not isinstance(payload, dict):
        return TokenLoadResult(status="corrupt", path=path, error="invalid_format")
    signed_license_token = payload.get("signed_license_token")
    if not isinstance(signed_license_token, str) or not signed_license_token.strip():
        return TokenLoadResult(status="corrupt", path=path, error="missing_signed_license_token")
    return TokenLoadResult(
        status="loaded",
        signed_license_token=signed_license_token.strip(),
        path=path,
    )


def save_signed_license_token(
    signed_license_token: str,
    *,
    token_path: Optional[Path] = None,
) -> None:
    if not signed_license_token:
        raise ValueError("signed_license_token must not be empty")
    path = Path(token_path) if token_path is not None else default_license_token_path()
    payload = {"signed_license_token": signed_license_token}
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = Path(temp_file.name)
            temp_file.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                LOGGER.warning("Failed to clean up temporary local license token file.")


def delete_signed_license_token(*, token_path: Optional[Path] = None) -> bool:
    path = Path(token_path) if token_path is not None else default_license_token_path()
    existed = path.exists()
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        LOGGER.warning("Failed to delete local license token: %s", exc.__class__.__name__)
        return False
    return existed
