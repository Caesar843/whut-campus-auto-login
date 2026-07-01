import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from campus_login.core.result import mask_account
from campus_login.credentials import CredentialStore, get_default_credential_store


APP_DIR_NAME = "WHUTCampusAutoLogin"
CONFIG_FILE_NAME = "config.json"
CONFIG_VERSION = 1


class LocalConfigError(RuntimeError):
    """Raised when local non-sensitive login config cannot be read or written."""


@dataclass(frozen=True)
class LoginConfig:
    username: str = ""
    password: Optional[str] = None
    config_exists: bool = False
    credential_exists: bool = False
    auto_login_enabled: bool = True
    updated_at: str = ""
    config_version: int = CONFIG_VERSION
    config_path: Optional[Path] = None

    def __repr__(self) -> str:
        password_display = "<PASSWORD>" if self.credential_exists else None
        return (
            "LoginConfig("
            f"username={mask_account(self.username)!r}, "
            f"password={password_display!r}, "
            f"config_exists={self.config_exists!r}, "
            f"credential_exists={self.credential_exists!r}, "
            f"auto_login_enabled={self.auto_login_enabled!r}, "
            f"config_version={self.config_version!r}"
            ")"
        )


def default_config_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if sys.platform == "win32" and appdata:
        return Path(appdata) / APP_DIR_NAME / CONFIG_FILE_NAME
    return Path.home() / ".config" / APP_DIR_NAME / CONFIG_FILE_NAME


def save_login_config(
    username: str,
    password: str,
    *,
    config_path: Optional[Path] = None,
    credential_store: Optional[CredentialStore] = None,
    auto_login_enabled: bool = True,
) -> LoginConfig:
    clean_username = str(username or "").strip()
    if not clean_username:
        raise LocalConfigError("Username must not be empty.")
    if not password:
        raise LocalConfigError("Password must not be empty.")

    path = _resolve_config_path(config_path)
    store = _resolve_credential_store(credential_store)
    store.save_password(password)
    payload = {
        "username": clean_username,
        "auto_login_enabled": bool(auto_login_enabled),
        "updated_at": _utc_now(),
        "config_version": CONFIG_VERSION,
    }

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        try:
            store.delete_password()
        except Exception:
            raise LocalConfigError(
                "Failed to write local login config; additionally failed to remove saved password."
            ) from exc
        raise LocalConfigError("Failed to write local login config.") from exc

    return load_login_config(config_path=path, credential_store=store)


def load_login_config(
    *,
    config_path: Optional[Path] = None,
    credential_store: Optional[CredentialStore] = None,
) -> LoginConfig:
    path = _resolve_config_path(config_path)
    config_exists = path.exists()
    payload = _read_config_payload(path) if config_exists else {}
    username = str(payload.get("username") or "").strip()
    password = _resolve_credential_store(credential_store).load_password()
    credential_exists = password is not None
    return LoginConfig(
        username=username,
        password=password,
        config_exists=config_exists,
        credential_exists=credential_exists,
        auto_login_enabled=bool(payload.get("auto_login_enabled", True)),
        updated_at=str(payload.get("updated_at") or ""),
        config_version=int(payload.get("config_version") or CONFIG_VERSION),
        config_path=path,
    )


def clear_login_config(
    *,
    config_path: Optional[Path] = None,
    credential_store: Optional[CredentialStore] = None,
) -> LoginConfig:
    path = _resolve_config_path(config_path)
    store = _resolve_credential_store(credential_store)
    remove_error: Optional[OSError] = None

    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        remove_error = exc

    try:
        store.delete_password()
    except Exception as exc:
        if remove_error is not None:
            raise LocalConfigError(
                "Failed to clear local login config: config file removal failed; "
                "password credential removal also failed."
            ) from remove_error
        raise LocalConfigError("Failed to remove saved login password.") from exc

    if remove_error is not None:
        raise LocalConfigError("Failed to remove local login config.") from remove_error

    return LoginConfig(config_exists=False, credential_exists=False, config_path=path)


def has_login_config(
    *,
    config_path: Optional[Path] = None,
    credential_store: Optional[CredentialStore] = None,
) -> bool:
    config = load_login_config(
        config_path=config_path,
        credential_store=credential_store,
    )
    return bool(config.username and config.config_exists and config.credential_exists)


def _resolve_config_path(config_path: Optional[Path]) -> Path:
    return Path(config_path) if config_path is not None else default_config_path()


def _resolve_credential_store(
    credential_store: Optional[CredentialStore],
) -> CredentialStore:
    return credential_store if credential_store is not None else get_default_credential_store()


def _read_config_payload(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LocalConfigError("Local login config is unreadable.") from exc
    if not isinstance(payload, dict):
        raise LocalConfigError("Local login config has an invalid format.")
    return payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
