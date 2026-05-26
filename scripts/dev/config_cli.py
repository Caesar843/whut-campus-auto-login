import argparse
import getpass
import sys
from pathlib import Path
from typing import Callable, Optional, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.core.result import mask_account  # noqa: E402
from campus_login.credentials import CredentialStore  # noqa: E402
from campus_login.local_config import (  # noqa: E402
    LoginConfig,
    clear_login_config,
    load_login_config,
    save_login_config,
)


PasswordReader = Callable[[str], str]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage local WHUT campus network login config."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    save_parser = subparsers.add_parser("save", help="Save username and password.")
    save_parser.add_argument("--username", required=True, help="Campus network username.")

    subparsers.add_parser("show", help="Show saved config status.")
    subparsers.add_parser("status", help="Show saved config status.")
    subparsers.add_parser("clear", help="Clear saved config and password.")
    return parser


def _contains_password_arg(argv: Sequence[str]) -> bool:
    return any(item == "--password" or item.startswith("--password=") for item in argv)


def _print_config(config: LoginConfig) -> None:
    print(f"username: {mask_account(config.username)}")
    print(f"config_exists: {_bool_text(config.config_exists)}")
    print(f"password_saved: {_bool_text(config.credential_exists)}")


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    config_path: Optional[Path] = None,
    credential_store: Optional[CredentialStore] = None,
    password_reader: PasswordReader = getpass.getpass,
) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if _contains_password_arg(args_list):
        print("--password is not supported. Enter the password when prompted.")
        return 2

    args = _build_parser().parse_args(args_list)

    if args.command == "save":
        password = password_reader("Campus network password: ")
        if not password:
            print("Password must not be empty.")
            return 2
        config = save_login_config(
            args.username,
            password,
            config_path=config_path,
            credential_store=credential_store,
        )
        print("Saved login config.")
        _print_config(config)
        return 0

    if args.command in {"show", "status"}:
        config = load_login_config(
            config_path=config_path,
            credential_store=credential_store,
        )
        _print_config(config)
        return 0

    if args.command == "clear":
        config = clear_login_config(
            config_path=config_path,
            credential_store=credential_store,
        )
        print("Cleared login config.")
        _print_config(config)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
