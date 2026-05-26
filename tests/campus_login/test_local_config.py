import importlib.util
import json
from pathlib import Path

from campus_login.local_config import (
    clear_login_config,
    has_login_config,
    load_login_config,
    save_login_config,
)


class MemoryCredentialStore:
    def __init__(self):
        self.password = None

    def save_password(self, password):
        self.password = password

    def load_password(self):
        return self.password

    def delete_password(self):
        existed = self.password is not None
        self.password = None
        return existed

    def has_password(self):
        return self.password is not None


def load_config_cli():
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "dev" / "config_cli.py"
    spec = importlib.util.spec_from_file_location("dev_config_cli", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_save_login_config_reads_username_and_password_without_plaintext_json(tmp_path):
    config_path = tmp_path / "config.json"
    credential_store = MemoryCredentialStore()

    saved = save_login_config(
        "366369",
        "secret-password",
        config_path=config_path,
        credential_store=credential_store,
    )
    loaded = load_login_config(
        config_path=config_path,
        credential_store=credential_store,
    )

    assert saved.config_exists is True
    assert saved.credential_exists is True
    assert loaded.username == "366369"
    assert loaded.password == "secret-password"
    assert loaded.config_exists is True
    assert loaded.credential_exists is True
    assert has_login_config(config_path=config_path, credential_store=credential_store) is True

    raw_config = config_path.read_text(encoding="utf-8")
    parsed = json.loads(raw_config)
    assert parsed["username"] == "366369"
    assert set(parsed) == {
        "username",
        "auto_login_enabled",
        "updated_at",
        "config_version",
    }
    assert "secret-password" not in raw_config
    for forbidden in ("password", "Cookie", "token", "SessionId", "UserMac"):
        assert forbidden not in parsed


def test_login_config_repr_masks_account_and_password(tmp_path):
    config_path = tmp_path / "config.json"
    credential_store = MemoryCredentialStore()

    result = save_login_config(
        "366369",
        "secret-password",
        config_path=config_path,
        credential_store=credential_store,
    )

    rendered = repr(result)
    assert "36****69" in rendered
    assert "<PASSWORD>" in rendered
    assert "366369" not in rendered
    assert "secret-password" not in rendered


def test_clear_login_config_removes_config_and_credential(tmp_path):
    config_path = tmp_path / "config.json"
    credential_store = MemoryCredentialStore()
    save_login_config(
        "366369",
        "secret-password",
        config_path=config_path,
        credential_store=credential_store,
    )

    cleared = clear_login_config(
        config_path=config_path,
        credential_store=credential_store,
    )
    loaded = load_login_config(
        config_path=config_path,
        credential_store=credential_store,
    )

    assert cleared.config_exists is False
    assert cleared.credential_exists is False
    assert loaded.config_exists is False
    assert loaded.credential_exists is False
    assert loaded.username == ""
    assert loaded.password is None
    assert credential_store.has_password() is False
    assert config_path.exists() is False
    assert has_login_config(config_path=config_path, credential_store=credential_store) is False


def test_config_cli_save_show_status_and_clear_never_print_plaintext(tmp_path, capsys):
    module = load_config_cli()
    config_path = tmp_path / "config.json"
    credential_store = MemoryCredentialStore()

    exit_code = module.main(
        ["save", "--username", "366369"],
        config_path=config_path,
        credential_store=credential_store,
        password_reader=lambda prompt: "secret-password",
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "username: 36****69" in output
    assert "password_saved: true" in output
    assert "366369" not in output
    assert "secret-password" not in output

    exit_code = module.main(
        ["show"],
        config_path=config_path,
        credential_store=credential_store,
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "username: 36****69" in output
    assert "config_exists: true" in output
    assert "password_saved: true" in output
    assert "366369" not in output
    assert "secret-password" not in output

    exit_code = module.main(
        ["status"],
        config_path=config_path,
        credential_store=credential_store,
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "username: 36****69" in output
    assert "config_exists: true" in output
    assert "password_saved: true" in output
    assert "366369" not in output
    assert "secret-password" not in output

    exit_code = module.main(
        ["clear"],
        config_path=config_path,
        credential_store=credential_store,
    )
    output = capsys.readouterr().out
    assert exit_code == 0
    assert "config_exists: false" in output
    assert "password_saved: false" in output
    assert "366369" not in output
    assert "secret-password" not in output


def test_config_cli_rejects_password_argument(tmp_path, capsys):
    module = load_config_cli()

    exit_code = module.main(
        ["save", "--username", "366369", "--password", "secret-password"],
        config_path=tmp_path / "config.json",
        credential_store=MemoryCredentialStore(),
        password_reader=lambda prompt: "unused",
    )

    output = capsys.readouterr().out
    assert exit_code == 2
    assert "--password is not supported" in output
    assert "secret-password" not in output
