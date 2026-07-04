import importlib.util
import json
from pathlib import Path

import pytest

import campus_login.local_config as local_config
from campus_login.local_config import (
    clear_login_config,
    has_login_config,
    load_login_config,
    LocalConfigError,
    save_login_config,
)


class MemoryCredentialStore:
    def __init__(self):
        self.password = None
        self.save_calls = 0
        self.delete_calls = 0

    def save_password(self, password):
        self.save_calls += 1
        self.password = password

    def load_password(self):
        return self.password

    def delete_password(self):
        self.delete_calls += 1
        existed = self.password is not None
        self.password = None
        return existed

    def has_password(self):
        return self.password is not None


class FailingDeleteCredentialStore(MemoryCredentialStore):
    def delete_password(self):
        self.delete_calls += 1
        raise RuntimeError("credential delete failed")


class FalseyCredentialStore(MemoryCredentialStore):
    def __bool__(self):
        return False


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
    assert "3****9" in rendered
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


def test_none_credential_store_uses_default_store(tmp_path, monkeypatch):
    default_store = MemoryCredentialStore()
    default_store.save_password("default-password")
    monkeypatch.setattr(local_config, "get_default_credential_store", lambda: default_store)

    loaded = load_login_config(config_path=tmp_path / "config.json", credential_store=None)

    assert loaded.password == "default-password"


def test_falsey_credential_store_is_not_replaced_by_default(tmp_path, monkeypatch):
    default_store = MemoryCredentialStore()
    default_store.save_password("default-password")
    falsey_store = FalseyCredentialStore()
    falsey_store.save_password("falsey-password")
    monkeypatch.setattr(local_config, "get_default_credential_store", lambda: default_store)

    loaded = load_login_config(config_path=tmp_path / "config.json", credential_store=falsey_store)

    assert loaded.password == "falsey-password"


def test_truthy_credential_store_is_not_replaced_by_default(tmp_path, monkeypatch):
    default_store = MemoryCredentialStore()
    default_store.save_password("default-password")
    credential_store = MemoryCredentialStore()
    credential_store.save_password("store-password")
    monkeypatch.setattr(local_config, "get_default_credential_store", lambda: default_store)

    loaded = load_login_config(config_path=tmp_path / "config.json", credential_store=credential_store)

    assert loaded.password == "store-password"


def test_clear_login_config_still_clears_password_when_config_delete_fails(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    credential_store = MemoryCredentialStore()
    credential_store.save_password("secret-password")

    def fail_unlink(self, missing_ok=False):
        raise OSError("config delete failed")

    monkeypatch.setattr(type(config_path), "unlink", fail_unlink)

    with pytest.raises(LocalConfigError) as exc_info:
        clear_login_config(
            config_path=config_path,
            credential_store=credential_store,
        )

    assert credential_store.delete_calls == 1
    assert credential_store.has_password() is False
    assert "secret-password" not in str(exc_info.value)


def test_clear_login_config_missing_file_still_clears_password(tmp_path):
    credential_store = MemoryCredentialStore()
    credential_store.save_password("secret-password")

    cleared = clear_login_config(
        config_path=tmp_path / "missing.json",
        credential_store=credential_store,
    )

    assert cleared.config_exists is False
    assert cleared.credential_exists is False
    assert credential_store.delete_calls == 1
    assert credential_store.has_password() is False


def test_clear_login_config_password_delete_failure_does_not_expose_password(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    credential_store = FailingDeleteCredentialStore()
    credential_store.save_password("secret-password")

    with pytest.raises(LocalConfigError) as exc_info:
        clear_login_config(
            config_path=config_path,
            credential_store=credential_store,
        )

    assert credential_store.delete_calls == 1
    assert "secret-password" not in str(exc_info.value)


def test_clear_login_config_reports_when_config_and_password_delete_both_fail(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    credential_store = FailingDeleteCredentialStore()
    credential_store.save_password("secret-password")

    def fail_unlink(self, missing_ok=False):
        raise OSError("config delete failed")

    monkeypatch.setattr(type(config_path), "unlink", fail_unlink)

    with pytest.raises(LocalConfigError) as exc_info:
        clear_login_config(
            config_path=config_path,
            credential_store=credential_store,
        )

    message = str(exc_info.value)
    assert credential_store.delete_calls == 1
    assert "config file removal failed" in message
    assert "password credential removal also failed" in message
    assert "secret-password" not in message


def test_save_login_config_rolls_back_password_when_config_write_fails(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    credential_store = MemoryCredentialStore()
    write_error = OSError("config write failed")

    def fail_write_text(self, *args, **kwargs):
        raise write_error

    monkeypatch.setattr(type(config_path), "write_text", fail_write_text)

    with pytest.raises(LocalConfigError) as exc_info:
        save_login_config(
            "366369",
            "secret-password",
            config_path=config_path,
            credential_store=credential_store,
        )

    assert credential_store.save_calls == 1
    assert credential_store.delete_calls == 1
    assert credential_store.has_password() is False
    assert exc_info.value.__cause__ is write_error
    assert "secret-password" not in str(exc_info.value)


def test_save_login_config_keeps_write_error_when_password_rollback_fails(
    tmp_path,
    monkeypatch,
):
    config_path = tmp_path / "config.json"
    credential_store = FailingDeleteCredentialStore()
    write_error = OSError("config write failed")

    def fail_write_text(self, *args, **kwargs):
        raise write_error

    monkeypatch.setattr(type(config_path), "write_text", fail_write_text)

    with pytest.raises(LocalConfigError) as exc_info:
        save_login_config(
            "366369",
            "secret-password",
            config_path=config_path,
            credential_store=credential_store,
        )

    assert credential_store.save_calls == 1
    assert credential_store.delete_calls == 1
    assert exc_info.value.__cause__ is write_error
    assert "secret-password" not in str(exc_info.value)


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
    assert "username: 3****9" in output
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
    assert "username: 3****9" in output
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
    assert "username: 3****9" in output
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


def test_load_login_config_raises_local_config_error_for_invalid_config_version(tmp_path):
    """config_version with non-numeric string raises LocalConfigError, not ValueError."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": "not-a-number"}),
        encoding="utf-8",
    )

    with pytest.raises(LocalConfigError) as exc_info:
        load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, ValueError)


def test_load_login_config_raises_local_config_error_for_list_config_version(tmp_path):
    """config_version as list raises LocalConfigError, not TypeError."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": [1]}),
        encoding="utf-8",
    )

    with pytest.raises(LocalConfigError) as exc_info:
        load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, TypeError)


def test_load_login_config_raises_local_config_error_for_dict_config_version(tmp_path):
    """config_version as dict raises LocalConfigError, not TypeError."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": {"a": 1}}),
        encoding="utf-8",
    )

    with pytest.raises(LocalConfigError) as exc_info:
        load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, TypeError)


@pytest.mark.parametrize("config_version", [None, False, 0, ""])
def test_load_login_config_uses_default_version_for_falsey_config_version(tmp_path, config_version):
    """Falsey config_version values keep the old fallback behavior."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": config_version}),
        encoding="utf-8",
    )

    config = load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert config.config_version == 1


def test_load_login_config_uses_default_version_for_missing(tmp_path):
    """config_version missing uses default CONFIG_VERSION."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369"}),
        encoding="utf-8",
    )

    config = load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert config.config_version == 1


@pytest.mark.parametrize("config_version", [1, 2])
def test_load_login_config_accepts_valid_integer_config_version(tmp_path, config_version):
    """Valid integer config_version is accepted."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": config_version}),
        encoding="utf-8",
    )

    config = load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert config.config_version == config_version


def test_load_login_config_accepts_numeric_string_config_version(tmp_path):
    """Numeric string config_version is accepted (int('1') works)."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": "1"}),
        encoding="utf-8",
    )

    config = load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert config.config_version == 1


def test_load_login_config_accepts_boolean_config_version(tmp_path):
    """Boolean config_version is accepted (int(True)==1)."""
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"username": "366369", "config_version": True}),
        encoding="utf-8",
    )

    config = load_login_config(config_path=config_path, credential_store=MemoryCredentialStore())

    assert config.config_version == 1
