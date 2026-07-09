from pathlib import Path
import json
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from campus_login.local_config import clear_login_config
from license_client.payment_state import (
    PAYMENT_STATE_SCHEMA_VERSION,
    PaymentState,
    PaymentStateStore,
    default_payment_state_path,
)


def _state(**overrides):
    values = {
        "order_id": "pay_1",
        "product_code": "annual_v1",
        "status": "WAITING_PAYMENT",
        "created_at": "2026-07-06T08:00:00Z",
        "expires_at": "2026-07-06T08:15:00Z",
        "updated_at": "2026-07-06T08:00:01Z",
    }
    values.update(overrides)
    return PaymentState(**values)


def test_payment_state_round_trips_minimal_fields(tmp_path):
    path = tmp_path / "中文 用户" / "payment_state.json"
    store = PaymentStateStore(path)

    store.save(_state())
    loaded = store.load()

    assert loaded == _state()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": PAYMENT_STATE_SCHEMA_VERSION,
        "order_id": "pay_1",
        "product_code": "annual_v1",
        "status": "WAITING_PAYMENT",
        "created_at": "2026-07-06T08:00:00Z",
        "expires_at": "2026-07-06T08:15:00Z",
        "updated_at": "2026-07-06T08:00:01Z",
    }
    assert "signed_license_token" not in path.read_text(encoding="utf-8")
    assert "device_fingerprint_hash" not in path.read_text(encoding="utf-8")


def test_payment_state_missing_or_corrupt_file_does_not_crash(tmp_path):
    store = PaymentStateStore(tmp_path / "missing.json")
    assert store.load() is None

    store.path.write_text("{not-json", encoding="utf-8")
    assert store.load() is None

    store.path.write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
    assert store.load() is None

    store.path.write_text(
        json.dumps(
            {
                "schema_version": PAYMENT_STATE_SCHEMA_VERSION,
                "order_id": "pay_1",
                "product_code": "annual_v1",
                "status": "WAITING_PAYMENT",
                "created_at": "not-time",
                "expires_at": "2026-07-06T08:15:00Z",
                "updated_at": "2026-07-06T08:00:01Z",
            }
        ),
        encoding="utf-8",
    )
    assert store.load() is None


def test_terminal_paid_or_closed_state_clears_active_state(tmp_path):
    store = PaymentStateStore(tmp_path / "payment_state.json")
    store.save(_state())

    store.save(_state(status="PAID"))
    assert store.load() is None
    assert not store.path.exists()

    store.save(_state())
    store.save(_state(status="CLOSED"))
    assert store.load() is None
    assert not store.path.exists()


def test_abnormal_state_is_not_auto_cleared(tmp_path):
    store = PaymentStateStore(tmp_path / "payment_state.json")

    store.save(_state(status="ABNORMAL"))

    assert store.load().status == "ABNORMAL"


def test_clear_login_config_does_not_delete_payment_state(tmp_path):
    config_path = tmp_path / "config.json"
    payment_path = tmp_path / "payment_state.json"
    store = PaymentStateStore(payment_path)
    store.save(_state())

    clear_login_config(
        config_path=config_path,
        credential_store=_FakeCredentialStore(),
    )

    assert store.load().order_id == "pay_1"


def test_default_payment_state_path_reuses_app_config_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.setattr("sys.platform", "win32")

    assert default_payment_state_path().name == "payment_state.json"
    assert default_payment_state_path().parent.name == "WHUTCampusAutoLogin"


class _FakeCredentialStore:
    def save_password(self, password):
        pass

    def load_password(self):
        return None

    def delete_password(self):
        return True
