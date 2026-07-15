import os
from pathlib import Path
import sys


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication

from desktop_app.payment_window import PaymentWindow
from license_client.license_state import LicenseDecision, LicenseStatus, evaluate_local_license
from license_client.payment_api import PaymentOrderResult, PaymentRefreshResult
from license_client.payment_state import PaymentStateStore
from license_client.token_store import load_signed_license_token, save_signed_license_token
from license_client.token_verify import verify_signed_license_token
from tests.license_server.test_license_server import _client, _register_payload
from tests.license_server.test_payment_api import MOCK_TOKEN


def _app():
    app = QApplication.instance()
    if app is None:
        app = QApplication(["test-payment-flow"])
    return app


def test_mock_payment_window_flow_refreshes_paid_license(tmp_path):
    _app()
    server, public_key_b64 = _client(
        tmp_path,
        payment_provider="mock",
        payment_mock_admin_token=MOCK_TOKEN,
    )
    initial_token = server.post("/device/register", json=_register_payload()).json()[
        "signed_license_token"
    ]
    token_path = tmp_path / "license_token.json"
    save_signed_license_token(initial_token, token_path=token_path)
    payment_api = _TestClientPaymentApi(server, initial_token)
    state_store = PaymentStateStore(tmp_path / "payment_state.json")
    window = PaymentWindow(
        api_client=payment_api,
        state_store=state_store,
        refresh_license_func=lambda: _refresh_license(server, public_key_b64, token_path),
        save_license_token_func=lambda token: save_signed_license_token(
            token,
            token_path=token_path,
        ),
    )
    _make_requests_sync(window)

    window._create_order()
    order_id = window._current_order_id
    server.post(
        f"/api/v1/payment/mock/orders/{order_id}/pay",
        headers={"X-Mock-Payment-Token": MOCK_TOKEN},
        json={},
    )
    window._manual_refresh()

    saved = load_signed_license_token(token_path=token_path).signed_license_token
    verification = verify_signed_license_token(
        saved,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-a",
    )
    assert verification.valid is True
    assert verification.payload["license_type"] == "paid"
    assert "正式版" in window.payment_area.text()
    assert state_store.load() is None
    assert payment_api.refreshed == [order_id]
    assert payment_api.queried == []


class _TestClientPaymentApi:
    def __init__(self, server, token):
        self.server = server
        self.token = token
        self.queried = []
        self.refreshed = []

    def create_or_resume_order(self, product_code):
        response = self.server.post(
            "/api/v1/payment/orders",
            headers=self._auth(),
            json={"product_code": product_code},
        )
        assert response.status_code == 200
        return _order(response.json())

    def get_order(self, order_id):
        self.queried.append(order_id)
        response = self.server.get(f"/api/v1/payment/orders/{order_id}", headers=self._auth())
        assert response.status_code == 200
        return _order(response.json())

    def refresh_order(self, order_id):
        self.refreshed.append(order_id)
        response = self.server.post(
            f"/api/v1/payment/orders/{order_id}/refresh",
            headers=self._auth(),
            json={},
        )
        assert response.status_code in {200, 202}
        return _refresh_order(response.json(), response.status_code)

    def _auth(self):
        return {"Authorization": f"Bearer {self.token}"}


def _refresh_license(server, public_key_b64, token_path):
    response = server.post(
        "/license/refresh",
        json={
            "product_id": "whut-campus-auto-login",
            "device_fingerprint_hash": "device-a",
        },
    )
    assert response.status_code == 200
    signed_token = response.json()["signed_license_token"]
    verification = verify_signed_license_token(
        signed_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash="device-a",
    )
    decision = evaluate_local_license(verification)
    assert decision.status == LicenseStatus.PAID_ACTIVE
    return LicenseDecision(
        status=decision.status,
        allowed=decision.allowed,
        reason=decision.reason,
        license_type=decision.license_type,
        expires_at=decision.expires_at,
        message_for_ui=decision.message_for_ui,
        signed_license_token=signed_token,
    )


def _order(payload):
    return PaymentOrderResult(
        order_id=payload["order_id"],
        product_code=payload["product_code"],
        amount_fen=payload["amount_fen"],
        currency=payload["currency"],
        provider=payload["provider"],
        status=payload["status"],
        code_url=payload["code_url"],
        created_at=payload["created_at"],
        expires_at=payload["expires_at"],
        paid_at=payload["paid_at"],
    )


def _refresh_order(payload, http_status):
    return PaymentRefreshResult(
        order_id=payload["order_id"],
        status=payload["status"],
        amount_fen=payload["amount_fen"],
        currency=payload["currency"],
        expires_at=payload["expires_at"],
        paid_at=payload["paid_at"],
        license_refresh_required=payload["license_refresh_required"],
        refresh_result=payload["refresh_result"],
        retry_after_seconds=payload["retry_after_seconds"],
        http_status=http_status,
    )


def _make_requests_sync(window):
    def sync_start(kind, action):
        if window._request_in_flight:
            return
        window._request_in_flight = True
        try:
            result = action()
            error = None
        except Exception as exc:
            result = None
            error = exc
        window._finish_request(window._generation, kind, result, error)

    window._start_request = sync_start
