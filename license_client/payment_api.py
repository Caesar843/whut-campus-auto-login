from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Callable, Optional
from urllib.parse import quote

import requests

from license_client.constants import resolve_license_server_url
from license_client.device_fingerprint import generate_device_fingerprint_hash
from license_client.http_transport import request as http_request
from license_client.license_api import LicenseApiClient
from license_client.license_guard import check_license_before_login
from license_client.token_store import TokenLoadResult, load_signed_license_token


ANNUAL_PRODUCT_CODE = "annual_v1"
ANNUAL_AMOUNT_FEN = 990
PAYMENT_CONNECT_TIMEOUT_SECONDS = 3.0
PAYMENT_READ_TIMEOUT_SECONDS = 5.0
PAYMENT_TIMEOUT = (PAYMENT_CONNECT_TIMEOUT_SECONDS, PAYMENT_READ_TIMEOUT_SECONDS)
PAYMENT_ORDER_ID_RE = re.compile(r"^pay_[0-9a-f]{32}$")


@dataclass(frozen=True)
class PaymentOrderResult:
    order_id: str
    product_code: str
    amount_fen: int
    currency: str
    provider: str
    status: str
    code_url: Optional[str] = field(repr=False)
    created_at: str
    expires_at: str
    paid_at: Optional[str]


class PaymentApiError(RuntimeError):
    def __init__(self, code: str, *, status_code: Optional[int] = None) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code

    def __repr__(self) -> str:
        return f"PaymentApiError(code={self.code!r}, status_code={self.status_code!r})"


class PaymentApiClient:
    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        timeout: tuple[float, float] | float = PAYMENT_TIMEOUT,
        token_path: Optional[Path] = None,
        token_loader: Optional[Callable[[], TokenLoadResult]] = None,
        token_initializer: Optional[Callable[[], Optional[str]]] = None,
    ) -> None:
        self.base_url = (base_url or resolve_license_server_url()).rstrip("/")
        self.timeout = timeout
        self._token_loader = token_loader or (
            lambda: load_signed_license_token(token_path=token_path)
        )
        self._token_initializer = token_initializer or (
            lambda: _initialize_signed_license_token(self.base_url, token_path=token_path)
        )

    def __repr__(self) -> str:
        return f"PaymentApiClient(base_url={self.base_url!r}, timeout={self.timeout!r})"

    def create_or_resume_order(
        self,
        product_code: str = ANNUAL_PRODUCT_CODE,
    ) -> PaymentOrderResult:
        payload = {"product_code": str(product_code)}
        response = self._request("post", "/api/v1/payment/orders", json=payload)
        return _order_result(response)

    def get_order(self, order_id: str) -> PaymentOrderResult:
        clean_order_id = _validated_order_id(order_id)
        quoted_order_id = quote(clean_order_id, safe="")
        response = self._request("get", f"/api/v1/payment/orders/{quoted_order_id}")
        return _order_result(response)

    def _request(self, method: str, path: str, **kwargs) -> dict[str, object]:
        token = self._signed_token()
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            if method == "post":
                response = http_request(
                    "post",
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    requests_module=requests,
                    **kwargs,
                )
            else:
                response = http_request(
                    "get",
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    requests_module=requests,
                    **kwargs,
                )
        except requests.Timeout as exc:
            raise PaymentApiError("request_timeout") from exc
        except requests.ConnectionError as exc:
            raise PaymentApiError("network_unreachable") from exc
        except requests.RequestException as exc:
            raise PaymentApiError("network_unreachable") from exc

        payload = _json_payload(response)
        if response.status_code >= 400:
            raise PaymentApiError(
                _error_code(response.status_code, payload),
                status_code=response.status_code,
            )
        return payload

    def _signed_token(self) -> str:
        loaded = self._token_loader()
        if loaded.signed_license_token:
            return loaded.signed_license_token
        initialized = self._token_initializer()
        if initialized:
            return initialized
        loaded = self._token_loader()
        if loaded.signed_license_token:
            return loaded.signed_license_token
        raise PaymentApiError("missing_signed_license_token")


def payment_error_message(error: PaymentApiError) -> str:
    if error.code == "invalid_payment_order_id":
        return "支付订单号格式无效，请重新创建订单。"
    messages = {
        "network_unreachable": "无法连接授权服务器，请检查网络后重试。",
        "request_timeout": "请求授权服务器超时，请稍后重试。",
        "missing_signed_license_token": "本地缺少授权凭证，请先初始化授权状态。",
        "token_rejected": "当前授权凭证无法创建支付订单，请联网刷新授权。",
        "payment_provider_not_configured": "支付服务暂未配置，请稍后再试。",
        "payment_provider_not_supported": "当前支付服务暂不可用，请稍后再试。",
        "unknown_product": "暂不支持当前授权产品。",
        "payment_order_not_found": "未找到该支付订单，或当前设备无权查看。",
        "server_security_error": "支付服务安全校验失败，请稍后再试或联系支持。",
        "invalid_response": "支付服务响应格式异常，请稍后再试。",
        "server_error": "支付服务暂时不可用，请稍后再试。",
    }
    return messages.get(error.code, "支付服务暂时不可用，请稍后再试。")


def _initialize_signed_license_token(
    base_url: str,
    *,
    token_path: Optional[Path],
) -> Optional[str]:
    device_hash = generate_device_fingerprint_hash()
    api_client = LicenseApiClient(base_url=base_url)
    decision = check_license_before_login(
        token_path=token_path,
        device_fingerprint_hash=device_hash,
        api_client=lambda: api_client.register_device(
            device_fingerprint_hash=device_hash,
        ),
    )
    return decision.signed_license_token


def _validated_order_id(order_id: str) -> str:
    if not isinstance(order_id, str):
        raise PaymentApiError("invalid_payment_order_id")
    clean_order_id = order_id.strip()
    if not PAYMENT_ORDER_ID_RE.fullmatch(clean_order_id):
        raise PaymentApiError("invalid_payment_order_id")
    return clean_order_id


def _json_payload(response) -> dict[str, object]:
    try:
        payload = response.json() if response.content else {}
    except ValueError as exc:
        if response.status_code >= 500:
            raise PaymentApiError("server_error", status_code=response.status_code) from exc
        raise PaymentApiError("invalid_response", status_code=response.status_code) from exc
    if not isinstance(payload, dict):
        raise PaymentApiError("invalid_response", status_code=response.status_code)
    return payload


def _error_code(status_code: int, payload: dict[str, object]) -> str:
    detail = str(payload.get("detail") or payload.get("status") or "").strip()
    if status_code in {401, 403}:
        return "token_rejected"
    if status_code == 404:
        return "payment_order_not_found"
    if detail in {
        "payment_provider_not_configured",
        "payment_provider_not_supported",
        "unknown_product",
    }:
        return detail
    if status_code == 409:
        return "server_security_error"
    if status_code >= 500:
        return "server_error"
    return "invalid_response"


def _order_result(payload: dict[str, object]) -> PaymentOrderResult:
    required = {
        "order_id",
        "product_code",
        "amount_fen",
        "currency",
        "provider",
        "status",
        "created_at",
        "expires_at",
    }
    if any(key not in payload for key in required):
        raise PaymentApiError("invalid_response")
    try:
        amount_fen = int(payload["amount_fen"])
    except (TypeError, ValueError) as exc:
        raise PaymentApiError("invalid_response") from exc
    return PaymentOrderResult(
        order_id=str(payload["order_id"]),
        product_code=str(payload["product_code"]),
        amount_fen=amount_fen,
        currency=str(payload["currency"]),
        provider=str(payload["provider"]),
        status=str(payload["status"]),
        code_url=_optional_text(payload.get("code_url")),
        created_at=str(payload["created_at"]),
        expires_at=str(payload["expires_at"]),
        paid_at=_optional_text(payload.get("paid_at")),
    )


def _optional_text(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    return text if text else None
