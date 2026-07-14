from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Callable, Mapping
from urllib.parse import quote, urlencode

import httpx
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from license_server.config import WechatPayConfig
from license_server.payment_gateway import (
    CloseOrderOutcome,
    CloseOrderResult,
    CreateNativeOrderRequest,
    GatewayOrder,
    QueryOrderOutcome,
    QueryOrderResult,
    VerifiedPaymentNotification,
)


DEFAULT_NOTIFICATION_TOLERANCE_SECONDS = 300
_MAX_NOTIFICATION_TIMESTAMP_DIGITS = 20
_SQLITE_INT64_MAX = (1 << 63) - 1
WECHAT_API_BASE_URL = "https://api.mch.weixin.qq.com"
WECHAT_HTTP_TIMEOUT = httpx.Timeout(
    10.0,
    connect=5.0,
    read=10.0,
    write=10.0,
    pool=5.0,
)
SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")


class WechatPaymentError(RuntimeError):
    def __init__(self, code: str, *, result_unknown: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.result_unknown = result_unknown


class WeChatNativePaymentGateway:
    def __init__(
        self,
        config: WechatPayConfig,
        *,
        client: httpx.Client | None = None,
        clock: Callable[[], datetime] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self._config = config
        self._private_key = _load_private_key(config)
        self._public_key = _load_public_key(config)
        self._client = client or httpx.Client(timeout=WECHAT_HTTP_TIMEOUT)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))

    def create_native_order(self, request: CreateNativeOrderRequest) -> GatewayOrder:
        payload: dict[str, object] = {
            "appid": self._config.app_id,
            "mchid": self._config.mch_id,
            "description": request.description,
            "out_trade_no": request.out_trade_no,
            "time_expire": _rfc3339(request.expires_at),
            "notify_url": request.notify_url,
            "amount": {"total": request.amount_fen, "currency": request.currency},
        }
        if request.attach is not None:
            payload["attach"] = request.attach
        try:
            response = self._send("POST", "/v3/pay/transactions/native", payload)
            if response.status_code >= 500:
                raise WechatPaymentError(
                    "PAYMENT_UPSTREAM_UNAVAILABLE",
                    result_unknown=True,
                )
            if response.status_code != 200:
                raise WechatPaymentError("PAYMENT_UPSTREAM_REJECTED")
            body = _json_object(response.content)
            code_url = body.get("code_url")
            if not isinstance(code_url, str) or not code_url:
                raise WechatPaymentError("PAYMENT_RESPONSE_INVALID")
        except WechatPaymentError as exc:
            if not exc.result_unknown and exc.code.startswith("PAYMENT_RESPONSE_"):
                raise WechatPaymentError(exc.code, result_unknown=True) from exc
            raise
        return GatewayOrder(
            code_url=code_url,
            provider_order_id=request.out_trade_no,
            provider_trade_state="NOTPAY",
            request_id=_request_id(response),
        )

    def query_order(self, order_id: str) -> QueryOrderResult:
        path = f"/v3/pay/transactions/out-trade-no/{quote(order_id, safe='')}"
        canonical_url = f"{path}?{urlencode({'mchid': self._config.mch_id})}"
        try:
            response = self._send("GET", canonical_url)
        except WechatPaymentError as exc:
            outcome = (
                QueryOrderOutcome.SIGNATURE_INVALID
                if exc.code.startswith("PAYMENT_RESPONSE_")
                else QueryOrderOutcome.HTTP_UNKNOWN
            )
            return QueryOrderResult(outcome=outcome, out_trade_no=order_id)
        if response.status_code == 404:
            body = _optional_json_object(response.content)
            outcome = (
                QueryOrderOutcome.NOT_FOUND
                if body.get("code") == "ORDER_NOT_EXIST"
                else QueryOrderOutcome.UNCLEAR
            )
            return QueryOrderResult(
                outcome=outcome,
                out_trade_no=order_id,
                request_id=_request_id(response),
            )
        if response.status_code >= 500:
            return QueryOrderResult(
                outcome=QueryOrderOutcome.HTTP_UNKNOWN,
                out_trade_no=order_id,
                request_id=_request_id(response),
            )
        if response.status_code != 200:
            return QueryOrderResult(
                outcome=QueryOrderOutcome.UNCLEAR,
                out_trade_no=order_id,
                request_id=_request_id(response),
            )
        try:
            body = _json_object(response.content)
            amount = body["amount"]
            if not isinstance(amount, dict):
                raise ValueError
            appid = _required_text(body, "appid")
            mchid = _required_text(body, "mchid")
            returned_order_id = _required_text(body, "out_trade_no")
            trade_state = _required_text(body, "trade_state")
            trade_type = _required_text(body, "trade_type")
            amount_total = amount["total"]
            if not isinstance(amount_total, int) or isinstance(amount_total, bool):
                raise ValueError
            currency = _required_text(amount, "currency")
            transaction_id = _optional_text(body, "transaction_id")
            success_time_text = _optional_text(body, "success_time")
            success_time = _parse_datetime(success_time_text) if success_time_text else None
            if trade_state == "SUCCESS" and (not transaction_id or not success_time):
                raise ValueError
        except (KeyError, TypeError, ValueError, WechatPaymentError):
            return QueryOrderResult(
                outcome=QueryOrderOutcome.UNCLEAR,
                out_trade_no=order_id,
                request_id=_request_id(response),
            )
        outcomes = {
            "SUCCESS": QueryOrderOutcome.PAID,
            "NOTPAY": QueryOrderOutcome.UNPAID,
            "USERPAYING": QueryOrderOutcome.UNPAID,
            "CLOSED": QueryOrderOutcome.CLOSED,
        }
        return QueryOrderResult(
            outcome=outcomes.get(trade_state, QueryOrderOutcome.UNCLEAR),
            out_trade_no=returned_order_id,
            transaction_id=transaction_id,
            trade_state=trade_state,
            trade_type=trade_type,
            amount_total=amount_total,
            currency=currency,
            success_time=success_time,
            appid=appid,
            mchid=mchid,
            request_id=_request_id(response),
        )

    def close_order(self, order_id: str) -> CloseOrderResult:
        path = f"/v3/pay/transactions/out-trade-no/{quote(order_id, safe='')}/close"
        try:
            response = self._send("POST", path, {"mchid": self._config.mch_id})
        except WechatPaymentError:
            return CloseOrderResult(outcome=CloseOrderOutcome.UNKNOWN)
        request_id = _request_id(response)
        if response.status_code == 204:
            return CloseOrderResult(CloseOrderOutcome.SUCCESS, request_id)
        body = _optional_json_object(response.content)
        code = body.get("code")
        outcomes = {
            "SUCCESS": CloseOrderOutcome.SUCCESS,
            "ORDER_PAID": CloseOrderOutcome.PAID,
            "ORDER_ALREADY_PAID": CloseOrderOutcome.PAID,
            "ORDER_CLOSED": CloseOrderOutcome.CLOSED,
            "ORDER_NOT_EXIST": CloseOrderOutcome.NOT_FOUND,
        }
        if code in outcomes:
            return CloseOrderResult(outcomes[code], request_id)
        if 400 <= response.status_code < 500:
            return CloseOrderResult(CloseOrderOutcome.REJECTED, request_id)
        return CloseOrderResult(CloseOrderOutcome.UNKNOWN, request_id)

    def parse_and_verify_notification(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        now: datetime | None = None,
    ) -> VerifiedPaymentNotification:
        return parse_and_verify_notification(
            headers,
            body,
            public_key_id=self._config.public_key_id,
            public_key=self._public_key,
            api_v3_key=self._config.api_v3_key,
            now=now,
        )

    def _send(
        self,
        method: str,
        canonical_url: str,
        payload: Mapping[str, object] | None = None,
    ) -> httpx.Response:
        body = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else b""
        )
        timestamp = int(_utc(self._clock()).timestamp())
        nonce = self._nonce_factory()
        message = canonical_request_message(method, canonical_url, timestamp, nonce, body)
        authorization = build_authorization_header(
            mchid=self._config.mch_id,
            serial_no=self._config.merchant_serial_no,
            nonce=nonce,
            timestamp=timestamp,
            signature=sign_request(self._private_key, message),
        )
        try:
            response = self._client.request(
                method,
                WECHAT_API_BASE_URL + canonical_url,
                content=body,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Authorization": authorization,
                },
            )
        except httpx.ConnectTimeout as exc:
            raise WechatPaymentError(
                "PAYMENT_CONNECT_TIMEOUT",
                result_unknown=True,
            ) from exc
        except (httpx.PoolTimeout, httpx.ConnectError) as exc:
            raise WechatPaymentError("PAYMENT_REQUEST_NOT_SENT") from exc
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.TransportError) as exc:
            raise WechatPaymentError("PAYMENT_RESULT_UNKNOWN", result_unknown=True) from exc
        verify_response_signature(
            response.headers,
            response.content,
            public_key_id=self._config.public_key_id,
            public_key=self._public_key,
        )
        return response


def canonical_request_message(
    method: str,
    canonical_url: str,
    timestamp: int,
    nonce: str,
    body: bytes,
) -> bytes:
    return (
        f"{method}\n{canonical_url}\n{timestamp}\n{nonce}\n".encode("utf-8")
        + body
        + b"\n"
    )


def sign_request(private_key: rsa.RSAPrivateKey, message: bytes) -> str:
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise WechatPaymentError("PAYMENT_REQUEST_SIGNING_KEY_INVALID")
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def build_authorization_header(
    *,
    mchid: str,
    serial_no: str,
    nonce: str,
    timestamp: int,
    signature: str,
) -> str:
    values = (mchid, serial_no, nonce, signature)
    if any('"' in value or "\n" in value or "\r" in value for value in values):
        raise WechatPaymentError("PAYMENT_REQUEST_AUTHORIZATION_INVALID")
    return (
        'WECHATPAY2-SHA256-RSA2048 '
        f'mchid="{mchid}",nonce_str="{nonce}",timestamp="{timestamp}",'
        f'serial_no="{serial_no}",signature="{signature}"'
    )


def verify_response_signature(
    headers: Mapping[str, str],
    body: bytes,
    *,
    public_key_id: str,
    public_key: rsa.RSAPublicKey,
) -> None:
    normalized = {str(name).lower(): str(value) for name, value in headers.items()}
    required = (
        "wechatpay-timestamp",
        "wechatpay-nonce",
        "wechatpay-signature",
        "wechatpay-serial",
    )
    if any(not normalized.get(name) for name in required):
        raise WechatPaymentError("PAYMENT_RESPONSE_SIGNATURE_MISSING")
    if normalized["wechatpay-serial"] != public_key_id:
        raise WechatPaymentError("PAYMENT_RESPONSE_KEY_ID_MISMATCH")
    try:
        signature = base64.b64decode(
            normalized["wechatpay-signature"],
            validate=True,
        )
        message = (
            normalized["wechatpay-timestamp"].encode("utf-8")
            + b"\n"
            + normalized["wechatpay-nonce"].encode("utf-8")
            + b"\n"
            + body
            + b"\n"
        )
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (binascii.Error, InvalidSignature, ValueError) as exc:
        raise WechatPaymentError("PAYMENT_RESPONSE_SIGNATURE_INVALID") from exc


def decrypt_notification_resource(
    resource: Mapping[str, object],
    api_v3_key: bytes,
) -> dict[str, object]:
    try:
        if resource.get("algorithm") != "AEAD_AES_256_GCM":
            raise ValueError
        nonce = _required_text(resource, "nonce").encode("utf-8")
        associated_data = _required_text(resource, "associated_data").encode("utf-8")
        ciphertext = base64.b64decode(
            _required_text(resource, "ciphertext"),
            validate=True,
        )
        plaintext = AESGCM(api_v3_key).decrypt(nonce, ciphertext, associated_data)
    except (binascii.Error, InvalidTag, TypeError, ValueError) as exc:
        raise WechatPaymentError("PAYMENT_NOTIFY_DECRYPT_FAILED") from exc
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID") from exc
    if not isinstance(payload, dict):
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID")
    return payload


def parse_and_verify_notification(
    headers: Mapping[str, str],
    body: bytes,
    *,
    public_key_id: str,
    public_key: rsa.RSAPublicKey,
    api_v3_key: bytes,
    now: datetime | None = None,
    tolerance_seconds: int = DEFAULT_NOTIFICATION_TOLERANCE_SECONDS,
) -> VerifiedPaymentNotification:
    timestamp = _parse_notification_timestamp(headers)
    current = _utc(now)
    if abs(int(current.timestamp()) - timestamp) > tolerance_seconds:
        raise WechatPaymentError("PAYMENT_NOTIFY_TIMESTAMP_INVALID")
    try:
        verify_response_signature(
            headers,
            body,
            public_key_id=public_key_id,
            public_key=public_key,
        )
    except WechatPaymentError as exc:
        raise WechatPaymentError("PAYMENT_NOTIFY_SIGNATURE_INVALID") from exc
    try:
        outer = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID") from exc
    if not isinstance(outer, dict) or not isinstance(outer.get("resource"), dict):
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID")
    if (
        outer.get("event_type") != "TRANSACTION.SUCCESS"
        or outer.get("resource_type") != "encrypt-resource"
        or outer["resource"].get("algorithm") != "AEAD_AES_256_GCM"
    ):
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID")
    transaction = decrypt_notification_resource(outer["resource"], api_v3_key)
    amount = transaction.get("amount")
    if not isinstance(amount, dict):
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID")
    try:
        amount_total = amount["total"]
        if (
            type(amount_total) is not int
            or amount_total <= 0
            or amount_total > _SQLITE_INT64_MAX
        ):
            raise ValueError
        trade_type = _required_text(transaction, "trade_type")
        trade_state = _required_text(transaction, "trade_state")
        if trade_type != "NATIVE" or trade_state != "SUCCESS":
            raise ValueError
        return VerifiedPaymentNotification(
            notification_id=_required_text(outer, "id"),
            event_type="TRANSACTION.SUCCESS",
            provider_created_time=_parse_datetime(_required_text(outer, "create_time")),
            appid=_required_text(transaction, "appid"),
            mchid=_required_text(transaction, "mchid"),
            out_trade_no=_required_text(transaction, "out_trade_no"),
            transaction_id=_required_text(transaction, "transaction_id"),
            trade_type=trade_type,
            trade_state=trade_state,
            amount_total=amount_total,
            currency=_required_text(amount, "currency"),
            success_time=_parse_datetime(_required_text(transaction, "success_time")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise WechatPaymentError("PAYMENT_NOTIFY_PAYLOAD_INVALID") from exc


def _required_text(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError
    return value


def _parse_notification_timestamp(headers: Mapping[str, str]) -> int:
    normalized = {str(name).lower(): value for name, value in headers.items()}
    value = normalized.get("wechatpay-timestamp")
    if not isinstance(value, str):
        raise WechatPaymentError("PAYMENT_NOTIFY_TIMESTAMP_INVALID")
    timestamp_text = value.strip(" \t")
    if (
        not timestamp_text
        or len(timestamp_text) > _MAX_NOTIFICATION_TIMESTAMP_DIGITS
        or not timestamp_text.isascii()
        or any(character < "0" or character > "9" for character in timestamp_text)
    ):
        raise WechatPaymentError("PAYMENT_NOTIFY_TIMESTAMP_INVALID")
    try:
        return int(timestamp_text, 10)
    except (ValueError, OverflowError) as exc:
        raise WechatPaymentError("PAYMENT_NOTIFY_TIMESTAMP_INVALID") from exc


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError
    return parsed


def _load_private_key(config: WechatPayConfig) -> rsa.RSAPrivateKey:
    try:
        key = load_pem_private_key(
            config.merchant_private_key_path.read_bytes(),
            password=None,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise WechatPaymentError("PAYMENT_CONFIG_PRIVATE_KEY_INVALID") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise WechatPaymentError("PAYMENT_CONFIG_PRIVATE_KEY_INVALID")
    return key


def _load_public_key(config: WechatPayConfig) -> rsa.RSAPublicKey:
    try:
        key = load_pem_public_key(config.public_key_path.read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise WechatPaymentError("PAYMENT_CONFIG_PUBLIC_KEY_INVALID") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise WechatPaymentError("PAYMENT_CONFIG_PUBLIC_KEY_INVALID")
    return key


def _rfc3339(value: datetime) -> str:
    return _utc(value).isoformat(timespec="seconds")


def _json_object(body: bytes) -> dict[str, object]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WechatPaymentError("PAYMENT_RESPONSE_INVALID") from exc
    if not isinstance(value, dict):
        raise WechatPaymentError("PAYMENT_RESPONSE_INVALID")
    return value


def _optional_json_object(body: bytes) -> dict[str, object]:
    if not body:
        return {}
    try:
        return _json_object(body)
    except WechatPaymentError:
        return {}


def _optional_text(values: Mapping[str, object], key: str) -> str | None:
    value = values.get(key)
    return value if isinstance(value, str) and value else None


def _request_id(response: httpx.Response) -> str | None:
    value = response.headers.get("Request-ID", "")
    return value if SAFE_REQUEST_ID.fullmatch(value) else None


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise WechatPaymentError("PAYMENT_NOTIFY_TIMESTAMP_INVALID")
    return current.astimezone(timezone.utc)
