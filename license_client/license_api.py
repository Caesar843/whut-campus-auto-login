from __future__ import annotations

import logging
import platform
import socket
from dataclasses import dataclass
from typing import Any, Mapping, Optional

import requests

from license_client.constants import APP_VERSION, PRODUCT_ID, resolve_license_server_url
from license_client.http_transport import request as http_request


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LicenseApiResult:
    reachable: bool
    status: str
    signed_license_token: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    error: Optional[str] = None


class LicenseApiClient:
    def __init__(self, base_url: Optional[str] = None, timeout: float = 2.0):
        self.base_url = (base_url or resolve_license_server_url()).rstrip("/")
        self.timeout = timeout

    def register_device(
        self,
        *,
        device_fingerprint_hash: str,
    ) -> LicenseApiResult:
        payload = {
            "product_id": PRODUCT_ID,
            "device_fingerprint_hash": device_fingerprint_hash,
            "device_name": socket.gethostname(),
            "os": platform.platform(),
            "app_version": APP_VERSION,
        }
        return self._post("/device/register", payload)

    def refresh_license(self, *, device_fingerprint_hash: str) -> LicenseApiResult:
        payload = {
            "product_id": PRODUCT_ID,
            "device_fingerprint_hash": device_fingerprint_hash,
            "app_version": APP_VERSION,
        }
        return self._post("/license/refresh", payload)

    def _post(self, path: str, payload: Mapping[str, Any]) -> LicenseApiResult:
        url = f"{self.base_url}{path}"
        try:
            response = http_request(
                "post",
                url,
                json=payload,
                timeout=self.timeout,
                requests_module=requests,
            )
        except requests.Timeout:
            LOGGER.warning("License server request failed: Timeout")
            return LicenseApiResult(
                reachable=False,
                status="request_timeout",
                error="request_timeout",
            )
        except requests.RequestException as exc:
            LOGGER.warning("License server request failed: %s", exc.__class__.__name__)
            return LicenseApiResult(
                reachable=False,
                status="network_unreachable",
                error="network_unreachable",
            )
        try:
            response_payload = response.json() if response.content else {}
        except ValueError:
            LOGGER.warning("License server response was not JSON.")
            if response.status_code >= 500:
                return LicenseApiResult(
                    reachable=False,
                    status="server_error",
                    error="server_error",
                )
            return LicenseApiResult(
                reachable=True,
                status="invalid_response",
                error="invalid_response",
            )
        if not isinstance(response_payload, dict):
            return LicenseApiResult(
                reachable=True,
                status="invalid_response",
                error="invalid_response",
            )
        if response.status_code >= 500:
            return LicenseApiResult(
                reachable=False,
                status="server_error",
                payload=response_payload,
                error="server_error",
            )
        if response.status_code >= 400:
            return LicenseApiResult(reachable=True, status=str(response_payload.get("status") or "error"), payload=response_payload)
        return LicenseApiResult(
            reachable=True,
            status=str(response_payload.get("status") or response_payload.get("license_status") or "ok"),
            signed_license_token=response_payload.get("signed_license_token"),
            payload=response_payload,
        )
