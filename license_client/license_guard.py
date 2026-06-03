from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Optional

from campus_login.core.result import LoginResult, mask_account
from campus_login.core.status import LoginStatus

from license_client.constants import PRODUCT_ID
from license_client.device_fingerprint import generate_device_fingerprint_hash
from license_client.license_api import LicenseApiClient, LicenseApiResult
from license_client.license_state import (
    LicenseDecision,
    LicenseStatus,
    evaluate_local_license,
    server_unreachable_decision,
    uninitialized_decision,
)
from license_client.token_store import (
    load_signed_license_token,
    save_signed_license_token,
)
from license_client.token_verify import verify_signed_license_token


LicenseCheckFunc = Callable[[], LicenseDecision]


def check_license_before_login(
    *,
    token_path: Optional[Path] = None,
    public_key_b64: Optional[str] = None,
    device_fingerprint_hash: Optional[str] = None,
    api_client: Optional[Callable[[], LicenseApiResult]] = None,
    campus_account: Optional[str] = None,
) -> LicenseDecision:
    current_device_hash = device_fingerprint_hash or generate_device_fingerprint_hash()
    loaded = load_signed_license_token(token_path=token_path)
    public_key = public_key_b64 or _public_key_from_env()

    if loaded.signed_license_token and public_key:
        local_decision = _verify_to_decision(
            loaded.signed_license_token,
            public_key_b64=public_key,
            device_fingerprint_hash=current_device_hash,
        )
        if local_decision.allowed:
            return local_decision
    elif loaded.signed_license_token and not public_key:
        local_decision = LicenseDecision(
            status=LicenseStatus.TOKEN_INVALID,
            allowed=False,
            reason="missing_public_key",
            message_for_ui="授权状态：授权异常，请联网刷新或联系开发者",
        )
    else:
        local_decision = uninitialized_decision()

    api_result = _call_api(
        api_client,
        device_fingerprint_hash=current_device_hash,
        needs_register=loaded.status == "missing",
        campus_account=campus_account,
    )
    if not api_result.reachable:
        return server_unreachable_decision()
    if not api_result.signed_license_token:
        return local_decision
    if not public_key:
        return LicenseDecision(
            status=LicenseStatus.TOKEN_INVALID,
            allowed=False,
            reason="missing_public_key",
            message_for_ui="授权状态：授权异常，请联网刷新或联系开发者",
        )

    refreshed_decision = _verify_to_decision(
        api_result.signed_license_token,
        public_key_b64=public_key,
        device_fingerprint_hash=current_device_hash,
    )
    if refreshed_decision.allowed:
        save_signed_license_token(api_result.signed_license_token, token_path=token_path)
    return refreshed_decision


def get_current_license_state(
    *,
    token_path: Optional[Path] = None,
    public_key_b64: Optional[str] = None,
    device_fingerprint_hash: Optional[str] = None,
) -> LicenseDecision:
    loaded = load_signed_license_token(token_path=token_path)
    if not loaded.signed_license_token:
        return uninitialized_decision()
    public_key = public_key_b64 or _public_key_from_env()
    if not public_key:
        return LicenseDecision(
            status=LicenseStatus.TOKEN_INVALID,
            allowed=False,
            reason="missing_public_key",
            message_for_ui="授权状态：授权异常，请联网刷新或联系开发者",
        )
    return _verify_to_decision(
        loaded.signed_license_token,
        public_key_b64=public_key,
        device_fingerprint_hash=device_fingerprint_hash or generate_device_fingerprint_hash(),
    )


def license_blocked_result(decision: LicenseDecision) -> LoginResult:
    return LoginResult(
        status=LoginStatus.UNKNOWN_ERROR,
        message=decision.message_for_ui or "License does not allow campus login.",
        error_code="LICENSE_BLOCKED",
        response_summary={
            "license_status": decision.status.value,
            "license_reason": decision.reason,
        },
    )


def _verify_to_decision(
    signed_license_token: str,
    *,
    public_key_b64: str,
    device_fingerprint_hash: str,
) -> LicenseDecision:
    verification = verify_signed_license_token(
        signed_license_token,
        public_key_b64=public_key_b64,
        current_device_fingerprint_hash=device_fingerprint_hash,
        expected_product_id=PRODUCT_ID,
    )
    decision = evaluate_local_license(verification)
    return LicenseDecision(
        status=decision.status,
        allowed=decision.allowed,
        reason=decision.reason,
        license_type=decision.license_type,
        expires_at=decision.expires_at,
        days_remaining=decision.days_remaining,
        message_for_ui=decision.message_for_ui,
        signed_license_token=signed_license_token if decision.allowed else None,
    )


def _call_api(
    api_client: Optional[Callable[[], LicenseApiResult]],
    *,
    device_fingerprint_hash: str,
    needs_register: bool,
    campus_account: Optional[str],
) -> LicenseApiResult:
    if api_client is not None:
        return api_client()
    client = LicenseApiClient()
    if needs_register:
        return client.register_device(
            device_fingerprint_hash=device_fingerprint_hash,
            campus_account_hash=_account_hash(campus_account),
            campus_account_masked=mask_account(campus_account),
        )
    return client.refresh_license(device_fingerprint_hash=device_fingerprint_hash)


def _account_hash(campus_account: Optional[str]) -> Optional[str]:
    if not campus_account:
        return None
    return hashlib.sha256(str(campus_account).strip().encode("utf-8")).hexdigest()


def _public_key_from_env() -> str:
    import os

    return os.environ.get("LICENSE_PUBLIC_KEY", "").strip()
