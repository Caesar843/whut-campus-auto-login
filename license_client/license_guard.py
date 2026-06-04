from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Callable, Optional

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.result import LoginResult, mask_account
from campus_login.core.status import LoginStatus
from campus_login.local_config import has_login_config

from license_client.constants import PRODUCT_ID
from license_client.device_fingerprint import generate_device_fingerprint_hash
from license_client.license_api import LicenseApiClient, LicenseApiResult
from license_client.license_state import (
    LicenseDecision,
    LicenseStatus,
    bootstrap_allowed_decision,
    evaluate_local_license,
    server_unreachable_decision,
    uninitialized_decision,
)
from license_client.token_store import (
    load_signed_license_token,
    save_signed_license_token,
)
from license_client.token_verify import verify_signed_license_token


LOGGER = logging.getLogger(__name__)
LicenseCheckFunc = Callable[..., LicenseDecision]
LicenseBootstrapSyncFunc = Callable[..., LicenseDecision]


def check_license_before_login(
    *,
    token_path: Optional[Path] = None,
    public_key_b64: Optional[str] = None,
    device_fingerprint_hash: Optional[str] = None,
    api_client: Optional[Callable[[], LicenseApiResult]] = None,
    campus_account: Optional[str] = None,
    saved_login_available_func: Callable[[], bool] = has_login_config,
    campus_network_probe_func: Optional[Callable[[], bool]] = None,
) -> LicenseDecision:
    current_device_hash = device_fingerprint_hash or generate_device_fingerprint_hash()
    loaded = load_signed_license_token(token_path=token_path)
    public_key = public_key_b64 or _public_key_from_env()

    if loaded.signed_license_token:
        if not public_key:
            return _missing_public_key_decision()
        return _verify_to_decision(
            loaded.signed_license_token,
            public_key_b64=public_key,
            device_fingerprint_hash=current_device_hash,
        )

    if loaded.status == "corrupt":
        return LicenseDecision(
            status=LicenseStatus.TOKEN_INVALID,
            allowed=False,
            reason=loaded.error or "corrupt_token_file",
            message_for_ui="本地授权凭证无效，请联网刷新授权。",
        )

    api_result = _call_api(
        api_client,
        device_fingerprint_hash=current_device_hash,
        needs_register=True,
        campus_account=campus_account,
    )
    if not api_result.reachable:
        if _can_bootstrap_login(
            saved_login_available_func=saved_login_available_func,
            campus_network_probe_func=campus_network_probe_func or default_campus_network_probe,
        ):
            return bootstrap_allowed_decision()
        return server_unreachable_decision()
    if not api_result.signed_license_token:
        return uninitialized_decision()
    if not public_key:
        return _missing_public_key_decision()

    refreshed_decision = _verify_to_decision(
        api_result.signed_license_token,
        public_key_b64=public_key,
        device_fingerprint_hash=current_device_hash,
    )
    if refreshed_decision.allowed:
        save_signed_license_token(api_result.signed_license_token, token_path=token_path)
    return refreshed_decision


def try_initialize_license_after_bootstrap_login(
    *,
    bootstrap_decision: LicenseDecision,
    token_path: Optional[Path] = None,
    public_key_b64: Optional[str] = None,
    device_fingerprint_hash: Optional[str] = None,
    api_client: Optional[Callable[[], LicenseApiResult]] = None,
    campus_account: Optional[str] = None,
) -> LicenseDecision:
    if not bootstrap_decision.bootstrap_required:
        return bootstrap_decision

    current_device_hash = device_fingerprint_hash or generate_device_fingerprint_hash()
    api_result = _call_api(
        api_client,
        device_fingerprint_hash=current_device_hash,
        needs_register=True,
        campus_account=campus_account,
    )
    if not api_result.reachable:
        return server_unreachable_decision()
    if not api_result.signed_license_token:
        return uninitialized_decision()

    public_key = public_key_b64 or _public_key_from_env()
    if not public_key:
        return _missing_public_key_decision()

    decision = _verify_to_decision(
        api_result.signed_license_token,
        public_key_b64=public_key,
        device_fingerprint_hash=current_device_hash,
    )
    if decision.allowed:
        save_signed_license_token(api_result.signed_license_token, token_path=token_path)
    return decision


def default_campus_network_probe(timeout: float = 1.5) -> bool:
    try:
        context = WhutCampusLoginAdapter(timeout=timeout, retry_delay=0).bootstrap_portal_context()
    except Exception as exc:
        LOGGER.info("Campus portal probe failed for bootstrap license flow: %s", exc.__class__.__name__)
        return False
    return bool(getattr(context, "portal_detected", False))


def get_current_license_state(
    *,
    token_path: Optional[Path] = None,
    public_key_b64: Optional[str] = None,
    device_fingerprint_hash: Optional[str] = None,
) -> LicenseDecision:
    loaded = load_signed_license_token(token_path=token_path)
    if not loaded.signed_license_token:
        if loaded.status == "corrupt":
            return LicenseDecision(
                status=LicenseStatus.TOKEN_INVALID,
                allowed=False,
                reason=loaded.error or "corrupt_token_file",
                message_for_ui="本地授权凭证无效，请联网刷新授权。",
            )
        return uninitialized_decision()
    public_key = public_key_b64 or _public_key_from_env()
    if not public_key:
        return _missing_public_key_decision()
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
        bootstrap_required=decision.bootstrap_required,
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


def _can_bootstrap_login(
    *,
    saved_login_available_func: Callable[[], bool],
    campus_network_probe_func: Callable[[], bool],
) -> bool:
    try:
        has_saved_login = bool(saved_login_available_func())
    except Exception as exc:
        LOGGER.warning("Saved login availability check failed: %s", exc.__class__.__name__)
        return False
    if not has_saved_login:
        return False
    try:
        return bool(campus_network_probe_func())
    except Exception as exc:
        LOGGER.warning("Campus network probe failed: %s", exc.__class__.__name__)
        return False


def _missing_public_key_decision() -> LicenseDecision:
    return LicenseDecision(
        status=LicenseStatus.TOKEN_INVALID,
        allowed=False,
        reason="missing_public_key",
        message_for_ui="本地授权凭证无效，请联网刷新授权。",
    )


def _account_hash(campus_account: Optional[str]) -> Optional[str]:
    if not campus_account:
        return None
    return hashlib.sha256(str(campus_account).strip().encode("utf-8")).hexdigest()


def _public_key_from_env() -> str:
    import os

    return os.environ.get("LICENSE_PUBLIC_KEY", "").strip()
