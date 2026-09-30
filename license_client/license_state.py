from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from license_client.token_verify import LicenseTokenVerification, parse_utc_datetime


class LicenseStatus(str, Enum):
    FREE = "free"
    UNINITIALIZED = "uninitialized"
    TRIAL_ACTIVE = "trial_active"
    TRIAL_EXPIRED = "trial_expired"
    PAID_ACTIVE = "paid_active"
    PAID_EXPIRED = "paid_expired"
    REVOKED = "revoked"
    TOKEN_INVALID = "token_invalid"
    SERVER_UNREACHABLE = "server_unreachable"
    BOOTSTRAP_ALLOWED = "bootstrap_allowed"
    CONFIG_ONLY = "config_only"


TOKEN_PERSIST_FAILED_WARNING = "token_persist_failed"
TOKEN_PERSIST_FAILED_MESSAGE = (
    "Current license is valid, but the local license token was not saved; "
    "restart or offline use may require another online check."
)

FREE_LICENSE_MESSAGE = "授权状态：免费版，永久免费使用，无试用期与内购限制。"


@dataclass(frozen=True)
class LicenseDecision:
    status: LicenseStatus
    allowed: bool
    reason: str
    license_type: Optional[str] = None
    expires_at: Optional[str] = None
    days_remaining: Optional[int] = None
    message_for_ui: str = ""
    signed_license_token: Optional[str] = None
    bootstrap_required: bool = False
    retryable: bool = False
    warning_code: Optional[str] = None
    usage_sync_required: bool = False


def free_decision(
    *,
    reason: str = "free_mode",
    usage_sync_required: bool = False,
    message_for_ui: Optional[str] = None,
) -> LicenseDecision:
    """免费版放行判定：允许所有功能，不读取本地凭证、不判断试用期。"""
    return LicenseDecision(
        status=LicenseStatus.FREE,
        allowed=True,
        reason=reason,
        license_type="free",
        message_for_ui=message_for_ui or FREE_LICENSE_MESSAGE,
        usage_sync_required=usage_sync_required,
    )


def evaluate_local_license(
    verification: LicenseTokenVerification,
    *,
    now: Optional[datetime] = None,
) -> LicenseDecision:
    payload = verification.payload or {}
    license_type = str(payload.get("license_type") or "")
    expires_at = str(payload.get("expires_at") or "") or None
    days_remaining = _days_remaining(expires_at, now)

    if verification.valid:
        if license_type in {"paid", "manual"}:
            status = LicenseStatus.PAID_ACTIVE
            return LicenseDecision(
                status=status,
                allowed=True,
                reason=status.value,
                license_type=license_type,
                expires_at=expires_at,
                days_remaining=days_remaining,
                message_for_ui=f"授权状态：免费版（历史凭证），有效期至 {_date_text(expires_at)}",
            )
        status = LicenseStatus.TRIAL_ACTIVE
        return LicenseDecision(
            status=status,
            allowed=True,
            reason=status.value,
            license_type=license_type or "trial",
            expires_at=expires_at,
            days_remaining=days_remaining,
            message_for_ui=f"授权状态：免费版（历史凭证），剩余 {max(days_remaining or 0, 0)} 天",
        )

    if verification.error == "expired":
        status = (
            LicenseStatus.PAID_EXPIRED
            if license_type in {"paid", "manual"}
            else LicenseStatus.TRIAL_EXPIRED
        )
        message = (
            "历史授权凭证已过期，请联网刷新授权。"
            if status == LicenseStatus.PAID_EXPIRED
            else "历史试用凭证已过期，请联网刷新授权。"
        )
        return LicenseDecision(
            status=status,
            allowed=False,
            reason=verification.error,
            license_type=license_type or None,
            expires_at=expires_at,
            days_remaining=0,
            message_for_ui=message,
        )
    if verification.error == "revoked":
        return LicenseDecision(
            status=LicenseStatus.REVOKED,
            allowed=False,
            reason="revoked",
            license_type=license_type or None,
            expires_at=expires_at,
            days_remaining=days_remaining,
            message_for_ui="本地授权凭证无效，请联网刷新授权。",
        )
    return LicenseDecision(
        status=LicenseStatus.TOKEN_INVALID,
        allowed=False,
        reason=verification.error or "token_invalid",
        license_type=license_type or None,
        expires_at=expires_at,
        days_remaining=days_remaining,
        message_for_ui="本地授权凭证无效，请联网刷新授权。",
    )


def uninitialized_decision(reason: str = "missing_signed_license_token") -> LicenseDecision:
    return LicenseDecision(
        status=LicenseStatus.UNINITIALIZED,
        allowed=False,
        reason=reason,
        retryable=True,
        message_for_ui="授权尚未初始化，或当前无法连接授权服务。请检查网络后点击“重试初始化”。",
    )


def server_unreachable_decision(
    *,
    allowed: bool = False,
    fallback: Optional[LicenseDecision] = None,
    reason: str = "server_unreachable",
    retryable: bool = False,
) -> LicenseDecision:
    if allowed and fallback is not None:
        return LicenseDecision(
            status=LicenseStatus.SERVER_UNREACHABLE,
            allowed=True,
            reason=reason,
            license_type=fallback.license_type,
            expires_at=fallback.expires_at,
            days_remaining=fallback.days_remaining,
            retryable=retryable,
            message_for_ui=f"授权状态：离线可用，本地授权有效至 {_date_text(fallback.expires_at)}",
        )
    return LicenseDecision(
        status=LicenseStatus.SERVER_UNREACHABLE,
        allowed=False,
        reason=reason,
        retryable=retryable,
        message_for_ui="授权尚未初始化，或当前无法连接授权服务。请检查网络后点击“重试初始化”。",
    )


def bootstrap_allowed_decision() -> LicenseDecision:
    return LicenseDecision(
        status=LicenseStatus.BOOTSTRAP_ALLOWED,
        allowed=True,
        reason="bootstrap_allowed",
        message_for_ui="首次使用：将先尝试完成校园网登录，联网后自动获取试用资格。",
        bootstrap_required=True,
    )


def _days_remaining(expires_at: Optional[str], now: Optional[datetime]) -> Optional[int]:
    parsed = parse_utc_datetime(expires_at or "")
    if parsed is None:
        return None
    current = now or datetime.now(timezone.utc)
    seconds = (parsed - current).total_seconds()
    if seconds <= 0:
        return 0
    return int((seconds + 86399) // 86400)


def _date_text(expires_at: Optional[str]) -> str:
    parsed = parse_utc_datetime(expires_at or "")
    if parsed is None:
        return "未知"
    return parsed.date().isoformat()
