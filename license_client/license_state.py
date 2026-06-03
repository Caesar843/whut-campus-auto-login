from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from license_client.token_verify import LicenseTokenVerification, parse_utc_datetime


class LicenseStatus(str, Enum):
    UNINITIALIZED = "uninitialized"
    TRIAL_ACTIVE = "trial_active"
    TRIAL_EXPIRED = "trial_expired"
    PAID_ACTIVE = "paid_active"
    PAID_EXPIRED = "paid_expired"
    REVOKED = "revoked"
    TOKEN_INVALID = "token_invalid"
    SERVER_UNREACHABLE = "server_unreachable"
    CONFIG_ONLY = "config_only"


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
                message_for_ui=f"授权状态：正式版，有效期至 {_date_text(expires_at)}",
            )
        status = LicenseStatus.TRIAL_ACTIVE
        return LicenseDecision(
            status=status,
            allowed=True,
            reason=status.value,
            license_type=license_type or "trial",
            expires_at=expires_at,
            days_remaining=days_remaining,
            message_for_ui=f"授权状态：试用中，剩余 {max(days_remaining or 0, 0)} 天",
        )

    if verification.error == "expired":
        status = LicenseStatus.PAID_EXPIRED if license_type in {"paid", "manual"} else LicenseStatus.TRIAL_EXPIRED
        message = "授权状态：正式版已过期，请续费" if status == LicenseStatus.PAID_EXPIRED else "授权状态：试用已结束，请购买正式版"
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
            message_for_ui="授权状态：授权异常，请联网刷新或联系开发者",
        )
    return LicenseDecision(
        status=LicenseStatus.TOKEN_INVALID,
        allowed=False,
        reason=verification.error or "token_invalid",
        license_type=license_type or None,
        expires_at=expires_at,
        days_remaining=days_remaining,
        message_for_ui="授权状态：授权异常，请联网刷新或联系开发者",
    )


def uninitialized_decision() -> LicenseDecision:
    return LicenseDecision(
        status=LicenseStatus.UNINITIALIZED,
        allowed=False,
        reason="missing_signed_license_token",
        message_for_ui="授权状态：未初始化，请连接网络后获取试用资格",
    )


def server_unreachable_decision(*, allowed: bool = False, fallback: Optional[LicenseDecision] = None) -> LicenseDecision:
    if allowed and fallback is not None:
        return LicenseDecision(
            status=LicenseStatus.SERVER_UNREACHABLE,
            allowed=True,
            reason="server_unreachable",
            license_type=fallback.license_type,
            expires_at=fallback.expires_at,
            days_remaining=fallback.days_remaining,
            message_for_ui=f"授权状态：离线可用，本地授权有效至 {_date_text(fallback.expires_at)}",
        )
    return LicenseDecision(
        status=LicenseStatus.SERVER_UNREACHABLE,
        allowed=False,
        reason="server_unreachable",
        message_for_ui="授权状态：未初始化，请连接网络后获取试用资格",
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
