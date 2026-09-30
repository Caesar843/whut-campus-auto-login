"""客户端授权入口（免费版）。

免费版语义：
- 授权判定不再阻断任何功能。校园网登录、开机自启、托盘后台一律放行，
  本地 signed_token、试用期、付费状态都不再参与判定；
- 客户端不再有支付入口，也不再因为授权状态弹窗或降级功能；
- 仍然会在软件启动时、以及校园网登录成功后，向授权服务上报一次设备使用情况
  （只上报设备指纹哈希与时间），用于服务端统计使用人数与活跃度。
  上报失败只记录日志，不影响任何功能。

服务端仍然保留设备注册与授权签发接口，供后台统计使用；
本文档中的“授权服务”不参与客户端功能开关。
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus

from license_client.device_fingerprint import generate_device_fingerprint_hash
from license_client.license_api import LicenseApiClient, LicenseApiResult
from license_client.license_state import (
    LicenseDecision,
    free_decision,
)


LOGGER = logging.getLogger(__name__)
LicenseCheckFunc = Callable[..., LicenseDecision]
LicenseBootstrapSyncFunc = Callable[..., LicenseDecision]
LicenseInitializeFunc = Callable[..., LicenseDecision]


def check_license_before_login() -> LicenseDecision:
    """登录前判定：免费版直接放行，不做网络请求、不读本地凭证、不判断试用期。"""
    return free_decision(usage_sync_required=True)


def initialize_license(
    *,
    device_fingerprint_hash: Optional[str] = None,
    api_client: Optional[Callable[[], LicenseApiResult]] = None,
) -> LicenseDecision:
    """软件启动时调用：上报一次设备使用情况，然后无条件放行。"""
    report_device_usage(
        device_fingerprint_hash=device_fingerprint_hash,
        api_client=api_client,
    )
    return free_decision()


def try_initialize_license_after_bootstrap_login(
    *,
    bootstrap_decision: LicenseDecision,
    device_fingerprint_hash: Optional[str] = None,
    api_client: Optional[Callable[[], LicenseApiResult]] = None,
) -> LicenseDecision:
    """校园网登录成功后调用：刷新一次设备使用情况（活跃度统计），仍然无条件放行。"""
    if not (
        bootstrap_decision.bootstrap_required
        or getattr(bootstrap_decision, "usage_sync_required", False)
    ):
        return bootstrap_decision
    report_device_usage(
        device_fingerprint_hash=device_fingerprint_hash,
        api_client=api_client,
    )
    return free_decision()


def get_current_license_state() -> LicenseDecision:
    """当前授权展示状态：免费版永远允许使用。"""
    return free_decision(usage_sync_required=True)


def report_device_usage(
    *,
    device_fingerprint_hash: Optional[str] = None,
    api_client: Optional[Callable[[], LicenseApiResult]] = None,
) -> Optional[LicenseApiResult]:
    """尽力上报设备使用情况；任何失败都不抛出，只记录日志。"""
    try:
        fingerprint = device_fingerprint_hash or generate_device_fingerprint_hash()
    except Exception as exc:
        LOGGER.warning("Device fingerprint generation failed: %s", exc.__class__.__name__)
        return None
    try:
        if api_client is not None:
            result = api_client()
        else:
            result = LicenseApiClient().register_device(
                device_fingerprint_hash=fingerprint
            )
    except Exception as exc:
        LOGGER.warning("Device usage report failed: %s", exc.__class__.__name__)
        return None
    if not getattr(result, "reachable", False):
        LOGGER.info(
            "Device usage report skipped: %s",
            getattr(result, "error", None) or getattr(result, "status", "unknown"),
        )
    return result


def license_blocked_result(decision: LicenseDecision) -> LoginResult:
    """保留的兼容出口：免费版不会产生阻断判定，调用方无需处理。"""
    return LoginResult(
        status=LoginStatus.UNKNOWN_ERROR,
        message=decision.message_for_ui or "License does not allow campus login.",
        error_code="LICENSE_BLOCKED",
        response_summary={
            "license_status": decision.status.value,
            "license_reason": decision.reason,
        },
    )