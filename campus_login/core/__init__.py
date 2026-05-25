"""Core campus login interfaces and result types."""

from campus_login.core.client import CampusLoginAdapter, login_with_adapter
from campus_login.core.result import LoginResult, mask_account
from campus_login.core.status import LoginStatus

__all__ = [
    "CampusLoginAdapter",
    "LoginResult",
    "LoginStatus",
    "login_with_adapter",
    "mask_account",
]

