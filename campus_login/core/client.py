from typing import Protocol

from campus_login.core.result import LoginResult


class CampusLoginAdapter(Protocol):
    def login(self, username: str, password: str) -> LoginResult:
        """Attempt campus network login with the given local credentials."""


class CampusLogoutAdapter(Protocol):
    def logout(self) -> LoginResult:
        """Attempt campus network logout for the current online session."""


def login_with_adapter(
    adapter: CampusLoginAdapter, username: str, password: str
) -> LoginResult:
    return adapter.login(username=username, password=password)


def logout_with_adapter(adapter: CampusLogoutAdapter) -> LoginResult:
    return adapter.logout()
