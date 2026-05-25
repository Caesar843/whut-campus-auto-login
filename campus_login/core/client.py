from typing import Protocol

from campus_login.core.result import LoginResult


class CampusLoginAdapter(Protocol):
    def login(self, username: str, password: str) -> LoginResult:
        """Attempt campus network login with the given local credentials."""


def login_with_adapter(
    adapter: CampusLoginAdapter, username: str, password: str
) -> LoginResult:
    return adapter.login(username=username, password=password)

