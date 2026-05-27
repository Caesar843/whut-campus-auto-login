from dataclasses import dataclass
from typing import Callable, Optional

from campus_login.adapters.whut import WhutCampusLoginAdapter
from campus_login.core.client import login_with_adapter
from campus_login.core.result import LoginResult
from campus_login.core.status import LoginStatus
from campus_login.local_config import load_login_config


AdapterFactory = Callable[[float], WhutCampusLoginAdapter]
ConfigLoader = Callable[[], object]


@dataclass(frozen=True)
class SavedLoginCredentials:
    username: str
    password: str
    config: object


def load_saved_login_credentials(
    config_loader: Optional[ConfigLoader] = None,
) -> SavedLoginCredentials:
    loader = config_loader or load_login_config
    config = loader()
    username = str(getattr(config, "username", "") or "").strip()
    password = getattr(config, "password", None) or ""
    return SavedLoginCredentials(username=username, password=password, config=config)


def login_with_saved_config(
    timeout: float = 5.0,
    *,
    adapter_factory: Optional[AdapterFactory] = None,
    config_loader: Optional[ConfigLoader] = None,
) -> LoginResult:
    credentials = load_saved_login_credentials(config_loader)
    if not credentials.username or not credentials.password:
        return LoginResult(
            status=LoginStatus.UNKNOWN_ERROR,
            message="Saved login config is incomplete.",
        )

    factory = adapter_factory or (
        lambda item_timeout: WhutCampusLoginAdapter(timeout=item_timeout)
    )
    return login_with_adapter(
        factory(timeout),
        credentials.username,
        credentials.password,
    )
