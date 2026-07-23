import re


APP_VERSION = "0.1.0"
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")


def windows_version_tuple(version: str) -> tuple[int, int, int, int]:
    if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("version must contain exactly three numeric segments")
    parts = tuple(int(part) for part in version.split("."))
    if any(part > 65535 for part in parts):
        raise ValueError("version segments must be between 0 and 65535")
    return parts[0], parts[1], parts[2], 0
