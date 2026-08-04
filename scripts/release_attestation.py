"""Offline, redacted evidence generation for a PyInstaller ``onedir`` artifact."""

from __future__ import annotations

import base64
import dis
import hashlib
import hmac
import importlib.metadata
import json
import os
import re
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import CodeType
from typing import Any, Callable, Iterable, Mapping

from license_client.public_key import validate_release_server_url
from app_version import APP_VERSION, windows_version_tuple


SCHEMA_VERSION = "p6-a1c-2"
PRODUCT_ID = "whut-campus-auto-login"
EMBEDDED_CONFIG_MODULE = "_license_client_embedded_build_config"
LICENSE_FILENAMES = {"license", "license.txt", "license.md", "copying", "notice", "authors"}
MAX_LICENSE_FILE_BYTES = 1024 * 1024
MAX_LICENSE_ARCHIVE_BYTES = 64 * 1024 * 1024
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_WINDOWS_REPARSE_POINT = 0x0400
MANIFEST_FIELDS = {
    "product_id",
    "app_version",
    "source_commit",
    "build_environment",
    "build_timestamp_utc",
    "python_version",
    "pyinstaller_version",
    "packaging_mode",
    "public_key_sha256",
    "artifact_verification",
}
VERIFICATION_FIELDS = {
    "embedded_config_present",
    "build_environment_match",
    "production_url_validated",
    "production_url_match",
    "public_key_sha256",
    "public_key_sha256_match",
}


class AttestationError(RuntimeError):
    """A controlled failure whose message contains no input values."""


def _path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _is_reparse_point(path: Path) -> bool:
    details = os.lstat(path)
    return stat.S_ISLNK(details.st_mode) or bool(getattr(details, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)


def _assert_not_reparse_point(path: Path) -> None:
    try:
        if _is_reparse_point(path):
            raise AttestationError("artifact path contains a reparse point")
    except AttestationError:
        raise
    except OSError as exc:
        raise AttestationError("artifact path is not accessible") from exc


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _assert_no_reparse_ancestors(path: Path) -> None:
    current = _absolute_path(path)
    while not os.path.lexists(current):
        if current.parent == current:
            raise AttestationError("artifact path is not accessible")
        current = current.parent
    while True:
        _assert_not_reparse_point(current)
        if current.parent == current:
            return
        current = current.parent


def validate_artifact_paths(onedir: Path, staging_dir: Path) -> tuple[Path, Path]:
    root = _absolute_path(onedir)
    staging = _absolute_path(staging_dir)
    _assert_no_reparse_ancestors(root)
    _assert_no_reparse_ancestors(staging.parent)
    if os.path.lexists(staging):
        _assert_not_reparse_point(staging)
    try:
        root = root.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise AttestationError("onedir input is not accessible") from exc
    if not root.is_dir():
        raise AttestationError("onedir input is not a directory")
    if staging == root or staging.is_relative_to(root) or root.is_relative_to(staging):
        raise AttestationError("staging directory must be separate from onedir")
    return root, staging


def validate_attestation_inputs(
    *,
    source_commit: str,
    app_version: str,
    build_environment: str,
    python_version: str,
    pyinstaller_version: str,
) -> None:
    if _COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise AttestationError("source commit must be a full lowercase SHA-1")
    try:
        windows_version_tuple(app_version)
    except ValueError as exc:
        raise AttestationError("app version is invalid") from exc
    if app_version != APP_VERSION or build_environment != "production":
        raise AttestationError("attestation inputs do not match the production baseline")
    try:
        baseline_path = Path(__file__).resolve().parents[1] / "packaging" / "windows" / "build_baseline.json"
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise AttestationError("build baseline is unavailable") from exc
    if python_version != baseline.get("python_version") or pyinstaller_version != baseline.get("pyinstaller_version"):
        raise AttestationError("attestation inputs do not match the build baseline")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_artifact_path(root: Path, path: Path) -> str:
    _assert_not_reparse_point(root)
    if os.path.lexists(path):
        _assert_not_reparse_point(path)
    root = root.resolve(strict=True)
    try:
        relative = path.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError) as exc:
        raise AttestationError("artifact path is outside the selected onedir directory") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise AttestationError("artifact relative path is invalid")
    return relative.as_posix()


def artifact_file_records(root: Path) -> list[dict[str, Any]]:
    root = _absolute_path(root)
    _assert_no_reparse_ancestors(root)
    try:
        root = root.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise AttestationError("onedir input is not accessible") from exc
    if not root.is_dir():
        raise AttestationError("onedir input is not a directory")
    records = []
    directories = [root]
    while directories:
        directory = directories.pop()
        _assert_not_reparse_point(directory)
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise AttestationError("artifact directory cannot be inspected") from exc
        for entry in entries:
            path = Path(entry.path)
            _assert_not_reparse_point(path)
            if entry.is_dir(follow_symlinks=False):
                directories.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise AttestationError("artifact contains a non-regular file")
            records.append(
                {
                    "relative_path": relative_artifact_path(root, path),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                }
            )
    records.sort(key=lambda item: item["relative_path"])
    keys = [_path_key(record["relative_path"]) for record in records]
    if len(keys) != len(set(keys)):
        raise AttestationError("artifact contains a Windows path collision")
    return records


def build_manifest(root: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
    if set(metadata) - MANIFEST_FIELDS:
        raise AttestationError("manifest metadata contains unapproved fields")
    verification = metadata.get("artifact_verification", {})
    if not isinstance(verification, Mapping) or set(verification) - VERIFICATION_FIELDS:
        raise AttestationError("manifest metadata contains invalid verification fields")
    for field, value in verification.items():
        if field == "public_key_sha256":
            if not _is_sha256(str(value)):
                raise AttestationError("manifest metadata contains invalid public-key fingerprint")
        elif not isinstance(value, bool):
            raise AttestationError("manifest metadata contains invalid verification value")
    if "public_key_sha256" in metadata and not _is_sha256(str(metadata["public_key_sha256"])):
        raise AttestationError("manifest metadata contains invalid public-key fingerprint")
    for field, value in metadata.items():
        if field in {"artifact_verification", "public_key_sha256"}:
            continue
        if not isinstance(value, str) or _looks_like_sensitive_location(value):
            raise AttestationError("manifest metadata contains unsafe value")
    manifest = {"schema_version": SCHEMA_VERSION, **dict(metadata), "files": artifact_file_records(root)}
    return manifest


def _looks_like_sensitive_location(value: str) -> bool:
    return "://" in value or Path(value).is_absolute() or PureWindowsPath(value).is_absolute()


def write_json(path: Path, value: Any) -> None:
    path.write_text(canonical_json(value), encoding="utf-8", newline="\n")


def create_release_zip(root: Path, zip_path: Path) -> None:
    records = artifact_file_records(root)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            archive.write(root / Path(record["relative_path"]), record["relative_path"])


def _sha256_zip_member(archive: zipfile.ZipFile, name: str) -> str:
    digest = hashlib.sha256()
    with archive.open(name, "r") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_zip_member_names(names: Iterable[str]) -> list[str]:
    checked = []
    for name in names:
        candidate = PurePosixPath(name)
        if (
            not name
            or "\\" in name
            or candidate.is_absolute()
            or str(candidate) != name
            or any(part in {"", ".", ".."} for part in candidate.parts)
            or PureWindowsPath(name).is_absolute()
            or PureWindowsPath(name).drive
            or any(part.rstrip(". ") != part or PureWindowsPath(part).is_reserved() for part in candidate.parts)
        ):
            raise AttestationError("ZIP member path is invalid")
        checked.append(name)
    if len(checked) != len(set(checked)) or len({_path_key(name) for name in checked}) != len(checked):
        raise AttestationError("ZIP members contain duplicate or Windows-colliding paths")
    return checked


def verify_zip_against_manifest(zip_path: Path, manifest: Mapping[str, Any]) -> None:
    expected_records = list(manifest.get("files", []))
    expected_names = _validate_zip_member_names(str(record["relative_path"]) for record in expected_records)
    expected = {record["relative_path"]: record for record in expected_records}
    if len(expected) != len(expected_records):
        raise AttestationError("ZIP members do not match manifest")
    with zipfile.ZipFile(zip_path) as archive:
        names = _validate_zip_member_names(archive.namelist())
        if names != sorted(names) or set(names) != set(expected):
            raise AttestationError("ZIP members do not match manifest")
        for name, record in expected.items():
            info = archive.getinfo(name)
            if info.file_size != record["size_bytes"] or _sha256_zip_member(archive, name) != record["sha256"]:
                raise AttestationError("ZIP member hash does not match manifest")


def build_spdx_sbom(components: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    packages = []
    used_ids: set[str] = set()
    for component in sorted(components, key=lambda item: (str(item["name"]).casefold(), str(item["version"]))):
        scope = str(component.get("scope", "uncertain"))
        if scope not in {"bundled", "build-test", "uncertain"}:
            raise AttestationError("SBOM component scope is invalid")
        name, version = str(component["name"]), str(component["version"])
        license_value = str(component.get("license") or "NOASSERTION")
        base_id = f"SPDXRef-Package-{_safe_name(name)}-{_safe_name(version)}"
        spdx_id = base_id
        suffix = 2
        while spdx_id in used_ids:
            spdx_id = f"{base_id}-{suffix}"
            suffix += 1
        used_ids.add(spdx_id)
        packages.append(
            {
                "SPDXID": spdx_id,
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": license_value,
                "licenseDeclared": license_value,
                "annotations": [
                    {
                        "annotationType": "OTHER",
                        "annotator": "Tool: P6-A1c-2",
                        "comment": f"scope={scope}",
                    }
                ],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "WHUT Campus Auto Login release artifact",
        "documentNamespace": "https://spdx.invalid/p6-a1c-2",
        "creationInfo": {"creators": ["Tool: P6-A1c-2"]},
        "packages": packages,
    }


def _safe_name(value: str) -> str:
    return "".join(character if character.isalnum() or character in {".", "-", "_"} else "-" for character in value).strip(".-_") or "unknown"


def collect_local_licenses(distributions: Iterable[Any], output_dir: Path) -> list[dict[str, str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    total_bytes = 0
    used_names = {_path_key(path.name) for path in output_dir.iterdir()}
    for distribution in sorted(distributions, key=lambda item: (str(item.name).casefold(), str(item.version))):
        metadata = distribution.metadata
        name, version = str(distribution.name), str(distribution.version)
        license_value = str(metadata.get("License-Expression") or metadata.get("License") or "NOASSERTION")
        candidates = []
        for item in distribution.files or []:
            candidate = Path(item)
            if candidate.name.casefold() not in LICENSE_FILENAMES:
                continue
            if candidate.is_absolute() or PureWindowsPath(str(candidate)).is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
                raise AttestationError("license metadata path is invalid")
            candidates.append(candidate)
        copied = []
        for candidate in sorted(candidates, key=lambda item: item.as_posix()):
            source = Path(distribution.locate_file(candidate))
            if not source.is_file() or source.is_symlink():
                continue
            with source.open("rb") as stream:
                data = stream.read(MAX_LICENSE_FILE_BYTES + 1)
            if len(data) > MAX_LICENSE_FILE_BYTES or total_bytes + len(data) > MAX_LICENSE_ARCHIVE_BYTES:
                raise AttestationError("license archive exceeds size limit")
            base_name = f"{_safe_name(name)}-{_safe_name(version)}-{_safe_name(source.name)}"
            destination = output_dir / base_name
            index = 2
            while _path_key(destination.name) in used_names:
                destination = output_dir / f"{base_name}-{index}"
                index += 1
            destination.write_bytes(data)
            used_names.add(_path_key(destination.name))
            total_bytes += len(data)
            copied.append(destination.name)
        records.append(
            {
                "name": name,
                "version": version,
                "license": license_value,
                "license_file_status": "present" if copied else "missing",
                "license_files": ",".join(copied),
            }
        )
    return records


def verify_embedded_build_config(
    config: Mapping[str, str] | None,
    *,
    approved_url: str,
    expected_public_key_sha256: str,
) -> dict[str, Any]:
    if not config:
        raise AttestationError("embedded configuration is missing")
    if config.get("BUILD_ENVIRONMENT") != "production":
        raise AttestationError("embedded build environment is not production")
    try:
        approved = validate_release_server_url(approved_url)
        embedded_url = validate_release_server_url(str(config.get("LICENSE_SERVER_URL", "")))
    except ValueError as exc:
        raise AttestationError("embedded production URL is not valid HTTPS") from exc
    if embedded_url != approved:
        raise AttestationError("embedded production URL does not match approved input")
    try:
        encoded_key = str(config.get("LICENSE_PUBLIC_KEY_B64", ""))
        raw_key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AttestationError("embedded public key is invalid") from exc
    if len(raw_key) != 32 or base64.b64encode(raw_key).decode("ascii") != encoded_key:
        raise AttestationError("embedded public key has invalid length")
    fingerprint = hashlib.sha256(raw_key).hexdigest()
    if not _is_sha256(expected_public_key_sha256) or not hmac.compare_digest(fingerprint, expected_public_key_sha256.lower()):
        raise AttestationError("embedded public key fingerprint does not match")
    return {
        "embedded_config_present": True,
        "build_environment_match": True,
        "production_url_validated": True,
        "production_url_match": True,
        "public_key_sha256": fingerprint,
        "public_key_sha256_match": True,
    }


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)


def embedded_config_from_code(code: CodeType) -> dict[str, str]:
    allowed = {"BUILD_ENVIRONMENT", "LICENSE_PUBLIC_KEY_B64", "LICENSE_SERVER_URL", "BUILD_SESSION_ID"}
    config: dict[str, str] = {}
    pending: Any = None
    for instruction in dis.get_instructions(code):
        if instruction.opname == "LOAD_CONST":
            pending = instruction.argval
        elif instruction.opname == "STORE_NAME" and instruction.argval in allowed:
            if not isinstance(pending, str):
                raise AttestationError("embedded configuration assignment is invalid")
            config[instruction.argval] = pending
            pending = None
    if not {"BUILD_ENVIRONMENT", "LICENSE_PUBLIC_KEY_B64", "LICENSE_SERVER_URL"} <= set(config):
        raise AttestationError("embedded configuration is missing required values")
    return config


def read_embedded_build_config(
    exe_path: Path,
    archive_reader_factory: Callable[[str], Any] | None = None,
) -> dict[str, str]:
    try:
        if archive_reader_factory is None:
            from PyInstaller.archive.readers import CArchiveReader

            archive_reader_factory = CArchiveReader
        archive = archive_reader_factory(str(exe_path))
        pyz_names = [name for name, entry in archive.toc.items() if entry[-1] == "z"]
        for name in sorted(pyz_names):
            pyz = archive.open_embedded_archive(name)
            if EMBEDDED_CONFIG_MODULE not in pyz.toc:
                continue
            code = pyz.extract(EMBEDDED_CONFIG_MODULE)
            if not isinstance(code, CodeType):
                raise AttestationError("embedded configuration is not executable module code")
            return embedded_config_from_code(code)
    except AttestationError:
        raise
    except Exception as exc:
        raise AttestationError("embedded configuration is missing or archive inspection failed") from exc
    raise AttestationError("embedded configuration is missing from PyInstaller archive")


def read_pyinstaller_module_names(exe_path: Path) -> set[str]:
    try:
        from PyInstaller.archive.readers import CArchiveReader

        archive = CArchiveReader(str(exe_path))
        names = set()
        for name, entry in archive.toc.items():
            if entry[-1] == "z":
                names.update(archive.open_embedded_archive(name).toc)
        return names
    except Exception as exc:
        raise AttestationError("PyInstaller archive module inventory is unavailable") from exc


MAX_ZIP_MEMBERS = 1000
MAX_ZIP_MEMBER_SIZE_BYTES = 50 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024

_BINARY_EXTENSIONS = {
    ".dll", ".exe", ".pyd", ".so", ".dylib", ".dat", ".bin",
    ".ico", ".png", ".jpg", ".jpeg", ".ttf", ".woff", ".woff2",
}

_PEM_PRIVATE_KEY_REGEX = re.compile(
    b"-----BEGIN (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----[^\\x00]{16,4096}?-----END (?:RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----"
)

_SENSITIVE_ASSIGNMENT_REGEX = re.compile(
    b"(?:LICENSE_PRIVATE_KEY|CAMPUS_PASSWORD)\\s*=\\s*['\"][^'\"]+['\"]|(?:LICENSE_PRIVATE_KEY|CAMPUS_PASSWORD)=[^\\s\\x00\\r\\n]{3,}"
)

_PROJECT_ABSOLUTE_PATH_REGEX = re.compile(
    b"(?:[A-Za-z]:[/\\\\]+(?:Users|home)[/\\\\]+|/home/|/Users/)[^\\s\\x00\\r\\n]*whut-campus-auto-login|/etc/whut-campus-auto-login|/var/lib/whut-campus-auto-login",
    re.IGNORECASE,
)

_TEXT_ABSOLUTE_PATH_REGEX = re.compile(
    b"(?:[A-Za-z]:[/\\\\]+Users[/\\\\]+|/home/|/Users/)(?:[^\\s\\x00\\r\\n]*whut-campus-auto-login|lenovo[/\\\\]+Desktop[/\\\\]+whut-campus-auto-login)",
    re.IGNORECASE,
)

_ENV_DUMP_KEYS = [
    re.compile(b"(?:^|[\\r\\n\\x00])PATH=[^\\r\\n\\x00]+"),
    re.compile(b"(?:^|[\\r\\n\\x00])(?:USERPROFILE|HOME)=[^\\r\\n\\x00]+"),
    re.compile(b"(?:^|[\\r\\n\\x00])(?:SYSTEMROOT|SHELL|TMP|TEMP)=[^\\r\\n\\x00]+"),
]


def _is_binary_path(path: Path) -> bool:
    return path.suffix.casefold() in _BINARY_EXTENSIONS


def _read_file_head_tail(path: Path, max_bytes: int = 10 * 1024 * 1024) -> bytes:
    file_size = path.stat().st_size
    if file_size <= max_bytes:
        return path.read_bytes()
    with path.open("rb") as stream:
        head = stream.read(max_bytes // 2)
        stream.seek(max(0, file_size - (max_bytes // 2)))
        tail = stream.read(max_bytes // 2)
        return head + b"\n...\n" + tail


def _check_content_category(path: Path) -> list[str]:
    categories = []
    data = _read_file_head_tail(path)
    is_binary = _is_binary_path(path)

    # 1. private_key_marker
    if _PEM_PRIVATE_KEY_REGEX.search(data):
        categories.append("private_key_marker")
    elif not is_binary:
        if b"Ed25519PrivateKey" in data:
            categories.append("private_key_marker")
        else:
            for pem_boundary in (
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN OPENSSH PRIVATE KEY-----",
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
            ):
                if pem_boundary in data:
                    categories.append("private_key_marker")
                    break

    # 2. credential_marker
    if _SENSITIVE_ASSIGNMENT_REGEX.search(data):
        categories.append("credential_marker")
    elif not is_binary and (b"LICENSE_PRIVATE_KEY" in data or b"CAMPUS_PASSWORD" in data):
        categories.append("credential_marker")

    # 3. absolute_path
    if is_binary:
        if _PROJECT_ABSOLUTE_PATH_REGEX.search(data):
            categories.append("absolute_path")
    else:
        if _PROJECT_ABSOLUTE_PATH_REGEX.search(data) or _TEXT_ABSOLUTE_PATH_REGEX.search(data):
            categories.append("absolute_path")

    # 4. environment_dump
    matches = sum(1 for p in _ENV_DUMP_KEYS if p.search(data))
    if matches >= 2:
        categories.append("environment_dump")

    return categories


def scan_forbidden_content(root: Path) -> list[dict[str, Any]]:
    findings = []
    for record in artifact_file_records(root):
        relative_path = record["relative_path"]
        parts = set(relative_path.split("/"))
        filename = Path(relative_path).name.casefold()
        categories = []
        if filename == ".env" or filename.startswith(".env."):
            categories.append("environment_file")
        if filename.endswith((".sqlite", ".sqlite3", ".db")):
            categories.append("sqlite_database")
        if filename.endswith((".pyc", ".pyo")) or "__pycache__" in parts:
            categories.append("exposed_bytecode")
        if filename == f"{EMBEDDED_CONFIG_MODULE}.py":
            categories.append("embedded_config_source")
        if {"tests", "scripts", "license_server", "build", ".git"} & parts:
            categories.append("disallowed_source_tree")
        if "token" in filename or "credential" in filename:
            categories.append("token_or_credential_file")

        file_path = root / Path(relative_path)
        if filename.endswith(".zip"):
            zip_findings = scan_zip_forbidden_content(file_path)
            for zf in zip_findings:
                categories.append(zf["category"])
        else:
            categories.extend(_check_content_category(file_path))

        findings.extend({"category": category, "count": 1, "relative_path": relative_path} for category in sorted(set(categories)))
    return sorted(findings, key=lambda item: (item["category"], item["relative_path"]))


def scan_zip_forbidden_content(zip_path: Path) -> list[dict[str, Any]]:
    findings = []
    with zipfile.ZipFile(zip_path) as archive:
        members = archive.infolist()
        if len(members) > MAX_ZIP_MEMBERS:
            raise AttestationError("ZIP archive exceeds member count limit")
        total_uncompressed = sum(info.file_size for info in members)
        if total_uncompressed > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES:
            raise AttestationError("ZIP archive exceeds total uncompressed size limit")

        checked_names = set(_validate_zip_member_names(archive.namelist()))
        for info in sorted(members, key=lambda item: item.filename):
            if info.filename not in checked_names or info.filename.endswith("/"):
                continue
            if info.file_size > MAX_ZIP_MEMBER_SIZE_BYTES:
                raise AttestationError("ZIP member exceeds uncompressed size limit")

            temporary = tempfile.TemporaryDirectory()
            try:
                path = Path(temporary.name) / info.filename
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info.filename) as source, path.open("wb") as destination:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
                member_findings = scan_forbidden_content(Path(temporary.name))
                for mf in member_findings:
                    if mf["category"] == "exposed_bytecode":
                        continue
                    findings.append({"category": mf["category"], "count": 1, "relative_path": info.filename})
            finally:
                temporary.cleanup()
    return findings


def write_sha256sums(paths: Mapping[str, Path], output_path: Path) -> None:
    lines = []
    for name in sorted(paths):
        if Path(name).name != name:
            raise AttestationError("checksum artifact name is invalid")
        lines.append(f"{sha256_file(paths[name])}  {name}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def verify_sha256sums(sums_path: Path, root: Path, external_paths: Mapping[str, Path] | None = None) -> None:
    external_paths = external_paths or {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        candidate = external_paths.get(name, root / name)
        if separator != "  " or not _is_sha256(digest) or Path(name).name != name or sha256_file(candidate) != digest:
            raise AttestationError("SHA256SUMS verification failed")


def publish_atomically(staging_dir: Path, writer: Callable[[Path], None]) -> None:
    staging_dir = _absolute_path(staging_dir)
    _assert_no_reparse_ancestors(staging_dir.parent)
    if os.path.lexists(staging_dir):
        _assert_not_reparse_point(staging_dir)
        raise AttestationError("staging destination already exists")
    staging_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{staging_dir.name}.", dir=staging_dir.parent))
    try:
        writer(temporary)
        os.replace(temporary, staging_dir)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def components_from_local_metadata(distributions: Iterable[Any], archive_modules: set[str]) -> list[dict[str, str]]:
    components = []
    archive_roots = {module.split(".", 1)[0] for module in archive_modules}
    for distribution in distributions:
        top_level_text = distribution.read_text("top_level.txt")
        top_levels = {line.strip() for line in (top_level_text or "").splitlines() if line.strip()}
        scope = "uncertain" if top_levels & archive_roots else "build-test" if top_levels else "uncertain"
        components.append(
            {
                "name": str(distribution.name),
                "version": str(distribution.version),
                "scope": scope,
                "license": str(distribution.metadata.get("License-Expression") or distribution.metadata.get("License") or "NOASSERTION"),
            }
        )
    return components


def attest_release(
    *,
    onedir: Path,
    staging_dir: Path,
    source_commit: str,
    app_version: str,
    build_environment: str,
    approved_license_server_url: str,
    expected_public_key_sha256: str,
    python_version: str,
    pyinstaller_version: str,
) -> dict[str, Any]:
    validate_attestation_inputs(
        source_commit=source_commit,
        app_version=app_version,
        build_environment=build_environment,
        python_version=python_version,
        pyinstaller_version=pyinstaller_version,
    )
    onedir, staging_dir = validate_artifact_paths(onedir, staging_dir)
    records = artifact_file_records(onedir)
    exe_records = [record for record in records if record["relative_path"].lower().endswith(".exe")]
    if len(exe_records) != 1:
        raise AttestationError("onedir must contain exactly one executable")
    if scan_forbidden_content(onedir):
        raise AttestationError("forbidden content found in onedir")
    verification = verify_embedded_build_config(
        read_embedded_build_config(onedir / Path(exe_records[0]["relative_path"])),
        approved_url=approved_license_server_url,
        expected_public_key_sha256=expected_public_key_sha256,
    )
    metadata = {
        "product_id": PRODUCT_ID,
        "app_version": app_version,
        "source_commit": source_commit,
        "build_environment": build_environment,
        "build_timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "python_version": python_version,
        "pyinstaller_version": pyinstaller_version,
        "packaging_mode": "onedir",
        "public_key_sha256": verification["public_key_sha256"],
        "artifact_verification": verification,
    }

    def writer(output: Path) -> None:
        manifest = build_manifest(onedir, metadata)
        manifest_path = output / "artifact-manifest.json"
        write_json(manifest_path, manifest)
        zip_path = output / "WHUTCampusAutoLogin.zip"
        create_release_zip(onedir, zip_path)
        verify_zip_against_manifest(zip_path, manifest)
        sbom_path = output / "sbom.spdx.json"
        write_json(
            sbom_path,
            build_spdx_sbom(
                components_from_local_metadata(
                    list(importlib.metadata.distributions()),
                    read_pyinstaller_module_names(onedir / Path(exe_records[0]["relative_path"])),
                )
            ),
        )
        licenses_dir = output / "third-party-licenses"
        license_records = collect_local_licenses(importlib.metadata.distributions(), licenses_dir)
        write_json(output / "third-party-licenses.json", license_records)
        license_zip = output / "third-party-licenses.zip"
        create_release_zip(licenses_dir, license_zip)
        write_json(output / "evidence.json", {"result": "PASS", "artifact_verification": verification})
        findings = (
            scan_zip_forbidden_content(zip_path)
            + scan_zip_forbidden_content(license_zip)
            + scan_forbidden_content(output)
        )
        if findings:
            raise AttestationError("forbidden content found in generated evidence")
        sums_path = output / "SHA256SUMS.txt"
        write_sha256sums(
            {
                Path(exe_records[0]["relative_path"]).name: onedir / Path(exe_records[0]["relative_path"]),
                zip_path.name: zip_path,
                manifest_path.name: manifest_path,
                sbom_path.name: sbom_path,
                license_zip.name: license_zip,
            },
            sums_path,
        )
        verify_sha256sums(
            sums_path,
            output,
            {Path(exe_records[0]["relative_path"]).name: onedir / Path(exe_records[0]["relative_path"])},
        )

    publish_atomically(staging_dir, writer)
    return {"result": "PASS", "public_key_sha256": verification["public_key_sha256"]}
