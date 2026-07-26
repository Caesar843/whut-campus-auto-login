"""Offline, redacted evidence generation for a PyInstaller ``onedir`` artifact."""

from __future__ import annotations

import base64
import dis
import hashlib
import hmac
import importlib.metadata
import json
import os
import shutil
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from types import CodeType
from typing import Any, Callable, Iterable, Mapping

from license_client.public_key import validate_release_server_url


SCHEMA_VERSION = "p6-a1c-2"
PRODUCT_ID = "whut-campus-auto-login"
EMBEDDED_CONFIG_MODULE = "_license_client_embedded_build_config"
LICENSE_FILENAMES = {"license", "license.txt", "license.md", "copying", "notice", "authors"}
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


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_artifact_path(root: Path, path: Path) -> str:
    root = root.resolve(strict=True)
    if path.is_symlink():
        raise AttestationError("artifact contains a symbolic link")
    try:
        relative = path.resolve(strict=True).relative_to(root)
    except (FileNotFoundError, ValueError) as exc:
        raise AttestationError("artifact path is outside the selected onedir directory") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise AttestationError("artifact relative path is invalid")
    return relative.as_posix()


def artifact_file_records(root: Path) -> list[dict[str, Any]]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise AttestationError("onedir input is not a directory")
    records = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise AttestationError("artifact contains a symbolic link")
        if not path.is_file():
            continue
        records.append(
            {
                "relative_path": relative_artifact_path(root, path),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return sorted(records, key=lambda item: item["relative_path"])


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


def verify_zip_against_manifest(zip_path: Path, manifest: Mapping[str, Any]) -> None:
    expected = {record["relative_path"]: record for record in manifest.get("files", [])}
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        if names != sorted(names) or set(names) != set(expected):
            raise AttestationError("ZIP members do not match manifest")
        for name, record in expected.items():
            info = archive.getinfo(name)
            if info.file_size != record["size_bytes"] or _sha256_zip_member(archive, name) != record["sha256"]:
                raise AttestationError("ZIP member hash does not match manifest")


def build_spdx_sbom(components: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    packages = []
    for component in sorted(components, key=lambda item: (str(item["name"]).casefold(), str(item["version"]))):
        scope = str(component.get("scope", "uncertain"))
        if scope not in {"bundled", "build-test", "uncertain"}:
            raise AttestationError("SBOM component scope is invalid")
        name, version = str(component["name"]), str(component["version"])
        license_value = str(component.get("license") or "NOASSERTION")
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{_safe_name(name)}-{_safe_name(version)}",
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
    for distribution in sorted(distributions, key=lambda item: (str(item.name).casefold(), str(item.version))):
        metadata = distribution.metadata
        name, version = str(distribution.name), str(distribution.version)
        license_value = str(metadata.get("License-Expression") or metadata.get("License") or "NOASSERTION")
        candidates = [
            Path(candidate)
            for candidate in (distribution.files or [])
            if Path(candidate).name.casefold() in LICENSE_FILENAMES
        ]
        copied = []
        for candidate in sorted(candidates, key=lambda item: item.as_posix()):
            source = Path(distribution.locate_file(candidate))
            if not source.is_file() or source.is_symlink():
                continue
            base_name = f"{_safe_name(name)}-{_safe_name(version)}-{_safe_name(source.name)}"
            destination = output_dir / base_name
            index = 2
            while destination.exists():
                destination = output_dir / f"{base_name}-{index}"
                index += 1
            destination.write_bytes(source.read_bytes())
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
        raw_key = base64.b64decode(str(config.get("LICENSE_PUBLIC_KEY_B64", "")), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AttestationError("embedded public key is invalid") from exc
    if len(raw_key) != 32:
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


_CONTENT_MARKERS = {
    "private_key_marker": (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----", b"Ed25519PrivateKey"),
    "credential_marker": (b"LICENSE_PRIVATE_KEY", b"CAMPUS_PASSWORD", b"Credential Manager"),
    "absolute_path": (b"C:\\Users\\", b"/home/", b"/Users/"),
    "environment_dump": (b"PATH=", b"USERPROFILE=", b"HOME="),
}


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
        data = (root / Path(relative_path)).read_bytes()
        for category, markers in _CONTENT_MARKERS.items():
            if any(marker in data for marker in markers):
                categories.append(category)
        findings.extend({"category": category, "count": 1, "relative_path": relative_path} for category in sorted(set(categories)))
    return sorted(findings, key=lambda item: (item["category"], item["relative_path"]))


def scan_zip_forbidden_content(zip_path: Path) -> list[dict[str, Any]]:
    findings = []
    with zipfile.ZipFile(zip_path) as archive:
        for member in sorted(archive.namelist()):
            if member.endswith("/"):
                continue
            temporary = tempfile.TemporaryDirectory()
            try:
                path = Path(temporary.name) / member
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.read(member))
                findings.extend(scan_forbidden_content(Path(temporary.name)))
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
    staging_dir = staging_dir.resolve()
    if staging_dir.exists():
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
        scope = "uncertain" if not top_levels else "bundled" if top_levels & archive_roots else "build-test"
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
    if build_environment != "production":
        raise AttestationError("attestation requires production build environment")
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
