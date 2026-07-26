import base64
import hashlib
import json
import os
import warnings
import zipfile
from pathlib import Path

import pytest


TEST_URL = "https://release-attestation-test.invalid"
TEST_PUBLIC_KEY = base64.b64encode(b"T" * 32).decode("ascii")
TEST_FINGERPRINT = hashlib.sha256(b"T" * 32).hexdigest()


def _module():
    import scripts.release_attestation as module

    return module


def _onedir(tmp_path: Path) -> Path:
    root = tmp_path / "WHUTCampusAutoLogin"
    (root / "_internal").mkdir(parents=True)
    (root / "WHUTCampusAutoLogin.exe").write_bytes(b"MZ-test")
    (root / "_internal" / "library.dat").write_bytes(b"library")
    return root


def _embedded_config(**overrides: str) -> dict[str, str]:
    values = {
        "BUILD_ENVIRONMENT": "production",
        "LICENSE_PUBLIC_KEY_B64": TEST_PUBLIC_KEY,
        "LICENSE_SERVER_URL": TEST_URL,
        "BUILD_SESSION_ID": "test-session-must-not-escape",
    }
    values.update(overrides)
    return values


def test_manifest_has_sorted_relative_records_and_redacted_metadata(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    (root / "a.txt").write_text("a", encoding="utf-8")
    metadata = {
        "product_id": "whut-campus-auto-login",
        "app_version": "0.1.0-test",
        "source_commit": "a" * 40,
        "build_environment": "production",
        "build_timestamp_utc": "2026-07-26T00:00:00Z",
        "python_version": "3.11.9",
        "pyinstaller_version": "6.21.0",
        "packaging_mode": "onedir",
        "public_key_sha256": TEST_FINGERPRINT,
        "artifact_verification": {"production_url_validated": True},
    }

    manifest = module.build_manifest(root, metadata)

    assert manifest["schema_version"] == "p6-a1c-2"
    assert [record["relative_path"] for record in manifest["files"]] == sorted(
        record["relative_path"] for record in manifest["files"]
    )
    assert all(not Path(record["relative_path"]).is_absolute() for record in manifest["files"])
    serialized = module.canonical_json(manifest)
    for forbidden in (str(root), TEST_URL, TEST_PUBLIC_KEY, "test-session-must-not-escape"):
        assert forbidden not in serialized


def test_manifest_rejects_path_outside_onedir(tmp_path):
    module = _module()
    root = _onedir(tmp_path)

    with pytest.raises(module.AttestationError, match="outside"):
        module.relative_artifact_path(root, tmp_path / "outside.txt")


def test_manifest_rejects_unapproved_metadata_without_echoing_it(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    secret_like_value = "operator-not-for-manifest"

    with pytest.raises(module.AttestationError, match="metadata") as raised:
        module.build_manifest(root, {"product_id": "test", "operator_name": secret_like_value})

    assert secret_like_value not in str(raised.value)
    assert secret_like_value not in repr(raised.value)


def test_manifest_rejects_url_or_absolute_path_in_an_allowed_field(tmp_path):
    module = _module()
    root = _onedir(tmp_path)

    with pytest.raises(module.AttestationError, match="metadata"):
        module.build_manifest(root, {"product_id": "test", "app_version": "https://release-attestation-test.invalid"})


def test_manifest_file_sizes_and_sha256_are_real(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    payload = b"attestation bytes"
    (root / "payload.bin").write_bytes(payload)

    records = module.artifact_file_records(root)
    record = next(item for item in records if item["relative_path"] == "payload.bin")

    assert record == {
        "relative_path": "payload.bin",
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def test_zip_contains_only_sorted_onedir_members(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    zip_path = tmp_path / "release.zip"

    module.create_release_zip(root, zip_path)

    with zipfile.ZipFile(zip_path) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert "WHUTCampusAutoLogin.exe" in archive.namelist()
        assert all(".." not in member for member in archive.namelist())
        assert all(not member.startswith("build/") for member in archive.namelist())


def test_zip_hashes_must_match_manifest(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    manifest = module.build_manifest(root, {"product_id": "test"})
    zip_path = tmp_path / "release.zip"
    module.create_release_zip(root, zip_path)

    assert module.verify_zip_against_manifest(zip_path, manifest) is None
    manifest["files"][0]["sha256"] = "0" * 64
    with pytest.raises(module.AttestationError, match="manifest"):
        module.verify_zip_against_manifest(zip_path, manifest)


@pytest.mark.parametrize("members", [("payload.bin", "payload.bin"), ("Payload.bin", "payload.bin")])
def test_zip_verifier_rejects_duplicate_or_windows_casefold_members(tmp_path, members):
    module = _module()
    root = _onedir(tmp_path)
    (root / "payload.bin").write_bytes(b"payload")
    manifest = module.build_manifest(root, {"product_id": "test"})
    archive = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w") as zipped:
            for record in manifest["files"]:
                if record["relative_path"] == "payload.bin":
                    for member in members:
                        zipped.writestr(member, b"payload")
                else:
                    zipped.writestr(record["relative_path"], (root / record["relative_path"]).read_bytes())

    with pytest.raises(module.AttestationError, match="ZIP"):
        module.verify_zip_against_manifest(archive, manifest)


def test_spdx_has_required_structure_and_scopes_are_not_overclaimed():
    module = _module()

    sbom = module.build_spdx_sbom(
        [
            {"name": "bundled-pkg", "version": "1", "scope": "bundled", "license": "MIT"},
            {"name": "test-pkg", "version": "2", "scope": "build-test", "license": None},
            {"name": "unknown-pkg", "version": "3", "scope": "uncertain", "license": ""},
        ]
    )

    assert sbom["spdxVersion"] == "SPDX-2.3"
    by_name = {package["name"]: package for package in sbom["packages"]}
    assert by_name["bundled-pkg"]["annotations"][0]["comment"] == "scope=bundled"
    assert by_name["test-pkg"]["annotations"][0]["comment"] == "scope=build-test"
    assert by_name["unknown-pkg"]["licenseConcluded"] == "NOASSERTION"


def test_spdx_assigns_unique_ids_after_safe_name_normalization():
    module = _module()

    sbom = module.build_spdx_sbom(
        [
            {"name": "a/b", "version": "1", "scope": "uncertain"},
            {"name": "a:b", "version": "1", "scope": "uncertain"},
        ]
    )

    assert len({package["SPDXID"] for package in sbom["packages"]}) == 2


class _Distribution:
    def __init__(self, name: str, version: str, metadata: dict[str, str], files: list[Path], located_files=None):
        self.name = name
        self.version = version
        self.metadata = metadata
        self.files = files
        self.located_files = located_files or {}

    def locate_file(self, file: Path) -> Path:
        return self.located_files.get(file, file)


def test_license_collection_records_metadata_files_missing_and_collisions(tmp_path):
    module = _module()
    first = tmp_path / "first" / "LICENSE"
    second = tmp_path / "second" / "LICENSE"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_text("first license", encoding="utf-8")
    second.write_text("second license", encoding="utf-8")
    output = tmp_path / "licenses"
    distributions = [
        _Distribution("alpha", "1.0", {"License": "MIT"}, [Path("LICENSE")], {Path("LICENSE"): first}),
        _Distribution("beta", "2.0", {"License-Expression": "Apache-2.0"}, [Path("LICENSE")], {Path("LICENSE"): second}),
        _Distribution("gamma", "3.0", {}, []),
    ]

    records = module.collect_local_licenses(distributions, output)

    assert [record["name"] for record in records] == ["alpha", "beta", "gamma"]
    assert records[0]["license"] == "MIT"
    assert records[1]["license"] == "Apache-2.0"
    assert records[2]["license"] == "NOASSERTION"
    assert records[2]["license_file_status"] == "missing"
    written = sorted(path.name for path in output.iterdir())
    assert written == ["alpha-1.0-LICENSE", "beta-2.0-LICENSE"]


def test_license_collection_rejects_metadata_path_traversal_and_oversized_file(tmp_path):
    module = _module()
    source = tmp_path / "outside" / "LICENSE"
    source.parent.mkdir()
    source.write_bytes(b"x" * (module.MAX_LICENSE_FILE_BYTES + 1))
    output = tmp_path / "licenses"

    class UnsafeDistribution(_Distribution):
        def locate_file(self, _file):
            return source

    with pytest.raises(module.AttestationError, match="license"):
        module.collect_local_licenses([UnsafeDistribution("unsafe", "1", {}, [Path("../LICENSE")])], output)

    with pytest.raises(module.AttestationError, match="license"):
        module.collect_local_licenses([UnsafeDistribution("large", "1", {}, [Path("LICENSE")])], output)


def test_embedded_config_requires_production_and_never_returns_key_or_session():
    module = _module()

    evidence = module.verify_embedded_build_config(
        _embedded_config(),
        approved_url=TEST_URL,
        expected_public_key_sha256=TEST_FINGERPRINT,
    )

    assert evidence == {
        "embedded_config_present": True,
        "build_environment_match": True,
        "production_url_validated": True,
        "production_url_match": True,
        "public_key_sha256": TEST_FINGERPRINT,
        "public_key_sha256_match": True,
    }
    assert TEST_PUBLIC_KEY not in repr(evidence)
    assert "test-session-must-not-escape" not in repr(evidence)


@pytest.mark.parametrize(
    "config, url, fingerprint, message",
    [
        (None, TEST_URL, TEST_FINGERPRINT, "missing"),
        (_embedded_config(BUILD_ENVIRONMENT="development"), TEST_URL, TEST_FINGERPRINT, "production"),
        (_embedded_config(LICENSE_SERVER_URL="https://other.invalid"), TEST_URL, TEST_FINGERPRINT, "URL"),
        (_embedded_config(LICENSE_SERVER_URL="http://127.0.0.1"), "http://127.0.0.1", TEST_FINGERPRINT, "HTTPS"),
        (_embedded_config(LICENSE_PUBLIC_KEY_B64="not-base64"), TEST_URL, TEST_FINGERPRINT, "public key"),
        (_embedded_config(LICENSE_PUBLIC_KEY_B64=base64.b64encode(b"x").decode("ascii")), TEST_URL, TEST_FINGERPRINT, "public key"),
        (_embedded_config(LICENSE_PUBLIC_KEY_B64=TEST_PUBLIC_KEY[:-2] + "R="), TEST_URL, TEST_FINGERPRINT, "public key"),
        (_embedded_config(), TEST_URL, "0" * 64, "fingerprint"),
    ],
)
def test_embedded_config_rejects_missing_or_invalid_values_without_echo(
    config, url, fingerprint, message
):
    module = _module()

    with pytest.raises(module.AttestationError, match=message) as raised:
        module.verify_embedded_build_config(
            config,
            approved_url=url,
            expected_public_key_sha256=fingerprint,
        )

    assert TEST_PUBLIC_KEY not in str(raised.value)
    assert "test-session-must-not-escape" not in repr(raised.value)


def test_embedded_config_reader_extracts_assignment_code_without_execution():
    module = _module()
    code = compile(
        "BUILD_ENVIRONMENT = 'production'\n"
        f"LICENSE_PUBLIC_KEY_B64 = {TEST_PUBLIC_KEY!r}\n"
        f"LICENSE_SERVER_URL = {TEST_URL!r}\n"
        "BUILD_SESSION_ID = 'test-session-must-not-escape'\n",
        "embedded.py",
        "exec",
    )

    assert module.embedded_config_from_code(code) == _embedded_config()


def test_embedded_config_reader_uses_archive_adapter_without_executing_an_exe(tmp_path):
    module = _module()
    code = compile(
        "BUILD_ENVIRONMENT = 'production'\n"
        f"LICENSE_PUBLIC_KEY_B64 = {TEST_PUBLIC_KEY!r}\n"
        f"LICENSE_SERVER_URL = {TEST_URL!r}\n"
        "BUILD_SESSION_ID = 'test-session-must-not-escape'\n",
        "embedded.py",
        "exec",
    )

    class Pyz:
        toc = {"_license_client_embedded_build_config": object()}

        @staticmethod
        def extract(_name):
            return code

    class Archive:
        toc = {"PYZ-00.pyz": (0, 0, 0, 0, "z")}

        @staticmethod
        def open_embedded_archive(_name):
            return Pyz()

    assert module.read_embedded_build_config(
        tmp_path / "ignored.exe", archive_reader_factory=lambda _path: Archive()
    ) == _embedded_config()


def test_embedded_config_reader_rejects_missing_module(tmp_path):
    module = _module()

    with pytest.raises(module.AttestationError, match="missing"):
        module.read_embedded_build_config(tmp_path / "not-a-pyinstaller.exe")


def test_forbidden_content_scanner_reports_category_count_and_path_only(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    marker = b"-----BEGIN PRIVATE KEY-----"
    (root / "unexpected.txt").write_bytes(marker)
    (root / ".env").write_text("ignored", encoding="utf-8")

    findings = module.scan_forbidden_content(root)

    assert {(item["category"], item["relative_path"]) for item in findings} >= {
        ("private_key_marker", "unexpected.txt"),
        ("environment_file", ".env"),
    }
    assert all(set(item) == {"category", "count", "relative_path"} for item in findings)
    assert marker.decode("ascii") not in json.dumps(findings)


def test_forbidden_content_scanner_allows_normal_internal_data_but_rejects_exposed_pyc(tmp_path):
    module = _module()
    root = _onedir(tmp_path)

    assert module.scan_forbidden_content(root) == []
    (root / "_internal" / "accidental.pyc").write_bytes(b"bytecode")
    assert any(item["category"] == "exposed_bytecode" for item in module.scan_forbidden_content(root))


def test_forbidden_content_scanner_rejects_exposed_embedded_config_source(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    (root / "_license_client_embedded_build_config.py").write_text("BUILD_ENVIRONMENT = 'production'", encoding="utf-8")

    findings = module.scan_forbidden_content(root)

    assert {item["category"] for item in findings} == {"embedded_config_source"}


def test_sha256sums_cross_checks_named_artifacts(tmp_path):
    module = _module()
    paths = {}
    for name in ("WHUTCampusAutoLogin.exe", "release.zip", "manifest.json", "sbom.json", "licenses.zip"):
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        paths[name] = path
    sums = tmp_path / "SHA256SUMS.txt"

    module.write_sha256sums(paths, sums)

    assert module.verify_sha256sums(sums, tmp_path) is None
    assert [line.split("  ")[1] for line in sums.read_text(encoding="utf-8").splitlines()] == sorted(paths)


def test_sha256sums_can_cross_check_the_original_executable_without_copying_it(tmp_path):
    module = _module()
    executable = tmp_path / "input" / "WHUTCampusAutoLogin.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"MZ")
    output = tmp_path / "output"
    output.mkdir()
    manifest = output / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    sums = output / "SHA256SUMS.txt"

    module.write_sha256sums({executable.name: executable, manifest.name: manifest}, sums)

    assert module.verify_sha256sums(sums, output, {executable.name: executable}) is None


def test_component_scope_uses_archive_module_evidence_without_claiming_all_installed_packages():
    module = _module()

    class Distribution:
        def __init__(self, name, top_level):
            self.name = name
            self.version = "1"
            self.metadata = {}
            self._top_level = top_level

        def read_text(self, name):
            return self._top_level if name == "top_level.txt" else None

    components = module.components_from_local_metadata(
        [Distribution("frozen", "frozen_module\n"), Distribution("build-only", "other\n"), Distribution("unknown", None)],
        {"frozen_module.submodule"},
    )

    assert {item["name"]: item["scope"] for item in components} == {
        "build-only": "build-test",
        "frozen": "uncertain",
        "unknown": "uncertain",
    }


def test_zip_scanner_reports_forbidden_member_without_showing_marker(tmp_path):
    module = _module()
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("leak.txt", b"-----BEGIN OPENSSH PRIVATE KEY-----")

    findings = module.scan_zip_forbidden_content(archive)

    assert findings == [{"category": "private_key_marker", "count": 1, "relative_path": "leak.txt"}]


def test_zip_scanner_rejects_path_escape_and_encrypted_private_key_marker(tmp_path):
    module = _module()
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("../escape.txt", b"safe")

    with pytest.raises(module.AttestationError, match="ZIP"):
        module.scan_zip_forbidden_content(archive)

    root = _onedir(tmp_path)
    (root / "encrypted.pem").write_bytes(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert any(item["category"] == "private_key_marker" for item in module.scan_forbidden_content(root))


def test_artifact_paths_reject_nested_staging_and_reparse_points(tmp_path, monkeypatch):
    module = _module()
    root = _onedir(tmp_path)

    with pytest.raises(module.AttestationError, match="staging"):
        module.validate_artifact_paths(root, root / "evidence")

    monkeypatch.setattr(module, "_is_reparse_point", lambda path: path == root)
    with pytest.raises(module.AttestationError, match="reparse"):
        module.artifact_file_records(root)


def test_attestation_input_validation_requires_fixed_baseline_and_full_commit():
    module = _module()
    valid = {
        "source_commit": "a" * 40,
        "app_version": "0.1.0",
        "build_environment": "production",
        "python_version": "3.11.9",
        "pyinstaller_version": "6.21.0",
    }

    assert module.validate_attestation_inputs(**valid) is None
    for field, value in (("source_commit", "short"), ("app_version", "0.1.0-test"), ("python_version", "3.12.0"), ("pyinstaller_version", "6.20.0")):
        invalid = {**valid, field: value}
        with pytest.raises(module.AttestationError):
            module.validate_attestation_inputs(**invalid)


def test_atomic_staging_removes_partial_output_on_failure_and_keeps_input(tmp_path):
    module = _module()
    root = _onedir(tmp_path)
    staging = tmp_path / "evidence"

    def fail_writer(temp_dir: Path) -> None:
        (temp_dir / "partial.json").write_text("partial", encoding="utf-8")
        raise module.AttestationError("controlled failure")

    with pytest.raises(module.AttestationError, match="controlled"):
        module.publish_atomically(staging, fail_writer)

    assert root.is_dir()
    assert not staging.exists()
    assert not list(tmp_path.glob(".evidence.*"))


def test_cli_returns_redacted_success_and_controlled_failure(tmp_path, capsys, monkeypatch):
    import scripts.release_artifact_attestation as cli

    onedir = _onedir(tmp_path)
    staging = tmp_path / "evidence"

    def success(**_kwargs):
        return {"result": "PASS", "public_key_sha256": TEST_FINGERPRINT}

    monkeypatch.setattr(cli, "attest_release", success)
    assert cli.main(_cli_args(onedir, staging)) == 0
    output = capsys.readouterr().out
    assert "result=PASS" in output
    assert TEST_URL not in output
    assert TEST_PUBLIC_KEY not in output

    def failure(**_kwargs):
        raise cli.AttestationError("embedded configuration validation failed")

    monkeypatch.setattr(cli, "attest_release", failure)
    assert cli.main(_cli_args(onedir, staging)) == 1
    output = capsys.readouterr().out
    assert "result=FAIL" in output
    assert TEST_URL not in output
    assert TEST_PUBLIC_KEY not in output

    unexpected_value = "https://release-attestation-test.invalid/unexpected"

    def unexpected(**_kwargs):
        raise OSError(unexpected_value)

    monkeypatch.setattr(cli, "attest_release", unexpected)
    assert cli.main(_cli_args(onedir, staging)) == 1
    output = capsys.readouterr().out
    assert "result=FAIL" in output
    assert unexpected_value not in output


def _cli_args(onedir: Path, staging: Path) -> list[str]:
    return [
        "--onedir", str(onedir),
        "--staging-dir", str(staging),
        "--source-commit", "a" * 40,
        "--app-version", "0.1.0-test",
        "--build-environment", "production",
        "--approved-license-server-url", TEST_URL,
        "--expected-public-key-sha256", TEST_FINGERPRINT,
        "--python-version", "3.11.9",
        "--pyinstaller-version", "6.21.0",
    ]
