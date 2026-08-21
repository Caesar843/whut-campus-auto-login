import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_windows.ps1"
INSTALLER_SCRIPT = ROOT / "scripts" / "build_windows_installer.ps1"
SIGNING_HELPER = ROOT / "scripts" / "release" / "windows_signing.ps1"
INSTALLER_DOC = ROOT / "docs" / "release" / "WINDOWS_INSTALLER.md"

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows public-beta channel")


def _write_public_beta_installer_fixture(tmp_path: Path, *, signature_status: str = "NotSigned") -> dict[str, Path]:
    repo = tmp_path / "repo"
    (repo / "scripts" / "release").mkdir(parents=True)
    (repo / "installer").mkdir()
    input_dir = repo / "dist" / "WHUTCampusAutoLogin"
    (input_dir / "_internal").mkdir(parents=True)
    (input_dir / "WHUTCampusAutoLogin.exe").write_bytes(b"MZ")
    iss = repo / "installer" / "WHUTCampusAutoLogin.iss"
    iss.write_text("; public beta test ISS\n", encoding="utf-8")
    (repo / "scripts" / "build_windows_installer.ps1").write_text(
        INSTALLER_SCRIPT.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (repo / "scripts" / "release" / "windows_signing.ps1").write_text(
        """
function Assert-WindowsSigningPreflight {
    param([string]$BuildEnvironment)
    return [pscustomobject]@{
        SigningRequired = ($BuildEnvironment -eq 'production')
        BuildEnvironment = $BuildEnvironment
        CertificateThumbprint = 'A'*40
        Store = 'CurrentUser'
        TimestampUrl = 'https://timestamp.example.test'
        SignToolPath = ''
    }
}
function Invoke-WindowsSigningArtifact {
    param([pscustomobject]$Configuration, [string]$ArtifactPath)
    Add-Content -LiteralPath $env:FAKE_SIGNING_LOG -Value ('sign:' + [IO.Path]::GetFileName($ArtifactPath))
}
function Assert-WindowsSigningArtifact {
    param([pscustomobject]$Configuration, [string]$ArtifactPath)
    Add-Content -LiteralPath $env:FAKE_SIGNING_LOG -Value ('verify:' + [IO.Path]::GetFileName($ArtifactPath))
}
function Get-AuthenticodeSignature {
    param([string]$FilePath)
    return [pscustomobject]@{Status='__SIGNATURE_STATUS__'; SignerCertificate=$null; TimeStamperCertificate=$null}
}
""".lstrip().replace("__SIGNATURE_STATUS__", signature_status),
        encoding="utf-8",
    )
    output_dir = repo / "installer" / "output"
    installer = output_dir / "WHUTCampusAutoLogin-0.1.0-public-beta-setup.exe"
    report = output_dir / "WHUTCampusAutoLogin-0.1.0-public-beta-setup-release-report.txt"
    iscc = tmp_path / "fake-iscc.cmd"
    marker = tmp_path / "iscc-called.txt"
    iscc.write_text(
        "@echo off\r\necho called>\"%FAKE_ISCC_MARKER%\"\r\n"
        "<nul set /p =MZ>\"%FAKE_ISCC_OUTPUT_PATH%\"\r\nexit /b 0\r\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "public-beta-test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "public-beta-test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, check=True, capture_output=True)
    return {
        "repo": repo,
        "input_dir": input_dir,
        "output_dir": output_dir,
        "installer": installer,
        "report": report,
        "iss": iss,
        "iscc": iscc,
        "marker": marker,
        "signing_log": tmp_path / "signing.log",
    }


def _run_public_beta_installer(fixture: dict[str, Path]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(
        {
            "FAKE_ISCC_MARKER": str(fixture["marker"]),
            "FAKE_ISCC_OUTPUT_PATH": str(fixture["installer"]),
            "FAKE_SIGNING_LOG": str(fixture["signing_log"]),
        }
    )
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(fixture["repo"] / "scripts" / "build_windows_installer.ps1"),
            "-BuildEnvironment",
            "public-beta",
            "-AppVersion",
            "0.1.0",
            "-InputDir",
            str(fixture["input_dir"]),
            "-OutputDir",
            str(fixture["output_dir"]),
            "-IsccPath",
            str(fixture["iscc"]),
            "-IssScript",
            str(fixture["iss"]),
        ],
        cwd=fixture["repo"],
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )


def test_public_beta_signing_configuration_is_explicitly_unsigned():
    command = (
        f". '{SIGNING_HELPER}'; "
        "$config = Get-WindowsSigningConfiguration -BuildEnvironment 'public-beta'; "
        "if ($config.BuildEnvironment -ne 'public-beta') { exit 1 }; "
        "if ($config.SigningRequired) { exit 2 }; exit 0"
    )
    env = os.environ.copy()
    env.update(
        {
            "WINDOWS_SIGNING_ENABLED": "false",
            "WINDOWS_SIGNING_CERT_SHA1": "",
            "WINDOWS_SIGNING_STORE": "",
            "WINDOWS_SIGNTOOL_PATH": "",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "",
        }
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )
    assert completed.returncode == 0, completed.stderr


def test_public_beta_rejects_signing_enabled_configuration():
    command = (
        f". '{SIGNING_HELPER}'; "
        "try { Get-WindowsSigningConfiguration -BuildEnvironment 'public-beta' | Out-Null; exit 1 } "
        "catch { if ($_.Exception.Message -like '*PUBLIC_BETA_SIGNING_CONFIGURATION_INVALID*') { exit 0 }; exit 2 }"
    )
    env = os.environ.copy()
    env.update(
        {
            "WINDOWS_SIGNING_ENABLED": "true",
            "WINDOWS_SIGNING_CERT_SHA1": "A" * 40,
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "https://timestamp.example.test",
        }
    )
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )
    assert completed.returncode == 0, completed.stderr


def test_public_beta_build_keeps_production_like_inputs_but_does_not_sign(tmp_path):
    from test_windows_build_config_lifecycle import _isolated_build_repo, _run_build, _valid_arguments

    repo = _isolated_build_repo(tmp_path)
    completed = _run_build(repo, *_valid_arguments("public-beta"))
    output = completed.stdout + completed.stderr

    assert completed.returncode == 0, output
    assert "BuildEnvironment: public-beta" in output
    assert "PUBLIC BETA BUILD" in output
    assert "Authenticode signing is intentionally not applied" in output
    assert "Authenticode: Valid" not in output


def test_public_beta_installer_uses_distinct_name_and_unsigned_report(tmp_path):
    fixture = _write_public_beta_installer_fixture(tmp_path)
    completed = _run_public_beta_installer(fixture)
    output = completed.stdout + completed.stderr

    assert completed.returncode == 0, output
    assert fixture["marker"].exists(), output
    assert fixture["installer"].is_file(), output
    assert not (fixture["output_dir"] / "WHUTCampusAutoLogin-0.1.0-setup.exe").exists()
    assert not fixture["signing_log"].exists()

    report = fixture["report"].read_text(encoding="utf-8")
    assert "ReleaseChannel: PublicBeta" in report
    assert "Artifact: WHUTCampusAutoLogin-0.1.0-public-beta-setup.exe" in report
    assert "Authenticode: NotSigned" in report
    assert "CodeSigningStatus: IntentionallyUnsignedPublicBeta" in report
    assert "ManualAcceptanceCompleted: No" in report
    assert "OwnerApproval: No" in report
    assert "PublicDownloadEnabled: No" in report
    assert "Authenticode: Valid" not in report
    assert "CodeSigningStatus: Verified" not in report

    expected_hash = hashlib.sha256(fixture["installer"].read_bytes()).hexdigest()
    match = re.search(r"^SHA256: ([0-9a-f]{64})$", report, re.MULTILINE)
    assert match
    assert match.group(1) == expected_hash


def test_public_beta_installer_requires_clean_git(tmp_path):
    fixture = _write_public_beta_installer_fixture(tmp_path)
    fixture["iss"].write_text("; dirty\n", encoding="utf-8")

    completed = _run_public_beta_installer(fixture)
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0, output
    assert "Public Beta build requires a clean git working tree" in output
    assert not fixture["marker"].exists()


def test_public_beta_rejects_signed_authenticode_state(tmp_path):
    fixture = _write_public_beta_installer_fixture(tmp_path, signature_status="Valid")

    completed = _run_public_beta_installer(fixture)
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0, output
    assert "PUBLIC_BETA_SIGNATURE_STATE_INVALID" in output
    assert not fixture["report"].exists()


def test_public_beta_refuses_existing_candidate_report(tmp_path):
    fixture = _write_public_beta_installer_fixture(tmp_path)
    fixture["output_dir"].mkdir(parents=True, exist_ok=True)
    fixture["report"].write_text("stale candidate\n", encoding="utf-8")

    completed = _run_public_beta_installer(fixture)
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0, output
    assert "PUBLIC_BETA_OUTPUT_EXISTS" in output
    assert not fixture["marker"].exists()


def test_public_beta_contract_is_documented_without_production_bypass():
    text = INSTALLER_DOC.read_text(encoding="utf-8")
    for marker in (
        "public-beta",
        "IntentionallyUnsignedPublicBeta",
        "Public Beta is an explicitly unsigned release channel",
        "Signed Production Authenticode requirement remains unchanged",
        "PublicDownloadEnabled",
        "OwnerApproval",
    ):
        assert marker in text
