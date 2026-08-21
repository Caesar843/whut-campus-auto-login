import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SIGNING_HELPER = ROOT / "scripts" / "release" / "windows_signing.ps1"
BUILD_SCRIPT = ROOT / "scripts" / "build_windows.ps1"
INSTALLER_SCRIPT = ROOT / "scripts" / "build_windows_installer.ps1"
INSTALLER_DOC = ROOT / "docs" / "release" / "WINDOWS_INSTALLER.md"


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows signing pipeline")


def _powershell(script: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        cwd=ROOT,
        env=merged_env,
        capture_output=True,
        text=True,
        errors="replace",
    )


def _load_helper_call(call: str) -> str:
    return (
        f"if (-not (Test-Path -LiteralPath '{SIGNING_HELPER}')) {{ throw 'HELPER_MISSING' }}; "
        f". '{SIGNING_HELPER}'; "
        f"{call}"
    )


def _write_installer_flow_fixture(tmp_path: Path) -> dict[str, Path]:
    repo = tmp_path / "repo"
    (repo / "scripts" / "release").mkdir(parents=True)
    (repo / "installer").mkdir()
    input_dir = repo / "dist" / "WHUTCampusAutoLogin"
    (input_dir / "_internal").mkdir(parents=True)
    (input_dir / "WHUTCampusAutoLogin.exe").write_bytes(b"MZ")
    (repo / "installer" / "WHUTCampusAutoLogin.iss").write_text("; test ISS\n", encoding="utf-8")
    (repo / "scripts" / "build_windows_installer.ps1").write_text(
        (ROOT / "scripts" / "build_windows_installer.ps1").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (repo / "scripts" / "release" / "windows_signing.ps1").write_text(
        """
function Assert-WindowsSigningPreflight {
    param([string]$BuildEnvironment)
    return [pscustomobject]@{SigningRequired=$true; CertificateThumbprint='A'*40; Store='CurrentUser'; TimestampUrl='https://timestamp.example.test'; SignToolPath=''}
}
function Assert-WindowsSigningArtifact {
    param([pscustomobject]$Configuration, [string]$ArtifactPath)
    Add-Content -LiteralPath $env:FAKE_SIGNING_LOG -Value ('verify:' + [IO.Path]::GetFileName($ArtifactPath))
    if ($env:FAKE_APP_VERIFY_FAIL -eq '1' -and [IO.Path]::GetFileName($ArtifactPath) -eq 'WHUTCampusAutoLogin.exe') { throw 'APP_VERIFY_FAIL' }
}
function Invoke-WindowsSigningArtifact {
    param([pscustomobject]$Configuration, [string]$ArtifactPath)
    Add-Content -LiteralPath $env:FAKE_SIGNING_LOG -Value ('sign:' + [IO.Path]::GetFileName($ArtifactPath))
    if ($env:FAKE_INSTALLER_SIGN_FAIL -eq '1' -and [IO.Path]::GetFileName($ArtifactPath) -like '*-setup.exe') { throw 'INSTALLER_SIGN_FAIL' }
}
""".lstrip(),
        encoding="utf-8",
    )
    output_dir = repo / "installer" / "output"
    installer_path = output_dir / "WHUTCampusAutoLogin-0.1.0-setup.exe"
    iscc = tmp_path / "fake-iscc.cmd"
    marker = tmp_path / "iscc-called.txt"
    iscc.write_text(
        "@echo off\r\necho called>\"%FAKE_ISCC_MARKER%\"\r\n"
        "<nul set /p =MZ>\"%FAKE_ISCC_OUTPUT_PATH%\"\r\n"
        "if \"%FAKE_ISCC_EXIT_CODE%\"==\"\" exit /b 0\r\n"
        "exit /b %FAKE_ISCC_EXIT_CODE%\r\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "signing-test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "signing-test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "fixture"], cwd=repo, check=True, capture_output=True)
    return {
        "repo": repo,
        "input_dir": input_dir,
        "output_dir": output_dir,
        "installer": installer_path,
        "iscc": iscc,
        "marker": marker,
        "signing_log": tmp_path / "signing.log",
    }


def _run_installer_fixture(fixture: dict[str, Path], **variables: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(
        {
            "FAKE_ISCC_MARKER": str(fixture["marker"]),
            "FAKE_ISCC_OUTPUT_PATH": str(fixture["installer"]),
            "FAKE_SIGNING_LOG": str(fixture["signing_log"]),
            **variables,
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
            "production",
            "-AppVersion",
            "0.1.0",
            "-InputDir",
            str(fixture["input_dir"]),
            "-OutputDir",
            str(fixture["output_dir"]),
            "-IsccPath",
            str(fixture["iscc"]),
            "-IssScript",
            str(fixture["repo"] / "installer" / "WHUTCampusAutoLogin.iss"),
        ],
        cwd=fixture["repo"],
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )


def test_signing_helper_exposes_single_store_thumbprint_contract():
    assert SIGNING_HELPER.is_file()
    text = SIGNING_HELPER.read_text(encoding="utf-8")
    for marker in (
        "WINDOWS_SIGNING_ENABLED",
        "WINDOWS_SIGNING_CERT_SHA1",
        "WINDOWS_SIGNING_STORE",
        "WINDOWS_SIGNTOOL_PATH",
        "WINDOWS_SIGNING_TIMESTAMP_URL",
        "Get-WindowsSigningConfiguration",
        "Invoke-WindowsSigningArtifact",
        "Assert-WindowsSigningArtifact",
        "'SHA256'",
        "'/sha1'",
        """'/tr'""",
        """'/td'""",
        """'/sm'""",
        "X509Chain",
        "CODE_SIGNING_CHAIN_INVALID",
    ):
        assert marker in text


def test_production_configuration_rejects_missing_thumbprint():
    completed = _powershell(
        _load_helper_call(
            "Get-WindowsSigningConfiguration -BuildEnvironment production"
        ),
        {
            "WINDOWS_SIGNING_ENABLED": "true",
            "WINDOWS_SIGNING_CERT_SHA1": "",
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "https://timestamp.example.test",
        },
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "CODE_SIGNING_CERT_THUMBPRINT_MISSING" in output


def test_production_configuration_requires_explicit_enabled_flag():
    completed = _powershell(
        _load_helper_call(
            "Get-WindowsSigningConfiguration -BuildEnvironment production"
        ),
        {
            "WINDOWS_SIGNING_ENABLED": "false",
            "WINDOWS_SIGNING_CERT_SHA1": "A" * 40,
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "https://timestamp.example.test",
        },
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "SIGNING_CONFIGURATION_MISSING" in output


def test_production_configuration_rejects_missing_timestamp_url():
    completed = _powershell(
        _load_helper_call(
            "Get-WindowsSigningConfiguration -BuildEnvironment production"
        ),
        {
            "WINDOWS_SIGNING_ENABLED": "true",
            "WINDOWS_SIGNING_CERT_SHA1": "A" * 40,
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "",
        },
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "TIMESTAMP_CONFIGURATION_MISSING" in output


def test_production_configuration_rejects_non_https_timestamp_url():
    completed = _powershell(
        _load_helper_call(
            "Get-WindowsSigningConfiguration -BuildEnvironment production"
        ),
        {
            "WINDOWS_SIGNING_ENABLED": "true",
            "WINDOWS_SIGNING_CERT_SHA1": "A" * 40,
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "http://timestamp.example.test",
        },
    )
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "TIMESTAMP_CONFIGURATION_MISSING" in output


def test_production_preflight_fails_closed_when_certificate_is_absent():
    completed = _powershell(
        _load_helper_call(
            "try { Assert-WindowsSigningPreflight -BuildEnvironment production } "
            "catch { if ($_.Exception.Message -like '*CODE_SIGNING_CERT_NOT_FOUND*') { exit 0 }; Write-Error $_; exit 2 }; exit 1"
        ),
        {
            "WINDOWS_SIGNING_ENABLED": "true",
            "WINDOWS_SIGNING_CERT_SHA1": "A" * 40,
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "https://timestamp.example.test",
            "WINDOWS_SIGNTOOL_PATH": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe",
        },
    )
    assert completed.returncode == 0, completed.stderr


def test_development_configuration_does_not_require_signing_material():
    completed = _powershell(
        _load_helper_call(
            "$config = Get-WindowsSigningConfiguration -BuildEnvironment development; "
            "if ($config.SigningRequired) { exit 1 }; exit 0"
        ),
        {
            "WINDOWS_SIGNING_ENABLED": "false",
            "WINDOWS_SIGNING_CERT_SHA1": "",
            "WINDOWS_SIGNING_STORE": "CurrentUser",
            "WINDOWS_SIGNING_TIMESTAMP_URL": "",
        },
    )
    assert completed.returncode == 0, completed.stderr


def test_thumbprint_normalization_rejects_ambiguous_values():
    completed = _powershell(
        _load_helper_call(
            "$valid = Normalize-WindowsSigningThumbprint 'aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa'; "
            "if ($valid -ne 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') { exit 1 }; "
            "try { Normalize-WindowsSigningThumbprint 'ABC' } catch { exit 0 }; exit 2"
        )
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("certificate_expression", "expected_code"),
    [
        (
            "[pscustomobject]@{HasPrivateKey=$false; NotBefore=[datetime]::UtcNow.AddDays(-1); NotAfter=[datetime]::UtcNow.AddDays(1); EnhancedKeyUsageList=@(); Subject='CN=Prod'; Issuer='CN=CA'}",
            "CODE_SIGNING_PRIVATE_KEY_UNAVAILABLE",
        ),
        (
            "[pscustomobject]@{HasPrivateKey=$true; NotBefore=[datetime]::UtcNow.AddDays(-1); NotAfter=[datetime]::UtcNow.AddDays(1); EnhancedKeyUsageList=@(); Subject='CN=Prod'; Issuer='CN=CA'}",
            "CODE_SIGNING_EKU_INVALID",
        ),
        (
            "[pscustomobject]@{HasPrivateKey=$true; NotBefore=[datetime]::UtcNow.AddDays(-2); NotAfter=[datetime]::UtcNow.AddDays(-1); EnhancedKeyUsageList=@([pscustomobject]@{ObjectId=[pscustomobject]@{Value='1.3.6.1.5.5.7.3.3'}}); Subject='CN=Prod'; Issuer='CN=CA'}",
            "CODE_SIGNING_CERT_EXPIRED",
        ),
        (
            "[pscustomobject]@{HasPrivateKey=$true; NotBefore=[datetime]::UtcNow.AddDays(-1); NotAfter=[datetime]::UtcNow.AddDays(1); EnhancedKeyUsageList=@([pscustomobject]@{ObjectId=[pscustomobject]@{Value='1.3.6.1.5.5.7.3.3'}}); Subject='CN=Prod'; Issuer='CN=Prod'}",
            "CODE_SIGNING_CERT_SELF_SIGNED",
        ),
    ],
)
def test_certificate_preflight_rejects_invalid_metadata(certificate_expression, expected_code):
    completed = _powershell(
        _load_helper_call(
            f"$certificate = {certificate_expression}; "
            "try { Assert-WindowsSigningCertificate -Certificate $certificate } "
            "catch { if ($_.Exception.Message -like '*" + expected_code + "*') { exit 0 }; Write-Error $_; exit 2 }; exit 1"
        )
    )
    assert completed.returncode == 0, completed.stderr


def test_signing_command_failure_is_not_suppressed(tmp_path):
    fake_tool = tmp_path / "signtool.cmd"
    fake_tool.write_text("@echo off\r\nexit /b 23\r\n", encoding="utf-8")
    artifact = tmp_path / "app.exe"
    artifact.write_bytes(b"MZ")
    command = (
        f"function Find-WindowsSignTool {{ return [pscustomobject]@{{Path='{fake_tool}'; Version='test'}} }}; "
        "function Get-WindowsSigningCertificate { return [pscustomobject]@{HasPrivateKey=$true} }; "
        "$config = [pscustomobject]@{SigningRequired=$true; CertificateThumbprint='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; Store='CurrentUser'; TimestampUrl='https://timestamp.example.test'; SignToolPath=''}; "
        f"try {{ Invoke-WindowsSigningArtifact -Configuration $config -ArtifactPath '{artifact}' }} "
        "catch { if ($_.Exception.Message -like '*SIGNING_COMMAND_FAILED*') { exit 0 }; Write-Error $_; exit 2 }; exit 1"
    )
    completed = _powershell(_load_helper_call(command))
    assert completed.returncode == 0, completed.stderr


def test_explicit_signtool_path_must_be_absolute():
    completed = _powershell(
        _load_helper_call(
            "$config = [pscustomobject]@{SignToolPath='signtool.exe'}; "
            "try { Find-WindowsSignTool -Configuration $config } "
            "catch { if ($_.Exception.Message -like '*SIGNTOOL_PATH_INVALID*') { exit 0 }; Write-Error $_; exit 2 }; exit 1"
        )
    )
    assert completed.returncode == 0, completed.stderr


def test_installer_does_not_invoke_iscc_when_app_verification_fails(tmp_path):
    fixture = _write_installer_flow_fixture(tmp_path)
    completed = _run_installer_fixture(fixture, FAKE_APP_VERIFY_FAIL="1")
    assert completed.returncode != 0
    assert not fixture["marker"].exists()
    assert not fixture["installer"].exists()


def test_installer_removes_new_formal_candidate_when_signing_fails(tmp_path):
    fixture = _write_installer_flow_fixture(tmp_path)
    completed = _run_installer_fixture(fixture, FAKE_INSTALLER_SIGN_FAIL="1")
    output = completed.stdout + completed.stderr
    assert completed.returncode != 0, output
    assert fixture["marker"].exists(), output
    assert not fixture["installer"].exists()


def test_installer_rejects_preexisting_production_candidate_without_overwrite(tmp_path):
    fixture = _write_installer_flow_fixture(tmp_path)
    fixture["installer"].parent.mkdir(parents=True, exist_ok=True)
    historical_candidate = b"historical-unsigned-candidate"
    fixture["installer"].write_bytes(historical_candidate)

    completed = _run_installer_fixture(fixture)
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0, output
    assert "PRODUCTION_OUTPUT_EXISTS" in output
    assert not fixture["marker"].exists()
    assert fixture["installer"].read_bytes() == historical_candidate


def test_installer_removes_new_candidate_when_iscc_fails_after_writing(tmp_path):
    fixture = _write_installer_flow_fixture(tmp_path)

    completed = _run_installer_fixture(fixture, FAKE_ISCC_EXIT_CODE="23")
    output = completed.stdout + completed.stderr

    assert completed.returncode != 0, output
    assert fixture["marker"].exists(), output
    assert not fixture["installer"].exists()


def test_app_signing_is_required_before_installer_build_and_final_hash():
    build_text = BUILD_SCRIPT.read_text(encoding="utf-8")
    installer_text = INSTALLER_SCRIPT.read_text(encoding="utf-8")
    assert "windows_signing.ps1" in build_text
    assert "Invoke-WindowsSigningArtifact" in build_text
    assert "Assert-WindowsSigningArtifact" in build_text
    assert "windows_signing.ps1" in installer_text
    assert "Assert-WindowsSigningArtifact" in installer_text
    assert installer_text.index("Assert-WindowsSigningArtifact") < installer_text.index("Running ISCC.exe")
    assert installer_text.index("Invoke-WindowsSigningArtifact") < installer_text.index("Get-FileHash")


def test_release_documentation_describes_the_fail_closed_signing_contract():
    text = INSTALLER_DOC.read_text(encoding="utf-8")
    for marker in (
        "WINDOWS_SIGNING_ENABLED",
        "WINDOWS_SIGNING_CERT_SHA1",
        "WINDOWS_SIGNING_STORE",
        "WINDOWS_SIGNTOOL_PATH",
        "WINDOWS_SIGNING_TIMESTAMP_URL",
        "RFC3161",
        "Code Signing EKU",
        "ManualAcceptance",
        "OwnerApproval",
        "CODE_SIGNING_CERT_NOT_FOUND",
    ):
        assert marker in text
