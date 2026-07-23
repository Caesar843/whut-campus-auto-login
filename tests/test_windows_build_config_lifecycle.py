import base64
import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_windows.ps1"
SPEC_PATH = ROOT / "WHUTCampusAutoLogin.spec"
BASELINE_PATH = ROOT / "packaging" / "windows" / "build_baseline.json"
LOCK_PATH = ROOT / "requirements-windows-build.lock.txt"
VERSION_GENERATOR = ROOT / "scripts" / "generate_windows_version_info.py"
ENVIRONMENT_VERIFIER = ROOT / "scripts" / "verify_windows_build_environment.py"
APP_VERSION_PATH = ROOT / "app_version.py"
APP_ICON_PATH = ROOT / "assets" / "windows" / "whut_campus_auto_login.ico"
EMBEDDED_MODULE = "_license_client_embedded_build_config"
EMBEDDED_FILENAME = f"{EMBEDDED_MODULE}.py"
VERSION_INFO_FILENAME = "windows_version_info.txt"
PUBLIC_KEY = base64.b64encode(b"k" * 32).decode("ascii")

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows build script")


def _isolated_build_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    for relative in (
        "scripts",
        "desktop_app",
        "license_client",
        "tools",
        "packaging/windows",
        "assets/windows",
    ):
        (repo / relative).mkdir(parents=True, exist_ok=True)
    shutil.copy2(BUILD_SCRIPT, repo / "scripts" / BUILD_SCRIPT.name)
    shutil.copy2(VERSION_GENERATOR, repo / "scripts" / VERSION_GENERATOR.name)
    shutil.copy2(ENVIRONMENT_VERIFIER, repo / "scripts" / ENVIRONMENT_VERIFIER.name)
    shutil.copy2(APP_VERSION_PATH, repo / APP_VERSION_PATH.name)
    shutil.copy2(BASELINE_PATH, repo / "packaging" / "windows" / BASELINE_PATH.name)
    shutil.copy2(LOCK_PATH, repo / LOCK_PATH.name)
    shutil.copy2(APP_ICON_PATH, repo / "assets" / "windows" / APP_ICON_PATH.name)
    shutil.copy2(ROOT / "license_client" / "__init__.py", repo / "license_client" / "__init__.py")
    shutil.copy2(ROOT / "license_client" / "public_key.py", repo / "license_client" / "public_key.py")
    (repo / "WHUTCampusAutoLogin.spec").write_text("# PyInstaller is stubbed in this test.\n", encoding="utf-8")
    (repo / "desktop_app" / "tray_app.py").write_text("# build entry stub\n", encoding="utf-8")
    (repo / "tools" / "python_stub.py").write_text(
        """
import os
import subprocess
import sys
from pathlib import Path


def main():
    args = sys.argv[1:]
    if args == ["--version"]:
        print(sys.version.split()[0])
        return 0
    if args == ["-c", "from app_version import APP_VERSION; print(APP_VERSION)"]:
        print("0.1.0")
        return 0
    if args == ["-m", "PyInstaller", "--version"]:
        print("6.21.0")
        return 0
    if args and Path(args[0]).name == "verify_windows_build_environment.py":
        (Path.cwd() / "build-environment-validator.called").write_text("called", encoding="utf-8")
        return int(os.environ.get("FAKE_BUILD_VALIDATOR_EXIT_CODE", "0"))
    if args and Path(args[0]).name == "generate_windows_version_info.py":
        return subprocess.run([os.environ["REAL_PYTHON"], *args], cwd=os.getcwd()).returncode
    if args[:2] == ["-m", "license_client.public_key"]:
        return subprocess.run([os.environ["REAL_PYTHON"], *args], cwd=os.getcwd()).returncode
    if args[:2] == ["-m", "PyInstaller"]:
        exit_code = int(os.environ.get("FAKE_PYINSTALLER_EXIT_CODE", "0"))
        if exit_code:
            return exit_code
        version_info = Path.cwd() / "build" / "generated" / "windows_version_info.txt"
        if not version_info.is_file():
            return 98
        exe = Path.cwd() / "dist" / "WHUTCampusAutoLogin" / "WHUTCampusAutoLogin.exe"
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(b"MZ")
        return 0
    return 97


raise SystemExit(main())
""".lstrip(),
        encoding="utf-8",
    )
    (repo / "tools" / "python.cmd").write_text(
        '@echo off\r\n"%REAL_PYTHON%" "%~dp0python_stub.py" %*\r\nexit /b %ERRORLEVEL%\r\n',
        encoding="utf-8",
    )
    return repo


def _generated_config(repo: Path) -> Path:
    return repo / "build" / "generated" / EMBEDDED_FILENAME


def _inject_final_cleanup_failure(repo: Path) -> None:
    script_path = repo / "scripts" / BUILD_SCRIPT.name
    content = script_path.read_text(encoding="utf-8")
    marker = "        Remove-GeneratedBuildConfig"
    marker_index = content.rfind(marker)
    assert marker_index != -1
    script_path.write_text(
        content[:marker_index]
        + '        throw "injected-cleanup-failure"'
        + content[marker_index + len(marker) :],
        encoding="utf-8",
    )


def _write_stale_config(repo: Path, environment: str = "preproduction") -> Path:
    config = _generated_config(repo)
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        f'BUILD_ENVIRONMENT = "{environment}"\n'
        f'LICENSE_PUBLIC_KEY_B64 = "{PUBLIC_KEY}"\n'
        'LICENSE_SERVER_URL = "https://stale.example.test"\n'
        'BUILD_SESSION_ID = "stale-session"\n',
        encoding="utf-8",
    )
    cache = config.parent / "__pycache__" / f"{EMBEDDED_MODULE}.cpython-311.pyc"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(b"stale bytecode")
    return config


def _run_build(
    repo: Path,
    *arguments: str,
    pyinstaller_exit_code: int = 0,
    validator_exit_code: int = 0,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(
        {
            "FAKE_PYINSTALLER_EXIT_CODE": str(pyinstaller_exit_code),
            "FAKE_BUILD_VALIDATOR_EXIT_CODE": str(validator_exit_code),
            "PATH": f"{repo / 'tools'}{os.pathsep}{env.get('PATH', '')}",
            "PYTHONDONTWRITEBYTECODE": "1",
            "REAL_PYTHON": sys.executable,
        }
    )
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(repo / "scripts" / BUILD_SCRIPT.name),
            *arguments,
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )


def _normalize_powershell_output(text: str) -> str:
    return "".join(text.splitlines())


def _valid_arguments(environment: str = "production") -> tuple[str, ...]:
    arguments = ["-BuildEnvironment", environment, "-LicensePublicKey", PUBLIC_KEY]
    if environment != "development":
        arguments.extend(["-LicenseServerUrl", f"https://{environment}.example.test"])
    return tuple(arguments)


def test_build_script_removes_stale_config_before_parameter_validation(tmp_path):
    repo = _isolated_build_repo(tmp_path)
    config = _write_stale_config(repo)

    completed = _run_build(
        repo,
        "-BuildEnvironment",
        "production",
        "-LicensePublicKey",
        PUBLIC_KEY,
    )

    assert completed.returncode != 0
    assert not config.exists()
    assert not list((config.parent / "__pycache__").glob(f"{EMBEDDED_MODULE}*.pyc"))


def test_build_script_validates_environment_before_deleting_build_directory(tmp_path):
    repo = _isolated_build_repo(tmp_path)
    sentinel = repo / "build" / "preserve-before-validation.txt"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.write_text("keep", encoding="utf-8")

    completed = _run_build(
        repo,
        *_valid_arguments(),
        validator_exit_code=31,
    )

    assert completed.returncode != 0
    assert sentinel.exists()
    assert (repo / "build-environment-validator.called").is_file()
    assert not _generated_config(repo).exists()


def test_build_script_generates_version_info_and_logs_release_baseline(tmp_path):
    repo = _isolated_build_repo(tmp_path)

    completed = _run_build(repo, *_valid_arguments())
    output = completed.stdout + completed.stderr
    version_info = repo / "build" / "generated" / VERSION_INFO_FILENAME

    assert completed.returncode == 0, output
    assert version_info.is_file()
    assert "ProductName" in version_info.read_text(encoding="utf-8")
    for expected in (
        "AppVersion: 0.1.0",
        "PythonVersion: 3.11.9",
        "PyInstallerVersion: 6.21.0",
        "PackagingMode: onedir",
    ):
        assert expected in output


@pytest.mark.parametrize(
    "server_url",
    [
        "http://localhost:8787",
        " https://production.example.test",
        "https://production.example.test ",
    ],
)
def test_build_script_leaves_no_config_after_invalid_url(tmp_path, server_url):
    repo = _isolated_build_repo(tmp_path)
    config = _write_stale_config(repo)

    completed = _run_build(
        repo,
        "-BuildEnvironment",
        "production",
        "-LicensePublicKey",
        PUBLIC_KEY,
        "-LicenseServerUrl",
        server_url,
    )

    assert completed.returncode != 0
    assert not config.exists()


def test_build_script_cleans_config_and_preserves_pyinstaller_failure_code(tmp_path):
    repo = _isolated_build_repo(tmp_path)
    config = _generated_config(repo)

    completed = _run_build(repo, *_valid_arguments(), pyinstaller_exit_code=23)

    assert completed.returncode == 23
    assert not config.exists()


def test_build_script_preserves_pyinstaller_failure_when_cleanup_also_fails(tmp_path):
    repo = _isolated_build_repo(tmp_path)
    _inject_final_cleanup_failure(repo)

    completed = _run_build(repo, *_valid_arguments(), pyinstaller_exit_code=23)
    output = _normalize_powershell_output(completed.stdout + completed.stderr)

    assert completed.returncode == 23, output
    assert "PyInstaller failed with exit code 23" in output
    assert "Generated license build config cleanup failed" in output
    assert "next build will retry cleanup before validation" in output


def test_build_script_fails_when_successful_build_cleanup_fails(tmp_path):
    repo = _isolated_build_repo(tmp_path)
    _inject_final_cleanup_failure(repo)

    completed = _run_build(repo, *_valid_arguments())
    output = _normalize_powershell_output(completed.stdout + completed.stderr)

    assert completed.returncode == 1, output
    assert "Generated license build config cleanup failed" in output
    assert "next build will retry cleanup before validation" in output


def test_build_script_cleans_config_after_success(tmp_path):
    repo = _isolated_build_repo(tmp_path)
    config = _generated_config(repo)

    completed = _run_build(repo, *_valid_arguments())

    assert completed.returncode == 0, completed.stderr
    assert not config.exists()


@pytest.mark.parametrize(
    ("stale_environment", "next_environment", "omit_release_url"),
    [
        ("preproduction", "production", True),
        ("production", "development", False),
    ],
)
def test_consecutive_builds_do_not_reuse_another_environment(
    tmp_path,
    stale_environment,
    next_environment,
    omit_release_url,
):
    repo = _isolated_build_repo(tmp_path)
    config = _write_stale_config(repo, stale_environment)
    arguments = list(_valid_arguments(next_environment))
    if omit_release_url:
        arguments = arguments[:-2]

    completed = _run_build(repo, *arguments)

    assert completed.returncode == (1 if omit_release_url else 0), completed.stderr
    assert not config.exists()


class _AnalysisResult:
    pure = []
    scripts = []
    binaries = []
    datas = []


def _execute_spec(spec_root: Path):
    captured = {"analysis": {}, "exe": {}, "collect": None}

    def analysis(*_args, **kwargs):
        captured["analysis"].update(kwargs)
        return _AnalysisResult()

    def pyz(*_args, **_kwargs):
        return object()

    def exe(*_args, **kwargs):
        captured["exe"].update(kwargs)
        return object()

    def collect(*args, **kwargs):
        captured["collect"] = (args, kwargs)
        return object()

    runpy.run_path(
        str(SPEC_PATH),
        init_globals={
            "SPECPATH": str(spec_root),
            "Analysis": analysis,
            "PYZ": pyz,
            "EXE": exe,
            "COLLECT": collect,
        },
    )
    return captured


@pytest.mark.parametrize("build_session_id", [None, "different-session"])
def test_spec_rejects_stale_config_without_matching_build_session(
    tmp_path,
    monkeypatch,
    build_session_id,
):
    _write_stale_config(tmp_path)
    if build_session_id is None:
        monkeypatch.delenv("WHUT_BUILD_SESSION_ID", raising=False)
    else:
        monkeypatch.setenv("WHUT_BUILD_SESSION_ID", build_session_id)

    with pytest.raises(RuntimeError, match="build session"):
        _execute_spec(tmp_path)


def test_spec_accepts_config_from_matching_build_session(tmp_path, monkeypatch):
    config = _write_stale_config(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8").replace("stale-session", "current-session"),
        encoding="utf-8",
    )
    icon = tmp_path / "assets" / "windows" / "whut_campus_auto_login.ico"
    icon.parent.mkdir(parents=True, exist_ok=True)
    icon.write_bytes(b"icon")
    version_info = tmp_path / "build" / "generated" / VERSION_INFO_FILENAME
    version_info.write_text("version info", encoding="utf-8")
    monkeypatch.setenv("WHUT_BUILD_SESSION_ID", "current-session")

    captured = _execute_spec(tmp_path)

    assert EMBEDDED_MODULE in captured["analysis"]["hiddenimports"]
    assert str(config.parent) in captured["analysis"]["pathex"]


def test_spec_wires_release_icon_version_info_and_onedir(tmp_path, monkeypatch):
    config = _write_stale_config(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8").replace("stale-session", "current-session"),
        encoding="utf-8",
    )
    icon = tmp_path / "assets" / "windows" / "whut_campus_auto_login.ico"
    icon.parent.mkdir(parents=True, exist_ok=True)
    icon.write_bytes(b"icon")
    version_info = tmp_path / "build" / "generated" / VERSION_INFO_FILENAME
    version_info.write_text("version info", encoding="utf-8")
    monkeypatch.setenv("WHUT_BUILD_SESSION_ID", "current-session")

    captured = _execute_spec(tmp_path)

    assert captured["analysis"]["datas"] == [(str(icon), "assets/windows")]
    assert "tests" in captured["analysis"]["excludes"]
    assert "scripts" in captured["analysis"]["excludes"]
    assert "license_server" in captured["analysis"]["excludes"]
    assert captured["exe"]["exclude_binaries"] is True
    assert captured["exe"]["icon"] == str(icon)
    assert captured["exe"]["version"] == str(version_info)
    assert captured["collect"] is not None
