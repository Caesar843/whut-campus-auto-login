"""
tests/test_windows_installer_baseline.py

Static validation of the Inno Setup installer script and build script.

These tests do NOT require Inno Setup to be installed, do NOT perform
actual installation, and do NOT modify the registry. They validate the
installer source files against the Phase 2-A / Phase 2-B specification.

Authority sources verified here:
    desktop_app/tray/runtime.py              APP_NAME
    desktop_app/autostart/windows_startup.py SHORTCUT_NAME
    desktop_app/runtime_logs.py              APP_DIR_NAME
    scripts/generate_windows_version_info.py VERSION_FIELDS
"""

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
ISS = ROOT / "installer" / "WHUTCampusAutoLogin.iss"
BUILD_SCRIPT = ROOT / "scripts" / "build_windows_installer.ps1"

# Authority constants -- must match source files exactly
AUTHORITY_APP_NAME = "武汉理工校园网助手"
AUTHORITY_EXE_NAME = "WHUTCampusAutoLogin.exe"
AUTHORITY_STARTUP_SHORTCUT = "whut-campus-auto-login.lnk"
AUTHORITY_APPDATA_DIR = "WHUTCampusAutoLogin"
AUTHORITY_PUBLISHER = "Caesar843"
# Fixed product GUID - must never change after first release
AUTHORITY_APP_ID = "8A3F2B1C-4D7E-4F9A-B2C3-D1E4F5A6B7C8"


@pytest.fixture(scope="module")
def iss_text():
    return ISS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def build_script_text():
    return BUILD_SCRIPT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. File existence
# ---------------------------------------------------------------------------
def test_iss_script_exists():
    assert ISS.exists(), f"Inno Setup script not found: {ISS}"


def test_build_script_exists():
    assert BUILD_SCRIPT.exists(), f"Build script not found: {BUILD_SCRIPT}"


# ---------------------------------------------------------------------------
# 2. Privileges -- must be current-user only
# ---------------------------------------------------------------------------
def test_privileges_required_lowest(iss_text):
    """PrivilegesRequired=lowest ensures no UAC admin prompt."""
    assert "PrivilegesRequired=lowest" in iss_text, (
        "PrivilegesRequired must be 'lowest' to avoid UAC elevation."
    )


def test_no_admin_privileges(iss_text):
    """Must not require administrator privileges."""
    lines = [l.strip() for l in iss_text.splitlines()]
    for line in lines:
        if line.startswith(";"):
            continue  # skip comments
        assert "PrivilegesRequired=admin" not in line, (
            "PrivilegesRequired=admin found -- installer must not require admin."
        )


# ---------------------------------------------------------------------------
# 3. Architecture
# ---------------------------------------------------------------------------
def test_x64_architecture_restriction(iss_text):
    """Must be limited to x64 compatible architectures."""
    assert "ArchitecturesAllowed=x64compatible" in iss_text, (
        "ArchitecturesAllowed must be x64compatible."
    )


# ---------------------------------------------------------------------------
# 4. Default install directory
# ---------------------------------------------------------------------------
def test_default_dir_in_localappdata(iss_text):
    """Default install dir must be under {localappdata}\\Programs\\ (no admin needed)."""
    assert "{localappdata}" in iss_text, (
        "DefaultDirName must use {localappdata} so no admin elevation is needed."
    )


def test_default_dir_not_program_files(iss_text):
    """Must not default to Program Files."""
    assert "{pf}" not in iss_text.lower().replace("{pf64}", "").replace("{pf32}", "")
    assert "Program Files" not in iss_text


def test_default_dir_not_appdata_roaming(iss_text):
    """Must not default to %APPDATA% (that is for user data, not the install dir)."""
    # DefaultDirName must not use {userappdata} or {commonappdata}
    default_match = re.search(r"DefaultDirName\s*=\s*(.+)", iss_text)
    assert default_match, "DefaultDirName not found"
    default_value = default_match.group(1).strip()
    assert "{userappdata}" not in default_value.lower()


# ---------------------------------------------------------------------------
# 5. Stable AppId
# ---------------------------------------------------------------------------
def test_stable_app_id_present(iss_text):
    """AppId must contain the fixed GUID and must not be a random placeholder."""
    assert AUTHORITY_APP_ID in iss_text, (
        f"AppId must contain fixed GUID {AUTHORITY_APP_ID}. "
        "Do not change AppId after first release (breaks upgrades)."
    )


def test_app_id_uses_double_brace(iss_text):
    """In Inno Setup, a literal { in AppId must be escaped as {{."""
    assert "AppId={{" in iss_text, "AppId must use {{ to escape the leading brace."


# ---------------------------------------------------------------------------
# 6. Main EXE path
# ---------------------------------------------------------------------------
def test_main_exe_referenced_in_iss(iss_text):
    """The main EXE filename must appear in the [Files] or [Run] section."""
    assert AUTHORITY_EXE_NAME in iss_text, (
        f"{AUTHORITY_EXE_NAME} must be referenced in the installer script."
    )


def test_main_exe_source_uses_inputdir_define(iss_text):
    """The EXE source path must use the InputDir preprocessor define."""
    assert "{#InputDir}" in iss_text, (
        "Installer must use {#InputDir} define for portable input path."
    )


# ---------------------------------------------------------------------------
# 7. onedir recursive copy
# ---------------------------------------------------------------------------
def test_internal_dir_recursively_copied(iss_text):
    """_internal\\ must be copied recursively with recursesubdirs."""
    assert "_internal" in iss_text, "_internal dir must be installed."
    assert "recursesubdirs" in iss_text.lower(), (
        "recursesubdirs flag must be set for _internal to copy entire Qt/crypto tree."
    )


# ---------------------------------------------------------------------------
# 8. Start Menu shortcut
# ---------------------------------------------------------------------------
def test_start_menu_shortcut_exists(iss_text):
    """A Start Menu shortcut for the app must be created."""
    assert "[Icons]" in iss_text, "[Icons] section must exist."
    assert "{group}" in iss_text, "Start Menu group shortcut must be defined."


def test_start_menu_shortcut_uses_authority_name(iss_text):
    """Start Menu shortcut must use the authority app name."""
    assert AUTHORITY_APP_NAME in iss_text, (
        f"Start Menu shortcut must use authority AppName: {AUTHORITY_APP_NAME}"
    )


# ---------------------------------------------------------------------------
# 9. Desktop shortcut: optional, default OFF
# ---------------------------------------------------------------------------
def test_desktop_shortcut_is_optional_task(iss_text):
    """Desktop shortcut must be a task (optional), not unconditional."""
    assert "desktopicon" in iss_text.lower(), (
        "Desktop shortcut must be controlled by a named task."
    )


def test_desktop_shortcut_default_unchecked(iss_text):
    """Desktop shortcut task must default to unchecked."""
    task_match = re.search(
        r'Name:\s*"desktopicon".*?Flags:\s*([^\n]+)',
        iss_text,
        re.IGNORECASE | re.DOTALL,
    )
    assert task_match, "desktopicon task with Flags not found."
    flags = task_match.group(1).lower()
    assert "unchecked" in flags, (
        "Desktop shortcut task must have 'unchecked' flag (off by default)."
    )


def test_desktop_icon_conditional_on_task(iss_text):
    """Desktop icon in [Icons] must reference the desktopicon task."""
    assert "Tasks: desktopicon" in iss_text or "Tasks:desktopicon" in iss_text, (
        "Desktop shortcut in [Icons] must be gated by Tasks: desktopicon."
    )


def test_no_commondesktop_in_iss(iss_text):
    """Installer script must NOT use {commondesktop} which targets C:\\Users\\Public\\Desktop requiring admin."""
    assert "{commondesktop}" not in iss_text.lower(), (
        "{commondesktop} found in ISS script. Must use {autodesktop} for per-user non-admin installation."
    )


def test_desktop_shortcut_uses_autodesktop(iss_text):
    """Optional desktop shortcut must use {autodesktop} path constant."""
    assert "{autodesktop}" in iss_text.lower(), (
        "Desktop shortcut must use {autodesktop} so it maps to current user's desktop when PrivilegesRequired=lowest."
    )


def test_start_menu_shortcut_uses_group_not_common(iss_text):
    """Start Menu shortcut must use {group} (user scope), not public common start menu."""
    icons_section = re.search(r"\[Icons\](.*?)(?:\[|\Z)", iss_text, re.DOTALL)
    assert icons_section, "[Icons] section must exist."
    icons_text = icons_section.group(1)
    assert "{commonprograms}" not in icons_text.lower(), "Start Menu shortcut must not target public common programs."
    assert "{commonstartmenu}" not in icons_text.lower(), "Start Menu shortcut must not target public common start menu."



# ---------------------------------------------------------------------------
# 10. Post-install launch: not elevated
# ---------------------------------------------------------------------------
def test_post_install_run_not_elevated(iss_text):
    """[Run] section must not use runasoriginaluser with elevation."""
    run_section = re.search(r"\[Run\](.*?)(?:\[|\Z)", iss_text, re.DOTALL)
    if run_section:
        run_text = run_section.group(1)
        assert "runasadmin" not in run_text.lower(), (
            "[Run] must not use runasadmin flag."
        )


def test_post_install_run_is_optional_task(iss_text):
    """Post-install launch must be a task (user choice), not forced."""
    assert "launchapp" in iss_text.lower(), (
        "Post-install launch must be a named task so users can opt out."
    )


# ---------------------------------------------------------------------------
# 11. Uninstall: must NOT delete APPDATA user data
# ---------------------------------------------------------------------------
def test_uninstall_does_not_delete_appdata(iss_text):
    """Uninstall must not touch %APPDATA%\\WHUTCampusAutoLogin (user logs/config/license)."""
    dangerous_patterns = [
        r"\{userappdata\}\\WHUTCampusAutoLogin\\\*",
        r"\{userappdata\}\\WHUTCampusAutoLogin\"",
        r"rmdir.*WHUTCampusAutoLogin",
    ]
    iss_lower = iss_text.lower()
    for pattern in dangerous_patterns:
        hits = re.findall(pattern, iss_lower)
        assert not hits, (
            f"Dangerous user-data deletion pattern found: {pattern}. "
            "Uninstall must preserve %APPDATA% user data."
        )


def test_uninstall_does_not_use_broad_wildcard_delete(iss_text):
    """Uninstall must not use wildcard deletion of entire app dir or user dirs."""
    broad_delete = re.findall(
        r'Type:\s*filesandordirs.*\{(?:app|userappdata)\}\\[*]',
        iss_text,
        re.IGNORECASE,
    )
    assert not broad_delete, (
        "Broad wildcard deletion found in [UninstallDelete]. This is unsafe."
    )


# ---------------------------------------------------------------------------
# 12. Uninstall: no Credential Manager deletion
# ---------------------------------------------------------------------------
def test_no_credential_manager_deletion(iss_text):
    """Installer must not delete Windows Credential Manager entries."""
    credential_patterns = [
        "cmdkey", "CredDelete", "CredentialManager",
        "Windows Credential", "CREDENTIAL_TYPE"
    ]
    for pat in credential_patterns:
        assert pat.lower() not in iss_text.lower(), (
            f"Credential Manager deletion pattern '{pat}' found. "
            "Uninstall must not delete user credentials."
        )


# ---------------------------------------------------------------------------
# 13. Startup shortcut cleanup: exact name only
# ---------------------------------------------------------------------------
def test_startup_shortcut_exact_name_cleaned(iss_text):
    """Uninstall must target the exact startup shortcut filename."""
    assert AUTHORITY_STARTUP_SHORTCUT in iss_text, (
        f"Uninstall must clean up '{AUTHORITY_STARTUP_SHORTCUT}' from Startup folder. "
        "This is the exact name from desktop_app/autostart/windows_startup.py SHORTCUT_NAME."
    )


def test_startup_shortcut_no_wildcard(iss_text):
    """Startup shortcut deletion must use exact path, not a wildcard."""
    uninstall_section = re.search(
        r"\[UninstallDelete\](.*?)(?:\[|\Z)", iss_text, re.DOTALL
    )
    if uninstall_section:
        section_text = uninstall_section.group(1)
        assert "*" not in section_text, (
            "Wildcard found in [UninstallDelete]. "
            "Startup shortcut deletion must use exact filename."
        )


# ---------------------------------------------------------------------------
# 14. No server-side or secret content
# ---------------------------------------------------------------------------
def test_no_mock_secret_in_iss(iss_text):
    """ISS script must not contain server credentials or signing keys."""
    forbidden = [
        "LICENSE_PRIVATE_KEY",
        "BEGIN PRIVATE KEY",
        "ADMIN_ACCESS_TOKEN",
        "pytest",
    ]
    for marker in forbidden:
        assert marker not in iss_text, (
            f"Forbidden marker '{marker}' found in installer script."
        )


def test_no_server_code_referenced(iss_text):
    """ISS must not include server-side modules or databases."""
    server_patterns = ["fastapi", "uvicorn", "sqlalchemy", "alembic", "license_server"]
    for pat in server_patterns:
        assert pat.lower() not in iss_text.lower(), (
            f"Server-side reference '{pat}' found in installer script."
        )


# ---------------------------------------------------------------------------
# 15. Build script: ISCC detection and exit-code handling
# ---------------------------------------------------------------------------
def test_build_script_checks_iscc_exit_code(build_script_text):
    """Build script must check ISCC.exe exit code and fail if nonzero."""
    assert "exitCode" in build_script_text or "ExitCode" in build_script_text, (
        "Build script must capture and check ISCC.exe exit code."
    )
    assert "Write-Error" in build_script_text, (
        "Build script must call Write-Error on ISCC failure."
    )


def test_build_script_outputs_sha256(build_script_text):
    """Build script must compute and print SHA-256 of the installer."""
    assert "SHA256" in build_script_text, (
        "Build script must output SHA-256 hash of the produced installer."
    )
    assert "Get-FileHash" in build_script_text, (
        "Build script must use Get-FileHash for SHA-256 computation."
    )


def test_build_script_validates_input_dir(build_script_text):
    """Build script must validate the InputDir exists and EXE is present."""
    assert "InputDir" in build_script_text
    assert "MainExe" in build_script_text or "main.exe" in build_script_text.lower() or "WHUTCampusAutoLogin.exe" in build_script_text


def test_build_script_validates_exe_size(build_script_text):
    """Build script must check the main EXE has nonzero size."""
    assert "exeSize" in build_script_text or "Length" in build_script_text, (
        "Build script must check EXE file size is > 0."
    )


# ---------------------------------------------------------------------------
# 16. Environment separation in output naming
# ---------------------------------------------------------------------------
def test_build_script_development_output_name_contains_development(build_script_text):
    """Development builds must have 'development' in output filename."""
    assert "development-setup" in build_script_text, (
        "Build script must suffix development installers with '-development-setup'."
    )


def test_build_script_development_and_production_different_names(build_script_text):
    """Development and production output basenames must differ."""
    assert "development-setup" in build_script_text, "Dev suffix must exist."
    lines = build_script_text.splitlines()
    dev_line = [l for l in lines if "development-setup" in l]
    prod_line = [l for l in lines if "WHUTCampusAutoLogin-$ShortVersion-setup" in l
                 and "development" not in l]
    assert dev_line, "Development output name line not found."
    assert prod_line, "Production output name (without development) line not found."


# ---------------------------------------------------------------------------
# 17. Build script: no secret printing
# ---------------------------------------------------------------------------
def test_build_script_does_not_print_secrets(build_script_text):
    """Build script must not print private keys or admin tokens."""
    dangerous = [
        "LICENSE_PRIVATE_KEY", "ADMIN_ACCESS_TOKEN",
    ]
    for d in dangerous:
        assert d not in build_script_text, (
            f"Build script must not reference secret '{d}'."
        )


# ---------------------------------------------------------------------------
# 18. Build script: forbidden content check present
# ---------------------------------------------------------------------------
def test_build_script_has_forbidden_content_check(build_script_text):
    """Build script must scan input dir for forbidden packages before calling ISCC."""
    assert "forbiddenPatterns" in build_script_text or "forbidden" in build_script_text.lower(), (
        "Build script must check input dir for forbidden content before compiling."
    )
    assert "pytest" in build_script_text, (
        "Build script forbidden-content list must include 'pytest'."
    )


# ---------------------------------------------------------------------------
# 19. ISS script does not auto-enable autostart
# ---------------------------------------------------------------------------
def test_installer_does_not_enable_autostart(iss_text):
    """Installer must not create the Startup shortcut. That is the app's job."""
    icons_section = re.search(r"\[Icons\](.*?)(?:\[|\Z)", iss_text, re.DOTALL)
    if icons_section:
        icons_text = icons_section.group(1)
        assert "Startup" not in icons_text, (
            "[Icons] must not create a Startup shortcut. "
            "Autostart is managed by the application itself."
        )
    files_section = re.search(r"\[Files\](.*?)(?:\[|\Z)", iss_text, re.DOTALL)
    if files_section:
        files_text = files_section.group(1)
        assert "Startup" not in files_text, (
            "[Files] must not write to the Startup folder."
        )


# ---------------------------------------------------------------------------
# 20. ISS script has running-app close mechanism
# ---------------------------------------------------------------------------
def test_iss_has_close_applications(iss_text):
    """Installer must prompt to close running instances (CloseApplications=yes)."""
    assert "CloseApplications=yes" in iss_text, (
        "CloseApplications=yes must be set to handle running instances safely."
    )


def test_iss_close_applications_filter_is_specific(iss_text):
    """CloseApplicationsFilter must name the specific EXE, not a wildcard."""
    filter_match = re.search(r"CloseApplicationsFilter\s*=\s*(.+)", iss_text)
    assert filter_match, "CloseApplicationsFilter must be defined."
    filter_value = filter_match.group(1).strip()
    assert filter_value == AUTHORITY_EXE_NAME, (
        f"CloseApplicationsFilter must be exactly '{AUTHORITY_EXE_NAME}', "
        f"not a wildcard or different EXE name. Got: {filter_value}"
    )


# ---------------------------------------------------------------------------
# 21. Phase 2-B Downgrade Protection Tests ([Code] based)
# ---------------------------------------------------------------------------
def test_no_allow_downgrade_setup_directive(iss_text):
    """Inno Setup 6 does not support AllowDowngrade in [Setup]. Must not be present."""
    lines = [l.strip() for l in iss_text.splitlines() if not l.strip().startswith(";")]
    for line in lines:
        assert not line.lower().startswith("allowdowngrade="), (
            "AllowDowngrade= directive is unrecognized by Inno Setup 6 and must not be used in [Setup]."
        )


def test_downgrade_protection_implemented_in_code_section(iss_text):
    """Downgrade protection must be implemented in [Code] section via InitializeSetup."""
    code_section_match = re.search(r"\[Code\](.*)", iss_text, re.DOTALL)
    assert code_section_match, "ISS must contain a [Code] section."
    code_text = code_section_match.group(1)

    assert "InitializeSetup" in code_text, (
        "InitializeSetup event function must be implemented in [Code] for downgrade protection."
    )
    assert "RegQueryStringValue" in code_text, (
        "RegQueryStringValue must be used to query the installed product version from registry."
    )
    assert "HKCU" in code_text, "Registry query must inspect HKCU for current-user installs."
    assert f"{{{AUTHORITY_APP_ID}}}_is1" in code_text, (
        f"Registry uninstall key must specifically target product AppId ({{{AUTHORITY_APP_ID}}}_is1)."
    )
    assert "CompareVersionStrings" in code_text, (
        "Numeric version comparison procedure (CompareVersionStrings) must be used instead of string comparison."
    )
    assert "Result := False" in code_text or "Result:=False" in code_text, (
        "InitializeSetup must set Result := False to abort setup when a downgrade is detected."
    )


# Helper function for Python unit test verifying version comparison algorithm semantics
def _compare_version_strings_py(v1: str, v2: str) -> int:
    """Python implementation matching the Pascal CompareVersionStrings algorithm."""
    parts1 = [int(p) for p in v1.split(".") if p.isdigit()]
    parts2 = [int(p) for p in v2.split(".") if p.isdigit()]
    max_len = max(len(parts1), len(parts2))
    parts1.extend([0] * (max_len - len(parts1)))
    parts2.extend([0] * (max_len - len(parts2)))
    for p1, p2 in zip(parts1, parts2):
        if p1 > p2:
            return 1
        if p1 < p2:
            return -1
    return 0


def test_version_comparison_logic_semantics():
    """Verify numeric version comparison rules: downgrade rejected (>0), repair allowed (==0), upgrade allowed (<0)."""
    # 1. Downgrade: installed > setup -> rejected (> 0)
    assert _compare_version_strings_py("0.2.0", "0.1.0") > 0
    assert _compare_version_strings_py("1.0.0", "0.9.9") > 0
    assert _compare_version_strings_py("0.1.1", "0.1.0") > 0
    assert _compare_version_strings_py("1.10.0", "1.9.0") > 0

    # 2. Repair / Reinstall: installed == setup -> allowed (== 0)
    assert _compare_version_strings_py("0.1.0", "0.1.0") == 0
    assert _compare_version_strings_py("1.2.3", "1.2.3") == 0

    # 3. Upgrade: installed < setup -> allowed (< 0)
    assert _compare_version_strings_py("0.1.0", "0.2.0") < 0
    assert _compare_version_strings_py("0.9.9", "1.0.0") < 0
    assert _compare_version_strings_py("0.1.0", "0.1.1") < 0
